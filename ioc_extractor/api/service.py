"""
service.py - Shared application service layer for GUI and REST API.

This module centralizes stateful application workflows (sessions, parsed IOCs,
history integration, exports, and long-running jobs) so both the Tkinter GUI
and a REST API can use the same backend logic.
"""

from __future__ import annotations

import csv
import email
import email.policy
import email.utils
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .. import app_settings as settings_store
from .. import enrichment
from .. import file_operations
from .. import ioc_history_db
from .. import ioc_parser
from .. import keychain
from .. import shell_runner
from .. import tree_sitter_ingest
from .. import virustotal as vt
from ..jsluice_handler import JsluiceHandler
from ..jsluice_installer import JsluiceInstaller
from ..nmap_handler import NmapHandler
from ..nmap_installer import NmapInstaller


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_utc(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def _line_col_for_offset(text: str, offset: int) -> tuple[int, int]:
    off = max(0, min(int(offset), len(text)))
    line_start = text.rfind("\n", 0, off) + 1
    line_no = text.count("\n", 0, off) + 1
    col_no = (off - line_start) + 1
    return line_no, col_no


def _line_text_for_span(text: str, start: int, end: int) -> str:
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    line_start = text.rfind("\n", 0, s) + 1
    line_end = text.find("\n", e)
    if line_end < 0:
        line_end = len(text)
    return text[line_start:line_end]


def _paragraph_text_for_span(text: str, start: int, end: int) -> str:
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    left = text.rfind("\n\n", 0, s)
    right = text.find("\n\n", e)
    p_start = 0 if left < 0 else left + 2
    p_end = len(text) if right < 0 else right
    return text[p_start:p_end].strip()


def _build_provenance_entries(
    text: str,
    spans: list[tuple[int, int, str]] | tuple[tuple[int, int, str], ...] | None,
) -> list[dict[str, Any]]:
    """Store lightweight provenance offsets/categories; enrich context lazily on lookup."""
    entries: list[dict[str, Any]] = []
    if not text or not spans:
        return entries
    for start, end, category in spans:
        try:
            s = int(start)
            e = int(end)
        except Exception:
            continue
        if e <= s or s < 0:
            continue
        entries.append(
            {
                "start": s,
                "end": e,
                "category": str(category or ""),
            }
        )
    return entries


def _deepcopy_ioc_map(iocs: dict[str, list[str]] | None) -> dict[str, list[str]]:
    if not isinstance(iocs, dict):
        return {}
    out: dict[str, list[str]] = {}
    for k, v in iocs.items():
        if not isinstance(k, str) or not isinstance(v, list):
            continue
        out[k] = [str(item) for item in v]
    return out


def _sanitize_ioc_map(iocs: dict[str, Any] | None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not isinstance(iocs, dict):
        return out
    for category, items in iocs.items():
        if not isinstance(category, str) or not category:
            continue
        if not isinstance(items, (list, tuple, set)):
            continue
        seen: set[str] = set()
        vals: list[str] = []
        for item in items:
            s = str(item).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            vals.append(s)
        if vals:
            out[category] = sorted(vals)
    return out


def _build_review_text(iocs: dict[str, list[str]]) -> str:
    """Text export similar to the GUI review pane (without tags)."""
    if not iocs:
        return ""
    parts: list[str] = []
    for category, items in iocs.items():
        if category.startswith("__error__"):
            real_name = category.replace("__error__", "")
            err = items[0] if items else "Unknown error"
            parts.append(f"--- Error in pattern {real_name}: {err} ---")
            parts.append("")
            continue
        parts.append(f"--- {category} ---")
        parts.extend(items)
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def _ioc_summary(iocs: dict[str, list[str]]) -> dict[str, Any]:
    total = 0
    categories = 0
    category_counts: dict[str, int] = {}
    for k, items in iocs.items():
        if k.startswith("__error__"):
            continue
        categories += 1
        count = len(items)
        category_counts[k] = count
        total += count
    return {
        "total_iocs": total,
        "category_count": categories,
        "categories": category_counts,
        "summary_text": file_operations.format_ioc_summary(
            {k: v for k, v in iocs.items() if not k.startswith("__error__")}
        ) if iocs else "No IOCs found",
    }


def _validate_nmap_target(target: str) -> None:
    """Reject obvious shell metacharacters until nmap handler is argv-based."""
    if not target or not target.strip():
        raise ValueError("target is required")
    if re.search(r"[;&|><`$\n\r]", target):
        raise ValueError("target contains unsupported shell metacharacters")


def _validate_nmap_ports(ports: str) -> None:
    if not ports:
        return
    if not re.fullmatch(r"[0-9,\-\s]+", ports):
        raise ValueError("ports must contain only digits, commas, dashes, and spaces")


def _validate_nmap_flags(flags: list[str]) -> None:
    for flag in flags:
        if not isinstance(flag, str):
            raise ValueError("nmap flags must be strings")
        if re.search(r"[;&|><`$\n\r]", flag):
            raise ValueError(f"unsafe nmap flag value: {flag!r}")


def _validate_nmap_extra_args(extra_args: str) -> None:
    if not extra_args:
        return
    # Until nmap_handler switches to argv + shell=False, reject shell control chars.
    if re.search(r"[;&|><`$\n\r]", extra_args):
        raise ValueError("extra_args contains unsupported shell metacharacters")


@dataclass
class SessionState:
    session_id: str
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    input_text: str = ""
    found_iocs: dict[str, list[str]] = field(default_factory=dict)
    provenance_entries: list[dict[str, Any]] = field(default_factory=list)
    review_source: str = "Parser"
    last_outputs: dict[str, Any] = field(default_factory=dict)
    loaded_history_collection_id: int | None = None

    def touch(self) -> None:
        self.updated_at = _utc_now_iso()

    def snapshot(self, include_iocs: bool = False, include_input: bool = False) -> dict[str, Any]:
        data = {
            "id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "review_source": self.review_source,
            "loaded_history_collection_id": self.loaded_history_collection_id,
            "ioc_summary": _ioc_summary(self.found_iocs),
            "provenance_available": bool(self.provenance_entries),
            "outputs_available": sorted(self.last_outputs.keys()),
        }
        if include_input:
            data["input_text"] = self.input_text
        if include_iocs:
            data["iocs"] = _deepcopy_ioc_map(self.found_iocs)
            data["review_text"] = _build_review_text(self.found_iocs)
        return data


@dataclass
class JobRecord:
    job_id: str
    kind: str
    label: str
    status: str = "queued"  # queued|running|done|failed|cancelled|cancel_requested
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    progress: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    logs: list[str] = field(default_factory=list)
    cancellable: bool = True
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _cancel_callback: Callable[[], None] | None = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def to_public(self, include_result: bool = False) -> dict[str, Any]:
        with self._lock:
            data = {
                "id": self.job_id,
                "kind": self.kind,
                "label": self.label,
                "status": self.status,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "progress": dict(self.progress),
                "error": self.error,
                "cancellable": self.cancellable,
                "logs": list(self.logs[-100:]),
            }
            if include_result:
                data["result"] = self.result
            return data

    def _touch(self) -> None:
        self.updated_at = _utc_now_iso()

    def append_log(self, msg: str) -> None:
        with self._lock:
            self.logs.append(str(msg))
            if len(self.logs) > 1000:
                self.logs = self.logs[-500:]
            self._touch()

    def set_progress(self, **kwargs: Any) -> None:
        with self._lock:
            self.progress.update(kwargs)
            self._touch()

    def mark_running(self) -> None:
        with self._lock:
            self.status = "running"
            self.started_at = _utc_now_iso()
            self._touch()

    def mark_done(self, result: Any) -> None:
        with self._lock:
            self.status = "done"
            self.result = result
            self.finished_at = _utc_now_iso()
            self._touch()

    def mark_failed(self, error: str) -> None:
        with self._lock:
            self.status = "failed"
            self.error = error
            self.finished_at = _utc_now_iso()
            self._touch()

    def mark_cancelled(self, result: Any = None) -> None:
        with self._lock:
            self.status = "cancelled"
            self.result = result
            self.finished_at = _utc_now_iso()
            self._touch()

    def request_cancel(self) -> bool:
        with self._lock:
            if not self.cancellable:
                return False
            if self.status in ("done", "failed", "cancelled"):
                return False
            self.status = "cancel_requested"
            self._cancel_event.set()
            self._touch()
            cb = self._cancel_callback
        if cb:
            try:
                cb()
            except Exception:
                pass
        return True

    def cancel_requested(self) -> bool:
        return self._cancel_event.is_set()


class AppService:
    """Stateful backend service used by REST API (and later GUI integration)."""

    def __init__(
        self,
        *,
        allow_shell_api: bool = False,
        auth_token: str | None = None,
        require_auth: bool = True,
        history_db_path: str | None = None,
    ):
        self._lock = threading.RLock()
        self.settings = settings_store.load_settings()
        self.jsluice = JsluiceHandler(
            temp_max_age=self.settings.jsluice_temp_max_age_seconds
        )
        self.history_db = ioc_history_db.IOCHistoryDB(history_db_path) if history_db_path else ioc_history_db.IOCHistoryDB()
        self.allow_shell_api = bool(allow_shell_api)
        self.require_auth = bool(require_auth)
        self.auth_scope = "admin"
        self.auth_token = ""
        self._auth_tokens: dict[str, dict[str, Any]] = {}
        self._primary_auth_token_id: str = ""
        self._auth_usage_last_persist_ts: float = 0.0
        self.auth_token_generated = self._initialize_auth_token_registry(explicit_auth_token=auth_token)

        self._sessions: dict[str, SessionState] = {}
        self._jobs: dict[str, JobRecord] = {}
        self._webhook_config: dict[str, Any] = {
            "enabled": bool(getattr(self.settings, "api_webhook_enabled", False)),
            "url": str(getattr(self.settings, "api_webhook_url", "") or "").strip(),
            "secret": str(getattr(self.settings, "api_webhook_secret", "") or "").strip(),
            "events": list(getattr(self.settings, "api_webhook_events", ["done", "failed", "cancelled"]) or []),
            "max_attempts": int(getattr(self.settings, "api_webhook_max_attempts", 3)),
            "retry_backoff_seconds": int(getattr(self.settings, "api_webhook_retry_backoff_seconds", 1)),
        }
        self._enrichment_cache_ttls: dict[str, int] = dict(
            getattr(self.settings, "enrichment_cache_ttl_seconds", {}) or {}
        )

    @staticmethod
    def _normalize_auth_scope(scope: str | None) -> str:
        s = str(scope or "admin").strip().lower()
        return s if s in {"read", "jobs", "admin"} else "admin"

    @staticmethod
    def _scope_allows(current: str, required: str) -> bool:
        rank = {"read": 1, "jobs": 2, "admin": 3}
        return rank.get(str(current or "").strip().lower(), 0) >= rank.get(str(required or "").strip().lower(), 99)

    def has_scope(self, required: str) -> bool:
        return self._scope_allows(self.auth_scope, required)

    @staticmethod
    def _mask_token_value(token: str) -> str:
        tok = str(token or "")
        if len(tok) <= 8:
            return "*" * len(tok)
        return f"{tok[:4]}...{tok[-4:]}"

    def _generate_unique_api_token_value(self) -> str:
        existing = {str(row.get("token") or "") for row in self._auth_tokens.values()}
        while True:
            candidate = secrets.token_urlsafe(32)
            if candidate not in existing:
                return candidate

    def _new_api_token_record(
        self,
        *,
        name: str,
        scope: str,
        token: str,
        enabled: bool = True,
        token_id: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
        last_used_at: str | None = None,
        last_used_count: int | None = None,
        expires_at: str | None = None,
        revoked_at: str | None = None,
        revoked_reason: str | None = None,
    ) -> dict[str, Any]:
        now = _utc_now_iso()
        try:
            luc = int(last_used_count or 0)
        except Exception:
            luc = 0
        return {
            "id": str(token_id or uuid.uuid4()),
            "name": str(name or "").strip()[:120],
            "token": str(token or "").strip(),
            "scope": self._normalize_auth_scope(scope),
            "enabled": bool(enabled),
            "created_at": str(created_at or now),
            "updated_at": str(updated_at or now),
            "last_used_at": str(last_used_at or "").strip()[:64],
            "last_used_count": max(0, luc),
            "expires_at": str(expires_at or "").strip()[:64],
            "revoked_at": str(revoked_at or "").strip()[:64],
            "revoked_reason": str(revoked_reason or "").strip()[:256],
        }

    @staticmethod
    def _token_is_revoked(row: dict[str, Any] | None) -> bool:
        return bool(str((row or {}).get("revoked_at") or "").strip())

    @staticmethod
    def _token_is_expired(row: dict[str, Any] | None, *, now: datetime | None = None) -> bool:
        exp = _parse_iso_utc(str((row or {}).get("expires_at") or ""))
        if exp is None:
            return False
        return exp <= (now or datetime.now(timezone.utc))

    def _coerce_token_expires_at(
        self,
        *,
        expires_at: str | None = None,
        expires_in_days: int | None = None,
    ) -> str:
        if expires_in_days is not None:
            days = int(expires_in_days)
            if days <= 0:
                return ""
            days = max(1, min(days, 3650))
            return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if expires_at is None:
            return ""
        dt = _parse_iso_utc(expires_at)
        if dt is None:
            raise ValueError("expires_at must be an ISO-8601 UTC timestamp")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _persist_auth_registry_usage_updates(self, *, force: bool = False) -> None:
        now_ts = time.time()
        if not force and (now_ts - float(self._auth_usage_last_persist_ts or 0.0)) < 10.0:
            return
        try:
            self._sync_auth_registry_to_legacy_fields(persist=True)
            self._auth_usage_last_persist_ts = now_ts
        except Exception:
            pass

    def _primary_auth_token_record(self) -> dict[str, Any] | None:
        row = self._auth_tokens.get(self._primary_auth_token_id)
        if isinstance(row, dict):
            return row
        for row in self._auth_tokens.values():
            if isinstance(row, dict):
                return row
        return None

    def _sync_auth_registry_to_legacy_fields(self, *, persist: bool = False) -> None:
        primary = self._primary_auth_token_record()
        self.auth_token = str((primary or {}).get("token") or "")
        self.auth_scope = self._normalize_auth_scope((primary or {}).get("scope"))
        self.settings.api_bearer_token = self.auth_token
        self.settings.api_auth_scope = self.auth_scope
        self.settings.api_auth_tokens = [dict(v) for v in self._auth_tokens.values()]
        self.settings.api_primary_auth_token_id = str(self._primary_auth_token_id or "")
        if persist:
            settings_store.save_settings(self.settings)
            self.settings = settings_store.load_settings()
            # preserve runtime registry order/data after load normalization
            self.settings.api_auth_tokens = [dict(v) for v in self._auth_tokens.values()]
            self.settings.api_primary_auth_token_id = str(self._primary_auth_token_id or "")
            self.settings.api_bearer_token = self.auth_token
            self.settings.api_auth_scope = self.auth_scope

    def _apply_legacy_primary_auth_overrides(self) -> None:
        primary = self._primary_auth_token_record()
        if primary is None:
            return
        legacy_token = str(getattr(self.settings, "api_bearer_token", "") or "").strip()
        legacy_scope = self._normalize_auth_scope(getattr(self.settings, "api_auth_scope", primary.get("scope")))
        changed = False
        if legacy_token and legacy_token != str(primary.get("token") or ""):
            # Ensure uniqueness before overriding.
            for tid, row in self._auth_tokens.items():
                if tid != str(primary.get("id")) and str(row.get("token") or "") == legacy_token:
                    break
            else:
                primary["token"] = legacy_token
                changed = True
        if legacy_scope != str(primary.get("scope") or ""):
            primary["scope"] = legacy_scope
            changed = True
        if changed:
            primary["updated_at"] = _utc_now_iso()
        self._sync_auth_registry_to_legacy_fields(persist=False)

    def _initialize_auth_token_registry(self, *, explicit_auth_token: str | None = None) -> bool:
        generated = False
        self._auth_tokens = {}
        self._primary_auth_token_id = ""
        normalized_rows = []
        try:
            normalized_rows = list(getattr(self.settings, "api_auth_tokens", []) or [])
        except Exception:
            normalized_rows = []
        for raw in normalized_rows:
            if not isinstance(raw, dict):
                continue
            token = str(raw.get("token") or "").strip()
            if not token:
                continue
            record = self._new_api_token_record(
                name=str(raw.get("name") or ""),
                scope=str(raw.get("scope") or "admin"),
                token=token,
                enabled=bool(raw.get("enabled", True)),
                token_id=str(raw.get("id") or "") or None,
                created_at=str(raw.get("created_at") or "") or None,
                updated_at=str(raw.get("updated_at") or "") or None,
                last_used_at=str(raw.get("last_used_at") or "") or None,
                last_used_count=raw.get("last_used_count"),
                expires_at=str(raw.get("expires_at") or "") or None,
                revoked_at=str(raw.get("revoked_at") or "") or None,
                revoked_reason=str(raw.get("revoked_reason") or "") or None,
            )
            if record["id"] in self._auth_tokens:
                continue
            if any(str(v.get("token") or "") == record["token"] for v in self._auth_tokens.values()):
                continue
            self._auth_tokens[record["id"]] = record

        legacy_token = str(getattr(self.settings, "api_bearer_token", "") or "").strip()
        legacy_scope = self._normalize_auth_scope(getattr(self.settings, "api_auth_scope", "admin"))
        if legacy_token and not any(str(v.get("token") or "") == legacy_token for v in self._auth_tokens.values()):
            legacy_name = "Primary Token"
            self._auth_tokens[str(uuid.uuid4())] = self._new_api_token_record(
                name=legacy_name,
                scope=legacy_scope,
                token=legacy_token,
            )

        explicit = str(explicit_auth_token or "").strip()
        if explicit:
            found_id = None
            for tid, row in self._auth_tokens.items():
                if str(row.get("token") or "") == explicit:
                    found_id = tid
                    break
            if found_id is None:
                rec = self._new_api_token_record(
                    name="Provided Token",
                    scope=legacy_scope,
                    token=explicit,
                )
                self._auth_tokens[rec["id"]] = rec
                found_id = rec["id"]
            self._primary_auth_token_id = str(found_id or "")

        preferred_primary = str(getattr(self.settings, "api_primary_auth_token_id", "") or "").strip()
        if not self._primary_auth_token_id and preferred_primary in self._auth_tokens:
            self._primary_auth_token_id = preferred_primary

        if not self._auth_tokens:
            rec = self._new_api_token_record(
                name="Primary Token",
                scope=legacy_scope,
                token=self._generate_unique_api_token_value(),
            )
            self._auth_tokens[rec["id"]] = rec
            self._primary_auth_token_id = rec["id"]
            generated = True

        if not self._primary_auth_token_id or self._primary_auth_token_id not in self._auth_tokens:
            try:
                self._primary_auth_token_id = next(iter(self._auth_tokens.keys()))
            except StopIteration:
                self._primary_auth_token_id = ""

        self._apply_legacy_primary_auth_overrides()
        return generated

    def authenticate_bearer_token(self, token: str) -> dict[str, Any] | None:
        tok = str(token or "").strip()
        if not tok:
            return None
        now_dt = datetime.now(timezone.utc)
        with self._lock:
            for row in self._auth_tokens.values():
                if str(row.get("token") or "") != tok:
                    continue
                if not bool(row.get("enabled", True)):
                    return None
                if self._token_is_revoked(row):
                    return None
                if self._token_is_expired(row, now=now_dt):
                    return None
                row["last_used_at"] = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    row["last_used_count"] = int(row.get("last_used_count", 0) or 0) + 1
                except Exception:
                    row["last_used_count"] = 1
                row["updated_at"] = _utc_now_iso()
                out = dict(row)
                out["is_primary"] = str(row.get("id") or "") == str(self._primary_auth_token_id or "")
                out["expired"] = False
                out["revoked"] = False
                self._persist_auth_registry_usage_updates(force=False)
                return out
        return None

    def list_api_auth_tokens(self, *, include_token_values: bool = False) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        now_dt = datetime.now(timezone.utc)
        for row in self._auth_tokens.values():
            token_val = str(row.get("token") or "")
            expired = self._token_is_expired(row, now=now_dt)
            revoked = self._token_is_revoked(row)
            enabled = bool(row.get("enabled", True))
            item = {
                "id": str(row.get("id") or ""),
                "name": str(row.get("name") or ""),
                "scope": self._normalize_auth_scope(row.get("scope")),
                "enabled": enabled,
                "created_at": str(row.get("created_at") or ""),
                "updated_at": str(row.get("updated_at") or ""),
                "last_used_at": str(row.get("last_used_at") or ""),
                "last_used_count": int(row.get("last_used_count", 0) or 0),
                "expires_at": str(row.get("expires_at") or ""),
                "revoked_at": str(row.get("revoked_at") or ""),
                "revoked_reason": str(row.get("revoked_reason") or ""),
                "expired": bool(expired),
                "revoked": bool(revoked),
                "usable": bool(enabled and not expired and not revoked),
                "is_primary": str(row.get("id") or "") == str(self._primary_auth_token_id or ""),
                "token_masked": self._mask_token_value(token_val),
            }
            if include_token_values:
                item["token"] = token_val
            rows.append(item)
        rows.sort(key=lambda r: (not bool(r.get("is_primary")), str(r.get("name") or "").casefold(), str(r.get("id") or "")))
        return {
            "count": len(rows),
            "primary_token_id": str(self._primary_auth_token_id or ""),
            "tokens": rows,
        }

    def get_primary_api_auth_token(self, *, include_token_value: bool = False) -> dict[str, Any] | None:
        primary = self._primary_auth_token_record()
        if primary is None:
            return None
        for row in self.list_api_auth_tokens(include_token_values=include_token_value)["tokens"]:
            if str(row.get("id") or "") == str(primary.get("id") or ""):
                return row
        return None

    def create_api_auth_token(
        self,
        *,
        name: str = "",
        scope: str = "admin",
        token: str | None = None,
        enabled: bool = True,
        set_primary: bool = False,
        expires_at: str | None = None,
        expires_in_days: int | None = None,
    ) -> dict[str, Any]:
        tok = str(token or "").strip() or self._generate_unique_api_token_value()
        if any(str(v.get("token") or "") == tok for v in self._auth_tokens.values()):
            raise ValueError("token already exists")
        expires = ""
        if expires_at is not None or expires_in_days is not None:
            expires = self._coerce_token_expires_at(expires_at=expires_at, expires_in_days=expires_in_days)
        rec = self._new_api_token_record(
            name=(str(name or "").strip() or f"Token {len(self._auth_tokens) + 1}"),
            scope=scope,
            token=tok,
            enabled=enabled,
            expires_at=expires or None,
        )
        self._auth_tokens[str(rec["id"])] = rec
        if set_primary or not self._primary_auth_token_id:
            self._primary_auth_token_id = str(rec["id"])
        self._sync_auth_registry_to_legacy_fields(persist=True)
        created_meta = None
        for row in self.list_api_auth_tokens(include_token_values=True)["tokens"]:
            if str(row.get("id") or "") == str(rec["id"]):
                created_meta = dict(row)
                break
        if created_meta is None:
            created_meta = {
                "id": str(rec["id"]),
                "name": str(rec["name"]),
                "scope": str(rec["scope"]),
                "enabled": bool(rec["enabled"]),
                "is_primary": str(rec["id"]) == str(self._primary_auth_token_id or ""),
                "token_masked": self._mask_token_value(tok),
            }
        out = self.list_api_auth_tokens(include_token_values=False)
        out["created"] = {
            **created_meta,
            "token": tok,
        }
        return out

    def update_api_auth_token(
        self,
        token_id: str,
        *,
        name: str | None = None,
        scope: str | None = None,
        enabled: bool | None = None,
        set_primary: bool | None = None,
        expires_at: str | None = None,
        expires_in_days: int | None = None,
        clear_expiration: bool | None = None,
        revoke: bool | None = None,
        revoke_reason: str | None = None,
    ) -> dict[str, Any]:
        tid = str(token_id or "").strip()
        row = self._auth_tokens.get(tid)
        if row is None:
            raise KeyError(f"auth token not found: {tid}")
        if name is not None:
            row["name"] = str(name or "").strip()[:120]
        if scope is not None:
            row["scope"] = self._normalize_auth_scope(scope)
        if enabled is not None:
            row["enabled"] = bool(enabled)
        if clear_expiration:
            row["expires_at"] = ""
        elif (expires_at is not None) or (expires_in_days is not None):
            row["expires_at"] = self._coerce_token_expires_at(
                expires_at=expires_at,
                expires_in_days=expires_in_days,
            )
        if revoke is True:
            row["revoked_at"] = _utc_now_iso()
            row["revoked_reason"] = str(revoke_reason or "manual revoke").strip()[:256]
            row["enabled"] = False
        elif revoke is False:
            row["revoked_at"] = ""
            row["revoked_reason"] = ""
        if set_primary is True:
            self._primary_auth_token_id = tid
        elif set_primary is False and self._primary_auth_token_id == tid:
            # keep a valid primary; choose another if possible
            for oid, other in self._auth_tokens.items():
                if oid != tid and bool(other.get("enabled", True)):
                    self._primary_auth_token_id = oid
                    break
        row["updated_at"] = _utc_now_iso()
        self._sync_auth_registry_to_legacy_fields(persist=True)
        return self.list_api_auth_tokens(include_token_values=False)

    def revoke_stale_api_auth_tokens(
        self,
        *,
        older_than_days: int,
        include_never_used: bool = True,
        include_primary: bool = False,
        only_enabled: bool = True,
    ) -> dict[str, Any]:
        days = max(1, min(int(older_than_days), 3650))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        updated: list[dict[str, Any]] = []
        now_iso = _utc_now_iso()
        with self._lock:
            for tid, row in self._auth_tokens.items():
                if not isinstance(row, dict):
                    continue
                if (not include_primary) and tid == str(self._primary_auth_token_id or ""):
                    continue
                if only_enabled and not bool(row.get("enabled", True)):
                    continue
                if self._token_is_revoked(row):
                    continue
                ref_dt = _parse_iso_utc(str(row.get("last_used_at") or ""))
                if ref_dt is None:
                    if not include_never_used:
                        continue
                    ref_dt = _parse_iso_utc(str(row.get("created_at") or ""))
                if ref_dt is None or ref_dt > cutoff:
                    continue
                row["revoked_at"] = now_iso
                row["revoked_reason"] = f"revoke_by_age:{days}d"
                row["enabled"] = False
                row["updated_at"] = now_iso
                updated.append(
                    {
                        "id": str(row.get("id") or tid),
                        "name": str(row.get("name") or ""),
                        "scope": str(row.get("scope") or "admin"),
                        "last_used_at": str(row.get("last_used_at") or ""),
                        "created_at": str(row.get("created_at") or ""),
                    }
                )
        if updated:
            self._sync_auth_registry_to_legacy_fields(persist=True)
        return {
            "revoked": len(updated),
            "older_than_days": days,
            "include_never_used": bool(include_never_used),
            "include_primary": bool(include_primary),
            "only_enabled": bool(only_enabled),
            "tokens": updated,
        }

    def rotate_api_auth_token(self, token_id: str) -> dict[str, Any]:
        tid = str(token_id or "").strip()
        row = self._auth_tokens.get(tid)
        if row is None:
            raise KeyError(f"auth token not found: {tid}")
        new_token = self._generate_unique_api_token_value()
        row["token"] = new_token
        row["updated_at"] = _utc_now_iso()
        self._sync_auth_registry_to_legacy_fields(persist=True)
        return {
            "rotated": True,
            "token_id": tid,
            "token": new_token,
            "token_masked": self._mask_token_value(new_token),
            "scope": str(row.get("scope") or "admin"),
            "is_primary": tid == str(self._primary_auth_token_id or ""),
        }

    def delete_api_auth_token(self, token_id: str) -> dict[str, Any]:
        tid = str(token_id or "").strip()
        was_primary = tid == str(self._primary_auth_token_id or "")
        row = self._auth_tokens.pop(tid, None)
        if row is None:
            raise KeyError(f"auth token not found: {tid}")
        replacement: dict[str, Any] | None = None
        if not self._auth_tokens:
            rec = self._new_api_token_record(
                name="Primary Token",
                scope="admin",
                token=self._generate_unique_api_token_value(),
            )
            self._auth_tokens[str(rec["id"])] = rec
            self._primary_auth_token_id = str(rec["id"])
            replacement = {
                "id": str(rec["id"]),
                "token": str(rec["token"]),
                "scope": str(rec["scope"]),
                "token_masked": self._mask_token_value(str(rec["token"])),
            }
        elif self._primary_auth_token_id == tid or self._primary_auth_token_id not in self._auth_tokens:
            try:
                self._primary_auth_token_id = next(iter(self._auth_tokens.keys()))
            except StopIteration:
                self._primary_auth_token_id = ""
        self._sync_auth_registry_to_legacy_fields(persist=True)
        return {
            "deleted": True,
            "token_id": tid,
            "was_primary": was_primary,
            "replacement": replacement,
            "tokens": self.list_api_auth_tokens(include_token_values=False),
        }

    def set_primary_api_auth_token(self, token_id: str) -> dict[str, Any]:
        tid = str(token_id or "").strip()
        if tid not in self._auth_tokens:
            raise KeyError(f"auth token not found: {tid}")
        self._primary_auth_token_id = tid
        self._sync_auth_registry_to_legacy_fields(persist=True)
        return {
            "primary_token_id": str(self._primary_auth_token_id or ""),
            "primary_scope": self.auth_scope,
            "tokens": self.list_api_auth_tokens(include_token_values=False),
        }

    def _normalized_webhook_config(self, updates: dict[str, Any] | None = None) -> dict[str, Any]:
        base = dict(self._webhook_config)
        if updates:
            base.update(updates)
        enabled = bool(base.get("enabled", False))
        url = str(base.get("url", "") or "").strip()
        secret = str(base.get("secret", "") or "").strip()
        raw_events = base.get("events", ["done", "failed", "cancelled"])
        try:
            max_attempts = int(base.get("max_attempts", 3))
        except Exception:
            max_attempts = 3
        try:
            retry_backoff_seconds = int(base.get("retry_backoff_seconds", 1))
        except Exception:
            retry_backoff_seconds = 1
        max_attempts = max(1, min(max_attempts, 10))
        retry_backoff_seconds = max(0, min(retry_backoff_seconds, 300))
        events: list[str] = []
        if isinstance(raw_events, (list, tuple)):
            for item in raw_events:
                ev = str(item or "").strip().lower()
                if ev in {"done", "failed", "cancelled"} and ev not in events:
                    events.append(ev)
        if not events:
            events = ["done", "failed", "cancelled"]
        return {
            "enabled": enabled,
            "url": url,
            "secret": secret,
            "events": events,
            "max_attempts": max_attempts,
            "retry_backoff_seconds": retry_backoff_seconds,
        }

    def _normalized_enrichment_cache_ttls(self, raw: dict[str, Any] | None = None) -> dict[str, int]:
        data = raw if raw is not None else self._enrichment_cache_ttls
        out: dict[str, int] = {}
        if not isinstance(data, dict):
            return out
        provider_ids = {str(p.get("id") or "") for p in enrichment.list_providers()}
        for key, value in data.items():
            provider = str(key or "").strip().lower()
            if not provider or (provider_ids and provider not in provider_ids):
                continue
            try:
                ttl = int(value)
            except Exception:
                continue
            out[provider] = max(60, min(ttl, 30 * 24 * 3600))
        return out

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(self, input_text: str = "") -> dict[str, Any]:
        sid = str(uuid.uuid4())
        sess = SessionState(session_id=sid, input_text=str(input_text or ""))
        with self._lock:
            self._sessions[sid] = sess
        return sess.snapshot(include_input=True)

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [s.snapshot() for s in self._sessions.values()]

    def get_session(self, session_id: str, *, include_iocs: bool = True, include_input: bool = True) -> dict[str, Any]:
        sess = self._require_session(session_id)
        return sess.snapshot(include_iocs=include_iocs, include_input=include_input)

    def delete_session(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            existed = self._sessions.pop(session_id, None)
        return {"deleted": existed is not None, "id": session_id}

    def set_session_input(self, session_id: str, input_text: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        with self._lock:
            sess.input_text = str(input_text or "")
            sess.touch()
        return sess.snapshot(include_input=True)

    def get_session_input(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        return {"id": sess.session_id, "input_text": sess.input_text}

    def parse_session(
        self,
        session_id: str,
        *,
        selected_patterns: list[str] | None = None,
        collect_spans: bool = True,
        build_provenance: bool | None = None,
    ) -> dict[str, Any]:
        sess = self._require_session(session_id)
        text = sess.input_text or ""
        if not text.strip():
            raise ValueError("session input_text is empty")

        selected: set[str] | None = None
        if selected_patterns:
            selected = {str(x) for x in selected_patterns if str(x).strip()}
        collect_spans = bool(collect_spans)
        if build_provenance is None:
            build_provenance = collect_spans
        build_provenance = bool(build_provenance and collect_spans)

        found, spans = ioc_parser.extract_iocs(
            text,
            selected_patterns=selected,
            collect_spans=collect_spans,
        )
        clean_found = {k: v for k, v in found.items() if not k.startswith("__error__")}
        errors = {k: v for k, v in found.items() if k.startswith("__error__")}
        summary = _ioc_summary(clean_found)
        total_iocs_count = int(summary.get("total_iocs") or 0)
        provenance = _build_provenance_entries(text, spans) if build_provenance else []
        with self._lock:
            sess.found_iocs = _deepcopy_ioc_map(clean_found)
            sess.provenance_entries = provenance
            sess.review_source = "Parser"
            sess.loaded_history_collection_id = None
            sess.last_outputs["parse"] = {
                "match_spans_count": len(spans),
                "provenance_entries_count": len(provenance),
                "spans_collected": collect_spans,
                "provenance_built": build_provenance,
                "total_iocs_count": total_iocs_count,
                "errors": errors,
                "selected_patterns": sorted(selected) if selected else None,
            }
            sess.touch()

        return {
            "session": sess.snapshot(include_iocs=True),
            "match_spans_count": len(spans),
            "provenance_entries_count": len(provenance),
            "spans_collected": collect_spans,
            "provenance_built": build_provenance,
            "total_iocs_count": total_iocs_count,
            "errors": errors,
        }

    def import_session_iocs(
        self,
        session_id: str,
        iocs: dict[str, Any],
        *,
        source_label: str = "API",
    ) -> dict[str, Any]:
        sess = self._require_session(session_id)
        sanitized = _sanitize_ioc_map(iocs)
        with self._lock:
            sess.found_iocs = sanitized
            sess.provenance_entries = []
            sess.review_source = source_label or "API"
            sess.loaded_history_collection_id = None
            sess.touch()
        return sess.snapshot(include_iocs=True)

    def get_session_iocs(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        return {
            "id": sess.session_id,
            "source": sess.review_source,
            "loaded_history_collection_id": sess.loaded_history_collection_id,
            "iocs": _deepcopy_ioc_map(sess.found_iocs),
            "review_text": _build_review_text(sess.found_iocs),
            "summary": _ioc_summary(sess.found_iocs),
        }

    def get_session_ioc_provenance(
        self,
        session_id: str,
        *,
        value: str,
        category: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        sess = self._require_session(session_id)
        text = sess.input_text or ""
        target_raw = str(value or "").strip()
        if not target_raw:
            raise ValueError("value is required")
        target_norm = ioc_parser.refang_text(target_raw)
        category_filter = str(category or "").strip()
        rows: list[dict[str, Any]] = []
        for entry in sess.provenance_entries:
            if not isinstance(entry, dict):
                continue
            try:
                s = int(entry.get("start", -1))
                e = int(entry.get("end", -1))
            except Exception:
                continue
            if e <= s or s < 0 or e > len(text):
                continue
            entry_category = str(entry.get("category", ""))
            if category_filter and entry_category != category_filter:
                continue
            raw_val = text[s:e]
            norm_val = ioc_parser.refang_text(raw_val)
            if raw_val == target_raw or norm_val == target_raw or norm_val == target_norm or ioc_parser.refang_text(raw_val) == target_norm:
                line_no, col_no = _line_col_for_offset(text, s)
                rows.append(
                    {
                        "start": s,
                        "end": e,
                        "category": entry_category,
                        "raw_value": raw_val,
                        "normalized_value": norm_val,
                        "line": line_no,
                        "column": col_no,
                        "line_text": _line_text_for_span(text, s, e),
                        "paragraph_text": _paragraph_text_for_span(text, s, e),
                    }
                )
                if len(rows) >= max(1, min(int(limit), 500)):
                    break
        return {
            "session_id": sess.session_id,
            "query": {"value": target_raw, "normalized_value": target_norm, "category": category_filter or None},
            "count": len(rows),
            "provenance": rows,
        }

    def get_session_match_spans(self, session_id: str, *, limit: int = 20000) -> dict[str, Any]:
        """Return stored parser match spans for UI highlighting without reparsing."""
        sess = self._require_session(session_id)
        lim = max(1, min(int(limit), 200000))
        out: list[tuple[int, int, str]] = []
        total = 0
        for entry in sess.provenance_entries:
            if not isinstance(entry, dict):
                continue
            total += 1
            if len(out) >= lim:
                continue
            try:
                s = int(entry.get("start", -1))
                e = int(entry.get("end", -1))
            except Exception:
                continue
            if e <= s or s < 0:
                continue
            out.append((s, e, str(entry.get("category", "") or "")))
        return {
            "session_id": sess.session_id,
            "count": total,
            "spans": out,
            "truncated": total > len(out),
        }

    def build_session_provenance(
        self,
        session_id: str,
        *,
        selected_patterns: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build span/provenance data for an already-parsed session (e.g., after Fast Parse)."""
        sess = self._require_session(session_id)
        text = sess.input_text or ""
        if not text.strip():
            raise ValueError("session input_text is empty")
        if str(sess.review_source or "") != "Parser":
            raise ValueError("provenance can only be built for parser-backed sessions")

        selected: set[str] | None = None
        selected_used: list[str] | None = None
        used_last_parse_scope = False
        if selected_patterns is None:
            last_parse = sess.last_outputs.get("parse") if isinstance(sess.last_outputs, dict) else None
            last_selected = None
            if isinstance(last_parse, dict):
                raw = last_parse.get("selected_patterns")
                if isinstance(raw, list) and raw:
                    last_selected = [str(x) for x in raw if str(x).strip()]
            if last_selected:
                selected_patterns = last_selected
                used_last_parse_scope = True
        if selected_patterns:
            selected = {str(x) for x in selected_patterns if str(x).strip()}
            selected_used = sorted(selected)

        _found, spans = ioc_parser.extract_iocs(
            text,
            selected_patterns=selected,
            collect_spans=True,
        )
        provenance = _build_provenance_entries(text, spans)
        with self._lock:
            sess.provenance_entries = provenance
            parse_meta = dict(sess.last_outputs.get("parse") or {})
            parse_meta.update(
                {
                    "match_spans_count": len(spans),
                    "provenance_entries_count": len(provenance),
                    "spans_collected": True,
                    "provenance_built": True,
                }
            )
            if selected_used is not None:
                parse_meta["selected_patterns"] = selected_used
            elif "selected_patterns" not in parse_meta:
                parse_meta["selected_patterns"] = None
            sess.last_outputs["parse"] = parse_meta
            sess.touch()
        return {
            "session_id": sess.session_id,
            "review_source": sess.review_source,
            "match_spans_count": len(spans),
            "provenance_entries_count": len(provenance),
            "selected_patterns": selected_used,
            "used_last_parse_scope": used_last_parse_scope,
        }

    def clear_session_iocs(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        with self._lock:
            sess.found_iocs.clear()
            sess.provenance_entries = []
            sess.review_source = "Parser"
            sess.loaded_history_collection_id = None
            sess.touch()
        return sess.snapshot(include_iocs=True)

    def defang_session_iocs(self, session_id: str) -> dict[str, Any]:
        return self._transform_session_iocs(session_id, "defang")

    def refang_session_iocs(self, session_id: str) -> dict[str, Any]:
        return self._transform_session_iocs(session_id, "refang")

    def _transform_session_iocs(self, session_id: str, op: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        if not sess.found_iocs:
            raise ValueError("session has no IOCs")
        with self._lock:
            if op == "defang":
                sess.found_iocs = ioc_parser.defang_ioc_map(sess.found_iocs)
            elif op == "refang":
                sess.found_iocs = ioc_parser.refang_ioc_map(sess.found_iocs)
            else:
                raise ValueError(f"unsupported transform: {op}")
            sess.touch()
        return self.get_session_iocs(session_id)

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def export_grouped_text(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        text = _build_review_text(sess.found_iocs)
        return {
            "format": "txt",
            "filename": f"ioc_export_{session_id[:8]}.txt",
            "content": text,
        }

    def export_json(self, session_id: str, include_metadata: bool = True) -> dict[str, Any]:
        sess = self._require_session(session_id)
        buf = {
            "metadata": None,
            "iocs": {k: sorted(v) for k, v in sess.found_iocs.items() if v},
        }
        if include_metadata:
            summary = _ioc_summary(sess.found_iocs)
            buf["metadata"] = {
                "exported_at": _utc_now_iso(),
                "total_iocs": summary["total_iocs"],
                "categories": summary["category_count"],
                "session_id": session_id,
                "source": sess.review_source,
            }
        else:
            buf.pop("metadata", None)
        return {
            "format": "json",
            "filename": f"ioc_export_{session_id[:8]}.json",
            "content": json.dumps(buf, indent=2, ensure_ascii=False) + "\n",
            "data": buf,
        }

    def export_csv(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        sio = io.StringIO()
        writer = csv.writer(sio)
        writer.writerow(["Category", "IOC"])
        for category, items in sorted(sess.found_iocs.items()):
            for ioc in sorted(items):
                writer.writerow([category, ioc])
        return {
            "format": "csv",
            "filename": f"ioc_export_{session_id[:8]}.csv",
            "content": sio.getvalue(),
        }

    def export_per_category(self, session_id: str) -> dict[str, Any]:
        sess = self._require_session(session_id)
        files: dict[str, str] = {}
        for category, items in sess.found_iocs.items():
            if not items:
                continue
            safe_name = re.sub(r"\s+", "_", "".join(
                c for c in category if c.isalnum() or c in (" ", "_", "-")
            ).rstrip() or "unknown_category")
            files[f"{safe_name}.txt"] = "\n".join(items) + "\n"
        return {"format": "per-category", "files": files}

    # ------------------------------------------------------------------
    # History (SQLite)
    # ------------------------------------------------------------------

    def history_search(self, query: str = "", limit: int = 250) -> dict[str, Any]:
        rows = self.history_db.search_collections(query=query, limit=limit)
        return {"query": query, "count": len(rows), "collections": rows}

    def history_get_collection(self, collection_id: int) -> dict[str, Any]:
        data = self.history_db.get_collection(collection_id)
        if not data:
            raise KeyError(f"history collection not found: {collection_id}")
        return data

    def history_compare_collections(self, collection_a_id: int, collection_b_id: int) -> dict[str, Any]:
        return self.history_db.compare_collections(collection_a_id, collection_b_id)

    def history_correlate_ioc(self, value: str, *, category: str | None = None, limit: int = 250) -> dict[str, Any]:
        return self.history_db.correlate_ioc(value, category=category, limit=limit)

    def history_ioc_stats(self, value: str, *, category: str | None = None) -> dict[str, Any]:
        return self.history_db.ioc_stats(value, category=category)

    def history_ioc_timeline(
        self,
        value: str,
        *,
        category: str | None = None,
        bucket: str = "day",
        limit: int = 500,
    ) -> dict[str, Any]:
        return self.history_db.ioc_timeline(value, category=category, bucket=bucket, limit=limit)

    def history_ioc_graph(
        self,
        value: str,
        *,
        category: str | None = None,
        limit: int = 250,
    ) -> dict[str, Any]:
        return self.history_db.ioc_graph(value, category=category, limit=limit)

    def history_cache_stats(self) -> dict[str, Any]:
        return self.history_db.get_enrichment_cache_stats()

    def history_cache_cleanup(
        self,
        *,
        remove_expired_only: bool = True,
        provider: str | None = None,
    ) -> dict[str, Any]:
        provider_id = str(provider or "").strip().lower() or None
        if provider_id:
            enrichment.get_provider_meta(provider_id)
        result = self.history_db.cleanup_enrichment_cache(
            remove_expired_only=remove_expired_only,
            provider=provider_id,
        )
        result["cache"] = self.history_db.get_enrichment_cache_stats()
        return result

    def history_cache_clear_provider(self, provider: str) -> dict[str, Any]:
        return self.history_cache_cleanup(remove_expired_only=False, provider=provider)

    def history_db_info(self) -> dict[str, Any]:
        return self.history_db.get_db_info()

    def history_db_backup(self, *, destination_path: str | None = None) -> dict[str, Any]:
        return self.history_db.backup_database(destination_path=destination_path)

    def history_db_export_snapshot(
        self,
        *,
        include_entries: bool = True,
        limit_collections: int = 500,
    ) -> dict[str, Any]:
        return self.history_db.export_snapshot(
            include_entries=include_entries,
            limit_collections=limit_collections,
        )

    def threat_aliases_list(self) -> dict[str, Any]:
        rows = self.history_db.list_threat_aliases()
        return {"count": len(rows), "aliases": rows}

    def threat_aliases_upsert(self, *, alias: str, canonical_name: str) -> dict[str, Any]:
        row = self.history_db.upsert_threat_alias(alias=alias, canonical_name=canonical_name)
        return {"saved": True, "alias": row}

    def threat_aliases_delete(self, alias: str) -> dict[str, Any]:
        return self.history_db.delete_threat_alias(alias)

    def threat_aliases_rebuild(self) -> dict[str, Any]:
        result = self.history_db.rebuild_threat_context_canonical()
        result["aliases"] = len(self.history_db.list_threat_aliases())
        return result

    def history_search_iocs(
        self,
        *,
        query: str = "",
        category_filter: str = "",
        date_window_days: int | None = None,
        limit: int = 2000,
    ) -> dict[str, Any]:
        return self.history_db.search_iocs(
            query=query,
            category_filter=category_filter,
            date_window_days=date_window_days,
            limit=limit,
        )

    def history_save_collection(
        self,
        *,
        collection_name: str,
        threat_context: str = "",
        notes: str = "",
        iocs: dict[str, Any] | None = None,
        session_id: str | None = None,
        source_label: str = "API",
    ) -> dict[str, Any]:
        if session_id:
            sess = self._require_session(session_id)
            ioc_map = sess.found_iocs
            source = sess.review_source or source_label
        else:
            if iocs is None:
                raise ValueError("either session_id or iocs is required")
            ioc_map = _sanitize_ioc_map(iocs)
            source = source_label or "API"
        saved = self.history_db.save_collection(
            collection_name=collection_name,
            threat_context=threat_context,
            notes=notes,
            ioc_map=ioc_map,
            source_label=source,
        )
        return {
            "saved": True,
            "collection_id": saved.collection_id,
            "collection_name": saved.collection_name,
            "threat_context": saved.threat_context,
            "total_iocs": saved.total_iocs,
            "category_count": saved.category_count,
            "created_at": saved.created_at,
        }

    def history_delete_collection(self, collection_id: int) -> dict[str, Any]:
        return self.history_db.delete_collection(collection_id)

    def watchlist_save(
        self,
        *,
        name: str,
        query: str = "",
        category_filter: str = "",
        date_window_days: int | None = None,
        notes: str = "",
        is_watchlist: bool = True,
    ) -> dict[str, Any]:
        return self.history_db.upsert_saved_search(
            name=name,
            query=query,
            category_filter=category_filter,
            date_window_days=date_window_days,
            notes=notes,
            is_watchlist=is_watchlist,
        )

    def watchlist_list(self, *, watchlists_only: bool = True, limit: int = 250) -> dict[str, Any]:
        rows = self.history_db.list_saved_searches(watchlists_only=watchlists_only, limit=limit)
        return {"count": len(rows), "watchlists": rows}

    def watchlist_delete(self, search_id: int) -> dict[str, Any]:
        return self.history_db.delete_saved_search(search_id)

    def watchlist_run(self, search_id: int, *, limit: int = 2000) -> dict[str, Any]:
        return self.history_db.run_saved_search(search_id, limit=limit)

    def history_load_into_session(self, session_id: str, collection_id: int) -> dict[str, Any]:
        sess = self._require_session(session_id)
        data = self.history_db.get_collection(collection_id)
        if not data:
            raise KeyError(f"history collection not found: {collection_id}")
        ioc_map = data.get("ioc_map")
        if not isinstance(ioc_map, dict):
            raise ValueError("history collection has no IOC data")
        with self._lock:
            sess.found_iocs = _deepcopy_ioc_map(ioc_map)
            sess.provenance_entries = []
            sess.review_source = "History"
            sess.loaded_history_collection_id = int(collection_id)
            sess.touch()
        return {
            "loaded": True,
            "collection_id": int(collection_id),
            "collection_name": data.get("collection_name", ""),
            "session": sess.snapshot(include_iocs=True),
        }

    # ------------------------------------------------------------------
    # Bulk ingest / multi-source parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_bytes(data: bytes) -> str:
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return data.decode(encoding)
            except Exception:
                continue
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _strip_html_text(text: str) -> str:
        if not text:
            return ""
        s = re.sub(r"(?is)<script.*?>.*?</script>", " ", text)
        s = re.sub(r"(?is)<style.*?>.*?</style>", " ", s)
        s = re.sub(r"(?i)<br\\s*/?>", "\n", s)
        s = re.sub(r"(?i)</p\\s*>", "\n\n", s)
        s = re.sub(r"(?i)</div\\s*>", "\n", s)
        s = re.sub(r"(?s)<[^>]+>", " ", s)
        s = html.unescape(s)
        s = re.sub(r"\r\n?", "\n", s)
        s = re.sub(r"[ \t]+\n", "\n", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
        return s.strip()

    @staticmethod
    def _extract_text_from_eml_bytes(data: bytes) -> str:
        try:
            msg = email.message_from_bytes(data, policy=email.policy.default)
        except Exception:
            return AppService._decode_bytes(data)
        lines: list[str] = []
        lines.append("--- EMAIL HEADERS ---")
        for key, val in msg.items():
            lines.append(f"{key}: {val}")
        lines.append("")
        lines.append("--- EMAIL BODY ---")

        def _body_parts(m) -> list[str]:
            parts: list[str] = []
            if m.is_multipart():
                for part in m.walk():
                    ctype = str(part.get_content_type() or "").lower()
                    if part.is_multipart():
                        continue
                    if ctype.startswith("text/"):
                        try:
                            content = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True) or b""
                            content = AppService._decode_bytes(payload)
                        parts.append(str(content))
                return parts
            try:
                return [str(m.get_content())]
            except Exception:
                payload = m.get_payload(decode=True) or b""
                return [AppService._decode_bytes(payload)]

        body = "\n\n".join(p for p in _body_parts(msg) if str(p).strip())
        lines.append(body.strip())
        return "\n".join(lines).strip()

    @staticmethod
    def _extract_text_from_pdf_file(path: Path) -> str:
        # Optional dependency. If missing, raise a clear error for the caller.
        try:
            from pypdf import PdfReader  # type: ignore
        except Exception as exc:
            raise RuntimeError("pypdf not installed (pip install pypdf)") from exc
        reader = PdfReader(str(path))
        chunks: list[str] = []
        for idx, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if text.strip():
                chunks.append(f"--- PDF PAGE {idx + 1} ---\n{text.strip()}")
        return "\n\n".join(chunks).strip()

    def _extract_text_from_file(self, path: Path) -> tuple[str, str]:
        suffix = path.suffix.lower()
        if suffix == ".pdf":
            return self._extract_text_from_pdf_file(path), "pdf"
        data = path.read_bytes()
        if suffix in (".eml", ".msg"):
            return self._extract_text_from_eml_bytes(data), "email"
        text = self._decode_bytes(data)
        if suffix in (".html", ".htm"):
            return self._strip_html_text(text), "html"
        return text, "text"

    def bulk_ingest_session(
        self,
        session_id: str,
        *,
        inline_text: str = "",
        urls: list[str] | None = None,
        file_paths: list[str] | None = None,
        folder_paths: list[str] | None = None,
        recursive: bool = True,
        parse_after_ingest: bool = True,
        selected_patterns: list[str] | None = None,
        max_files: int = 500,
        max_url_bytes: int = 2_000_000,
        use_tree_sitter_code_ingest: bool = False,
        include_tree_sitter_previews: bool = False,
        tree_sitter_preview_max_files: int = 20,
        tree_sitter_preview_max_chars: int = 12000,
    ) -> dict[str, Any]:
        sess = self._require_session(session_id)
        sources: list[dict[str, Any]] = []
        errors: list[str] = []
        combined_parts: list[str] = []
        ts_enabled = bool(use_tree_sitter_code_ingest)
        ts_info: dict[str, Any] = {
            "enabled": ts_enabled,
            "available": None,
            "loader": None,
            "files_analyzed": 0,
            "supplements_added": 0,
            "errors": [],
            "previews": [],
        }
        _ts_missing_reported = False

        def _append_source(kind: str, label: str, text: str) -> None:
            body = str(text or "").strip()
            if not body:
                return
            sources.append({"kind": kind, "label": label, "chars": len(body)})
            combined_parts.append(f"===== SOURCE: {kind.upper()} | {label} =====\n{body}\n")

        if inline_text.strip():
            _append_source("inline", "Pasted CTI / text", inline_text)

        for raw_url in (urls or []):
            url = str(raw_url or "").strip()
            if not url:
                continue
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "IOC-Citadel/1.0 (+local-bulk-ingest)"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = resp.read(max_url_bytes + 1)
                    if len(data) > max_url_bytes:
                        raise ValueError(f"URL response too large (> {max_url_bytes} bytes)")
                    text = self._decode_bytes(data)
                    ctype = str(resp.headers.get("Content-Type", "")).lower()
                    if "html" in ctype:
                        text = self._strip_html_text(text)
                    _append_source("url", url, text)
            except Exception as exc:
                errors.append(f"URL {url}: {type(exc).__name__}: {exc}")

        collected_files: list[Path] = []
        seen_files: set[str] = set()
        for raw_path in (file_paths or []):
            p = Path(str(raw_path or "").strip()).expanduser()
            if not p:
                continue
            try:
                rp = str(p.resolve())
            except Exception:
                rp = str(p)
            if rp in seen_files:
                continue
            seen_files.add(rp)
            if p.is_file():
                collected_files.append(p)
        for raw_folder in (folder_paths or []):
            folder = Path(str(raw_folder or "").strip()).expanduser()
            if not str(folder).strip() or not folder.exists() or not folder.is_dir():
                continue
            iterator = folder.rglob("*") if recursive else folder.glob("*")
            for path in iterator:
                if len(collected_files) >= max_files:
                    break
                try:
                    if not path.is_file():
                        continue
                except Exception:
                    continue
                try:
                    rp = str(path.resolve())
                except Exception:
                    rp = str(path)
                if rp in seen_files:
                    continue
                seen_files.add(rp)
                collected_files.append(path)

        supported_suffixes = {
            ".txt", ".log", ".json", ".csv", ".xml", ".html", ".htm", ".js", ".md",
            ".yml", ".yaml", ".ini", ".conf", ".cfg", ".ps1", ".bat", ".sh", ".eml", ".msg", ".pdf",
            ".py", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".bash", ".zsh",
        }
        files_processed = 0
        files_skipped = 0
        for path in collected_files[:max_files]:
            suffix = path.suffix.lower()
            if suffix and suffix not in supported_suffixes:
                files_skipped += 1
                continue
            try:
                text, fmt = self._extract_text_from_file(path)
                if not text.strip():
                    continue
                _append_source(fmt, str(path), text)
                if ts_enabled and fmt == "text":
                    ts_result = tree_sitter_ingest.build_code_aware_supplement(path, text)
                    if ts_result.get("supported"):
                        ts_info["files_analyzed"] = int(ts_info.get("files_analyzed", 0) or 0) + 1
                        if ts_info.get("available") is None:
                            ts_info["available"] = bool(ts_result.get("available"))
                        if ts_result.get("loader"):
                            ts_info["loader"] = ts_result.get("loader")
                        ts_err = str(ts_result.get("error") or "").strip()
                        if ts_err:
                            if bool(ts_result.get("available")) is False:
                                if not _ts_missing_reported:
                                    _ts_missing_reported = True
                                    ts_info["errors"].append(ts_err)
                            else:
                                ts_info["errors"].append(f"{path.name}: {ts_err}")
                        supplement = str(ts_result.get("supplement_text") or "").strip()
                        if supplement:
                            lang = str(ts_result.get("language") or "code")
                            _append_source("treesitter", f"{path} [{lang}]", supplement)
                            ts_info["supplements_added"] = int(ts_info.get("supplements_added", 0) or 0) + 1
                            if include_tree_sitter_previews:
                                previews = ts_info.get("previews")
                                if isinstance(previews, list) and len(previews) < max(1, int(tree_sitter_preview_max_files)):
                                    preview_text = supplement
                                    max_chars = max(500, min(int(tree_sitter_preview_max_chars), 200_000))
                                    if len(preview_text) > max_chars:
                                        preview_text = preview_text[:max_chars].rstrip() + "\n...[truncated]"
                                    previews.append(
                                        {
                                            "path": str(path),
                                            "language": lang,
                                            "preview_text": preview_text,
                                            "stats": dict(ts_result.get("stats") or {}),
                                        }
                                    )
                files_processed += 1
            except Exception as exc:
                errors.append(f"File {path}: {type(exc).__name__}: {exc}")

        combined_text = "\n\n".join(part.strip() for part in combined_parts if part.strip()).strip()
        if not combined_text:
            raise ValueError("No ingestable content found in the provided URLs/files/folders/text.")

        with self._lock:
            sess.input_text = combined_text
            sess.touch()
            sess.last_outputs["bulk_ingest"] = {
                "sources": sources,
                "errors": errors,
                "files_processed": files_processed,
                "files_skipped": files_skipped,
                "tree_sitter": ts_info,
            }

        out: dict[str, Any] = {
            "session_id": sess.session_id,
            "sources_count": len(sources),
            "sources": sources,
            "errors": errors,
            "files_processed": files_processed,
            "files_skipped": files_skipped,
            "input_chars": len(combined_text),
            "tree_sitter": ts_info,
        }
        if parse_after_ingest:
            parsed = self.parse_session(session_id, selected_patterns=selected_patterns)
            out["parse"] = {
                "match_spans_count": parsed.get("match_spans_count", 0),
                "provenance_entries_count": parsed.get("provenance_entries_count", 0),
                "errors": parsed.get("errors") or {},
            }
            out["session"] = parsed.get("session")
        else:
            out["session"] = sess.snapshot(include_input=True)
        return out

    # ------------------------------------------------------------------
    # Settings and capabilities
    # ------------------------------------------------------------------

    def get_capabilities(self) -> dict[str, Any]:
        nmap = NmapHandler()
        history_info = self.history_db.get_db_info()
        return {
            "api": {
                "allow_shell_api": self.allow_shell_api,
                "require_auth": self.require_auth,
                "auth_scope": self.auth_scope,
                "auth_token_generated": self.auth_token_generated,
                "auth_tokens": {
                    "count": len(self._auth_tokens),
                    "primary_token_id": str(self._primary_auth_token_id or ""),
                },
                "webhook": self.get_job_webhook_config(include_secret=False),
            },
            "tools": {
                "jsluice_available": self.jsluice.available,
                "nmap_available": nmap.available,
                "keychain_available": keychain.is_available(),
                "tree_sitter_code_ingest": tree_sitter_ingest.availability_info(),
            },
            "history": {
                "db_path": str(self.history_db.db_path),
                "collection_count": self.history_db.count_collections(),
                "enrichment_cache": self.history_db.get_enrichment_cache_stats(),
                "db_info": history_info,
                "threat_alias_count": len(self.history_db.list_threat_aliases()),
            },
            "vt_rate_limiter": {
                "requests_remaining": vt.get_rate_limiter().requests_remaining,
            },
            "enrichment": {
                "providers": enrichment.list_providers(),
                "cache_ttl_seconds": self.get_enrichment_cache_ttl_settings(),
            },
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            sessions = len(self._sessions)
            jobs = len(self._jobs)
            running_jobs = sum(1 for j in self._jobs.values() if j.status in ("queued", "running", "cancel_requested"))
        return {
            "now": _utc_now_iso(),
            "sessions": sessions,
            "jobs_total": jobs,
            "jobs_active": running_jobs,
            "capabilities": self.get_capabilities(),
        }

    def get_settings(self) -> dict[str, Any]:
        s = self.settings
        return {
            "shell_timeout_seconds": s.shell_timeout_seconds,
            "nmap_timeout_seconds": s.nmap_timeout_seconds,
            "jsluice_temp_max_age_seconds": s.jsluice_temp_max_age_seconds,
            "ui_density": s.ui_density,
            "default_parse_groups": list(s.default_parse_groups),
            "api_auth_scope": self.auth_scope,
            "api_auth_tokens": self.list_api_auth_tokens(include_token_values=False),
            "api_webhook": self.get_job_webhook_config(include_secret=False),
            "api_webhook_max_attempts": int(getattr(s, "api_webhook_max_attempts", 3)),
            "api_webhook_retry_backoff_seconds": int(getattr(s, "api_webhook_retry_backoff_seconds", 1)),
            "enrichment_cache_ttl_seconds": self.get_enrichment_cache_ttl_settings(),
        }

    def get_enrichment_cache_ttl_settings(self) -> dict[str, int]:
        return dict(self._normalized_enrichment_cache_ttls())

    def update_enrichment_cache_ttl_settings(self, ttl_seconds_by_provider: dict[str, Any]) -> dict[str, Any]:
        self._enrichment_cache_ttls = self._normalized_enrichment_cache_ttls(ttl_seconds_by_provider)
        try:
            self.settings.enrichment_cache_ttl_seconds = dict(self._enrichment_cache_ttls)
            settings_store.save_settings(self.settings)
            self.settings = settings_store.load_settings()
        except Exception:
            pass
        return self.get_enrichment_cache_ttl_settings()

    def get_job_webhook_config(self, *, include_secret: bool = False) -> dict[str, Any]:
        cfg = self._normalized_webhook_config()
        out = {
            "enabled": bool(cfg["enabled"]),
            "url": str(cfg["url"] or ""),
            "events": list(cfg["events"]),
            "max_attempts": int(cfg.get("max_attempts", 3)),
            "retry_backoff_seconds": int(cfg.get("retry_backoff_seconds", 1)),
            "has_secret": bool(str(cfg["secret"] or "").strip()),
        }
        if include_secret:
            out["secret"] = str(cfg["secret"] or "")
        return out

    def get_job_webhook_delivery_history(
        self,
        *,
        limit: int = 200,
        job_id: str | None = None,
        status: str | None = None,
        event: str | None = None,
        provider: str | None = None,
        include_payloads: bool = False,
    ) -> dict[str, Any]:
        return self.history_db.list_webhook_delivery_history(
            limit=limit,
            job_id=job_id,
            status=status,
            event=event,
            provider=provider,
            include_payloads=include_payloads,
        )

    def get_job_webhook_delivery_history_record(
        self,
        record_id: int,
        *,
        include_payloads: bool = True,
    ) -> dict[str, Any]:
        row = self.history_db.get_webhook_delivery_history_record(
            int(record_id),
            include_payloads=include_payloads,
        )
        if not row:
            raise KeyError(f"webhook delivery record not found: {int(record_id)}")
        return row

    def clear_job_webhook_delivery_history(self, *, older_than_days: int | None = None) -> dict[str, Any]:
        result = self.history_db.clear_webhook_delivery_history(older_than_days=older_than_days)
        result["history"] = self.history_db.list_webhook_delivery_history(limit=50, include_payloads=False)
        return result

    def update_job_webhook_config(
        self,
        *,
        enabled: bool | None = None,
        url: str | None = None,
        secret: str | None = None,
        events: list[str] | None = None,
        max_attempts: int | None = None,
        retry_backoff_seconds: int | None = None,
        persist: bool = True,
    ) -> dict[str, Any]:
        updates: dict[str, Any] = {}
        if enabled is not None:
            updates["enabled"] = bool(enabled)
        if url is not None:
            updates["url"] = str(url or "").strip()
        if secret is not None:
            updates["secret"] = str(secret or "").strip()
        if events is not None:
            updates["events"] = list(events)
        if max_attempts is not None:
            updates["max_attempts"] = int(max_attempts)
        if retry_backoff_seconds is not None:
            updates["retry_backoff_seconds"] = int(retry_backoff_seconds)
        self._webhook_config = self._normalized_webhook_config(updates)
        if persist:
            try:
                self.settings.api_webhook_enabled = bool(self._webhook_config["enabled"])
                self.settings.api_webhook_url = str(self._webhook_config["url"] or "")
                self.settings.api_webhook_secret = str(self._webhook_config["secret"] or "")
                self.settings.api_webhook_events = list(self._webhook_config["events"] or [])
                self.settings.api_webhook_max_attempts = int(self._webhook_config.get("max_attempts", 3))
                self.settings.api_webhook_retry_backoff_seconds = int(
                    self._webhook_config.get("retry_backoff_seconds", 1)
                )
                settings_store.save_settings(self.settings)
                self.settings = settings_store.load_settings()
            except Exception:
                pass
        return self.get_job_webhook_config(include_secret=False)

    def _build_job_webhook_payload(self, job: JobRecord, event: str) -> dict[str, Any]:
        return {
            "event": f"job.{event}",
            "job": job.to_public(include_result=True),
            "service": "IOC Citadel",
            "emitted_at": _utc_now_iso(),
        }

    def _send_job_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        cfg = self._normalized_webhook_config()
        url = str(cfg.get("url") or "").strip()
        if not cfg.get("enabled") or not url:
            return {"sent": False, "reason": "disabled_or_missing_url"}
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "IOC-Citadel/REST-Webhook",
            "X-IOC-Citadel-Event": str(payload.get("event") or ""),
        }
        secret = str(cfg.get("secret") or "").strip()
        if secret:
            sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-IOC-Citadel-Signature"] = f"sha256={sig}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = getattr(resp, "status", None) or getattr(resp, "code", None) or 200
                return {"sent": True, "status_code": int(status)}
        except urllib.error.HTTPError as exc:
            return {"sent": False, "status_code": int(getattr(exc, "code", 0) or 0), "error": f"HTTPError: {exc}"}
        except Exception as exc:
            return {"sent": False, "error": f"{type(exc).__name__}: {exc}"}

    def _send_job_webhook_with_retries(
        self,
        payload: dict[str, Any],
        *,
        max_attempts: int | None = None,
        retry_backoff_seconds: float | None = None,
        job: JobRecord | None = None,
        event: str = "",
        record_history: bool = True,
    ) -> dict[str, Any]:
        cfg = self._normalized_webhook_config()
        target_url = str(cfg.get("url") or "").strip()
        if not cfg.get("enabled") or not target_url:
            result = {"sent": False, "reason": "disabled_or_missing_url"}
            if record_history:
                try:
                    self.history_db.record_webhook_delivery_attempt(
                        delivery_id=str(uuid.uuid4()),
                        job_id=str((job.job_id if job else "") or ""),
                        job_kind=str((job.kind if job else "") or ""),
                        event=str(event or payload.get("event") or ""),
                        target_url=target_url,
                        attempt_no=1,
                        status="skipped",
                        error=str(result.get("reason") or ""),
                        response=result,
                        payload=payload,
                        final_attempt=True,
                    )
                except Exception:
                    pass
            return {**result, "attempts": 0}

        try:
            attempts = int(max_attempts if max_attempts is not None else cfg.get("max_attempts", 3))
        except Exception:
            attempts = 3
        attempts = max(1, min(attempts, 10))
        try:
            backoff = float(
                retry_backoff_seconds if retry_backoff_seconds is not None else cfg.get("retry_backoff_seconds", 1)
            )
        except Exception:
            backoff = 1.0
        backoff = max(0.0, min(backoff, 300.0))
        delivery_id = str(uuid.uuid4())
        attempt_results: list[dict[str, Any]] = []
        final: dict[str, Any] = {"sent": False}
        for attempt_no in range(1, attempts + 1):
            final_attempt = attempt_no >= attempts
            result = self._send_job_webhook(payload)
            final = dict(result)
            attempt_record = {
                "attempt_no": attempt_no,
                "final_attempt": final_attempt,
                **result,
            }
            attempt_results.append(attempt_record)
            if record_history:
                try:
                    self.history_db.record_webhook_delivery_attempt(
                        delivery_id=delivery_id,
                        job_id=str((job.job_id if job else "") or ""),
                        job_kind=str((job.kind if job else "") or ""),
                        event=str(event or payload.get("event") or ""),
                        target_url=target_url,
                        attempt_no=attempt_no,
                        status=("sent" if bool(result.get("sent")) else "failed"),
                        status_code=result.get("status_code"),
                        error=str(result.get("error") or result.get("reason") or ""),
                        response=result,
                        payload=payload,
                        final_attempt=final_attempt or bool(result.get("sent")),
                    )
                except Exception:
                    pass
            if result.get("sent"):
                break
            if not final_attempt:
                try:
                    time.sleep(backoff * (2 ** (attempt_no - 1)))
                except Exception:
                    pass
        return {
            **final,
            "delivery_id": delivery_id,
            "attempts": len(attempt_results),
            "attempt_results": attempt_results,
            "target_url": target_url,
            "event": str(event or payload.get("event") or ""),
        }

    def _dispatch_job_webhook_async(self, job: JobRecord, event: str) -> None:
        cfg = self._normalized_webhook_config()
        if not cfg.get("enabled"):
            return
        if event not in set(cfg.get("events") or []):
            return
        payload = self._build_job_webhook_payload(job, event)

        def _worker():
            result = self._send_job_webhook_with_retries(payload, job=job, event=event)
            try:
                job.append_log(f"webhook[{event}]: {result}")
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def test_job_webhook(self, *, include_sample_result: bool = True) -> dict[str, Any]:
        sample_job = JobRecord(job_id="webhook-test", kind="test", label="Webhook Test", status="done")
        sample_job.mark_running()
        if include_sample_result:
            sample_job.mark_done({"ok": True, "sample": True})
        else:
            sample_job.mark_done(None)
        payload = self._build_job_webhook_payload(sample_job, "done")
        send_result = self._send_job_webhook_with_retries(payload, job=sample_job, event="done")
        return {"payload": payload, "send_result": send_result}

    def export_openclaw_config(
        self,
        *,
        base_url: str,
        include_token: bool = True,
    ) -> dict[str, Any]:
        url = str(base_url or "").strip().rstrip("/")
        if not url:
            raise ValueError("base_url is required")
        headers = {}
        token = str(self.auth_token or "").strip() if include_token else ""
        if self.require_auth and token:
            headers["Authorization"] = f"Bearer {token}"
        return {
            "name": "IOC Citadel OpenClaw Integration",
            "base_url": url,
            "auth_required": bool(self.require_auth),
            "auth_scope": self.auth_scope,
            "headers": headers,
            "endpoints": {
                "health": f"{url}/api/v1/health",
                "capabilities": f"{url}/api/v1/capabilities",
                "sessions": f"{url}/api/v1/sessions",
                "auth_tokens": f"{url}/api/v1/auth/tokens",
                "auth_tokens_revoke_stale": f"{url}/api/v1/auth/tokens/revoke-stale",
                "parse": f"{url}/api/v1/sessions/{{session_id}}/parse",
                "jobs": f"{url}/api/v1/jobs",
                "job_events_sse": f"{url}/api/v1/jobs/events/stream",
                "enrich_providers": f"{url}/api/v1/enrich/providers",
                "enrich_lookup": f"{url}/api/v1/enrich/{{provider}}/lookup",
                "enrich_cache_ttl_settings": f"{url}/api/v1/enrich/cache/settings",
                "history_compare": f"{url}/api/v1/history/compare",
                "history_correlate": f"{url}/api/v1/history/correlate",
                "ioc_stats": f"{url}/api/v1/history/iocs/stats",
                "ioc_timeline": f"{url}/api/v1/history/iocs/timeline",
                "ioc_graph": f"{url}/api/v1/history/iocs/graph",
                "history_ioc_search": f"{url}/api/v1/history/iocs/search",
                "history_cache_stats": f"{url}/api/v1/history/cache",
                "history_cache_cleanup": f"{url}/api/v1/history/cache/cleanup",
                "history_cache_clear_provider": f"{url}/api/v1/history/cache/providers/{{provider}}/clear",
                "history_db_info": f"{url}/api/v1/history/db/info",
                "history_db_backup": f"{url}/api/v1/history/db/backup",
                "history_db_export": f"{url}/api/v1/history/db/export",
                "threat_aliases": f"{url}/api/v1/history/threat-aliases",
                "threat_aliases_rebuild": f"{url}/api/v1/history/threat-aliases/rebuild",
                "job_webhook_config": f"{url}/api/v1/webhooks/job-completion",
                "job_webhook_test": f"{url}/api/v1/webhooks/job-completion/test",
                "job_webhook_history": f"{url}/api/v1/webhooks/job-completion/history",
            },
            "examples": {
                "enrich_urlscan_lookup": {
                    "method": "POST",
                    "path": "/api/v1/enrich/urlscan/lookup",
                    "json": {"values": ["example.com", "hxxp://evil[.]example/login"], "limit": 10},
                },
                "sse_job_events": {
                    "method": "GET",
                    "path": "/api/v1/jobs/events/stream?poll_ms=500",
                },
                "threat_alias_upsert": {
                    "method": "POST",
                    "path": "/api/v1/history/threat-aliases",
                    "json": {"alias": "Cozy Bear", "canonical_name": "APT29"},
                },
                "webhook_config": {
                    "method": "PUT",
                    "path": "/api/v1/webhooks/job-completion",
                    "json": {"enabled": True, "url": "https://example.com/webhooks/ioc-citadel", "events": ["done", "failed"]},
                },
                "api_token_create": {
                    "method": "POST",
                    "path": "/api/v1/auth/tokens",
                    "json": {"name": "OpenClaw Jobs", "scope": "jobs", "set_primary": False},
                },
                "revoke_stale_tokens": {
                    "method": "POST",
                    "path": "/api/v1/auth/tokens/revoke-stale",
                    "json": {"older_than_days": 30, "include_never_used": True, "include_primary": False},
                },
            },
        }

    def update_settings(self, **updates: Any) -> dict[str, Any]:
        merged = settings_store.AppSettings(
            shell_timeout_seconds=updates.get("shell_timeout_seconds", self.settings.shell_timeout_seconds),
            nmap_timeout_seconds=updates.get("nmap_timeout_seconds", self.settings.nmap_timeout_seconds),
            jsluice_temp_max_age_seconds=updates.get(
                "jsluice_temp_max_age_seconds",
                self.settings.jsluice_temp_max_age_seconds,
            ),
            ui_density=updates.get("ui_density", self.settings.ui_density),
            default_parse_groups=updates.get("default_parse_groups", self.settings.default_parse_groups),
            api_auth_scope=updates.get("api_auth_scope", self.auth_scope),
            api_webhook_enabled=updates.get(
                "api_webhook_enabled",
                bool(self._webhook_config.get("enabled", False)),
            ),
            api_webhook_url=updates.get("api_webhook_url", str(self._webhook_config.get("url", "") or "")),
            api_webhook_secret=updates.get("api_webhook_secret", str(self._webhook_config.get("secret", "") or "")),
            api_webhook_events=updates.get("api_webhook_events", list(self._webhook_config.get("events", []) or [])),
            api_webhook_max_attempts=updates.get(
                "api_webhook_max_attempts",
                int(self._webhook_config.get("max_attempts", 3)),
            ),
            api_webhook_retry_backoff_seconds=updates.get(
                "api_webhook_retry_backoff_seconds",
                int(self._webhook_config.get("retry_backoff_seconds", 1)),
            ),
            enrichment_cache_ttl_seconds=updates.get(
                "enrichment_cache_ttl_seconds",
                dict(self._enrichment_cache_ttls),
            ),
        ).normalized()
        settings_store.save_settings(merged)
        self.settings = merged
        # Keep backward-compatible token/scope fields in sync with the token registry's primary token.
        self._initialize_auth_token_registry(explicit_auth_token=str(getattr(self.settings, "api_bearer_token", "") or "").strip() or None)
        self.auth_scope = self._normalize_auth_scope(getattr(self.settings, "api_auth_scope", "admin"))
        # The settings path above may set primary scope/token via legacy fields; apply them to primary registry token.
        self._apply_legacy_primary_auth_overrides()
        self._webhook_config = self._normalized_webhook_config(
            {
                "enabled": getattr(self.settings, "api_webhook_enabled", False),
                "url": getattr(self.settings, "api_webhook_url", ""),
                "secret": getattr(self.settings, "api_webhook_secret", ""),
                "events": getattr(self.settings, "api_webhook_events", []),
                "max_attempts": getattr(self.settings, "api_webhook_max_attempts", 3),
                "retry_backoff_seconds": getattr(self.settings, "api_webhook_retry_backoff_seconds", 1),
            }
        )
        self._enrichment_cache_ttls = self._normalized_enrichment_cache_ttls(
            getattr(self.settings, "enrichment_cache_ttl_seconds", {})
        )
        try:
            self.jsluice.set_temp_max_age(self.settings.jsluice_temp_max_age_seconds)
        except Exception:
            pass
        return self.get_settings()

    # ------------------------------------------------------------------
    # VT / enrichment key management
    # ------------------------------------------------------------------

    def vt_key_status(self) -> dict[str, Any]:
        return {
            "stored": bool(keychain.load_api_key()),
            "secure_storage_available": keychain.is_available(),
        }

    def vt_key_store(self, api_key: str) -> dict[str, Any]:
        key = str(api_key or "").strip()
        if not key:
            raise ValueError("api_key is required")
        ok = keychain.store_api_key(key)
        return {"stored": bool(ok)}

    def vt_key_delete(self) -> dict[str, Any]:
        ok = keychain.delete_api_key()
        return {"deleted": bool(ok)}

    def intel_provider_list(self) -> dict[str, Any]:
        providers = enrichment.list_providers()
        out: list[dict[str, Any]] = []
        for p in providers:
            pid = str(p.get("id") or "")
            row = dict(p)
            try:
                row["stored"] = bool(keychain.load_provider_api_key(pid))
            except Exception:
                row["stored"] = False
            row["secure_storage_available"] = keychain.is_available()
            out.append(row)
        return {"providers": out}

    def intel_provider_key_status(self, provider: str) -> dict[str, Any]:
        meta = enrichment.get_provider_meta(provider)
        return {
            "provider": meta.provider_id,
            "label": meta.label,
            "requires_api_key": meta.requires_api_key,
            "optional_api_key": meta.optional_api_key,
            "stored": bool(keychain.load_provider_api_key(meta.provider_id)),
            "secure_storage_available": keychain.is_available(),
        }

    def intel_provider_key_store(self, provider: str, api_key: str) -> dict[str, Any]:
        meta = enrichment.get_provider_meta(provider)
        key = str(api_key or "").strip()
        if not key:
            raise ValueError("api_key is required")
        ok = keychain.store_provider_api_key(meta.provider_id, key)
        return {"provider": meta.provider_id, "stored": bool(ok)}

    def intel_provider_key_delete(self, provider: str) -> dict[str, Any]:
        meta = enrichment.get_provider_meta(provider)
        ok = keychain.delete_provider_api_key(meta.provider_id)
        return {"provider": meta.provider_id, "deleted": bool(ok)}

    def _resolve_vt_key(self, explicit_key: str | None) -> str:
        key = (explicit_key or "").strip()
        if key:
            return key
        stored = keychain.load_api_key()
        if stored:
            return stored
        raise ValueError("VirusTotal API key not provided and no stored key found")

    def _resolve_intel_provider_key(self, provider: str, explicit_key: str | None) -> str | None:
        meta = enrichment.get_provider_meta(provider)
        key = (explicit_key or "").strip()
        if key:
            return key
        stored = keychain.load_provider_api_key(meta.provider_id)
        if stored:
            return stored
        if meta.requires_api_key:
            raise ValueError(f"{meta.label} API key not provided and no stored key found")
        return None

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def list_jobs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return [j.to_public(include_result=False) for j in jobs[: max(1, min(limit, 1000))]]

    def get_job(self, job_id: str, include_result: bool = False) -> dict[str, Any]:
        job = self._require_job(job_id)
        return job.to_public(include_result=include_result)

    def get_job_result(self, job_id: str) -> dict[str, Any]:
        job = self._require_job(job_id)
        data = job.to_public(include_result=True)
        data["result_only"] = job.result
        return data

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        job = self._require_job(job_id)
        ok = job.request_cancel()
        return {"id": job_id, "cancel_requested": ok, "status": job.to_public()["status"]}

    def _create_job(
        self,
        *,
        kind: str,
        label: str,
        cancellable: bool = True,
        cancel_callback: Callable[[], None] | None = None,
        target: Callable[[JobRecord], Any],
    ) -> dict[str, Any]:
        jid = str(uuid.uuid4())
        job = JobRecord(job_id=jid, kind=kind, label=label, cancellable=cancellable)
        job._cancel_callback = cancel_callback
        with self._lock:
            self._jobs[jid] = job

        def _worker():
            job.mark_running()
            try:
                result = target(job)
                if job.cancel_requested():
                    job.mark_cancelled(result)
                    self._dispatch_job_webhook_async(job, "cancelled")
                else:
                    job.mark_done(result)
                    self._dispatch_job_webhook_async(job, "done")
            except Exception as exc:
                tb = traceback.format_exc(limit=8)
                job.mark_failed(f"{type(exc).__name__}: {exc}")
                job.append_log(tb)
                self._dispatch_job_webhook_async(job, "failed")

        threading.Thread(target=_worker, daemon=True).start()
        return job.to_public()

    # ------------------------------------------------------------------
    # VT jobs
    # ------------------------------------------------------------------

    @staticmethod
    def _prepare_vt_values(values: list[str]) -> list[tuple[str, str]]:
        prepared: list[tuple[str, str]] = []
        for v in values:
            orig = str(v).strip()
            if not orig:
                continue
            prepared.append((orig, ioc_parser.refang_text(orig)))
        return prepared

    def _vt_batch_job(
        self,
        *,
        kind: str,
        label: str,
        values: list[str],
        api_key: str,
        per_item_fn: Callable[[str], Any],
        precheck: Callable[[str], bool] | None = None,
    ) -> dict[str, Any]:
        prepared = self._prepare_vt_values(values)
        if not prepared:
            raise ValueError("values list is empty")

        def _run(job: JobRecord) -> dict[str, Any]:
            results: list[dict[str, Any]] = []
            total = len(prepared)
            for idx, (orig, query_val) in enumerate(prepared, 1):
                if job.cancel_requested():
                    job.append_log("Cancellation requested; stopping batch.")
                    break
                job.set_progress(current=idx - 1, total=total, current_value=orig)
                if precheck and not precheck(query_val):
                    results.append({"input": orig, "query": query_val, "skipped": True, "reason": "unsupported input"})
                    continue
                item_result = per_item_fn(query_val)
                results.append({"input": orig, "query": query_val, "result": item_result})
                job.set_progress(current=idx, total=total, current_value=orig)
            return {
                "count_requested": len(values),
                "count_processed": len(results),
                "results": results,
            }

        return self._create_job(kind=kind, label=label, target=_run)

    def start_vt_check_job(self, values: list[str], *, api_key: str | None = None) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        return self._vt_batch_job(
            kind="vt_check",
            label="VirusTotal Check",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.query_ioc(key, q),
            precheck=None,
        )

    def start_vt_submit_urls_job(self, values: list[str], *, api_key: str | None = None) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        return self._vt_batch_job(
            kind="vt_submit_urls",
            label="VirusTotal Submit URLs",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.submit_url(key, q),
            precheck=vt.is_url,
        )

    def start_vt_hash_details_job(self, values: list[str], *, api_key: str | None = None) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        return self._vt_batch_job(
            kind="vt_hash_details",
            label="VirusTotal Hash Details",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.get_hash_details(key, q),
            precheck=vt.is_hash,
        )

    def start_vt_mitre_job(self, values: list[str], *, api_key: str | None = None) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        return self._vt_batch_job(
            kind="vt_mitre",
            label="VirusTotal MITRE TTPs",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.get_mitre_ttps(key, q),
            precheck=vt.is_hash,
        )

    def start_vt_behavior_job(self, values: list[str], *, api_key: str | None = None) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        return self._vt_batch_job(
            kind="vt_behavior",
            label="VirusTotal Behavior Analysis",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.get_file_behavior(key, q),
            precheck=vt.is_hash,
        )

    def start_vt_resolutions_job(
        self,
        values: list[str],
        *,
        api_key: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        lim = max(1, min(int(limit), 100))
        return self._vt_batch_job(
            kind="vt_resolutions",
            label="VirusTotal DNS Resolutions",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.get_resolutions(key, q, limit=lim),
            precheck=lambda q: vt.is_ip(q) or vt.is_domain(q),
        )

    def start_vt_communicating_files_job(
        self,
        values: list[str],
        *,
        api_key: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        key = self._resolve_vt_key(api_key)
        lim = max(1, min(int(limit), 100))
        return self._vt_batch_job(
            kind="vt_communicating_files",
            label="VirusTotal Communicating Files",
            values=values,
            api_key=key,
            per_item_fn=lambda q: vt.get_communicating_files(key, q, limit=lim),
            precheck=lambda q: vt.is_ip(q) or vt.is_domain(q),
        )

    # ------------------------------------------------------------------
    # Multi-provider enrichment jobs
    # ------------------------------------------------------------------

    def _intel_batch_job(
        self,
        *,
        provider: str,
        values: list[str],
        api_key: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        meta = enrichment.get_provider_meta(provider)
        prepared = self._prepare_vt_values(values)
        if not prepared:
            raise ValueError("values list is empty")
        key = self._resolve_intel_provider_key(meta.provider_id, api_key)
        eff_limit = None if limit is None else max(1, min(int(limit), 500))
        cache_request_key = {"limit": eff_limit}

        def _cache_ttl_seconds(provider_id: str, entry: dict[str, Any] | None) -> int:
            pid = str(provider_id or "").strip().lower()
            override = self.get_enrichment_cache_ttl_settings().get(pid)
            if override is not None:
                return int(override)
            # Conservative defaults; short TTLs for volatile reputation/noise APIs.
            if pid in ("abuseipdb", "greynoise"):
                return 6 * 3600
            if pid in ("urlscan", "passive_dns"):
                return 12 * 3600
            if pid in ("otx",):
                return 12 * 3600
            if pid in ("whois_rdap",):
                return 7 * 24 * 3600
            return 24 * 3600

        def _run(job: JobRecord) -> dict[str, Any]:
            results: list[dict[str, Any]] = []
            total = len(prepared)
            for idx, (orig, query_val) in enumerate(prepared, 1):
                if job.cancel_requested():
                    job.append_log("Cancellation requested; stopping batch.")
                    break
                job.set_progress(
                    current=idx - 1,
                    total=total,
                    current_value=orig,
                    provider=meta.provider_id,
                )
                query_ioc_type = enrichment.detect_ioc_type(query_val)
                entry: dict[str, Any] | Any
                cache_hit = self.history_db.get_enrichment_cache_entry(
                    provider=meta.provider_id,
                    query=query_val,
                    ioc_type=query_ioc_type,
                    request_key=cache_request_key,
                )
                if cache_hit and isinstance(cache_hit.get("payload"), dict):
                    entry = dict(cache_hit.get("payload") or {})
                    if isinstance(entry, dict):
                        entry["cached"] = True
                        entry["cache_meta"] = {
                            "cache_id": cache_hit.get("id"),
                            "fetched_at": cache_hit.get("fetched_at"),
                            "expires_at": cache_hit.get("expires_at"),
                            "hit_count": cache_hit.get("hit_count"),
                        }
                    job.append_log(f"Cache hit ({meta.provider_id}): {query_val}")
                else:
                    entry = enrichment.lookup(
                        meta.provider_id,
                        query_val,
                        api_key=key,
                        limit=eff_limit,
                    )
                    if isinstance(entry, dict):
                        entry.setdefault("provider", meta.provider_id)
                        entry.setdefault("provider_label", meta.label)
                        entry.setdefault("query", query_val)
                        try:
                            self.history_db.put_enrichment_cache_entry(
                                provider=meta.provider_id,
                                query=query_val,
                                ioc_type=str(entry.get("ioc_type") or ""),
                                request_key=cache_request_key,
                                payload=entry,
                                summary=str(entry.get("summary") or ""),
                                link=str(entry.get("link") or ""),
                                ttl_seconds=_cache_ttl_seconds(meta.provider_id, entry),
                            )
                        except Exception as cache_exc:
                            job.append_log(f"Cache store warning ({meta.provider_id}): {cache_exc}")
                results.append({"input": orig, "query": query_val, **(entry if isinstance(entry, dict) else {"result": entry})})
                job.set_progress(
                    current=idx,
                    total=total,
                    current_value=orig,
                    provider=meta.provider_id,
                )
            return {
                "provider": meta.provider_id,
                "provider_label": meta.label,
                "limit": eff_limit,
                "count_requested": len(values),
                "count_processed": len(results),
                "results": results,
            }

        return self._create_job(
            kind=f"intel_enrich_{meta.provider_id}",
            label=f"{meta.label} Lookup",
            target=_run,
        )

    def start_intel_lookup_job(
        self,
        provider: str,
        values: list[str],
        *,
        api_key: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        return self._intel_batch_job(
            provider=provider,
            values=values,
            api_key=api_key,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Jsluice / Nmap / Shell / Installers jobs
    # ------------------------------------------------------------------

    def start_jsluice_job(
        self,
        *,
        text: str,
        mode: str,
        custom_options: str = "",
        raw_output: bool = False,
    ) -> dict[str, Any]:
        if not str(text or "").strip():
            raise ValueError("text is required")

        def _run(job: JobRecord) -> dict[str, Any]:
            job.set_progress(stage="running")
            result = self.jsluice.run(text, mode, custom_options, raw_output)
            return result

        return self._create_job(kind="jsluice_run", label=f"Jsluice ({mode})", target=_run)

    def start_nmap_job(
        self,
        *,
        target: str,
        scan_type_flag: str = "",
        flags: list[str] | None = None,
        ports: str = "",
        extra_args: str = "",
        use_sudo: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        _validate_nmap_target(target)
        _validate_nmap_ports(ports)
        flags_list = [str(f) for f in (flags or []) if str(f).strip()]
        _validate_nmap_flags(flags_list)
        _validate_nmap_extra_args(extra_args)
        if ports:
            flags_list = list(flags_list) + [f"-p {ports}"]

        handler = NmapHandler()
        if not handler.available:
            raise RuntimeError("nmap is not installed or not found in PATH")

        effective_timeout = (
            int(timeout) if timeout is not None else self.settings.nmap_timeout_seconds
        )

        def _run(job: JobRecord) -> dict[str, Any]:
            job.set_progress(stage="running", target=target)
            result = handler.run(
                target=target,
                scan_type_flag=scan_type_flag,
                flags=flags_list,
                extra_args=extra_args,
                use_sudo=bool(use_sudo),
                timeout=effective_timeout,
            )
            return result

        return self._create_job(
            kind="nmap_run",
            label=f"Nmap {target}",
            cancel_callback=handler.stop,
            target=_run,
        )

    def start_shell_job(self, *, command: str, timeout: int | None = None) -> dict[str, Any]:
        if not self.allow_shell_api:
            raise PermissionError("shell API endpoint is disabled")
        cmd = str(command or "").strip()
        if not cmd:
            raise ValueError("command is required")
        effective_timeout = (
            int(timeout) if timeout is not None else self.settings.shell_timeout_seconds
        )

        def _run(job: JobRecord) -> dict[str, Any]:
            job.set_progress(stage="running")
            # Note: shell_runner currently uses shell=True; keep shell API disabled
            # by default and require explicit opt-in.
            result = shell_runner.run_command_raw(cmd, timeout=effective_timeout)
            return result

        return self._create_job(
            kind="shell_run",
            label=f"Shell: {cmd[:48]}",
            cancellable=False,
            target=_run,
        )

    def start_jsluice_install_job(self) -> dict[str, Any]:
        installer = JsluiceInstaller()

        def _run(job: JobRecord) -> dict[str, Any]:
            def _progress(msg: str) -> None:
                job.append_log(msg)
                job.set_progress(message=msg)
            result = installer.full_install(_progress)
            try:
                self.jsluice.reinitialize()
            except Exception:
                pass
            return result

        return self._create_job(
            kind="jsluice_install",
            label="Install jsluice",
            cancellable=False,
            target=_run,
        )

    def start_nmap_install_job(self) -> dict[str, Any]:
        installer = NmapInstaller()

        def _run(job: JobRecord) -> dict[str, Any]:
            def _progress(msg: str) -> None:
                job.append_log(msg)
                job.set_progress(message=msg)
            result = installer.full_install(_progress)
            return result

        return self._create_job(
            kind="nmap_install",
            label="Install nmap",
            cancellable=False,
            target=_run,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_session(self, session_id: str) -> SessionState:
        with self._lock:
            sess = self._sessions.get(session_id)
        if sess is None:
            raise KeyError(f"session not found: {session_id}")
        return sess

    def _require_job(self, job_id: str) -> JobRecord:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        return job
