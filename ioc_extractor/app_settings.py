"""
app_settings.py - Persisted user preferences for IOC Citadel.

Stores a small JSON document in the user's home directory so desktop
preferences survive restarts without adding external dependencies.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .constants import APP_BRAND, APP_TITLE


SETTINGS_PATH = Path.home() / ".ioc_extractor_gui_settings.json"


@dataclass
class AppSettings:
    shell_timeout_seconds: int = 30
    nmap_timeout_seconds: int = 300
    jsluice_temp_max_age_seconds: int = 3600
    ui_density: str = "normal"  # compact | normal | comfortable
    default_parse_groups: list[str] = field(default_factory=list)
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    api_require_auth: bool = True
    api_bearer_token: str = ""
    api_auth_scope: str = "admin"  # read | jobs | admin
    api_auth_tokens: list[dict[str, Any]] = field(default_factory=list)
    api_primary_auth_token_id: str = ""
    api_allow_shell_endpoint: bool = False
    api_webhook_enabled: bool = False
    api_webhook_url: str = ""
    api_webhook_secret: str = ""
    api_webhook_events: list[str] = field(default_factory=lambda: ["done", "failed", "cancelled"])
    api_webhook_max_attempts: int = 3
    api_webhook_retry_backoff_seconds: int = 1
    enrichment_cache_ttl_seconds: dict[str, int] = field(default_factory=dict)
    qt_splitter_sizes: dict[str, list[int]] = field(default_factory=dict)
    qt_input_parse_highlighting_enabled: bool = True
    qt_input_parse_highlight_alpha: int = 60
    qt_input_parse_highlight_max_spans: int = 12000
    qt_theme_name: str = "Bulwark Black theme 1"
    qt_brand_product_name: str = APP_TITLE
    qt_brand_byline: str = APP_BRAND
    qt_brand_logo_path: str = ""

    def normalized(self) -> "AppSettings":
        """Return a sanitized copy with safe bounds and known values."""
        density = self.ui_density if self.ui_density in {
            "compact", "normal", "comfortable"
        } else "normal"
        api_host = str(getattr(self, "api_host", "127.0.0.1") or "127.0.0.1").strip()
        if not api_host:
            api_host = "127.0.0.1"
        # Keep this conservative by default; only allow wildcard hosts if explicitly set.
        api_port = max(1, min(int(getattr(self, "api_port", 8765)), 65535))
        api_token = str(getattr(self, "api_bearer_token", "") or "").strip()
        api_auth_scope = str(getattr(self, "api_auth_scope", "admin") or "admin").strip().lower()
        if api_auth_scope not in {"read", "jobs", "admin"}:
            api_auth_scope = "admin"
        api_auth_tokens = self._normalize_api_auth_tokens(getattr(self, "api_auth_tokens", []))
        api_primary_auth_token_id = str(getattr(self, "api_primary_auth_token_id", "") or "").strip()
        valid_ids = {str(item.get("id") or "") for item in api_auth_tokens if isinstance(item, dict)}
        if api_primary_auth_token_id and api_primary_auth_token_id not in valid_ids:
            api_primary_auth_token_id = ""
        if not api_primary_auth_token_id and api_auth_tokens:
            try:
                api_primary_auth_token_id = str(api_auth_tokens[0].get("id") or "")
            except Exception:
                api_primary_auth_token_id = ""
        api_webhook_enabled = bool(getattr(self, "api_webhook_enabled", False))
        api_webhook_url = str(getattr(self, "api_webhook_url", "") or "").strip()
        api_webhook_secret = str(getattr(self, "api_webhook_secret", "") or "").strip()
        raw_events = getattr(self, "api_webhook_events", ["done", "failed", "cancelled"])
        webhook_events: list[str] = []
        if isinstance(raw_events, (list, tuple)):
            for e in raw_events:
                ev = str(e or "").strip().lower()
                if ev in {"done", "failed", "cancelled"} and ev not in webhook_events:
                    webhook_events.append(ev)
        if not webhook_events:
            webhook_events = ["done", "failed", "cancelled"]
        try:
            webhook_max_attempts = int(getattr(self, "api_webhook_max_attempts", 3))
        except Exception:
            webhook_max_attempts = 3
        webhook_max_attempts = max(1, min(webhook_max_attempts, 10))
        try:
            webhook_retry_backoff_seconds = int(getattr(self, "api_webhook_retry_backoff_seconds", 1))
        except Exception:
            webhook_retry_backoff_seconds = 1
        webhook_retry_backoff_seconds = max(0, min(webhook_retry_backoff_seconds, 300))
        cache_ttls = self._normalize_cache_ttls(getattr(self, "enrichment_cache_ttl_seconds", {}))
        groups = [
            str(g) for g in self.default_parse_groups
            if isinstance(g, str)
        ]
        splitter_sizes = self._normalize_qt_splitter_sizes(
            getattr(self, "qt_splitter_sizes", {})
        )
        qt_parse_hl_enabled = bool(
            getattr(self, "qt_input_parse_highlighting_enabled", True)
        )
        try:
            qt_parse_hl_alpha = int(getattr(self, "qt_input_parse_highlight_alpha", 60))
        except Exception:
            qt_parse_hl_alpha = 60
        qt_parse_hl_alpha = max(10, min(qt_parse_hl_alpha, 200))
        try:
            qt_parse_hl_max_spans = int(
                getattr(self, "qt_input_parse_highlight_max_spans", 12000)
            )
        except Exception:
            qt_parse_hl_max_spans = 12000
        qt_parse_hl_max_spans = max(250, min(qt_parse_hl_max_spans, 100000))
        qt_theme_name = str(getattr(self, "qt_theme_name", "Bulwark Black theme 1") or "").strip()
        if not qt_theme_name:
            qt_theme_name = "Bulwark Black theme 1"
        qt_brand_product_name = str(
            getattr(self, "qt_brand_product_name", APP_TITLE) or APP_TITLE
        ).strip()
        if not qt_brand_product_name:
            qt_brand_product_name = APP_TITLE
        qt_brand_byline = str(
            getattr(self, "qt_brand_byline", APP_BRAND) or APP_BRAND
        ).strip()
        qt_brand_logo_path = str(
            getattr(self, "qt_brand_logo_path", "") or ""
        ).strip()
        return AppSettings(
            shell_timeout_seconds=max(1, min(int(self.shell_timeout_seconds), 3600)),
            nmap_timeout_seconds=max(10, min(int(self.nmap_timeout_seconds), 7200)),
            jsluice_temp_max_age_seconds=max(
                60, min(int(self.jsluice_temp_max_age_seconds), 7 * 24 * 3600)
            ),
            ui_density=density,
            default_parse_groups=groups,
            api_host=api_host,
            api_port=api_port,
            api_require_auth=bool(getattr(self, "api_require_auth", True)),
            api_bearer_token=api_token,
            api_auth_scope=api_auth_scope,
            api_auth_tokens=api_auth_tokens,
            api_primary_auth_token_id=api_primary_auth_token_id,
            api_allow_shell_endpoint=bool(
                getattr(self, "api_allow_shell_endpoint", False)
            ),
            api_webhook_enabled=api_webhook_enabled,
            api_webhook_url=api_webhook_url[:2048],
            api_webhook_secret=api_webhook_secret[:2048],
            api_webhook_events=webhook_events,
            api_webhook_max_attempts=webhook_max_attempts,
            api_webhook_retry_backoff_seconds=webhook_retry_backoff_seconds,
            enrichment_cache_ttl_seconds=cache_ttls,
            qt_splitter_sizes=splitter_sizes,
            qt_input_parse_highlighting_enabled=qt_parse_hl_enabled,
            qt_input_parse_highlight_alpha=qt_parse_hl_alpha,
            qt_input_parse_highlight_max_spans=qt_parse_hl_max_spans,
            qt_theme_name=qt_theme_name,
            qt_brand_product_name=qt_brand_product_name[:120],
            qt_brand_byline=qt_brand_byline[:160],
            qt_brand_logo_path=qt_brand_logo_path[:2048],
        )

    @staticmethod
    def _normalize_qt_splitter_sizes(raw: Any) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {}
        if not isinstance(raw, dict):
            return out
        for key, value in raw.items():
            if not isinstance(key, str) or not key.strip():
                continue
            if not isinstance(value, (list, tuple)):
                continue
            sizes: list[int] = []
            for item in value:
                try:
                    n = int(item)
                except Exception:
                    continue
                if n > 0:
                    sizes.append(n)
            if len(sizes) >= 2:
                out[key] = sizes
        return out

    @staticmethod
    def _normalize_cache_ttls(raw: Any) -> dict[str, int]:
        out: dict[str, int] = {}
        if not isinstance(raw, dict):
            return out
        for key, value in raw.items():
            provider = str(key or "").strip().lower()
            if not provider:
                continue
            try:
                ttl = int(value)
            except Exception:
                continue
            # 60s .. 30 days
            out[provider] = max(60, min(ttl, 30 * 24 * 3600))
        return out

    @staticmethod
    def _normalize_api_auth_tokens(raw: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not isinstance(raw, (list, tuple)):
            return out
        seen_ids: set[str] = set()
        seen_tokens: set[str] = set()
        for item in raw:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token", "") or "").strip()
            if not token:
                continue
            token_id = str(item.get("id", "") or "").strip()
            if not token_id:
                continue
            if token_id in seen_ids or token in seen_tokens:
                continue
            scope = str(item.get("scope", "admin") or "admin").strip().lower()
            if scope not in {"read", "jobs", "admin"}:
                scope = "admin"
            name = str(item.get("name", "") or "").strip()[:120]
            created_at = str(item.get("created_at", "") or "").strip()[:64]
            updated_at = str(item.get("updated_at", "") or "").strip()[:64]
            last_used_at = str(item.get("last_used_at", "") or "").strip()[:64]
            expires_at = str(item.get("expires_at", "") or "").strip()[:64]
            revoked_at = str(item.get("revoked_at", "") or "").strip()[:64]
            revoked_reason = str(item.get("revoked_reason", "") or "").strip()[:256]
            enabled = bool(item.get("enabled", True))
            try:
                last_used_count = int(item.get("last_used_count", 0) or 0)
            except Exception:
                last_used_count = 0
            out.append(
                {
                    "id": token_id[:120],
                    "name": name,
                    "token": token[:4096],
                    "scope": scope,
                    "enabled": enabled,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "last_used_at": last_used_at,
                    "last_used_count": max(0, last_used_count),
                    "expires_at": expires_at,
                    "revoked_at": revoked_at,
                    "revoked_reason": revoked_reason,
                }
            )
            seen_ids.add(token_id)
            seen_tokens.add(token)
        return out


def load_settings() -> AppSettings:
    """Load settings from disk, returning defaults on error."""
    try:
        if not SETTINGS_PATH.exists():
            return AppSettings()
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return AppSettings()
        return AppSettings(
            shell_timeout_seconds=data.get("shell_timeout_seconds", 30),
            nmap_timeout_seconds=data.get("nmap_timeout_seconds", 300),
            jsluice_temp_max_age_seconds=data.get(
                "jsluice_temp_max_age_seconds", 3600
            ),
            ui_density=data.get("ui_density", "normal"),
            default_parse_groups=data.get("default_parse_groups", []),
            api_host=data.get("api_host", "127.0.0.1"),
            api_port=data.get("api_port", 8765),
            api_require_auth=data.get("api_require_auth", True),
            api_bearer_token=data.get("api_bearer_token", ""),
            api_auth_scope=data.get("api_auth_scope", "admin"),
            api_auth_tokens=data.get("api_auth_tokens", []),
            api_primary_auth_token_id=data.get("api_primary_auth_token_id", ""),
            api_allow_shell_endpoint=data.get("api_allow_shell_endpoint", False),
            api_webhook_enabled=data.get("api_webhook_enabled", False),
            api_webhook_url=data.get("api_webhook_url", ""),
            api_webhook_secret=data.get("api_webhook_secret", ""),
            api_webhook_events=data.get("api_webhook_events", ["done", "failed", "cancelled"]),
            api_webhook_max_attempts=data.get("api_webhook_max_attempts", 3),
            api_webhook_retry_backoff_seconds=data.get("api_webhook_retry_backoff_seconds", 1),
            enrichment_cache_ttl_seconds=data.get("enrichment_cache_ttl_seconds", {}),
            qt_splitter_sizes=data.get("qt_splitter_sizes", {}),
            qt_input_parse_highlighting_enabled=data.get("qt_input_parse_highlighting_enabled", True),
            qt_input_parse_highlight_alpha=data.get("qt_input_parse_highlight_alpha", 60),
            qt_input_parse_highlight_max_spans=data.get("qt_input_parse_highlight_max_spans", 12000),
            qt_theme_name=data.get("qt_theme_name", "Bulwark Black theme 1"),
            qt_brand_product_name=data.get("qt_brand_product_name", APP_TITLE),
            qt_brand_byline=data.get("qt_brand_byline", APP_BRAND),
            qt_brand_logo_path=data.get("qt_brand_logo_path", ""),
        ).normalized()
    except Exception:
        return AppSettings()


def save_settings(settings: AppSettings) -> None:
    """Persist settings to disk as JSON."""
    normalized = settings.normalized()
    SETTINGS_PATH.write_text(
        json.dumps(asdict(normalized), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
