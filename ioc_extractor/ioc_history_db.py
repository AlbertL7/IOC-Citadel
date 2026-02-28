"""
ioc_history_db.py - SQLite-backed history of parsed IOC collections.

Stores named IOC sets so analysts can search past malware / threat-group
investigations and reload the extracted indicators into the review pane.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import ioc_parser


DEFAULT_DB_PATH = Path.home() / ".ioc_extractor_ioc_history.sqlite3"
SCHEMA_VERSION = 3

# Built-in canonical mapping for common threat group aliases. Users can add more
# aliases via the threat_aliases table and REST/UI surfaces.
_DEFAULT_THREAT_ALIAS_GROUPS: dict[str, tuple[str, ...]] = {
    "APT29": ("Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes", "UNC2452"),
    "APT28": ("Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"),
    "Lazarus Group": ("Hidden Cobra", "ZINC", "Diamond Sleet"),
    "Sandworm": ("Voodoo Bear", "IRON VIKING", "Seashell Blizzard"),
    "Scattered Spider": ("UNC3944", "Oktapus", "Muddled Libra", "0ktapus"),
    "FIN7": ("Carbanak Group", "Navigator Group"),
    "Wizard Spider": ("TrickBot Group", "TEMP.MixMaster"),
    "TA542": ("Emotet",),
}

_DEFAULT_THREAT_ALIAS_LOOKUP: dict[str, str] = {}
for _canon, _aliases in _DEFAULT_THREAT_ALIAS_GROUPS.items():
    _DEFAULT_THREAT_ALIAS_LOOKUP[_canon.casefold()] = _canon
    for _alias in _aliases:
        _DEFAULT_THREAT_ALIAS_LOOKUP[str(_alias).casefold()] = _canon


@dataclass(slots=True)
class SavedCollectionResult:
    collection_id: int
    collection_name: str
    threat_context: str
    total_iocs: int
    category_count: int
    created_at: str


class IOCHistoryDB:
    """Small wrapper around a local SQLite database for IOC history."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path).expanduser() if db_path else DEFAULT_DB_PATH
        self.ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # Multi-threaded jobs/webhooks/cache writes can briefly contend; favor resiliency over strict defaults.
        try:
            conn.execute("PRAGMA busy_timeout = 10000")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA synchronous = NORMAL")
        except Exception:
            pass
        return conn

    def ensure_schema(self) -> None:
        """Create the DB schema if it does not already exist."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ioc_collections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_name TEXT NOT NULL,
                    threat_context TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    source_label TEXT NOT NULL DEFAULT 'Parser',
                    total_iocs INTEGER NOT NULL DEFAULT 0,
                    category_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                );

                CREATE TABLE IF NOT EXISTS ioc_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'Parser',
                    created_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    FOREIGN KEY (collection_id)
                        REFERENCES ioc_collections(id) ON DELETE CASCADE,
                    UNIQUE (collection_id, category, value)
                );

                CREATE INDEX IF NOT EXISTS idx_ioc_collections_created_at
                    ON ioc_collections(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ioc_collections_name
                    ON ioc_collections(collection_name);
                CREATE INDEX IF NOT EXISTS idx_ioc_collections_threat_context
                    ON ioc_collections(threat_context);
                CREATE INDEX IF NOT EXISTS idx_ioc_entries_collection
                    ON ioc_entries(collection_id);
                CREATE INDEX IF NOT EXISTS idx_ioc_entries_value
                    ON ioc_entries(value);
                CREATE INDEX IF NOT EXISTS idx_ioc_entries_normalized_value
                    ON ioc_entries(normalized_value);
                CREATE INDEX IF NOT EXISTS idx_ioc_entries_category
                    ON ioc_entries(category);

                CREATE TABLE IF NOT EXISTS saved_searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    query TEXT NOT NULL DEFAULT '',
                    category_filter TEXT NOT NULL DEFAULT '',
                    date_window_days INTEGER,
                    is_watchlist INTEGER NOT NULL DEFAULT 1,
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    updated_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_saved_searches_updated_at
                    ON saved_searches(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_saved_searches_name
                    ON saved_searches(name);

                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    query TEXT NOT NULL,
                    normalized_query TEXT NOT NULL,
                    ioc_type TEXT NOT NULL DEFAULT '',
                    request_key TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    link TEXT NOT NULL DEFAULT '',
                    response_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    expires_at TEXT,
                    last_accessed_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    hit_count INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(provider, normalized_query, ioc_type, request_key)
                );

                CREATE INDEX IF NOT EXISTS idx_enrichment_cache_lookup
                    ON enrichment_cache(provider, normalized_query, ioc_type, request_key);
                CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires
                    ON enrichment_cache(expires_at);
                CREATE INDEX IF NOT EXISTS idx_enrichment_cache_accessed
                    ON enrichment_cache(last_accessed_at DESC);

                CREATE TABLE IF NOT EXISTS threat_aliases (
                    alias TEXT PRIMARY KEY,
                    canonical_name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    updated_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_threat_aliases_canonical
                    ON threat_aliases(canonical_name);

                CREATE TABLE IF NOT EXISTS webhook_delivery_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_id TEXT NOT NULL,
                    job_id TEXT NOT NULL DEFAULT '',
                    job_kind TEXT NOT NULL DEFAULT '',
                    event TEXT NOT NULL DEFAULT '',
                    target_url TEXT NOT NULL DEFAULT '',
                    attempt_no INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'pending',
                    status_code INTEGER,
                    error TEXT NOT NULL DEFAULT '',
                    response_json TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '',
                    final_attempt INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_webhook_delivery_history_delivery
                    ON webhook_delivery_history(delivery_id, attempt_no DESC);
                CREATE INDEX IF NOT EXISTS idx_webhook_delivery_history_job
                    ON webhook_delivery_history(job_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_webhook_delivery_history_created
                    ON webhook_delivery_history(created_at DESC);
                """
            )
            self._migrate_schema(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Apply additive schema migrations and lightweight data backfills."""
        self._ensure_column(
            conn,
            table="ioc_collections",
            column="threat_context_canonical",
            ddl="ALTER TABLE ioc_collections ADD COLUMN threat_context_canonical TEXT NOT NULL DEFAULT ''",
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ioc_collections_threat_context_canonical
                ON ioc_collections(threat_context_canonical)
            """
        )
        # Backfill canonical threat context for existing rows missing the value.
        rows = conn.execute(
            """
            SELECT id, threat_context
            FROM ioc_collections
            WHERE COALESCE(threat_context_canonical, '') = ''
            """
        ).fetchall()
        if rows:
            updates: list[tuple[str, int]] = []
            for row in rows:
                raw = str(row["threat_context"] or "")
                updates.append((self.normalize_threat_context(raw, conn=conn), int(row["id"])))
            conn.executemany(
                "UPDATE ioc_collections SET threat_context_canonical = ? WHERE id = ?",
                updates,
            )
        try:
            conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        except Exception:
            pass

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection,
        *,
        table: str,
        column: str,
        ddl: str,
    ) -> None:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(r["name"]) for r in cols if r["name"] is not None}
        if column not in names:
            conn.execute(ddl)

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _sanitize_ioc_map(ioc_map: dict[str, Any] | None) -> dict[str, list[str]]:
        cleaned: dict[str, list[str]] = {}
        if not isinstance(ioc_map, dict):
            return cleaned
        for category, items in ioc_map.items():
            if not isinstance(category, str) or not category or category.startswith("__"):
                continue
            if not isinstance(items, (list, tuple, set)):
                continue
            seen: set[str] = set()
            values: list[str] = []
            for raw in items:
                value = str(raw).strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                values.append(value)
            if values:
                cleaned[category] = values
        return cleaned

    def list_threat_aliases(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alias, canonical_name, created_at, updated_at
                FROM threat_aliases
                ORDER BY canonical_name COLLATE NOCASE, alias COLLATE NOCASE
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_threat_alias(self, *, alias: str, canonical_name: str) -> dict[str, Any]:
        alias_text = str(alias or "").strip()
        canonical = str(canonical_name or "").strip()
        if not alias_text:
            raise ValueError("alias is required")
        if not canonical:
            raise ValueError("canonical_name is required")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO threat_aliases (alias, canonical_name, created_at, updated_at)
                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                ON CONFLICT(alias) DO UPDATE SET
                    canonical_name = excluded.canonical_name,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                """,
                (alias_text, canonical),
            )
            row = conn.execute(
                "SELECT alias, canonical_name, created_at, updated_at FROM threat_aliases WHERE alias = ?",
                (alias_text,),
            ).fetchone()
        return dict(row) if row else {"alias": alias_text, "canonical_name": canonical}

    def delete_threat_alias(self, alias: str) -> dict[str, Any]:
        alias_text = str(alias or "").strip()
        if not alias_text:
            raise ValueError("alias is required")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT alias, canonical_name FROM threat_aliases WHERE alias = ?",
                (alias_text,),
            ).fetchone()
            if row is None:
                raise KeyError(f"threat alias not found: {alias_text}")
            conn.execute("DELETE FROM threat_aliases WHERE alias = ?", (alias_text,))
        return {"deleted": True, "alias": str(row["alias"]), "canonical_name": str(row["canonical_name"])}

    def _threat_alias_lookup(self, conn: sqlite3.Connection | None = None) -> dict[str, str]:
        lookup = dict(_DEFAULT_THREAT_ALIAS_LOOKUP)
        owns_conn = False
        if conn is None:
            conn = self._connect()
            owns_conn = True
        try:
            rows = conn.execute(
                "SELECT alias, canonical_name FROM threat_aliases"
            ).fetchall()
            for row in rows:
                alias = str(row["alias"] or "").strip()
                canonical = str(row["canonical_name"] or "").strip()
                if alias and canonical:
                    lookup[alias.casefold()] = canonical
        finally:
            if owns_conn:
                conn.close()
        return lookup

    def normalize_threat_context(self, threat_context: str, *, conn: sqlite3.Connection | None = None) -> str:
        raw = str(threat_context or "").strip()
        if not raw:
            return ""
        lookup = self._threat_alias_lookup(conn)
        # Support multi-valued labels separated by common delimiters.
        parts = [p.strip() for p in re.split(r"\s*(?:,|;|/|\||\\\\)\s*", raw) if p.strip()]
        if not parts:
            return raw
        normalized_parts: list[str] = []
        seen: set[str] = set()
        for part in parts:
            canonical = lookup.get(part.casefold(), part)
            key = canonical.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized_parts.append(canonical)
        if not normalized_parts:
            return raw
        if len(normalized_parts) == 1:
            return normalized_parts[0]
        return " / ".join(normalized_parts)

    def rebuild_threat_context_canonical(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, threat_context FROM ioc_collections"
            ).fetchall()
            updates = [
                (self.normalize_threat_context(str(r["threat_context"] or ""), conn=conn), int(r["id"]))
                for r in rows
            ]
            if updates:
                conn.executemany(
                    "UPDATE ioc_collections SET threat_context_canonical = ? WHERE id = ?",
                    updates,
                )
        return {"updated": len(updates)}

    def save_collection(
        self,
        collection_name: str,
        ioc_map: dict[str, Any],
        threat_context: str = "",
        notes: str = "",
        source_label: str = "Parser",
    ) -> SavedCollectionResult:
        """Persist a named IOC collection and all IOC rows."""
        name = str(collection_name).strip()
        if not name:
            raise ValueError("Collection name is required.")

        cleaned = self._sanitize_ioc_map(ioc_map)
        if not cleaned:
            raise ValueError("No valid IOC data to save.")

        threat_ctx = str(threat_context or "").strip()
        with self._connect() as conn:
            threat_ctx_canonical = self.normalize_threat_context(threat_ctx, conn=conn)
            notes_text = str(notes or "").strip()
            src_label = str(source_label or "Parser").strip() or "Parser"
            total_iocs = sum(len(items) for items in cleaned.values())
            category_count = len(cleaned)

            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO ioc_collections (
                    collection_name, threat_context, threat_context_canonical, notes, source_label,
                    total_iocs, category_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, threat_ctx, threat_ctx_canonical, notes_text, src_label, total_iocs, category_count),
            )
            collection_id = int(cur.lastrowid)

            rows: list[tuple[int, str, str, str, str]] = []
            for category, items in cleaned.items():
                for value in items:
                    rows.append(
                        (
                            collection_id,
                            category,
                            value,
                            ioc_parser.refang_text(value),
                            src_label,
                        )
                    )
            cur.executemany(
                """
                INSERT OR IGNORE INTO ioc_entries (
                    collection_id, category, value, normalized_value, source
                ) VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )

            row = cur.execute(
                "SELECT created_at FROM ioc_collections WHERE id = ?",
                (collection_id,),
            ).fetchone()
            created_at = str(row["created_at"]) if row else ""

        return SavedCollectionResult(
            collection_id=collection_id,
            collection_name=name,
            threat_context=threat_ctx_canonical or threat_ctx,
            total_iocs=total_iocs,
            category_count=category_count,
            created_at=created_at,
        )

    def search_collections(self, query: str = "", limit: int = 250) -> list[dict[str, Any]]:
        """Search saved IOC collections by name, context, notes, or IOC values."""
        q = str(query or "").strip()
        lim = max(1, min(int(limit), 1000))

        sql = """
            SELECT
                c.id,
                c.collection_name,
                c.threat_context,
                c.threat_context_canonical,
                c.notes,
                c.source_label,
                c.total_iocs,
                c.category_count,
                c.created_at
            FROM ioc_collections c
        """
        params: list[Any] = []

        if q:
            like = f"%{q}%"
            sql += """
                WHERE
                    c.collection_name LIKE ? COLLATE NOCASE OR
                    c.threat_context LIKE ? COLLATE NOCASE OR
                    c.threat_context_canonical LIKE ? COLLATE NOCASE OR
                    c.notes LIKE ? COLLATE NOCASE OR
                    EXISTS (
                        SELECT 1
                        FROM ioc_entries e
                        WHERE e.collection_id = c.id
                          AND (
                              e.category LIKE ? COLLATE NOCASE OR
                              e.value LIKE ? COLLATE NOCASE OR
                              e.normalized_value LIKE ? COLLATE NOCASE
                          )
                    )
            """
            params.extend([like, like, like, like, like, like, like])

        sql += " ORDER BY c.created_at DESC LIMIT ?"
        params.append(lim)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [dict(row) for row in rows]

    def get_collection(self, collection_id: int) -> dict[str, Any] | None:
        """Return collection metadata and IOC rows/map for a saved collection."""
        cid = int(collection_id)
        with self._connect() as conn:
            meta = conn.execute(
                """
                SELECT
                    id,
                    collection_name,
                    threat_context,
                    threat_context_canonical,
                    notes,
                    source_label,
                    total_iocs,
                    category_count,
                    created_at
                FROM ioc_collections
                WHERE id = ?
                """,
                (cid,),
            ).fetchone()
            if meta is None:
                return None

            rows = conn.execute(
                """
                SELECT category, value, normalized_value, source
                FROM ioc_entries
                WHERE collection_id = ?
                ORDER BY category COLLATE NOCASE, value COLLATE NOCASE
                """,
                (cid,),
            ).fetchall()

        ioc_map: dict[str, list[str]] = {}
        entries: list[dict[str, Any]] = []
        for row in rows:
            category = str(row["category"])
            value = str(row["value"])
            normalized = str(row["normalized_value"])
            source = str(row["source"])
            ioc_map.setdefault(category, []).append(value)
            entries.append(
                {
                    "category": category,
                    "value": value,
                    "normalized_value": normalized,
                    "source": source,
                }
            )

        result = dict(meta)
        result["ioc_map"] = ioc_map
        result["entries"] = entries
        return result

    def get_collection_entries(self, collection_id: int) -> list[dict[str, Any]]:
        """Return IOC rows for a collection (without metadata)."""
        data = self.get_collection(collection_id)
        if not data:
            return []
        entries = data.get("entries")
        return entries if isinstance(entries, list) else []

    def compare_collections(self, collection_a_id: int, collection_b_id: int) -> dict[str, Any]:
        """Compare two saved collections using normalized IOC values."""
        a = self.get_collection(int(collection_a_id))
        b = self.get_collection(int(collection_b_id))
        if not a:
            raise KeyError(f"history collection not found: {int(collection_a_id)}")
        if not b:
            raise KeyError(f"history collection not found: {int(collection_b_id)}")

        def _rows(data: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
            out: dict[tuple[str, str], dict[str, Any]] = {}
            for e in (data.get("entries") or []):
                if not isinstance(e, dict):
                    continue
                category = str(e.get("category", "") or "")
                raw_value = str(e.get("value", "") or "")
                normalized = str(e.get("normalized_value", "") or ioc_parser.refang_text(raw_value))
                if not category or not normalized:
                    continue
                key = (category, normalized)
                if key not in out:
                    out[key] = {
                        "category": category,
                        "value": raw_value,
                        "normalized_value": normalized,
                        "source": str(e.get("source", "") or ""),
                    }
            return out

        a_map = _rows(a)
        b_map = _rows(b)
        a_keys = set(a_map.keys())
        b_keys = set(b_map.keys())

        def _sorted_rows(keys: set[tuple[str, str]], left: dict[tuple[str, str], dict[str, Any]], right: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for key in sorted(keys, key=lambda t: (t[0].casefold(), t[1].casefold())):
                row = dict(right.get(key) or left.get(key) or {})
                row["in_a"] = key in a_keys
                row["in_b"] = key in b_keys
                rows.append(row)
            return rows

        added_keys = b_keys - a_keys
        removed_keys = a_keys - b_keys
        unchanged_keys = a_keys & b_keys

        return {
            "collection_a": {
                "id": int(a["id"]),
                "collection_name": str(a.get("collection_name", "")),
                "threat_context": str(a.get("threat_context", "")),
                "threat_context_canonical": str(a.get("threat_context_canonical", "") or ""),
                "created_at": str(a.get("created_at", "")),
            },
            "collection_b": {
                "id": int(b["id"]),
                "collection_name": str(b.get("collection_name", "")),
                "threat_context": str(b.get("threat_context", "")),
                "threat_context_canonical": str(b.get("threat_context_canonical", "") or ""),
                "created_at": str(b.get("created_at", "")),
            },
            "summary": {
                "added": len(added_keys),
                "removed": len(removed_keys),
                "unchanged": len(unchanged_keys),
                "total_a": len(a_keys),
                "total_b": len(b_keys),
            },
            "added": _sorted_rows(added_keys, a_map, b_map),
            "removed": _sorted_rows(removed_keys, a_map, b_map),
            "unchanged": _sorted_rows(unchanged_keys, a_map, b_map),
        }

    def correlate_ioc(self, value: str, category: str | None = None, limit: int = 250) -> dict[str, Any]:
        """Show where an IOC appears across saved history collections."""
        raw_value = str(value or "").strip()
        if not raw_value:
            raise ValueError("value is required")
        normalized = ioc_parser.refang_text(raw_value)
        lim = max(1, min(int(limit), 2000))
        category_filter = str(category or "").strip()

        params: list[Any] = [raw_value, normalized]
        sql = """
            SELECT
                c.id AS collection_id,
                c.collection_name,
                c.threat_context,
                c.threat_context_canonical,
                c.notes,
                c.created_at,
                e.category,
                e.value,
                e.normalized_value,
                e.source
            FROM ioc_entries e
            JOIN ioc_collections c
              ON c.id = e.collection_id
            WHERE (e.value = ? OR e.normalized_value = ?)
        """
        if category_filter:
            sql += " AND e.category = ?"
            params.append(category_filter)
        sql += " ORDER BY c.created_at DESC LIMIT ?"
        params.append(lim)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        collections: list[dict[str, Any]] = []
        threat_groups: list[str] = []
        seen_threats: set[str] = set()
        categories: set[str] = set()
        first_seen = ""
        last_seen = ""
        for row in rows:
            created_at = str(row["created_at"] or "")
            if not last_seen:
                last_seen = created_at
            first_seen = created_at or first_seen
            category_name = str(row["category"] or "")
            if category_name:
                categories.add(category_name)
            threat = str(row["threat_context"] or "").strip()
            threat_canonical = str(row["threat_context_canonical"] or "").strip()
            threat_display = threat_canonical or threat
            if threat_display and threat_display.casefold() not in seen_threats:
                seen_threats.add(threat_display.casefold())
                threat_groups.append(threat_display)
            collections.append(
                {
                    "collection_id": int(row["collection_id"]),
                    "collection_name": str(row["collection_name"] or ""),
                    "threat_context": threat,
                    "threat_context_canonical": threat_canonical or None,
                    "created_at": created_at,
                    "category": category_name,
                    "value": str(row["value"] or ""),
                    "normalized_value": str(row["normalized_value"] or ""),
                    "source": str(row["source"] or ""),
                    "notes": str(row["notes"] or ""),
                }
            )

        return {
            "query": {"value": raw_value, "normalized_value": normalized, "category": category_filter or None},
            "summary": {
                "hits": len(collections),
                "occurrence_count": len(collections),
                "collections": len({int(r["collection_id"]) for r in collections}),
                "collection_count": len({int(r["collection_id"]) for r in collections}),
                "first_seen": first_seen or None,
                "last_seen": last_seen or None,
                "categories": sorted(categories, key=str.casefold),
                "threat_groups": threat_groups,
                "threat_group_count": len(threat_groups),
                "campaign_count": len(threat_groups),
            },
            "collections": collections,
        }

    def search_iocs(
        self,
        *,
        query: str = "",
        category_filter: str = "",
        date_window_days: int | None = None,
        limit: int = 2000,
    ) -> dict[str, Any]:
        """Search IOC rows with collection metadata and optional time/category filters."""
        q = str(query or "").strip()
        cat = str(category_filter or "").strip()
        lim = max(1, min(int(limit), 10000))
        params: list[Any] = []
        sql = """
            SELECT
                c.id AS collection_id,
                c.collection_name,
                c.threat_context,
                c.threat_context_canonical,
                c.created_at,
                e.category,
                e.value,
                e.normalized_value,
                e.source
            FROM ioc_entries e
            JOIN ioc_collections c ON c.id = e.collection_id
            WHERE 1=1
        """
        if q:
            like = f"%{q}%"
            sql += """
                AND (
                    c.collection_name LIKE ? COLLATE NOCASE OR
                    c.threat_context LIKE ? COLLATE NOCASE OR
                    c.threat_context_canonical LIKE ? COLLATE NOCASE OR
                    c.notes LIKE ? COLLATE NOCASE OR
                    e.category LIKE ? COLLATE NOCASE OR
                    e.value LIKE ? COLLATE NOCASE OR
                    e.normalized_value LIKE ? COLLATE NOCASE
                )
            """
            params.extend([like, like, like, like, like, like, like])
        if cat:
            sql += " AND e.category = ?"
            params.append(cat)
        if date_window_days is not None:
            days = max(1, min(int(date_window_days), 3650))
            sql += " AND c.created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)"
            params.append(f"-{days} days")
        sql += " ORDER BY c.created_at DESC, e.category COLLATE NOCASE, e.value COLLATE NOCASE LIMIT ?"
        params.append(lim)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        out_rows = [dict(r) for r in rows]
        return {
            "query": q,
            "category_filter": cat or None,
            "date_window_days": (None if date_window_days is None else max(1, min(int(date_window_days), 3650))),
            "count": len(out_rows),
            "rows": out_rows,
        }

    def upsert_saved_search(
        self,
        *,
        name: str,
        query: str = "",
        category_filter: str = "",
        date_window_days: int | None = None,
        is_watchlist: bool = True,
        notes: str = "",
    ) -> dict[str, Any]:
        search_name = str(name or "").strip()
        if not search_name:
            raise ValueError("saved search name is required")
        q = str(query or "").strip()
        cat = str(category_filter or "").strip()
        notes_text = str(notes or "").strip()
        days_val = None if date_window_days in (None, "", 0) else max(1, min(int(date_window_days), 3650))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO saved_searches (
                    name, query, category_filter, date_window_days, is_watchlist, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                ON CONFLICT(name) DO UPDATE SET
                    query = excluded.query,
                    category_filter = excluded.category_filter,
                    date_window_days = excluded.date_window_days,
                    is_watchlist = excluded.is_watchlist,
                    notes = excluded.notes,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                """,
                (search_name, q, cat, days_val, 1 if is_watchlist else 0, notes_text),
            )
            row = conn.execute(
                """
                SELECT id, name, query, category_filter, date_window_days, is_watchlist, notes, created_at, updated_at
                FROM saved_searches
                WHERE name = ?
                """,
                (search_name,),
            ).fetchone()
        return dict(row) if row else {"name": search_name}

    def list_saved_searches(self, *, watchlists_only: bool = False, limit: int = 250) -> list[dict[str, Any]]:
        lim = max(1, min(int(limit), 2000))
        params: list[Any] = []
        sql = """
            SELECT id, name, query, category_filter, date_window_days, is_watchlist, notes, created_at, updated_at
            FROM saved_searches
        """
        if watchlists_only:
            sql += " WHERE is_watchlist = 1"
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(lim)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def delete_saved_search(self, search_id: int) -> dict[str, Any]:
        sid = int(search_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name FROM saved_searches WHERE id = ?",
                (sid,),
            ).fetchone()
            if row is None:
                raise KeyError(f"saved search not found: {sid}")
            conn.execute("DELETE FROM saved_searches WHERE id = ?", (sid,))
        return {"deleted": True, "id": int(row["id"]), "name": str(row["name"])}

    def get_saved_search(self, search_id: int) -> dict[str, Any]:
        sid = int(search_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, name, query, category_filter, date_window_days, is_watchlist, notes, created_at, updated_at
                FROM saved_searches WHERE id = ?
                """,
                (sid,),
            ).fetchone()
        if row is None:
            raise KeyError(f"saved search not found: {sid}")
        return dict(row)

    def run_saved_search(self, search_id: int, *, limit: int = 2000) -> dict[str, Any]:
        row = self.get_saved_search(search_id)
        result = self.search_iocs(
            query=str(row.get("query") or ""),
            category_filter=str(row.get("category_filter") or ""),
            date_window_days=row.get("date_window_days"),
            limit=limit,
        )
        result["saved_search"] = row
        return result

    def delete_collection(self, collection_id: int) -> dict[str, Any]:
        """Delete a saved collection and all IOC entries (cascade)."""
        cid = int(collection_id)
        with self._connect() as conn:
            meta = conn.execute(
                """
                SELECT id, collection_name, total_iocs, category_count
                FROM ioc_collections
                WHERE id = ?
                """,
                (cid,),
            ).fetchone()
            if meta is None:
                raise KeyError(f"history collection not found: {cid}")
            conn.execute("DELETE FROM ioc_collections WHERE id = ?", (cid,))
        return {
            "deleted": True,
            "collection_id": int(meta["id"]),
            "collection_name": str(meta["collection_name"]),
            "total_iocs": int(meta["total_iocs"] or 0),
            "category_count": int(meta["category_count"] or 0),
        }

    # ------------------------------------------------------------------
    # Enrichment cache (SQLite)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_cache_request_key(request_key: str | dict[str, Any] | None) -> str:
        if request_key is None:
            return ""
        if isinstance(request_key, dict):
            try:
                return json.dumps(request_key, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            except Exception:
                return str(request_key)
        return str(request_key or "")

    def get_enrichment_cache_entry(
        self,
        *,
        provider: str,
        query: str,
        ioc_type: str = "",
        request_key: str | dict[str, Any] | None = None,
        allow_expired: bool = False,
    ) -> dict[str, Any] | None:
        prov = str(provider or "").strip().lower()
        raw_query = str(query or "").strip()
        if not prov or not raw_query:
            return None
        normalized = ioc_parser.refang_text(raw_query)
        req_key = self._normalize_cache_request_key(request_key)
        now_iso = self._utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    id, provider, query, normalized_query, ioc_type, request_key,
                    summary, link, response_json, fetched_at, expires_at, last_accessed_at, hit_count
                FROM enrichment_cache
                WHERE provider = ?
                  AND normalized_query = ?
                  AND ioc_type = ?
                  AND request_key = ?
                """,
                (prov, normalized, str(ioc_type or ""), req_key),
            ).fetchone()
            if row is None:
                return None
            expires_at = str(row["expires_at"] or "")
            expired = bool(expires_at and expires_at <= now_iso)
            if expired and not allow_expired:
                return None
            conn.execute(
                """
                UPDATE enrichment_cache
                SET hit_count = hit_count + 1,
                    last_accessed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                WHERE id = ?
                """,
                (int(row["id"]),),
            )
        response_json = str(row["response_json"] or "")
        try:
            payload = json.loads(response_json)
        except Exception:
            payload = None
        return {
            "id": int(row["id"]),
            "provider": str(row["provider"] or ""),
            "query": str(row["query"] or ""),
            "normalized_query": str(row["normalized_query"] or ""),
            "ioc_type": str(row["ioc_type"] or ""),
            "request_key": str(row["request_key"] or ""),
            "summary": str(row["summary"] or ""),
            "link": str(row["link"] or ""),
            "fetched_at": str(row["fetched_at"] or ""),
            "expires_at": (str(row["expires_at"]) if row["expires_at"] else None),
            "last_accessed_at": str(row["last_accessed_at"] or ""),
            "hit_count": int(row["hit_count"] or 0) + 1,  # reflects post-read increment
            "expired": expired,
            "payload": payload,
        }

    def put_enrichment_cache_entry(
        self,
        *,
        provider: str,
        query: str,
        ioc_type: str = "",
        request_key: str | dict[str, Any] | None = None,
        payload: Any,
        summary: str = "",
        link: str = "",
        ttl_seconds: int | None = 86400,
    ) -> dict[str, Any]:
        prov = str(provider or "").strip().lower()
        raw_query = str(query or "").strip()
        if not prov:
            raise ValueError("provider is required")
        if not raw_query:
            raise ValueError("query is required")
        normalized = ioc_parser.refang_text(raw_query)
        req_key = self._normalize_cache_request_key(request_key)
        try:
            payload_json = json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))
        except Exception:
            payload_json = json.dumps({"repr": str(payload)}, ensure_ascii=False)
        expires_at: str | None = None
        if ttl_seconds is not None:
            ttl = max(1, min(int(ttl_seconds), 365 * 24 * 3600))
            expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO enrichment_cache (
                    provider, query, normalized_query, ioc_type, request_key,
                    summary, link, response_json, fetched_at, expires_at, last_accessed_at, hit_count
                )
                VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 0
                )
                ON CONFLICT(provider, normalized_query, ioc_type, request_key) DO UPDATE SET
                    query = excluded.query,
                    summary = excluded.summary,
                    link = excluded.link,
                    response_json = excluded.response_json,
                    fetched_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                    expires_at = excluded.expires_at
                """,
                (
                    prov,
                    raw_query,
                    normalized,
                    str(ioc_type or ""),
                    req_key,
                    str(summary or ""),
                    str(link or ""),
                    payload_json,
                    expires_at,
                ),
            )
            row = conn.execute(
                """
                SELECT id, fetched_at, expires_at
                FROM enrichment_cache
                WHERE provider = ? AND normalized_query = ? AND ioc_type = ? AND request_key = ?
                """,
                (prov, normalized, str(ioc_type or ""), req_key),
            ).fetchone()
        return {
            "cached": True,
            "provider": prov,
            "normalized_query": normalized,
            "ioc_type": str(ioc_type or ""),
            "request_key": req_key,
            "cache_id": int(row["id"]) if row else None,
            "fetched_at": str(row["fetched_at"] or "") if row else self._utc_now_iso(),
            "expires_at": (str(row["expires_at"]) if row and row["expires_at"] else expires_at),
        }

    def get_enrichment_cache_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) AS n FROM enrichment_cache"
            ).fetchone()
            provider_rows = conn.execute(
                """
                SELECT provider, COUNT(*) AS count
                FROM enrichment_cache
                GROUP BY provider
                ORDER BY provider COLLATE NOCASE
                """
            ).fetchall()
            expired_row = conn.execute(
                """
                SELECT COUNT(*) AS n
                FROM enrichment_cache
                WHERE expires_at IS NOT NULL
                  AND expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                """
            ).fetchone()
        by_provider = {str(r["provider"]): int(r["count"] or 0) for r in provider_rows}
        return {
            "entries": int(total_row["n"] or 0) if total_row else 0,
            "expired_entries": int(expired_row["n"] or 0) if expired_row else 0,
            "providers": by_provider,
        }

    # ------------------------------------------------------------------
    # IOC analytics (stats / timeline / graph)
    # ------------------------------------------------------------------

    def ioc_stats(self, value: str, category: str | None = None) -> dict[str, Any]:
        raw_value = str(value or "").strip()
        if not raw_value:
            raise ValueError("value is required")
        normalized = ioc_parser.refang_text(raw_value)
        cat = str(category or "").strip()
        params: list[Any] = [raw_value, normalized]
        where_cat = ""
        if cat:
            where_cat = " AND e.category = ?"
            params.append(cat)
        campaign_expr = "COALESCE(NULLIF(trim(c.threat_context_canonical), ''), NULLIF(trim(c.threat_context), ''))"
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS occurrence_count,
                    COUNT(DISTINCT e.collection_id) AS collection_count,
                    COUNT(DISTINCT e.category) AS category_count,
                    COUNT(DISTINCT {campaign_expr}) AS campaign_count,
                    MIN(c.created_at) AS first_seen,
                    MAX(c.created_at) AS last_seen
                FROM ioc_entries e
                JOIN ioc_collections c ON c.id = e.collection_id
                WHERE (e.value = ? OR e.normalized_value = ?)
                {where_cat}
                """,
                params,
            ).fetchone()
            category_rows = conn.execute(
                f"""
                SELECT e.category, COUNT(*) AS occurrence_count, COUNT(DISTINCT e.collection_id) AS collection_count
                FROM ioc_entries e
                JOIN ioc_collections c ON c.id = e.collection_id
                WHERE (e.value = ? OR e.normalized_value = ?)
                {where_cat}
                GROUP BY e.category
                ORDER BY occurrence_count DESC, e.category COLLATE NOCASE
                """,
                params,
            ).fetchall()
            threat_rows = conn.execute(
                f"""
                SELECT
                    {campaign_expr} AS threat_context_canonical,
                    MIN(c.threat_context) AS threat_context,
                    COUNT(*) AS occurrence_count,
                    COUNT(DISTINCT e.collection_id) AS collection_count
                FROM ioc_entries e
                JOIN ioc_collections c ON c.id = e.collection_id
                WHERE (e.value = ? OR e.normalized_value = ?)
                {where_cat}
                  AND {campaign_expr} IS NOT NULL
                GROUP BY {campaign_expr}
                ORDER BY occurrence_count DESC, {campaign_expr} COLLATE NOCASE
                LIMIT 50
                """,
                params,
            ).fetchall()
        summary = {
            "occurrence_count": int(row["occurrence_count"] or 0) if row else 0,
            "collection_count": int(row["collection_count"] or 0) if row else 0,
            "category_count": int(row["category_count"] or 0) if row else 0,
            "campaign_count": int(row["campaign_count"] or 0) if row else 0,
            "first_seen": (str(row["first_seen"]) if row and row["first_seen"] else None),
            "last_seen": (str(row["last_seen"]) if row and row["last_seen"] else None),
        }
        return {
            "query": {"value": raw_value, "normalized_value": normalized, "category": cat or None},
            "summary": summary,
            "categories": [
                {
                    "category": str(r["category"] or ""),
                    "occurrence_count": int(r["occurrence_count"] or 0),
                    "collection_count": int(r["collection_count"] or 0),
                }
                for r in category_rows
            ],
            "campaigns": [
                {
                    "threat_context": str(r["threat_context"] or ""),
                    "threat_context_canonical": str(r["threat_context_canonical"] or ""),
                    "occurrence_count": int(r["occurrence_count"] or 0),
                    "collection_count": int(r["collection_count"] or 0),
                }
                for r in threat_rows
            ],
        }

    def ioc_timeline(
        self,
        value: str,
        *,
        category: str | None = None,
        bucket: str = "day",
        limit: int = 500,
    ) -> dict[str, Any]:
        raw_value = str(value or "").strip()
        if not raw_value:
            raise ValueError("value is required")
        normalized = ioc_parser.refang_text(raw_value)
        cat = str(category or "").strip()
        bucket_key = str(bucket or "day").strip().lower()
        if bucket_key not in {"day", "hour", "month"}:
            raise ValueError("bucket must be one of: day, hour, month")
        if bucket_key == "hour":
            bucket_expr = "substr(c.created_at, 1, 13) || ':00:00Z'"
        elif bucket_key == "month":
            bucket_expr = "substr(c.created_at, 1, 7) || '-01T00:00:00Z'"
        else:
            bucket_expr = "substr(c.created_at, 1, 10)"
        params: list[Any] = [raw_value, normalized]
        where_cat = ""
        if cat:
            where_cat = " AND e.category = ?"
            params.append(cat)
        campaign_expr = "COALESCE(NULLIF(trim(c.threat_context_canonical), ''), NULLIF(trim(c.threat_context), ''))"
        params.append(max(1, min(int(limit), 5000)))
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    {bucket_expr} AS bucket,
                    COUNT(*) AS occurrence_count,
                    COUNT(DISTINCT e.collection_id) AS collection_count,
                    COUNT(DISTINCT {campaign_expr}) AS campaign_count
                FROM ioc_entries e
                JOIN ioc_collections c ON c.id = e.collection_id
                WHERE (e.value = ? OR e.normalized_value = ?)
                {where_cat}
                GROUP BY bucket
                ORDER BY bucket ASC
                LIMIT ?
                """,
                params,
            ).fetchall()
        points = [
            {
                "bucket": str(r["bucket"] or ""),
                "occurrence_count": int(r["occurrence_count"] or 0),
                "collection_count": int(r["collection_count"] or 0),
                "campaign_count": int(r["campaign_count"] or 0),
            }
            for r in rows
        ]
        return {
            "query": {"value": raw_value, "normalized_value": normalized, "category": cat or None},
            "bucket": bucket_key,
            "count": len(points),
            "points": points,
        }

    def ioc_graph(
        self,
        value: str,
        *,
        category: str | None = None,
        limit: int = 250,
    ) -> dict[str, Any]:
        corr = self.correlate_ioc(value, category=category, limit=limit)
        rows = list(corr.get("collections") or [])
        query = corr.get("query") or {}
        q_norm = str(query.get("normalized_value") or query.get("value") or "")
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        node_seen: set[str] = set()

        def _add_node(node_id: str, node_type: str, label: str, **attrs: Any):
            if node_id in node_seen:
                return
            node_seen.add(node_id)
            item = {"id": node_id, "type": node_type, "label": label}
            item.update(attrs)
            nodes.append(item)

        root_id = f"ioc:{q_norm}"
        _add_node(
            root_id,
            "ioc",
            q_norm,
            raw_value=str(query.get("value") or ""),
            normalized_value=q_norm,
            category=str(query.get("category") or "") or None,
        )

        collection_seen: set[int] = set()
        threat_seen: set[str] = set()
        category_seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            cid = int(row.get("collection_id") or 0)
            cname = str(row.get("collection_name") or f"Collection {cid}")
            cat_name = str(row.get("category") or "")
            threat = str(row.get("threat_context") or "").strip()
            threat_canonical = str(row.get("threat_context_canonical") or "").strip()
            threat_display = threat_canonical or threat
            created_at = str(row.get("created_at") or "")
            coll_node = f"collection:{cid}"
            if cid not in collection_seen:
                collection_seen.add(cid)
                _add_node(
                    coll_node,
                    "collection",
                    cname,
                    collection_id=cid,
                    created_at=created_at,
                    threat_context=threat or None,
                    threat_context_canonical=threat_canonical or None,
                )
            edges.append({"source": root_id, "target": coll_node, "type": "observed_in", "category": cat_name, "created_at": created_at})
            if cat_name:
                cat_node = f"category:{cat_name}"
                if cat_name not in category_seen:
                    category_seen.add(cat_name)
                    _add_node(cat_node, "category", cat_name)
                edges.append({"source": root_id, "target": cat_node, "type": "ioc_category"})
                edges.append({"source": coll_node, "target": cat_node, "type": "contains_category"})
            if threat_display:
                t_key = threat_display.casefold()
                threat_node = f"threat:{t_key}"
                if t_key not in threat_seen:
                    threat_seen.add(t_key)
                    _add_node(
                        threat_node,
                        "threat",
                        threat_display,
                        threat_context=threat or None,
                        threat_context_canonical=threat_canonical or None,
                    )
                edges.append({"source": coll_node, "target": threat_node, "type": "attributed_to"})

        return {
            "query": query,
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "collections": len(collection_seen),
                "categories": len(category_seen),
                "campaigns": len(threat_seen),
            },
            "nodes": nodes,
            "edges": edges,
        }

    def cleanup_enrichment_cache(
        self,
        *,
        remove_expired_only: bool = True,
        provider: str | None = None,
    ) -> dict[str, Any]:
        provider_id = str(provider or "").strip().lower()
        with self._connect() as conn:
            if remove_expired_only and provider_id:
                cur = conn.execute(
                    """
                    DELETE FROM enrichment_cache
                    WHERE provider = ?
                      AND expires_at IS NOT NULL
                      AND expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    """,
                    (provider_id,),
                )
            elif remove_expired_only:
                cur = conn.execute(
                    """
                    DELETE FROM enrichment_cache
                    WHERE expires_at IS NOT NULL
                      AND expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    """
                )
            elif provider_id:
                cur = conn.execute(
                    "DELETE FROM enrichment_cache WHERE provider = ?",
                    (provider_id,),
                )
            else:
                cur = conn.execute("DELETE FROM enrichment_cache")
        return {
            "deleted": int(cur.rowcount if cur.rowcount is not None else 0),
            "provider": provider_id or None,
            "expired_only": bool(remove_expired_only),
        }

    # ------------------------------------------------------------------
    # Webhook delivery history
    # ------------------------------------------------------------------

    def record_webhook_delivery_attempt(
        self,
        *,
        delivery_id: str,
        job_id: str = "",
        job_kind: str = "",
        event: str = "",
        target_url: str = "",
        attempt_no: int = 1,
        status: str = "pending",
        status_code: int | None = None,
        error: str = "",
        response: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        final_attempt: bool = False,
    ) -> dict[str, Any]:
        did = str(delivery_id or "").strip()
        if not did:
            raise ValueError("delivery_id is required")
        try:
            response_json = json.dumps(response or {}, ensure_ascii=False, default=str)
        except Exception:
            response_json = json.dumps({"repr": str(response)}, ensure_ascii=False)
        try:
            payload_json = json.dumps(payload or {}, ensure_ascii=False, default=str)
        except Exception:
            payload_json = json.dumps({"repr": str(payload)}, ensure_ascii=False)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO webhook_delivery_history (
                    delivery_id, job_id, job_kind, event, target_url, attempt_no,
                    status, status_code, error, response_json, payload_json, final_attempt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    did,
                    str(job_id or ""),
                    str(job_kind or ""),
                    str(event or ""),
                    str(target_url or ""),
                    max(1, int(attempt_no)),
                    str(status or "pending"),
                    (None if status_code is None else int(status_code)),
                    str(error or ""),
                    response_json,
                    payload_json,
                    1 if final_attempt else 0,
                ),
            )
            row_id = int(cur.lastrowid)
            row = conn.execute(
                """
                SELECT id, delivery_id, job_id, job_kind, event, target_url, attempt_no,
                       status, status_code, error, final_attempt, created_at
                FROM webhook_delivery_history
                WHERE id = ?
                """,
                (row_id,),
            ).fetchone()
        return dict(row) if row else {"id": row_id, "delivery_id": did}

    def list_webhook_delivery_history(
        self,
        *,
        limit: int = 200,
        job_id: str | None = None,
        status: str | None = None,
        event: str | None = None,
        provider: str | None = None,
        include_payloads: bool = False,
    ) -> dict[str, Any]:
        lim = max(1, min(int(limit), 5000))
        job_id_val = str(job_id or "").strip()
        status_val = str(status or "").strip().lower()
        event_val = str(event or "").strip().lower()
        provider_val = str(provider or "").strip()
        params: list[Any] = []
        sql = """
            SELECT
                w.id, w.delivery_id, w.job_id, w.job_kind, w.event, w.target_url,
                w.attempt_no, w.status, w.status_code, w.error,
                w.response_json, w.payload_json, w.final_attempt, w.created_at
            FROM webhook_delivery_history w
            WHERE 1=1
        """
        if job_id_val:
            sql += " AND w.job_id = ?"
            params.append(job_id_val)
        if status_val:
            sql += " AND lower(w.status) = ?"
            params.append(status_val)
        if event_val:
            sql += " AND lower(w.event) = ?"
            params.append(event_val)
        if provider_val:
            sql += " AND lower(w.target_url) LIKE ?"
            params.append(f"%{provider_val.lower()}%")
        sql += " ORDER BY w.created_at DESC, w.id DESC LIMIT ?"
        params.append(lim)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            summary_rows = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM webhook_delivery_history
                WHERE (? = '' OR job_id = ?)
                  AND (? = '' OR lower(status) = ?)
                  AND (? = '' OR lower(event) = ?)
                  AND (? = '' OR lower(target_url) LIKE ?)
                GROUP BY status
                ORDER BY status
                """,
                (
                    job_id_val,
                    job_id_val,
                    status_val,
                    status_val,
                    event_val,
                    event_val,
                    provider_val.lower(),
                    (f"%{provider_val.lower()}%" if provider_val else ""),
                ),
            ).fetchall()
        out_rows: list[dict[str, Any]] = []
        for r in rows:
            item = {
                "id": int(r["id"]),
                "delivery_id": str(r["delivery_id"] or ""),
                "job_id": str(r["job_id"] or ""),
                "job_kind": str(r["job_kind"] or ""),
                "event": str(r["event"] or ""),
                "target_url": str(r["target_url"] or ""),
                "attempt_no": int(r["attempt_no"] or 0),
                "status": str(r["status"] or ""),
                "status_code": (None if r["status_code"] is None else int(r["status_code"])),
                "error": str(r["error"] or ""),
                "final_attempt": bool(r["final_attempt"]),
                "created_at": str(r["created_at"] or ""),
            }
            if include_payloads:
                try:
                    item["response"] = json.loads(str(r["response_json"] or "{}"))
                except Exception:
                    item["response"] = str(r["response_json"] or "")
                try:
                    item["payload"] = json.loads(str(r["payload_json"] or "{}"))
                except Exception:
                    item["payload"] = str(r["payload_json"] or "")
            out_rows.append(item)
        return {
            "count": len(out_rows),
            "rows": out_rows,
            "filters": {
                "job_id": job_id_val or None,
                "status": status_val or None,
                "event": event_val or None,
                "provider": provider_val or None,
                "limit": lim,
            },
            "summary_by_status": {
                str(s["status"] or ""): int(s["count"] or 0)
                for s in summary_rows
            },
        }

    def get_webhook_delivery_history_record(
        self,
        record_id: int,
        *,
        include_payloads: bool = True,
    ) -> dict[str, Any] | None:
        rid = int(record_id)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    w.id, w.delivery_id, w.job_id, w.job_kind, w.event, w.target_url,
                    w.attempt_no, w.status, w.status_code, w.error,
                    w.response_json, w.payload_json, w.final_attempt, w.created_at
                FROM webhook_delivery_history w
                WHERE w.id = ?
                """,
                (rid,),
            ).fetchone()
        if row is None:
            return None
        item: dict[str, Any] = {
            "id": int(row["id"]),
            "delivery_id": str(row["delivery_id"] or ""),
            "job_id": str(row["job_id"] or ""),
            "job_kind": str(row["job_kind"] or ""),
            "event": str(row["event"] or ""),
            "target_url": str(row["target_url"] or ""),
            "attempt_no": int(row["attempt_no"] or 0),
            "status": str(row["status"] or ""),
            "status_code": (None if row["status_code"] is None else int(row["status_code"])),
            "error": str(row["error"] or ""),
            "final_attempt": bool(row["final_attempt"]),
            "created_at": str(row["created_at"] or ""),
        }
        if include_payloads:
            try:
                item["response"] = json.loads(str(row["response_json"] or "{}"))
            except Exception:
                item["response"] = str(row["response_json"] or "")
            try:
                item["payload"] = json.loads(str(row["payload_json"] or "{}"))
            except Exception:
                item["payload"] = str(row["payload_json"] or "")
        return item

    def clear_webhook_delivery_history(self, *, older_than_days: int | None = None) -> dict[str, Any]:
        with self._connect() as conn:
            if older_than_days is None:
                cur = conn.execute("DELETE FROM webhook_delivery_history")
            else:
                days = max(1, min(int(older_than_days), 36500))
                cur = conn.execute(
                    """
                    DELETE FROM webhook_delivery_history
                    WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)
                    """,
                    (f"-{days} days",),
                )
        return {"deleted": int(cur.rowcount if cur.rowcount is not None else 0), "older_than_days": older_than_days}

    def get_db_info(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
            user_version = int(row[0]) if row and len(row) > 0 else 0
            webhook_count_row = conn.execute(
                "SELECT COUNT(*) AS n FROM webhook_delivery_history"
            ).fetchone()
            webhook_count = int(webhook_count_row["n"] or 0) if webhook_count_row else 0
        return {
            "db_path": str(self.db_path),
            "schema_version": int(SCHEMA_VERSION),
            "user_version": int(user_version),
            "collection_count": self.count_collections(),
            "cache": self.get_enrichment_cache_stats(),
            "webhook_delivery_history_count": webhook_count,
        }

    def backup_database(self, destination_path: str | Path | None = None) -> dict[str, Any]:
        dest = Path(destination_path).expanduser() if destination_path else (
            self.db_path.parent / f"{self.db_path.stem}_backup_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}{self.db_path.suffix}"
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as src_conn:
            dst_conn = sqlite3.connect(str(dest))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        size = dest.stat().st_size if dest.exists() else 0
        return {
            "ok": True,
            "destination_path": str(dest),
            "bytes": int(size),
        }

    def export_snapshot(self, *, include_entries: bool = True, limit_collections: int = 500) -> dict[str, Any]:
        lim = max(1, min(int(limit_collections), 5000))
        with self._connect() as conn:
            collections = conn.execute(
                """
                SELECT
                    id, collection_name, threat_context, threat_context_canonical,
                    notes, source_label, total_iocs, category_count, created_at
                FROM ioc_collections
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (lim,),
            ).fetchall()
            saved_searches = conn.execute(
                """
                SELECT id, name, query, category_filter, date_window_days, is_watchlist, notes, created_at, updated_at
                FROM saved_searches
                ORDER BY updated_at DESC
                """
            ).fetchall()
            aliases = conn.execute(
                "SELECT alias, canonical_name, created_at, updated_at FROM threat_aliases ORDER BY canonical_name, alias"
            ).fetchall()
            webhook_rows = conn.execute(
                """
                SELECT id, delivery_id, job_id, job_kind, event, target_url, attempt_no,
                       status, status_code, error, final_attempt, created_at
                FROM webhook_delivery_history
                ORDER BY created_at DESC, id DESC
                LIMIT 1000
                """
            ).fetchall()
            entries: list[sqlite3.Row] = []
            if include_entries and collections:
                ids = [int(r["id"]) for r in collections]
                placeholders = ",".join("?" for _ in ids)
                entries = conn.execute(
                    f"""
                    SELECT collection_id, category, value, normalized_value, source, created_at
                    FROM ioc_entries
                    WHERE collection_id IN ({placeholders})
                    ORDER BY collection_id DESC, category COLLATE NOCASE, value COLLATE NOCASE
                    """,
                    ids,
                ).fetchall()
        return {
            "exported_at": self._utc_now_iso(),
            "db_info": self.get_db_info(),
            "collections": [dict(r) for r in collections],
            "saved_searches": [dict(r) for r in saved_searches],
            "threat_aliases": [dict(r) for r in aliases],
            "webhook_delivery_history": [dict(r) for r in webhook_rows],
            "entries": [dict(r) for r in entries] if include_entries else [],
        }

    def count_collections(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM ioc_collections").fetchone()
        return int(row["n"]) if row else 0
