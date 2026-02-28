"""
server.py - FastAPI REST API for IOC Citadel.

Exposes a local-first authenticated REST interface for parsing IOCs, managing
session state, searching history, and running long-running analyses as jobs.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

from .. import __version__ as APP_VERSION
from .service import AppService

try:
    from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
    from fastapi.responses import JSONResponse, StreamingResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, Field
except Exception as _IMPORT_ERR:  # pragma: no cover - optional dependency
    APIRouter = Depends = FastAPI = HTTPException = Query = Request = JSONResponse = StreamingResponse = None  # type: ignore[assignment]
    HTTPAuthorizationCredentials = HTTPBearer = None  # type: ignore[assignment]
    BaseModel = object  # type: ignore[assignment]
    Field = lambda *args, **kwargs: None  # type: ignore[assignment]
    _FASTAPI_IMPORT_ERROR = _IMPORT_ERR
else:
    _FASTAPI_IMPORT_ERROR = None


class SessionCreateRequest(BaseModel):
    input_text: str = ""


class SessionInputRequest(BaseModel):
    input_text: str


class ParseRequest(BaseModel):
    selected_patterns: list[str] | None = None


class BulkIngestRequest(BaseModel):
    inline_text: str = ""
    urls: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    folder_paths: list[str] = Field(default_factory=list)
    recursive: bool = True
    parse_after_ingest: bool = True
    use_tree_sitter_code_ingest: bool = False
    include_tree_sitter_previews: bool = False
    tree_sitter_preview_max_files: int = 20
    tree_sitter_preview_max_chars: int = 12_000
    selected_patterns: list[str] | None = None
    max_files: int = 500
    max_url_bytes: int = 2_000_000


class ImportIocsRequest(BaseModel):
    iocs: dict[str, list[str]]
    source_label: str = "API"


class ExportJsonRequest(BaseModel):
    include_metadata: bool = True


class HistorySaveRequest(BaseModel):
    collection_name: str
    threat_context: str = ""
    notes: str = ""
    session_id: str | None = None
    iocs: dict[str, list[str]] | None = None
    source_label: str = "API"


class HistoryCompareRequest(BaseModel):
    collection_a_id: int
    collection_b_id: int


class WatchlistSaveRequest(BaseModel):
    name: str
    query: str = ""
    category_filter: str = ""
    date_window_days: int | None = None
    notes: str = ""
    is_watchlist: bool = True


class SettingsUpdateRequest(BaseModel):
    shell_timeout_seconds: int | None = None
    nmap_timeout_seconds: int | None = None
    jsluice_temp_max_age_seconds: int | None = None
    ui_density: str | None = None
    default_parse_groups: list[str] | None = None
    api_auth_scope: str | None = None
    api_webhook_enabled: bool | None = None
    api_webhook_url: str | None = None
    api_webhook_secret: str | None = None
    api_webhook_events: list[str] | None = None
    api_webhook_max_attempts: int | None = None
    api_webhook_retry_backoff_seconds: int | None = None
    enrichment_cache_ttl_seconds: dict[str, int] | None = None


class HistoryCacheCleanupRequest(BaseModel):
    remove_expired_only: bool = True
    provider: str | None = None


class HistoryDbBackupRequest(BaseModel):
    destination_path: str | None = None


class ThreatAliasUpsertRequest(BaseModel):
    alias: str
    canonical_name: str


class EnrichmentCacheTtlSettingsRequest(BaseModel):
    ttl_seconds_by_provider: dict[str, int]


class JobWebhookConfigRequest(BaseModel):
    enabled: bool | None = None
    url: str | None = None
    secret: str | None = None
    events: list[str] | None = None
    max_attempts: int | None = None
    retry_backoff_seconds: int | None = None


class JobWebhookTestRequest(BaseModel):
    include_sample_result: bool = True


class WebhookHistoryClearRequest(BaseModel):
    older_than_days: int | None = None


class ApiAuthTokenCreateRequest(BaseModel):
    name: str = ""
    scope: str = "admin"
    token: str | None = None
    enabled: bool = True
    set_primary: bool = False
    expires_at: str | None = None
    expires_in_days: int | None = None


class ApiAuthTokenUpdateRequest(BaseModel):
    name: str | None = None
    scope: str | None = None
    enabled: bool | None = None
    set_primary: bool | None = None
    expires_at: str | None = None
    expires_in_days: int | None = None
    clear_expiration: bool | None = None
    revoke: bool | None = None
    revoke_reason: str | None = None


class ApiAuthTokenRevokeStaleRequest(BaseModel):
    older_than_days: int = Field(..., ge=1, le=3650)
    include_never_used: bool = True
    include_primary: bool = False
    only_enabled: bool = True


class VTKeyStoreRequest(BaseModel):
    api_key: str


class VTBatchRequest(BaseModel):
    values: list[str]
    api_key: str | None = None
    limit: int | None = None


class IntelLookupRequest(BaseModel):
    values: list[str]
    api_key: str | None = None
    limit: int | None = None


class OpenClawConfigExportRequest(BaseModel):
    base_url: str | None = None
    include_token: bool = True


class JsluiceRunRequest(BaseModel):
    text: str
    mode: str
    custom_options: str = ""
    raw_output: bool = False


class NmapRunRequest(BaseModel):
    target: str
    scan_type_flag: str = ""
    flags: list[str] = Field(default_factory=list)
    ports: str = ""
    extra_args: str = ""
    use_sudo: bool = False
    timeout: int | None = None


class ShellRunRequest(BaseModel):
    command: str
    timeout: int | None = None


def _http_error_from_exc(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")


def create_api_app(service: AppService | None = None) -> FastAPI:
    """
    Build the FastAPI app.

    Raises RuntimeError if FastAPI/Pydantic dependencies are not installed.
    """
    if _FASTAPI_IMPORT_ERROR is not None:
        raise RuntimeError(
            "FastAPI API dependencies are not installed. "
            "Install 'fastapi' and 'uvicorn'."
        ) from _FASTAPI_IMPORT_ERROR

    svc = service or AppService()
    app = FastAPI(
        title="IOC Citadel REST API",
        version=APP_VERSION,
        description=(
            "Local-first REST API for IOC Citadel GUI features. "
            "Long-running operations return jobs that can be polled/cancelled."
        ),
    )
    app.state.service = svc

    bearer = HTTPBearer(auto_error=False)

    def _get_service(request: Request) -> AppService:
        return request.app.state.service

    def _auth_guard(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> None:
        service_obj: AppService = request.app.state.service
        if not service_obj.require_auth:
            return
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token_record = service_obj.authenticate_bearer_token(credentials.credentials)
        if token_record is None:
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        # Scope model: GET/HEAD -> read, mutating requests -> jobs, admin endpoints -> admin.
        if service_obj.require_auth:
            path = str(request.url.path or "")
            method = str(request.method or "GET").upper()
            required_scope = "read"
            if method not in {"GET", "HEAD", "OPTIONS"}:
                required_scope = "jobs"
            # POST endpoints that are read-like.
            if path.endswith("/history/compare") or path.endswith("/opclaw/config"):
                required_scope = "read"
            # Admin endpoints (settings/key management/cache/db/alias/webhook/system-level).
            admin_prefixes = (
                "/api/v1/auth/tokens",
                "/api/v1/settings",
                "/api/v1/vt/key",
                "/api/v1/enrich/cache/settings",
                "/api/v1/history/cache",
                "/api/v1/history/db",
                "/api/v1/history/threat-aliases",
                "/api/v1/webhooks/job-completion",
                "/api/v1/installers/",
            )
            if path.startswith(admin_prefixes) or path.endswith("/shell/run"):
                # GET /settings remains read-only
                if not (path == "/api/v1/settings" and method == "GET"):
                    required_scope = "admin"
            # Provider key management endpoints are admin.
            if re.match(r"^/api/v1/enrich/[^/]+/key$", path):
                required_scope = "admin"
            if path.endswith("/jobs/events/stream"):
                required_scope = "read"
            request.state.required_scope = required_scope
            token_scope = service_obj._normalize_auth_scope(token_record.get("scope"))  # type: ignore[arg-type]
            if not service_obj._scope_allows(token_scope, required_scope):
                raise HTTPException(
                    status_code=403,
                    detail=f"Bearer token lacks required scope: {required_scope}",
                )
            request.state.auth_scope = token_scope
            request.state.auth_token_id = str(token_record.get("id") or "")

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(_auth_guard)])

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(_request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

    @app.get("/api/v1/health")
    def health(request: Request):
        service_obj: AppService = request.app.state.service
        return {
            "ok": True,
            "version": APP_VERSION,
            "auth_required": service_obj.require_auth,
            "auth_scope": getattr(service_obj, "auth_scope", "admin"),
            "now": service_obj.get_status()["now"],
        }

    @api.get("/capabilities")
    def capabilities(service_obj: AppService = Depends(_get_service)):
        return service_obj.get_capabilities()

    @api.get("/status")
    def status(service_obj: AppService = Depends(_get_service)):
        return service_obj.get_status()

    # ------------------------------------------------------------------
    # API auth token management (admin)
    # ------------------------------------------------------------------

    @api.get("/auth/tokens")
    def auth_tokens_list(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.list_api_auth_tokens(include_token_values=False)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/auth/tokens")
    def auth_tokens_create(req: ApiAuthTokenCreateRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.create_api_auth_token(
                name=req.name,
                scope=req.scope,
                token=req.token,
                enabled=bool(req.enabled),
                set_primary=bool(req.set_primary),
                expires_at=req.expires_at,
                expires_in_days=req.expires_in_days,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.put("/auth/tokens/{token_id}")
    def auth_tokens_update(
        token_id: str,
        req: ApiAuthTokenUpdateRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            payload = req.model_dump(exclude_none=True)
            return service_obj.update_api_auth_token(token_id, **payload)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/auth/tokens/revoke-stale")
    def auth_tokens_revoke_stale(
        req: ApiAuthTokenRevokeStaleRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.revoke_stale_api_auth_tokens(
                older_than_days=int(req.older_than_days),
                include_never_used=bool(req.include_never_used),
                include_primary=bool(req.include_primary),
                only_enabled=bool(req.only_enabled),
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/auth/tokens/{token_id}/rotate")
    def auth_tokens_rotate(token_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.rotate_api_auth_token(token_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/auth/tokens/{token_id}/primary")
    def auth_tokens_set_primary(token_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.set_primary_api_auth_token(token_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/auth/tokens/{token_id}")
    def auth_tokens_delete(token_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.delete_api_auth_token(token_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # Sessions / input / parsing / IOC transforms
    # ------------------------------------------------------------------

    @api.post("/sessions")
    def create_session(req: SessionCreateRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.create_session(input_text=req.input_text)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/sessions")
    def list_sessions(service_obj: AppService = Depends(_get_service)):
        return {"sessions": service_obj.list_sessions()}

    @api.get("/sessions/{session_id}")
    def get_session(
        session_id: str,
        include_iocs: bool = True,
        include_input: bool = True,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.get_session(session_id, include_iocs=include_iocs, include_input=include_input)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/sessions/{session_id}")
    def delete_session(session_id: str, service_obj: AppService = Depends(_get_service)):
        return service_obj.delete_session(session_id)

    @api.get("/sessions/{session_id}/input")
    def get_session_input(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.get_session_input(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.put("/sessions/{session_id}/input")
    def set_session_input(
        session_id: str,
        req: SessionInputRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.set_session_input(session_id, req.input_text)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/parse")
    def parse_session(
        session_id: str,
        req: ParseRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.parse_session(session_id, selected_patterns=req.selected_patterns)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/bulk-ingest")
    def bulk_ingest_session(
        session_id: str,
        req: BulkIngestRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.bulk_ingest_session(
                session_id,
                inline_text=req.inline_text,
                urls=req.urls,
                file_paths=req.file_paths,
                folder_paths=req.folder_paths,
                recursive=req.recursive,
                parse_after_ingest=req.parse_after_ingest,
                use_tree_sitter_code_ingest=req.use_tree_sitter_code_ingest,
                include_tree_sitter_previews=req.include_tree_sitter_previews,
                tree_sitter_preview_max_files=req.tree_sitter_preview_max_files,
                tree_sitter_preview_max_chars=req.tree_sitter_preview_max_chars,
                selected_patterns=req.selected_patterns,
                max_files=req.max_files,
                max_url_bytes=req.max_url_bytes,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/sessions/{session_id}/iocs")
    def get_session_iocs(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.get_session_iocs(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/sessions/{session_id}/iocs/provenance")
    def get_session_ioc_provenance(
        session_id: str,
        value: str = Query(..., min_length=1),
        category: str | None = None,
        limit: int = Query(50, ge=1, le=500),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.get_session_ioc_provenance(
                session_id,
                value=value,
                category=category,
                limit=limit,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/iocs/import")
    def import_session_iocs(
        session_id: str,
        req: ImportIocsRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.import_session_iocs(session_id, req.iocs, source_label=req.source_label)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/sessions/{session_id}/iocs")
    def clear_session_iocs(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.clear_session_iocs(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/iocs/defang")
    def defang_session_iocs(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.defang_session_iocs(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/iocs/refang")
    def refang_session_iocs(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.refang_session_iocs(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    @api.post("/sessions/{session_id}/exports/grouped-text")
    def export_grouped_text(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.export_grouped_text(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/exports/json")
    def export_json(
        session_id: str,
        req: ExportJsonRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.export_json(session_id, include_metadata=req.include_metadata)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/exports/csv")
    def export_csv(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.export_csv(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/exports/per-category")
    def export_per_category(session_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.export_per_category(session_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    @api.post("/history/collections")
    def history_save(req: HistorySaveRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_save_collection(
                collection_name=req.collection_name,
                threat_context=req.threat_context,
                notes=req.notes,
                session_id=req.session_id,
                iocs=req.iocs,
                source_label=req.source_label,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/compare")
    def history_compare(req: HistoryCompareRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_compare_collections(req.collection_a_id, req.collection_b_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/collections")
    def history_search(
        q: str = "",
        limit: int = Query(250, ge=1, le=1000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_search(query=q, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/correlate")
    def history_correlate(
        value: str = Query(..., min_length=1),
        category: str | None = None,
        limit: int = Query(250, ge=1, le=2000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_correlate_ioc(value, category=category, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/iocs/stats")
    def history_ioc_stats(
        value: str = Query(..., min_length=1),
        category: str | None = None,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_ioc_stats(value, category=category)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/iocs/timeline")
    def history_ioc_timeline(
        value: str = Query(..., min_length=1),
        category: str | None = None,
        bucket: str = Query("day"),
        limit: int = Query(500, ge=1, le=5000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_ioc_timeline(value, category=category, bucket=bucket, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/iocs/graph")
    def history_ioc_graph(
        value: str = Query(..., min_length=1),
        category: str | None = None,
        limit: int = Query(250, ge=1, le=5000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_ioc_graph(value, category=category, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/iocs/search")
    def history_ioc_search(
        q: str = "",
        category_filter: str = "",
        date_window_days: int | None = Query(None, ge=1, le=3650),
        limit: int = Query(2000, ge=1, le=10000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_search_iocs(
                query=q,
                category_filter=category_filter,
                date_window_days=date_window_days,
                limit=limit,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/cache")
    def history_cache_stats(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_cache_stats()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/cache/cleanup")
    def history_cache_cleanup(
        req: HistoryCacheCleanupRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_cache_cleanup(
                remove_expired_only=bool(req.remove_expired_only),
                provider=req.provider,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/cache/providers/{provider}/clear")
    def history_cache_clear_provider(
        provider: str,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_cache_clear_provider(provider)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/db/info")
    def history_db_info(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_db_info()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/db/backup")
    def history_db_backup(
        req: HistoryDbBackupRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_db_backup(destination_path=req.destination_path)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/db/export")
    def history_db_export(
        include_entries: bool = Query(False),
        limit_collections: int = Query(500, ge=1, le=5000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_db_export_snapshot(
                include_entries=include_entries,
                limit_collections=limit_collections,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/threat-aliases")
    def threat_aliases_list(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.threat_aliases_list()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/threat-aliases")
    def threat_aliases_upsert(
        req: ThreatAliasUpsertRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.threat_aliases_upsert(
                alias=req.alias,
                canonical_name=req.canonical_name,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/history/threat-aliases/rebuild")
    def threat_aliases_rebuild(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.threat_aliases_rebuild()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/history/threat-aliases")
    def threat_aliases_delete(
        alias: str = Query(..., min_length=1),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.threat_aliases_delete(alias)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/collections/{collection_id}")
    def history_get_collection(collection_id: int, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_get_collection(collection_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/history/collections/{collection_id}/iocs")
    def history_get_collection_iocs(collection_id: int, service_obj: AppService = Depends(_get_service)):
        try:
            data = service_obj.history_get_collection(collection_id)
            return {"collection_id": collection_id, "ioc_map": data.get("ioc_map", {}), "entries": data.get("entries", [])}
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/sessions/{session_id}/history/load/{collection_id}")
    def history_load_into_session(
        session_id: str,
        collection_id: int,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.history_load_into_session(session_id, collection_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/watchlists")
    def watchlist_list(
        watchlists_only: bool = True,
        limit: int = Query(250, ge=1, le=2000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.watchlist_list(watchlists_only=watchlists_only, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/watchlists")
    def watchlist_save(req: WatchlistSaveRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.watchlist_save(
                name=req.name,
                query=req.query,
                category_filter=req.category_filter,
                date_window_days=req.date_window_days,
                notes=req.notes,
                is_watchlist=req.is_watchlist,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/watchlists/{search_id}")
    def watchlist_get(search_id: int, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.history_db.get_saved_search(search_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/watchlists/{search_id}/run")
    def watchlist_run(
        search_id: int,
        limit: int = Query(2000, ge=1, le=10000),
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.watchlist_run(search_id, limit=limit)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/watchlists/{search_id}")
    def watchlist_delete(search_id: int, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.watchlist_delete(search_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # Settings / VT key management
    # ------------------------------------------------------------------

    @api.get("/settings")
    def get_settings(service_obj: AppService = Depends(_get_service)):
        return service_obj.get_settings()

    @api.put("/settings")
    def update_settings(req: SettingsUpdateRequest, service_obj: AppService = Depends(_get_service)):
        try:
            payload = req.model_dump(exclude_none=True)
            return service_obj.update_settings(**payload)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/opclaw/config")
    def opclaw_config_export(
        req: OpenClawConfigExportRequest,
        request: Request,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            base_url = (req.base_url or "").strip()
            if not base_url:
                base_url = str(request.base_url).rstrip("/")
            return service_obj.export_openclaw_config(
                base_url=base_url,
                include_token=bool(req.include_token),
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/vt/key")
    def vt_key_status(service_obj: AppService = Depends(_get_service)):
        return service_obj.vt_key_status()

    @api.post("/vt/key")
    def vt_key_store(req: VTKeyStoreRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.vt_key_store(req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/vt/key")
    def vt_key_delete(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.vt_key_delete()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/enrich/providers")
    def enrich_providers(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.intel_provider_list()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/enrich/cache/settings")
    def enrich_cache_settings(service_obj: AppService = Depends(_get_service)):
        try:
            return {"ttl_seconds_by_provider": service_obj.get_enrichment_cache_ttl_settings()}
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.put("/enrich/cache/settings")
    def enrich_cache_settings_update(
        req: EnrichmentCacheTtlSettingsRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return {"ttl_seconds_by_provider": service_obj.update_enrichment_cache_ttl_settings(req.ttl_seconds_by_provider)}
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/enrich/{provider}/key")
    def enrich_provider_key_status(provider: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.intel_provider_key_status(provider)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/enrich/{provider}/key")
    def enrich_provider_key_store(
        provider: str,
        req: VTKeyStoreRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.intel_provider_key_store(provider, req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/enrich/{provider}/key")
    def enrich_provider_key_delete(provider: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.intel_provider_key_delete(provider)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/webhooks/job-completion")
    def job_webhook_config(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.get_job_webhook_config(include_secret=False)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.put("/webhooks/job-completion")
    def job_webhook_config_update(
        req: JobWebhookConfigRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            payload = req.model_dump(exclude_none=True)
            return service_obj.update_job_webhook_config(**payload)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/webhooks/job-completion/test")
    def job_webhook_test(
        req: JobWebhookTestRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.test_job_webhook(include_sample_result=bool(req.include_sample_result))
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/webhooks/job-completion/history")
    def job_webhook_history(
        limit: int = Query(200, ge=1, le=5000),
        job_id: str | None = None,
        status: str | None = None,
        event: str | None = None,
        provider: str | None = None,
        include_payloads: bool = False,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.get_job_webhook_delivery_history(
                limit=limit,
                job_id=job_id,
                status=status,
                event=event,
                provider=provider,
                include_payloads=include_payloads,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.delete("/webhooks/job-completion/history")
    def job_webhook_history_clear(
        req: WebhookHistoryClearRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.clear_job_webhook_delivery_history(
                older_than_days=req.older_than_days,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/enrich/{provider}/lookup")
    def enrich_lookup(
        provider: str,
        req: IntelLookupRequest,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.start_intel_lookup_job(
                provider,
                req.values,
                api_key=req.api_key,
                limit=req.limit,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    @api.get("/jobs")
    def list_jobs(
        limit: int = Query(200, ge=1, le=1000),
        service_obj: AppService = Depends(_get_service),
    ):
        return {"jobs": service_obj.list_jobs(limit=limit)}

    @api.get("/jobs/{job_id}")
    def get_job(
        job_id: str,
        include_result: bool = False,
        service_obj: AppService = Depends(_get_service),
    ):
        try:
            return service_obj.get_job(job_id, include_result=include_result)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/jobs/{job_id}/result")
    def get_job_result(job_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.get_job_result(job_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.get("/jobs/events/stream")
    def jobs_events(
        job_id: str | None = None,
        include_result: bool = Query(False),
        poll_ms: int = Query(500, ge=100, le=10000),
        heartbeat_seconds: int = Query(15, ge=5, le=300),
        max_events: int | None = Query(None, ge=1, le=1000),
        service_obj: AppService = Depends(_get_service),
    ):
        poll_interval = max(0.1, min(float(poll_ms) / 1000.0, 10.0))
        heartbeat_interval = max(5.0, min(float(heartbeat_seconds), 300.0))

        def _sse(event_name: str, data: Any) -> str:
            return f"event: {event_name}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"

        def _iter_events():
            sent = 0
            last_ping = time.monotonic()
            if job_id:
                last_sig: tuple[str, str] | None = None
                while True:
                    try:
                        job = service_obj.get_job(job_id, include_result=include_result)
                    except Exception as exc:
                        yield _sse("error", {"error": str(exc), "job_id": job_id})
                        break
                    sig = (str(job.get("updated_at") or ""), str(job.get("status") or ""))
                    if sig != last_sig:
                        yield _sse("job", job)
                        sent += 1
                        last_sig = sig
                        if max_events is not None and sent >= max_events:
                            break
                    if str(job.get("status") or "") in {"done", "failed", "cancelled"} and max_events is None:
                        # Keep stream alive for terminal status only if client wants a long subscription;
                        # emit heartbeats until disconnected.
                        pass
                    now = time.monotonic()
                    if now - last_ping >= heartbeat_interval:
                        last_ping = now
                        yield ": keepalive\n\n"
                    time.sleep(poll_interval)
                return

            last_seen: dict[str, tuple[str, str]] = {}
            while True:
                jobs = service_obj.list_jobs(limit=300)
                current_ids: set[str] = set()
                emitted_any = False
                for job in jobs:
                    jid = str(job.get("id") or "")
                    if not jid:
                        continue
                    current_ids.add(jid)
                    sig = (str(job.get("updated_at") or ""), str(job.get("status") or ""))
                    if last_seen.get(jid) != sig:
                        payload = service_obj.get_job(jid, include_result=include_result)
                        yield _sse("job", payload)
                        sent += 1
                        emitted_any = True
                        last_seen[jid] = sig
                        if max_events is not None and sent >= max_events:
                            return
                removed = sorted(set(last_seen.keys()) - current_ids)
                for jid in removed:
                    yield _sse("job_removed", {"id": jid})
                    sent += 1
                    emitted_any = True
                    last_seen.pop(jid, None)
                    if max_events is not None and sent >= max_events:
                        return
                now = time.monotonic()
                if (not emitted_any) and now - last_ping >= heartbeat_interval:
                    last_ping = now
                    yield ": keepalive\n\n"
                time.sleep(poll_interval)

        return StreamingResponse(
            _iter_events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @api.post("/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.cancel_job(job_id)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # VirusTotal jobs
    # ------------------------------------------------------------------

    @api.post("/vt/check")
    def vt_check(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_check_job(req.values, api_key=req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/submit-urls")
    def vt_submit_urls(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_submit_urls_job(req.values, api_key=req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/hash-details")
    def vt_hash_details(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_hash_details_job(req.values, api_key=req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/mitre")
    def vt_mitre(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_mitre_job(req.values, api_key=req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/behavior")
    def vt_behavior(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_behavior_job(req.values, api_key=req.api_key)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/resolutions")
    def vt_resolutions(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_resolutions_job(
                req.values,
                api_key=req.api_key,
                limit=req.limit or 20,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/vt/communicating-files")
    def vt_communicating_files(req: VTBatchRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_vt_communicating_files_job(
                req.values,
                api_key=req.api_key,
                limit=req.limit or 10,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    # ------------------------------------------------------------------
    # Jsluice / Nmap / Shell / installers jobs
    # ------------------------------------------------------------------

    @api.post("/jsluice/run")
    def jsluice_run(req: JsluiceRunRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_jsluice_job(
                text=req.text,
                mode=req.mode,
                custom_options=req.custom_options,
                raw_output=req.raw_output,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/nmap/run")
    def nmap_run(req: NmapRunRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_nmap_job(
                target=req.target,
                scan_type_flag=req.scan_type_flag,
                flags=req.flags,
                ports=req.ports,
                extra_args=req.extra_args,
                use_sudo=req.use_sudo,
                timeout=req.timeout,
            )
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/shell/run")
    def shell_run(req: ShellRunRequest, service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_shell_job(command=req.command, timeout=req.timeout)
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/installers/jsluice")
    def install_jsluice(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_jsluice_install_job()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    @api.post("/installers/nmap")
    def install_nmap(service_obj: AppService = Depends(_get_service)):
        try:
            return service_obj.start_nmap_install_job()
        except Exception as exc:
            raise _http_error_from_exc(exc)

    app.include_router(api)
    return app
