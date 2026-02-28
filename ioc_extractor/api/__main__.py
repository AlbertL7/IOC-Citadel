"""
CLI entrypoint for the IOC Citadel REST API server.

Run:
    python -m ioc_extractor.api --host 127.0.0.1 --port 8765
"""

from __future__ import annotations

import argparse
import sys

from .server import create_api_app
from .service import AppService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IOC Citadel REST API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument("--token", default="", help="Bearer token (generated if omitted)")
    parser.add_argument("--no-auth", action="store_true", help="Disable bearer auth (not recommended)")
    parser.add_argument(
        "--allow-shell-api",
        action="store_true",
        help="Enable /shell/run endpoint (disabled by default; dangerous)",
    )
    parser.add_argument(
        "--history-db-path",
        default="",
        help="Optional SQLite path for IOC history DB",
    )
    parser.add_argument("--log-level", default="info", help="Uvicorn log level")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        print(
            "Missing API runtime dependency: uvicorn (and likely fastapi).\n"
            "Install requirements and retry.",
            file=sys.stderr,
        )
        print(f"Import error: {exc}", file=sys.stderr)
        return 2

    service = AppService(
        allow_shell_api=args.allow_shell_api,
        auth_token=args.token or None,
        require_auth=not args.no_auth,
        history_db_path=args.history_db_path or None,
    )
    app = create_api_app(service)

    print(f"IOC Citadel REST API listening on http://{args.host}:{args.port}")
    if service.require_auth:
        print("Bearer auth: enabled")
        if service.auth_token_generated:
            print("Generated bearer token (save this):")
            print(service.auth_token)
        else:
            print("Using provided bearer token.")
    else:
        print("Bearer auth: disabled (not recommended)")
    if service.allow_shell_api:
        print("Shell API endpoint: ENABLED (dangerous)")
    else:
        print("Shell API endpoint: disabled")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=str(args.log_level).lower(),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
