"""REST API package for IOC Citadel."""

from .server import create_api_app
from .service import AppService

__all__ = ["create_api_app", "AppService"]
