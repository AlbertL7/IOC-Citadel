"""
keychain.py - Secure credential storage for IOC Citadel.

Uses the macOS Keychain (via the 'security' CLI) to store API keys
persistently and securely. The key is encrypted at rest by the OS
and protected by the user's login credentials.

On non-macOS platforms, falls back to the 'keyring' library if
installed, otherwise stores nothing (session-only).

All functions are safe to call on any platform — they return None
or False gracefully when secure storage is unavailable.
"""

import logging
import platform
import re
import subprocess

log = logging.getLogger(__name__)

# Keychain identifiers
_SERVICE = "IOC-Extractor"
_ACCOUNT_VT = "virustotal-api-key"

_IS_MACOS = platform.system() == "Darwin"


# ---------------------------------------------------------------------------
# macOS Keychain via 'security' CLI
# ---------------------------------------------------------------------------

def _macos_store(service: str, account: str, password: str) -> bool:
    """Store a password in the macOS login Keychain. Returns True on success."""
    try:
        # Delete existing entry first (silently ignore if not found)
        subprocess.run(
            ["security", "delete-generic-password",
             "-s", service, "-a", account],
            capture_output=True,
        )
        # Add the new entry
        result = subprocess.run(
            ["security", "add-generic-password",
             "-s", service, "-a", account,
             "-w", password,
             "-U"],  # -U = update if exists
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return True
        log.warning("Keychain store failed: %s", result.stderr.strip())
        return False
    except FileNotFoundError:
        log.warning("'security' CLI not found")
        return False
    except Exception as exc:
        log.warning("Keychain store error: %s", exc)
        return False


def _macos_load(service: str, account: str) -> str | None:
    """Load a password from the macOS login Keychain."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", service, "-a", account,
             "-w"],  # -w = print password only
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            pw = result.stdout.strip()
            return pw if pw else None
        return None
    except FileNotFoundError:
        return None
    except Exception as exc:
        log.warning("Keychain load error: %s", exc)
        return None


def _macos_delete(service: str, account: str) -> bool:
    """Delete a password from the macOS login Keychain."""
    try:
        result = subprocess.run(
            ["security", "delete-generic-password",
             "-s", service, "-a", account],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except Exception as exc:
        log.warning("Keychain delete error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Fallback: keyring library (cross-platform)
# ---------------------------------------------------------------------------

def _keyring_store(service: str, account: str, password: str) -> bool:
    try:
        import keyring as kr
        kr.set_password(service, account, password)
        return True
    except Exception:
        return False


def _keyring_load(service: str, account: str) -> str | None:
    try:
        import keyring as kr
        return kr.get_password(service, account)
    except Exception:
        return None


def _keyring_delete(service: str, account: str) -> bool:
    try:
        import keyring as kr
        kr.delete_password(service, account)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def store_api_key(api_key: str) -> bool:
    """
    Securely store the VirusTotal API key.

    Uses macOS Keychain on Darwin, keyring library elsewhere.
    Returns True if the key was stored successfully.
    """
    if _IS_MACOS:
        return _macos_store(_SERVICE, _ACCOUNT_VT, api_key)
    return _keyring_store(_SERVICE, _ACCOUNT_VT, api_key)


def load_api_key() -> str | None:
    """
    Load the VirusTotal API key from secure storage.

    Returns the key string, or None if not found / unavailable.
    """
    if _IS_MACOS:
        return _macos_load(_SERVICE, _ACCOUNT_VT)
    return _keyring_load(_SERVICE, _ACCOUNT_VT)


def delete_api_key() -> bool:
    """
    Remove the stored VirusTotal API key.

    Returns True if deleted (or already absent).
    """
    if _IS_MACOS:
        return _macos_delete(_SERVICE, _ACCOUNT_VT)
    return _keyring_delete(_SERVICE, _ACCOUNT_VT)


def _provider_account(provider_id: str) -> str:
    pid = str(provider_id or "").strip().lower()
    pid = re.sub(r"[^a-z0-9._-]+", "-", pid).strip("-")
    if not pid:
        raise ValueError("provider_id is required")
    return f"provider-{pid}-api-key"


def store_provider_api_key(provider_id: str, api_key: str) -> bool:
    key = str(api_key or "").strip()
    if not key:
        return False
    account = _provider_account(provider_id)
    if _IS_MACOS:
        return _macos_store(_SERVICE, account, key)
    return _keyring_store(_SERVICE, account, key)


def load_provider_api_key(provider_id: str) -> str | None:
    account = _provider_account(provider_id)
    if _IS_MACOS:
        return _macos_load(_SERVICE, account)
    return _keyring_load(_SERVICE, account)


def delete_provider_api_key(provider_id: str) -> bool:
    account = _provider_account(provider_id)
    if _IS_MACOS:
        return _macos_delete(_SERVICE, account)
    return _keyring_delete(_SERVICE, account)


def is_available() -> bool:
    """Return True if secure storage is available on this platform."""
    if _IS_MACOS:
        try:
            result = subprocess.run(
                ["security", "help"],
                capture_output=True,
            )
            return True
        except FileNotFoundError:
            return False
    try:
        import keyring  # noqa: F401
        return True
    except ImportError:
        return False
