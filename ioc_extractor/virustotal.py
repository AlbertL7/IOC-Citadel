"""
virustotal.py - VirusTotal API integration.

Handles all communication with the VirusTotal v3 API including:
  - IP address / domain / URL / hash reputation lookups
  - URL submission for scanning
  - Hash detail retrieval (MD5/SHA1/SHA256)
  - MITRE ATT&CK TTP retrieval from behavioral analysis
  - Rate limiting for free-tier API keys (4 req/min)

All methods are stateless functions that accept an API key parameter,
making them easy to test and reuse independently of the GUI.
"""

import base64
import re
import time
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Optional, Union

import requests

from .constants import (
    VT_API_BASE,
    VT_DOMAIN_ENDPOINT,
    VT_FILES_ENDPOINT,
    VT_GUI_BASE,
    VT_IP_ENDPOINT,
    VT_MITRE_REQUEST_TIMEOUT,
    VT_RATE_LIMIT_REQUESTS,
    VT_RATE_LIMIT_WINDOW,
    VT_REQUEST_TIMEOUT,
    VT_URL_ENDPOINT,
)


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe sliding-window rate limiter for VT API calls."""

    def __init__(self, max_requests: int = VT_RATE_LIMIT_REQUESTS,
                 window_seconds: int = VT_RATE_LIMIT_WINDOW):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: deque = deque()
        self._lock = threading.Lock()

    def wait_if_needed(self) -> float:
        """
        Block until a request slot is available.

        Returns the number of seconds waited (0.0 if no wait needed).
        """
        waited = 0.0
        with self._lock:
            now = time.monotonic()
            # Purge timestamps outside the window
            while self._timestamps and self._timestamps[0] <= now - self._window:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._max:
                # Must wait until the oldest request expires
                sleep_time = self._timestamps[0] + self._window - now + 0.1
                if sleep_time > 0:
                    waited = sleep_time

        if waited > 0:
            time.sleep(waited)

        with self._lock:
            self._timestamps.append(time.monotonic())

        return waited

    @property
    def requests_remaining(self) -> int:
        """How many requests can be made right now without waiting."""
        with self._lock:
            now = time.monotonic()
            while self._timestamps and self._timestamps[0] <= now - self._window:
                self._timestamps.popleft()
            return max(0, self._max - len(self._timestamps))


# Global rate limiter instance
_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    """Return the global rate limiter (for status display)."""
    return _rate_limiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_url(text: str) -> bool:
    """Return True if *text* looks like an HTTP(S) URL."""
    if not isinstance(text, str):
        return False
    return text.startswith("http://") or text.startswith("https://")


def is_hash(text: str) -> bool:
    """Return True if *text* looks like an MD5, SHA-1, or SHA-256 hex hash."""
    if not isinstance(text, str):
        return False
    return len(text) in (32, 40, 64) and all(
        c in "0123456789abcdefABCDEF" for c in text
    )


# Simple IPv4 pattern — matches standard dotted-quad notation
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Domain pattern — at least two labels separated by dots, TLD 2-63 chars
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_ip(text: str) -> bool:
    """Return True if *text* is a valid IPv4 address."""
    if not isinstance(text, str):
        return False
    return bool(_IPV4_RE.match(text))


def is_domain(text: str) -> bool:
    """Return True if *text* looks like a domain name (not an IP or URL)."""
    if not isinstance(text, str):
        return False
    # Reject if it looks like an IP, URL, or hash
    if is_ip(text) or is_url(text) or is_hash(text):
        return False
    return bool(_DOMAIN_RE.match(text))


def _vt_headers(api_key: str) -> dict:
    """Build standard VirusTotal request headers."""
    return {"Accept": "application/json", "x-apikey": api_key}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _format_timestamp(ts) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    if not ts:
        return "N/A"
    try:
        return (
            datetime.fromtimestamp(ts, tz=timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S UTC")
        )
    except (ValueError, OSError, TypeError):
        return "Invalid Date"


def _format_score_line(stats: dict) -> str:
    """Build 'Score: X/Y malicious (Z suspicious)' from analysis stats."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    line = f"Score: {malicious}/{total} malicious"
    if suspicious:
        line += f" ({suspicious} suspicious)"
    return line


def _build_ip_details(attrs: dict) -> str:
    """Extract IP-specific fields from VT attributes."""
    lines = []
    country = attrs.get("country", "")
    asn = attrs.get("asn")
    as_owner = attrs.get("as_owner", "")
    network = attrs.get("network", "")
    reputation = attrs.get("reputation")
    jarm = attrs.get("jarm", "")
    rir = attrs.get("regional_internet_registry", "")

    if country:
        lines.append(f"Country: {country}")
    if asn:
        owner_part = f" ({as_owner})" if as_owner else ""
        lines.append(f"ASN: AS{asn}{owner_part}")
    if network:
        lines.append(f"Network: {network}")
    if rir:
        lines.append(f"RIR: {rir}")
    if reputation is not None:
        lines.append(f"Community Reputation: {reputation}")
    if jarm:
        lines.append(f"JARM: {jarm}")

    # HTTPS certificate info
    cert = attrs.get("last_https_certificate", {})
    if cert:
        subject = cert.get("subject", {})
        cn = subject.get("CN", "")
        issuer = cert.get("issuer", {})
        issuer_o = issuer.get("O", "")
        if cn:
            lines.append(f"TLS Cert CN: {cn}")
        if issuer_o:
            lines.append(f"TLS Cert Issuer: {issuer_o}")

    # WHOIS snippet
    whois = attrs.get("whois", "")
    if whois:
        # Show first 3 meaningful lines of whois
        whois_lines = [
            l.strip() for l in whois.splitlines()
            if l.strip() and not l.strip().startswith(("%", "#", ">>>"))
        ][:3]
        if whois_lines:
            lines.append(f"WHOIS: {' | '.join(whois_lines)}")

    return "\n".join(lines)


def _build_domain_details(attrs: dict) -> str:
    """Extract domain-specific fields from VT attributes."""
    lines = []
    registrar = attrs.get("registrar", "")
    creation_date = attrs.get("creation_date")
    reputation = attrs.get("reputation")
    categories = attrs.get("categories", {})
    jarm = attrs.get("jarm", "")

    if registrar:
        lines.append(f"Registrar: {registrar}")
    if creation_date:
        lines.append(f"Created: {_format_timestamp(creation_date)}")
    if reputation is not None:
        lines.append(f"Community Reputation: {reputation}")
    if jarm:
        lines.append(f"JARM: {jarm}")

    # Categories from various engines
    if categories:
        cat_values = sorted(set(categories.values()))
        if cat_values:
            lines.append(f"Categories: {', '.join(cat_values[:5])}")

    # DNS records
    for rec_type in ("last_dns_records_date",):
        ts = attrs.get(rec_type)
        if ts:
            lines.append(f"Last DNS Lookup: {_format_timestamp(ts)}")

    # WHOIS snippet
    whois = attrs.get("whois", "")
    if whois:
        whois_lines = [
            l.strip() for l in whois.splitlines()
            if l.strip() and not l.strip().startswith(("%", "#", ">>>"))
        ][:3]
        if whois_lines:
            lines.append(f"WHOIS: {' | '.join(whois_lines)}")

    # HTTPS certificate
    cert = attrs.get("last_https_certificate", {})
    if cert:
        subject = cert.get("subject", {})
        cn = subject.get("CN", "")
        issuer = cert.get("issuer", {})
        issuer_o = issuer.get("O", "")
        if cn:
            lines.append(f"TLS Cert CN: {cn}")
        if issuer_o:
            lines.append(f"TLS Cert Issuer: {issuer_o}")

    return "\n".join(lines)


def _build_file_details(attrs: dict) -> str:
    """Extract file/hash-specific fields from VT attributes."""
    lines = []

    # File identification
    type_desc = attrs.get("type_description", "")
    type_tag = attrs.get("type_tag", "")
    magic = attrs.get("magic", "")
    size = attrs.get("size")
    meaningful_name = attrs.get("meaningful_name", "")
    names = attrs.get("names", [])

    if type_desc:
        tag_part = f" [{type_tag}]" if type_tag else ""
        lines.append(f"Type: {type_desc}{tag_part}")
    if meaningful_name:
        lines.append(f"Name: {meaningful_name}")
    elif names:
        lines.append(f"Name(s): {', '.join(names[:3])}")
    if size:
        if size >= 1_048_576:
            lines.append(f"Size: {size:,} bytes ({size / 1_048_576:.1f} MB)")
        elif size >= 1024:
            lines.append(f"Size: {size:,} bytes ({size / 1024:.1f} KB)")
        else:
            lines.append(f"Size: {size:,} bytes")
    if magic:
        lines.append(f"Magic: {magic[:100]}")

    # Hashes
    md5 = attrs.get("md5", "")
    sha1 = attrs.get("sha1", "")
    sha256 = attrs.get("sha256", "")
    ssdeep = attrs.get("ssdeep", "")
    if md5:
        lines.append(f"MD5:    {md5}")
    if sha1:
        lines.append(f"SHA-1:  {sha1}")
    if sha256:
        lines.append(f"SHA-256:{sha256}")
    if ssdeep:
        lines.append(f"SSDeep: {ssdeep}")

    # Threat classification
    threat_class = attrs.get("popular_threat_classification", {})
    if threat_class:
        label = threat_class.get("suggested_threat_label", "")
        if label:
            lines.append(f"Threat Label: {label}")
        categories = threat_class.get("popular_threat_category", [])
        if categories:
            cat_names = [c.get("value", "") for c in categories[:3] if c.get("value")]
            if cat_names:
                lines.append(f"Categories: {', '.join(cat_names)}")
        family = threat_class.get("popular_threat_name", [])
        if family:
            fam_names = [f_.get("value", "") for f_ in family[:3] if f_.get("value")]
            if fam_names:
                lines.append(f"Families: {', '.join(fam_names)}")

    # Tags
    tags = attrs.get("tags", [])
    if tags:
        lines.append(f"Tags: {', '.join(tags[:8])}")

    # Sandbox verdicts
    verdicts = attrs.get("sandbox_verdicts", {})
    if verdicts:
        verdict_parts = []
        for sandbox_name, v in list(verdicts.items())[:3]:
            cat = v.get("category", "")
            if cat:
                verdict_parts.append(f"{sandbox_name}: {cat}")
        if verdict_parts:
            lines.append(f"Sandbox Verdicts: {' | '.join(verdict_parts)}")

    # Sigma / YARA
    sigma = attrs.get("sigma_analysis_results", [])
    if sigma:
        lines.append(f"Sigma Rules Matched: {len(sigma)}")
    yara = attrs.get("crowdsourced_yara_results", [])
    if yara:
        rule_names = [r.get("rule_name", "") for r in yara[:5] if r.get("rule_name")]
        if rule_names:
            lines.append(f"YARA Matches: {', '.join(rule_names)}")

    # First/last submission
    first_sub = attrs.get("first_submission_date")
    last_sub = attrs.get("last_submission_date")
    if first_sub:
        lines.append(f"First Submitted: {_format_timestamp(first_sub)}")
    if last_sub:
        lines.append(f"Last Submitted: {_format_timestamp(last_sub)}")

    return "\n".join(lines)


def _build_url_details(attrs: dict) -> str:
    """Extract URL-specific fields from VT attributes."""
    lines = []
    final_url = attrs.get("last_final_url", "")
    title = attrs.get("title", "")
    last_http_code = attrs.get("last_http_response_content_length")
    http_status = attrs.get("last_http_response_code")
    trackers = attrs.get("trackers", {})
    categories = attrs.get("categories", {})
    reputation = attrs.get("reputation")

    if final_url:
        lines.append(f"Final URL: {final_url}")
    if title:
        lines.append(f"Page Title: {title}")
    if http_status:
        lines.append(f"HTTP Status: {http_status}")
    if reputation is not None:
        lines.append(f"Community Reputation: {reputation}")
    if categories:
        cat_values = sorted(set(categories.values()))
        if cat_values:
            lines.append(f"Categories: {', '.join(cat_values[:5])}")
    if trackers:
        tracker_names = sorted(trackers.keys())[:5]
        lines.append(f"Trackers: {', '.join(tracker_names)}")

    return "\n".join(lines)


def query_ioc(api_key: str, ioc: str, progress_callback=None) -> str:
    """
    Query VirusTotal for a single IOC (IP, domain, URL, or hash).

    Returns a human-readable result string with type-specific details.

    Parameters
    ----------
    progress_callback : callable, optional
        Called with status string before rate-limiting wait.
    """
    if not api_key:
        return "Error: VT API Key not available."

    headers = _vt_headers(api_key)
    report_link = "N/A"
    api_url: Optional[str] = None
    ioc_type = "Unknown"

    if is_url(ioc):
        try:
            encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            api_url = f"{VT_API_BASE}/urls/{encoded_url}"
            report_link = f"{VT_GUI_BASE}/url/{encoded_url}/detection"
            ioc_type = "URL"
        except Exception as exc:
            return f"Error encoding URL {ioc}: {exc}"

    elif is_ip(ioc):
        api_url = f"{VT_IP_ENDPOINT}/{ioc}"
        report_link = f"{VT_GUI_BASE}/ip-address/{ioc}"
        ioc_type = "IP"

    elif is_hash(ioc):
        api_url = f"{VT_FILES_ENDPOINT}/{ioc}"
        report_link = f"{VT_GUI_BASE}/file/{ioc}/detection"
        ioc_type = "Hash"

    elif is_domain(ioc):
        api_url = f"{VT_DOMAIN_ENDPOINT}/{ioc}"
        report_link = f"{VT_GUI_BASE}/domain/{ioc}"
        ioc_type = "Domain"

    else:
        return f"IOC type not recognized/supported for query: {ioc}"

    # Rate limit
    remaining = _rate_limiter.requests_remaining
    if remaining == 0 and progress_callback:
        progress_callback("Rate limit reached, waiting...")
    _rate_limiter.wait_if_needed()

    try:
        response = requests.get(api_url, headers=headers, timeout=VT_REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})

                # Common fields for all types
                parts = [
                    _format_score_line(stats),
                    f"Last Analysis: {_format_timestamp(attrs.get('last_analysis_date'))}",
                ]

                # Type-specific enrichment
                if ioc_type == "IP":
                    detail = _build_ip_details(attrs)
                elif ioc_type == "Domain":
                    detail = _build_domain_details(attrs)
                elif ioc_type == "Hash":
                    detail = _build_file_details(attrs)
                elif ioc_type == "URL":
                    detail = _build_url_details(attrs)
                else:
                    detail = ""

                if detail:
                    parts.append(detail)

                parts.append(f"Link: {report_link}")
                return "\n".join(parts)

            return f"Error: Unexpected data structure in VT response for {ioc}"

        elif response.status_code == 404:
            return f"{ioc_type} not found on VirusTotal."

        elif response.status_code == 429:
            return "Rate limited by VirusTotal. Try again in a moment."

        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP Status {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP Status {response.status_code} - {response.text[:100]}"
            return f"Error querying VirusTotal for {ioc}: {error_msg}"

    except requests.exceptions.RequestException as exc:
        return f"Network Error querying VirusTotal for {ioc}: {exc}"
    except Exception as exc:
        return f"Unexpected Error querying VT for {ioc}: {exc}"


def submit_url(api_key: str, url: str) -> dict:
    """
    Submit a URL to VirusTotal for scanning.

    Returns a dict with keys: ``success`` (bool), ``message`` (str),
    and optionally ``report_link`` (str).
    """
    if not api_key:
        return {"success": False, "message": "API Key not available."}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)
    try:
        response = requests.post(
            VT_URL_ENDPOINT,
            headers=headers,
            data={"url": url},
            timeout=VT_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            return {
                "success": True,
                "message": "Submitted/Queued successfully.",
                "report_link": f"{VT_GUI_BASE}/url/{encoded}/detection",
            }
        try:
            error_msg = (
                response.json()
                .get("error", {})
                .get("message", f"HTTP {response.status_code}")
            )
        except ValueError:
            error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
        return {"success": False, "message": f"Error submitting: {error_msg}"}

    except requests.exceptions.RequestException as exc:
        return {"success": False, "message": f"Network Error: {exc}"}
    except Exception as exc:
        return {"success": False, "message": f"Unexpected Error: {exc}"}


def get_hash_details(api_key: str, hash_value: str) -> dict:
    """
    Retrieve MD5, SHA-1, and SHA-256 for a given file hash.

    Returns a dict with hash keys or an ``error`` key.
    """
    if not api_key:
        return {"error": "API Key not available"}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)
    try:
        response = requests.get(
            f"{VT_FILES_ENDPOINT}/{hash_value}",
            headers=headers,
            timeout=VT_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            return {
                "md5": attrs.get("md5", "N/A"),
                "sha1": attrs.get("sha1", "N/A"),
                "sha256": attrs.get("sha256", "N/A"),
            }
        elif response.status_code == 404:
            return {"error": "Hash not found on VirusTotal."}
        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
            return {"error": error_msg}

    except requests.exceptions.RequestException as exc:
        return {"error": f"Network Error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Error: {exc}"}


def get_mitre_ttps(api_key: str, hash_value: str) -> Union[list, dict]:
    """
    Retrieve MITRE ATT&CK techniques for a file hash.

    Returns a list of TTP dicts on success, or a dict with ``error`` key.
    """
    if not api_key:
        return {"error": "API Key not available"}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)
    endpoint = f"{VT_FILES_ENDPOINT}/{hash_value}/behaviour_mitre_trees"

    try:
        response = requests.get(
            endpoint, headers=headers, timeout=VT_MITRE_REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            sandboxes = data.get("data", {})
            if not sandboxes:
                return {"error": "No MITRE behaviour data found."}

            all_ttps: dict = {}
            for _sandbox_name, results in sandboxes.items():
                for tactic in results.get("tactics", []):
                    tactic_name = tactic.get("name", "Unknown Tactic")
                    for technique in tactic.get("techniques", []):
                        tid = technique.get("id")
                        tname = technique.get("name", "Unknown Technique")
                        tlink = technique.get("link", "")
                        if tid:
                            if tid not in all_ttps:
                                all_ttps[tid] = {
                                    "name": tname,
                                    "link": tlink,
                                    "tactics": set(),
                                }
                            all_ttps[tid]["tactics"].add(tactic_name)

            if not all_ttps:
                return {"error": "No specific MITRE Techniques extracted."}

            return [
                {
                    "id": tid,
                    "name": d["name"],
                    "link": d["link"],
                    "tactics": sorted(d["tactics"]),
                }
                for tid, d in sorted(all_ttps.items())
            ]

        elif response.status_code == 404:
            return {"error": "Hash not found / no behaviour report."}
        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
            return {"error": error_msg}

    except requests.exceptions.RequestException as exc:
        return {"error": f"Network Error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Error: {exc}"}


# ---------------------------------------------------------------------------
# Sandbox Behavioral Data
# ---------------------------------------------------------------------------

def get_file_behavior(api_key: str, hash_value: str) -> dict:
    """
    Retrieve sandbox behavioral summary for a file hash.

    Uses the /files/{id}/behaviour_summary endpoint to get:
    - Processes spawned, command executions
    - Files dropped / opened / written
    - Registry keys set / opened
    - Mutexes created
    - DNS lookups / HTTP conversations / IP traffic
    - JA3 digests, services started

    Returns a dict with behavioral categories, or a dict with ``error`` key.
    """
    if not api_key:
        return {"error": "API Key not available"}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)
    endpoint = f"{VT_FILES_ENDPOINT}/{hash_value}/behaviour_summary"

    try:
        response = requests.get(
            endpoint, headers=headers, timeout=VT_MITRE_REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            if not data:
                return {"error": "No behavioral data found."}

            result: dict = {}
            _BEHAVIOR_FIELDS = [
                ("processes_created", 20),
                ("command_executions", 20),
                ("files_dropped", 20),
                ("files_opened", 15),
                ("files_written", 15),
                ("registry_keys_set", 15),
                ("registry_keys_opened", 10),
                ("mutexes_created", 15),
                ("dns_lookups", 20),
                ("http_conversations", 15),
                ("ip_traffic", 15),
                ("ja3_digests", 10),
                ("services_started", 10),
            ]
            for field, cap in _BEHAVIOR_FIELDS:
                items = data.get(field, [])
                if items:
                    result[field] = items[:cap]

            if not result:
                return {"error": "Behavioral data was empty."}
            return result

        elif response.status_code == 404:
            return {"error": "Hash not found / no sandbox report."}
        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
            return {"error": error_msg}

    except requests.exceptions.RequestException as exc:
        return {"error": f"Network Error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Error: {exc}"}


# ---------------------------------------------------------------------------
# DNS Resolutions (IP ↔ Domain)
# ---------------------------------------------------------------------------

def get_resolutions(api_key: str, ioc: str, limit: int = 20) -> Union[list, dict]:
    """
    Retrieve DNS resolutions for an IP address or domain.

    For IPs: returns domains that have resolved to this IP.
    For domains: returns IPs that this domain has resolved to.

    Returns a list of resolution dicts, or a dict with ``error`` key.
    """
    if not api_key:
        return {"error": "API Key not available"}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)

    if is_ip(ioc):
        endpoint = f"{VT_IP_ENDPOINT}/{ioc}/resolutions"
    elif is_domain(ioc):
        endpoint = f"{VT_DOMAIN_ENDPOINT}/{ioc}/resolutions"
    else:
        return {"error": f"Resolutions require an IP or domain, got: {ioc}"}

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            params={"limit": limit},
            timeout=VT_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            data = response.json()
            items = data.get("data", [])
            if not items:
                return {"error": "No resolution records found."}

            results = []
            for item in items:
                attrs = item.get("attributes", {})
                host = attrs.get("host_name", "")
                ip_addr = attrs.get("ip_address", "")
                date = _format_timestamp(attrs.get("date"))
                resolver = attrs.get("resolver", "")

                entry: dict = {}
                if host:
                    entry["host"] = host
                if ip_addr:
                    entry["ip"] = ip_addr
                if date != "N/A":
                    entry["date"] = date
                if resolver:
                    entry["resolver"] = resolver
                if entry:
                    results.append(entry)

            return results if results else {"error": "No resolution data extracted."}

        elif response.status_code == 404:
            return {"error": "IOC not found on VirusTotal."}
        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
            return {"error": error_msg}

    except requests.exceptions.RequestException as exc:
        return {"error": f"Network Error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Error: {exc}"}


# ---------------------------------------------------------------------------
# Communicating Files (IP / Domain → Malware)
# ---------------------------------------------------------------------------

def get_communicating_files(api_key: str, ioc: str, limit: int = 10) -> Union[list, dict]:
    """
    Retrieve files that communicate with a given IP or domain.

    Returns a list of file info dicts, or a dict with ``error`` key.
    """
    if not api_key:
        return {"error": "API Key not available"}

    _rate_limiter.wait_if_needed()
    headers = _vt_headers(api_key)

    if is_ip(ioc):
        endpoint = f"{VT_IP_ENDPOINT}/{ioc}/communicating_files"
    elif is_domain(ioc):
        endpoint = f"{VT_DOMAIN_ENDPOINT}/{ioc}/communicating_files"
    else:
        return {"error": f"Communicating files require an IP or domain, got: {ioc}"}

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            params={"limit": limit},
            timeout=VT_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            data = response.json()
            items = data.get("data", [])
            if not items:
                return {"error": "No communicating files found."}

            results = []
            for item in items:
                attrs = item.get("attributes", {})
                sha256 = attrs.get("sha256", "")
                name = attrs.get("meaningful_name", "")
                stats = attrs.get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                total = sum(stats.values())
                threat = attrs.get("popular_threat_classification", {})
                label = threat.get("suggested_threat_label", "")

                entry: dict = {"sha256": sha256}
                if name:
                    entry["name"] = name
                entry["score"] = f"{mal}/{total}"
                if label:
                    entry["threat_label"] = label
                results.append(entry)

            return results

        elif response.status_code == 404:
            return {"error": "IOC not found on VirusTotal."}
        else:
            try:
                error_msg = (
                    response.json()
                    .get("error", {})
                    .get("message", f"HTTP {response.status_code}")
                )
            except ValueError:
                error_msg = f"HTTP {response.status_code} - {response.text[:100]}"
            return {"error": error_msg}

    except requests.exceptions.RequestException as exc:
        return {"error": f"Network Error: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Error: {exc}"}
