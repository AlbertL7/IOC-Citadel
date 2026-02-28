"""
enrichment.py - Multi-provider IOC enrichment helpers for IOC Citadel.

Provides a small provider catalog and best-effort lookup functions for common
intel sources. Network failures and provider-side errors are returned as
structured error dictionaries (not raised) so batch jobs can continue.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import requests

from . import ioc_parser
from . import virustotal as vt


DEFAULT_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class ProviderMeta:
    provider_id: str
    label: str
    description: str
    supported_types: tuple[str, ...]
    requires_api_key: bool = False
    optional_api_key: bool = False


PROVIDERS: dict[str, ProviderMeta] = {
    "abuseipdb": ProviderMeta(
        provider_id="abuseipdb",
        label="AbuseIPDB",
        description="IP reputation / abuse reports",
        supported_types=("ip",),
        requires_api_key=True,
    ),
    "greynoise": ProviderMeta(
        provider_id="greynoise",
        label="GreyNoise",
        description="Internet scanner/noise IP context",
        supported_types=("ip",),
        requires_api_key=True,
    ),
    "urlscan": ProviderMeta(
        provider_id="urlscan",
        label="urlscan.io",
        description="URL/domain scan/search intel",
        supported_types=("url", "domain", "ip", "hash"),
        optional_api_key=True,
    ),
    "otx": ProviderMeta(
        provider_id="otx",
        label="AlienVault OTX",
        description="OTX indicator details",
        supported_types=("url", "domain", "ip", "hash"),
        optional_api_key=True,
    ),
    "whois_rdap": ProviderMeta(
        provider_id="whois_rdap",
        label="WHOIS / RDAP",
        description="RDAP lookups for domains and IPs",
        supported_types=("domain", "ip", "url"),
    ),
    "passive_dns": ProviderMeta(
        provider_id="passive_dns",
        label="Passive DNS (OTX)",
        description="OTX passive DNS history for domains/IPs",
        supported_types=("domain", "ip"),
        optional_api_key=True,
    ),
}


def list_providers() -> list[dict[str, Any]]:
    return [
        {
            "id": p.provider_id,
            "label": p.label,
            "description": p.description,
            "supported_types": list(p.supported_types),
            "requires_api_key": p.requires_api_key,
            "optional_api_key": p.optional_api_key,
        }
        for p in sorted(PROVIDERS.values(), key=lambda x: x.label.casefold())
    ]


def get_provider_meta(provider_id: str) -> ProviderMeta:
    pid = normalize_provider_id(provider_id)
    meta = PROVIDERS.get(pid)
    if meta is None:
        raise ValueError(f"unsupported provider: {provider_id}")
    return meta


def normalize_provider_id(provider_id: str) -> str:
    return str(provider_id or "").strip().lower().replace("-", "_")


def detect_ioc_type(value: str) -> str:
    q = ioc_parser.refang_text(str(value or "").strip())
    if not q:
        return "unknown"
    try:
        if vt.is_url(q):
            return "url"
    except Exception:
        pass
    try:
        if vt.is_ip(q):
            return "ip"
    except Exception:
        pass
    try:
        if vt.is_hash(q):
            return "hash"
    except Exception:
        pass
    try:
        if vt.is_domain(q):
            return "domain"
    except Exception:
        pass
    if _looks_email(q):
        return "email"
    return "unknown"


def lookup(
    provider_id: str,
    value: str,
    *,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    limit: int | None = None,
) -> dict[str, Any]:
    meta = get_provider_meta(provider_id)
    raw_input = str(value or "").strip()
    query = ioc_parser.refang_text(raw_input)
    ioc_type = detect_ioc_type(query)
    if not query:
        return _entry_error(meta, raw_input, query, ioc_type, "empty input")
    if ioc_type not in meta.supported_types:
        return {
            "provider": meta.provider_id,
            "provider_label": meta.label,
            "ioc_type": ioc_type,
            "query": query,
            "skipped": True,
            "reason": f"unsupported input type for {meta.label}: {ioc_type}",
            "summary": f"Unsupported type: {ioc_type}",
            "link": _provider_link(meta.provider_id, query, ioc_type),
        }
    if meta.requires_api_key and not str(api_key or "").strip():
        return _entry_error(meta, raw_input, query, ioc_type, f"{meta.label} API key required")

    try:
        if meta.provider_id == "abuseipdb":
            payload = _lookup_abuseipdb(query, api_key=api_key, timeout=timeout)
        elif meta.provider_id == "greynoise":
            payload = _lookup_greynoise(query, api_key=api_key, timeout=timeout)
        elif meta.provider_id == "urlscan":
            payload = _lookup_urlscan(query, ioc_type=ioc_type, api_key=api_key, timeout=timeout, limit=limit)
        elif meta.provider_id == "otx":
            payload = _lookup_otx(query, ioc_type=ioc_type, api_key=api_key, timeout=timeout)
        elif meta.provider_id == "whois_rdap":
            payload = _lookup_rdap(query, ioc_type=ioc_type, timeout=timeout)
        elif meta.provider_id == "passive_dns":
            payload = _lookup_passive_dns(query, ioc_type=ioc_type, api_key=api_key, timeout=timeout, limit=limit)
        else:
            return _entry_error(meta, raw_input, query, ioc_type, "provider dispatch not implemented")
    except Exception as exc:
        return _entry_error(meta, raw_input, query, ioc_type, f"{type(exc).__name__}: {exc}")

    entry = {
        "provider": meta.provider_id,
        "provider_label": meta.label,
        "ioc_type": ioc_type,
        "query": query,
        "result": payload,
    }
    entry["summary"] = _summarize_entry(entry)
    entry["link"] = _provider_link(meta.provider_id, query, ioc_type, payload=payload)
    return entry


def _looks_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value or ""))


def _http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=max(1, int(timeout)))
    content_type = str(resp.headers.get("content-type", "")).lower()
    try:
        body = resp.json()
    except Exception:
        body = {"raw_text": resp.text}
    return {
        "ok": bool(resp.ok),
        "status_code": int(resp.status_code),
        "url": resp.url,
        "content_type": content_type,
        "body": body,
    }


def _entry_error(meta: ProviderMeta, raw_input: str, query: str, ioc_type: str, msg: str) -> dict[str, Any]:
    return {
        "provider": meta.provider_id,
        "provider_label": meta.label,
        "ioc_type": ioc_type,
        "query": query or raw_input,
        "result": {"error": msg},
        "summary": msg,
        "link": _provider_link(meta.provider_id, query or raw_input, ioc_type),
    }


def _lookup_abuseipdb(ip: str, *, api_key: str | None, timeout: int) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "Key": str(api_key or "").strip(),
        "User-Agent": "IOC-Citadel/1 enrichment",
    }
    return _http_get_json(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
        timeout=timeout,
    )


def _lookup_greynoise(ip: str, *, api_key: str | None, timeout: int) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "IOC-Citadel/1 enrichment",
    }
    key = str(api_key or "").strip()
    if key:
        headers["key"] = key
    return _http_get_json(
        f"https://api.greynoise.io/v3/community/{quote(ip, safe='')}",
        headers=headers,
        timeout=timeout,
    )


def _lookup_urlscan(
    query: str,
    *,
    ioc_type: str,
    api_key: str | None,
    timeout: int,
    limit: int | None,
) -> dict[str, Any]:
    if ioc_type == "url":
        search_q = f'page.url:"{query}"'
    elif ioc_type == "domain":
        search_q = f"domain:{query}"
    elif ioc_type == "ip":
        search_q = f"ip:{query}"
    elif ioc_type == "hash":
        search_q = f"hash:{query}"
    else:
        search_q = query
    headers = {
        "Accept": "application/json",
        "User-Agent": "IOC-Citadel/1 enrichment",
    }
    key = str(api_key or "").strip()
    if key:
        headers["API-Key"] = key
    lim = max(1, min(int(limit or 10), 200))
    return _http_get_json(
        "https://urlscan.io/api/v1/search/",
        headers=headers,
        params={"q": search_q, "size": lim},
        timeout=timeout,
    )


def _lookup_otx(query: str, *, ioc_type: str, api_key: str | None, timeout: int) -> dict[str, Any]:
    path = _otx_indicator_path(query, ioc_type, section="general")
    headers = {
        "Accept": "application/json",
        "User-Agent": "IOC-Citadel/1 enrichment",
    }
    key = str(api_key or "").strip()
    if key:
        headers["X-OTX-API-KEY"] = key
    return _http_get_json(f"https://otx.alienvault.com{path}", headers=headers, timeout=timeout)


def _lookup_passive_dns(
    query: str,
    *,
    ioc_type: str,
    api_key: str | None,
    timeout: int,
    limit: int | None,
) -> dict[str, Any]:
    path = _otx_indicator_path(query, ioc_type, section="passive_dns")
    headers = {
        "Accept": "application/json",
        "User-Agent": "IOC-Citadel/1 enrichment",
    }
    key = str(api_key or "").strip()
    if key:
        headers["X-OTX-API-KEY"] = key
    out = _http_get_json(f"https://otx.alienvault.com{path}", headers=headers, timeout=timeout)
    body = out.get("body")
    if isinstance(body, dict) and isinstance(body.get("passive_dns"), list):
        lim = max(1, min(int(limit or 20), 500))
        body = dict(body)
        body["passive_dns"] = list(body.get("passive_dns") or [])[:lim]
        out["body"] = body
    return out


def _lookup_rdap(query: str, *, ioc_type: str, timeout: int) -> dict[str, Any]:
    q = query
    t = ioc_type
    if ioc_type == "url":
        host = (urlparse(query).hostname or "").strip().lower()
        if not host:
            return {"ok": False, "status_code": 0, "body": {"error": "could not extract hostname from URL"}}
        q = host
        t = "ip" if vt.is_ip(host) else "domain"
    if t == "domain":
        url = f"https://rdap.org/domain/{quote(q, safe='')}"
    elif t == "ip":
        url = f"https://rdap.org/ip/{quote(q, safe='')}"
    else:
        return {"ok": False, "status_code": 0, "body": {"error": f"unsupported RDAP type: {ioc_type}"}}
    return _http_get_json(url, headers={"Accept": "application/rdap+json, application/json"}, timeout=timeout)


def _otx_indicator_path(query: str, ioc_type: str, *, section: str) -> str:
    if ioc_type == "domain":
        return f"/api/v1/indicators/domain/{quote(query, safe='')}/{section}"
    if ioc_type == "ip":
        # OTX API uses IPv4/IPv6 type segments.
        seg = "IPv6" if ":" in query else "IPv4"
        return f"/api/v1/indicators/{seg}/{quote(query, safe='')}/{section}"
    if ioc_type == "hash":
        return f"/api/v1/indicators/file/{quote(query, safe='')}/{section}"
    if ioc_type == "url":
        return f"/api/v1/indicators/url/{quote(query, safe='')}/{section}"
    raise ValueError(f"unsupported OTX indicator type: {ioc_type}")


def _summarize_entry(entry: dict[str, Any]) -> str:
    if entry.get("skipped"):
        return str(entry.get("reason") or "skipped")
    res = entry.get("result")
    if not isinstance(res, dict):
        return type(res).__name__
    body = res.get("body")
    if isinstance(body, dict):
        if body.get("error"):
            return str(body.get("error"))
        provider = str(entry.get("provider") or "")
        if provider == "abuseipdb":
            data = body.get("data") if isinstance(body.get("data"), dict) else {}
            if data:
                score = data.get("abuseConfidenceScore")
                reports = data.get("totalReports")
                country = data.get("countryCode")
                parts = []
                if score is not None:
                    parts.append(f"score={score}")
                if reports is not None:
                    parts.append(f"reports={reports}")
                if country:
                    parts.append(str(country))
                return " | ".join(parts) or "AbuseIPDB response"
        if provider == "greynoise":
            parts = []
            if "noise" in body:
                parts.append(f"noise={body.get('noise')}")
            if "riot" in body:
                parts.append(f"riot={body.get('riot')}")
            if body.get("classification"):
                parts.append(f"class={body.get('classification')}")
            if body.get("name"):
                parts.append(str(body.get("name")))
            return " | ".join(parts) or "GreyNoise response"
        if provider == "urlscan":
            if isinstance(body.get("results"), list):
                return f"{len(body.get('results') or [])} result(s)"
        if provider == "otx":
            pulse_info = body.get("pulse_info") if isinstance(body.get("pulse_info"), dict) else {}
            if "count" in pulse_info:
                return f"pulse_count={pulse_info.get('count')}"
        if provider == "passive_dns":
            if isinstance(body.get("passive_dns"), list):
                return f"{len(body.get('passive_dns') or [])} passive DNS row(s)"
        if provider == "whois_rdap":
            if body.get("handle"):
                return f"handle={body.get('handle')}"
            if body.get("ldhName"):
                return str(body.get("ldhName"))
        keys = list(body.keys())
        return ", ".join(map(str, keys[:5])) or "dict result"
    if isinstance(body, list):
        return f"{len(body)} item(s)"
    if isinstance(body, str):
        return (body.splitlines() or [""])[0][:200]
    return f"status={res.get('status_code')}"


def _provider_link(
    provider_id: str,
    query: str,
    ioc_type: str,
    *,
    payload: dict[str, Any] | None = None,
) -> str | None:
    q = str(query or "").strip()
    if not q:
        return None
    pid = normalize_provider_id(provider_id)
    if pid == "abuseipdb" and ioc_type == "ip":
        return f"https://www.abuseipdb.com/check/{q}"
    if pid == "greynoise" and ioc_type == "ip":
        return f"https://viz.greynoise.io/ip/{q}"
    if pid == "urlscan":
        # Prefer first result page URL if present.
        try:
            body = (payload or {}).get("body")
            if isinstance(body, dict) and isinstance(body.get("results"), list) and body["results"]:
                first = body["results"][0]
                if isinstance(first, dict):
                    for key in ("result", "task", "page"):
                        node = first.get(key)
                        if isinstance(node, dict):
                            for sub in ("url",):
                                v = node.get(sub)
                                if isinstance(v, str) and v.startswith("http"):
                                    return v
                    if isinstance(first.get("result"), str) and str(first["result"]).startswith("http"):
                        return str(first["result"])
        except Exception:
            pass
        return f"https://urlscan.io/search/#{quote(q, safe='')}"
    if pid in ("otx", "passive_dns"):
        if ioc_type == "ip":
            typ = "IPv6" if ":" in q else "IPv4"
            return f"https://otx.alienvault.com/indicator/{typ}/{quote(q, safe='')}"
        if ioc_type == "domain":
            return f"https://otx.alienvault.com/indicator/domain/{quote(q, safe='')}"
        if ioc_type == "hash":
            return f"https://otx.alienvault.com/indicator/file/{quote(q, safe='')}"
        if ioc_type == "url":
            return f"https://otx.alienvault.com/indicator/url/{quote(q, safe='')}"
    if pid == "whois_rdap":
        if ioc_type == "url":
            host = (urlparse(q).hostname or "").strip()
            if host:
                q = host
                ioc_type = "ip" if vt.is_ip(host) else "domain"
        if ioc_type == "ip":
            return f"https://rdap.org/ip/{quote(q, safe='')}"
        if ioc_type == "domain":
            return f"https://rdap.org/domain/{quote(q, safe='')}"
    return None

