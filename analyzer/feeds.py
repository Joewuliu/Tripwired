"""Threat feeds: is this link already known to be malicious?

check_feeds never raises. Each source answers with one entry (or one entry per match):
  {"source", "status": "hit",         "url", "kind", "detail"}
  {"source", "status": "clear"}
  {"source", "status": "not_checked", "detail"}   # no API key
  {"source", "status": "error",       "detail"}   # unreachable, slow, or unusable
"""
import asyncio
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from enrich import registered_domain
from platforms import is_free_host, is_shared_host

SAFE_BROWSING = "Google Safe Browsing"
URLHAUS = "URLhaus"
OPENPHISH = "OpenPhish"
SOURCES = (SAFE_BROWSING, URLHAUS, OPENPHISH)

SOURCE_TIMEOUT_S = 5.0
MAX_URLHAUS_URLS = 10
OPENPHISH_FEED = "https://openphish.com/feed.txt"
OPENPHISH_PATH = Path(__file__).resolve().parent.parent / "data" / "openphish.txt"
OPENPHISH_MAX_AGE_S = 3600

_SAFE_BROWSING_KINDS = {
    "SOCIAL_ENGINEERING": "phishing",
    "MALWARE": "malware",
    "UNWANTED_SOFTWARE": "unwanted software",
}


def _client(timeout: float = SOURCE_TIMEOUT_S, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, **kwargs)


def _hit(source: str, url: str, kind: str, detail: str = "") -> dict:
    return {"source": source, "status": "hit", "url": url, "kind": kind, "detail": detail or kind}


def _status(source: str, status: str, detail: str | None = None) -> dict:
    entry = {"source": source, "status": status}
    if detail:
        entry["detail"] = detail
    return entry


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


# --- Google Safe Browsing ---------------------------------------------------------------

async def _safe_browsing(urls: list[str], key: str, timeout: float) -> list[dict]:
    body = {
        "client": {"clientId": "tripwire", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(_SAFE_BROWSING_KINDS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }
    async with _client(timeout) as client:
        response = await client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, json=body
        )
        response.raise_for_status()
    hits = [
        _hit(SAFE_BROWSING, m["threat"]["url"], _SAFE_BROWSING_KINDS.get(m["threatType"], m["threatType"].lower()))
        for m in response.json().get("matches", [])
    ]
    return hits or [_status(SAFE_BROWSING, "clear")]


# --- URLhaus ----------------------------------------------------------------------------

async def _urlhaus_one(client: httpx.AsyncClient, url: str, key: str) -> dict | None:
    response = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key})
    response.raise_for_status()
    data = response.json()
    if data.get("query_status") != "ok":
        return None
    threat = str(data.get("threat", "malware")).replace("_", " ")
    return _hit(URLHAUS, url, "malware distribution", f"{threat} ({data.get('url_status', 'unknown')})")


async def _urlhaus(urls: list[str], key: str, timeout: float) -> list[dict]:
    async with _client(timeout) as client:
        found = await asyncio.gather(*(_urlhaus_one(client, url, key) for url in urls[:MAX_URLHAUS_URLS]))
    return [hit for hit in found if hit] or [_status(URLHAUS, "clear")]


# --- OpenPhish (a public list, cached for an hour) ---------------------------------------

_openphish_cache: dict = {"stamp": None, "parsed": None}


def _read_openphish(path: Path) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """What the list says, at the right granularity for where the page lives:

    urls     every listed URL (the only thing that counts on a shared host such as docs.google.com)
    domains  registered domains an attacker owns outright
    hosts    full hostnames on free-hosting platforms (evil.netlify.app is one person's site)
    """
    stamp = (str(path), path.stat().st_mtime_ns)
    if _openphish_cache["stamp"] == stamp:
        return _openphish_cache["parsed"]
    lines = (line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines())
    urls = frozenset(line for line in lines if line)
    domains, hosts = set(), set()
    for url in urls:
        host = _host(url)
        if not host or is_shared_host(host):
            continue
        (hosts if is_free_host(host) else domains).add(host if is_free_host(host) else registered_domain(host))
    parsed = (urls, frozenset(domains - {""}), frozenset(hosts))
    _openphish_cache.update(stamp=stamp, parsed=parsed)
    return parsed


async def _refresh_openphish(path: Path, timeout: float, force: bool = False) -> None:
    """Download the list unless the saved copy is under an hour old. A failed download keeps the old copy."""
    if not force and path.exists() and time.time() - path.stat().st_mtime < OPENPHISH_MAX_AGE_S:
        return
    try:
        async with _client(timeout, follow_redirects=True) as client:
            response = await client.get(OPENPHISH_FEED)
            response.raise_for_status()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(response.text, encoding="utf-8")
    except Exception:
        if not path.exists():
            raise


async def refresh_openphish(timeout: float = SOURCE_TIMEOUT_S) -> None:
    """Fetch the OpenPhish list now, ignoring the hour-old cache (a live check wants today's links).
    Raises if there is no download and no saved copy."""
    await _refresh_openphish(OPENPHISH_PATH, timeout, force=True)


async def _openphish(urls: list[str], timeout: float) -> list[dict]:
    await _refresh_openphish(OPENPHISH_PATH, timeout)
    listed_urls, listed_domains, listed_hosts = await asyncio.to_thread(_read_openphish, OPENPHISH_PATH)
    hits = []
    for url in urls:
        host = _host(url)
        if url in listed_urls:
            hits.append(_hit(OPENPHISH, url, "phishing", "exact URL is on the list"))
        elif is_shared_host(host):
            continue  # a listing for one page says nothing about the rest of the host
        elif is_free_host(host):
            if host in listed_hosts:
                hits.append(_hit(OPENPHISH, url, "phishing", "this site is on the list"))
        elif host and registered_domain(host) in listed_domains:
            hits.append(_hit(OPENPHISH, url, "phishing", "domain is on the list"))
    return hits or [_status(OPENPHISH, "clear")]


# --- putting them together --------------------------------------------------------------

async def _guarded(source: str, coro, timeout: float) -> list[dict]:
    """Never raises. Only the exception class is kept: httpx messages can contain the API key."""
    try:
        return await asyncio.wait_for(coro, timeout)
    except Exception as exc:
        return [_status(source, "error", type(exc).__name__)]


async def _skipped(source: str, key_name: str) -> list[dict]:
    return [_status(source, "not_checked", f"{key_name} is not set")]


def _keyed(source: str, key_name: str, run, urls: list[str], timeout: float):
    key = os.environ.get(key_name, "").strip()
    if not key:
        return _skipped(source, key_name)
    return _guarded(source, run(urls, key, timeout), timeout)


async def check_feeds(urls: list[str], timeout: float = SOURCE_TIMEOUT_S) -> list[dict]:
    """Ask every feed about every URL (duplicates dropped). One answer per source, or one per match."""
    urls = list(dict.fromkeys(urls))
    batches = await asyncio.gather(
        _keyed(SAFE_BROWSING, "SAFE_BROWSING_API_KEY", _safe_browsing, urls, timeout),
        _keyed(URLHAUS, "URLHAUS_AUTH_KEY", _urlhaus, urls, timeout),
        _guarded(OPENPHISH, _openphish(urls, timeout), timeout),
    )
    return [entry for batch in batches for entry in batch]


def failed(detail: str) -> list[dict]:
    """The answer for every source when the whole check could not finish in time."""
    return [_status(source, "error", detail) for source in SOURCES]


def merge_results(*result_lists: list[dict]) -> list[dict]:
    """Combine several check_feeds runs: any hit wins, then error, then not_checked, then clear."""
    by_source: dict[str, list[dict]] = {}
    for results in result_lists:
        for entry in results:
            by_source.setdefault(entry["source"], []).append(entry)
    merged = []
    for entries in by_source.values():
        hits = [e for e in entries if e["status"] == "hit"]
        if hits:
            merged += hits
            continue
        for status in ("error", "not_checked", "clear"):
            match = next((e for e in entries if e["status"] == status), None)
            if match:
                merged.append(match)
                break
    return merged
