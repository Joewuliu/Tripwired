import asyncio
import os
import time

import httpx
import pytest

import feeds
from feeds import (
    OPENPHISH,
    SAFE_BROWSING,
    URLHAUS,
    check_feeds,
    failed,
    merge_results,
)

SECRET = "sekret-key-123"


def mock_http(monkeypatch, handler):
    """Route every feed request through handler(request). Returns the list of requests seen."""
    seen = []

    async def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        result = handler(request)
        return await result if asyncio.iscoroutine(result) else result

    def factory(timeout=5.0, **kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(respond), timeout=timeout, **kwargs)

    monkeypatch.setattr(feeds, "_client", factory)
    return seen


def openphish_list(*lines: str, age_s: float = 0) -> None:
    feeds.OPENPHISH_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if age_s:
        old = time.time() - age_s
        os.utime(feeds.OPENPHISH_PATH, (old, old))


def by_source(entries: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for entry in entries:
        out.setdefault(entry["source"], []).append(entry)
    return out


# --- keys ---------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_missing_key_is_not_checked_and_makes_no_request(monkeypatch):
    openphish_list("https://evil.example/x")
    seen = mock_http(monkeypatch, lambda request: httpx.Response(500))
    result = by_source(await check_feeds(["https://fine.example/"]))
    assert result[SAFE_BROWSING] == [
        {"source": SAFE_BROWSING, "status": "not_checked", "detail": "SAFE_BROWSING_API_KEY is not set"}
    ]
    assert result[URLHAUS][0]["status"] == "not_checked"
    assert result[OPENPHISH] == [{"source": OPENPHISH, "status": "clear"}]
    assert seen == []


@pytest.mark.asyncio
async def test_a_blank_key_counts_as_missing(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "   ")
    openphish_list()
    result = by_source(await check_feeds(["https://fine.example/"]))
    assert result[SAFE_BROWSING][0]["status"] == "not_checked"


# --- Safe Browsing ------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safe_browsing_hit(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", SECRET)
    openphish_list()

    def handler(request):
        assert request.url.path.endswith("threatMatches:find")
        assert request.url.params["key"] == SECRET
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://evil.example/x"}}]})

    mock_http(monkeypatch, handler)
    hits = by_source(await check_feeds(["https://evil.example/x"]))[SAFE_BROWSING]
    assert hits == [{"source": SAFE_BROWSING, "status": "hit", "url": "https://evil.example/x", "kind": "phishing", "detail": "phishing"}]


@pytest.mark.asyncio
async def test_safe_browsing_clear(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", SECRET)
    openphish_list()
    mock_http(monkeypatch, lambda request: httpx.Response(200, json={}))
    assert by_source(await check_feeds(["https://fine.example/"]))[SAFE_BROWSING] == [{"source": SAFE_BROWSING, "status": "clear"}]


@pytest.mark.asyncio
async def test_a_failing_source_is_an_error_that_never_contains_the_key(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", SECRET)
    monkeypatch.setenv("URLHAUS_AUTH_KEY", SECRET)
    openphish_list()
    mock_http(monkeypatch, lambda request: httpx.Response(500))  # httpx's own message would include the url, key and all
    entries = await check_feeds(["https://fine.example/"])
    result = by_source(entries)
    assert result[SAFE_BROWSING][0] == {"source": SAFE_BROWSING, "status": "error", "detail": "HTTPStatusError"}
    assert result[URLHAUS][0]["status"] == "error"
    assert SECRET not in str(entries)


@pytest.mark.asyncio
async def test_a_slow_source_times_out_without_holding_up_the_others(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", SECRET)
    openphish_list("https://evil.example/x")

    async def slow(request):
        await asyncio.sleep(2)
        return httpx.Response(200, json={})

    mock_http(monkeypatch, slow)
    started = time.monotonic()
    result = by_source(await check_feeds(["https://evil.example/x"], timeout=0.1))
    assert time.monotonic() - started < 1.5
    assert result[SAFE_BROWSING][0]["detail"] == "TimeoutError"
    assert result[OPENPHISH][0]["status"] == "hit"


# --- URLhaus ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlhaus_hit_sends_the_auth_key_and_the_url(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", SECRET)
    openphish_list()

    def handler(request):
        assert request.headers["Auth-Key"] == SECRET
        assert b"url=https%3A%2F%2Fevil.example%2Fx.exe" in request.content
        return httpx.Response(200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online"})

    mock_http(monkeypatch, handler)
    hits = by_source(await check_feeds(["https://evil.example/x.exe"]))[URLHAUS]
    assert hits == [{"source": URLHAUS, "status": "hit", "url": "https://evil.example/x.exe",
                     "kind": "malware distribution", "detail": "malware download (online)"}]


@pytest.mark.asyncio
async def test_urlhaus_no_results_is_clear(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", SECRET)
    openphish_list()
    mock_http(monkeypatch, lambda request: httpx.Response(200, json={"query_status": "no_results"}))
    assert by_source(await check_feeds(["https://fine.example/"]))[URLHAUS] == [{"source": URLHAUS, "status": "clear"}]


@pytest.mark.asyncio
async def test_urlhaus_is_asked_about_at_most_ten_urls(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", SECRET)
    openphish_list()
    seen = mock_http(monkeypatch, lambda request: httpx.Response(200, json={"query_status": "no_results"}))
    await check_feeds([f"https://site{i}.example/" for i in range(25)])
    assert len(seen) == feeds.MAX_URLHAUS_URLS


# --- OpenPhish: what a listing means ------------------------------------------------------

async def openphish_result(*urls: str) -> list[dict]:
    return by_source(await check_feeds(list(urls)))[OPENPHISH]


@pytest.mark.asyncio
async def test_openphish_exact_url_and_the_domain_attackers_own(monkeypatch):
    openphish_list("https://secure-chase.top/login/a")
    mock_http(monkeypatch, lambda request: httpx.Response(500))
    exact = await openphish_result("https://secure-chase.top/login/a")
    assert exact[0]["status"] == "hit" and exact[0]["detail"] == "exact URL is on the list"
    same_domain = await openphish_result("https://login.secure-chase.top/other?x=1")
    assert same_domain[0]["status"] == "hit" and same_domain[0]["detail"] == "domain is on the list"
    assert (await openphish_result("https://chase.com/"))[0]["status"] == "clear"


@pytest.mark.asyncio
async def test_a_listing_on_a_shared_host_matches_only_that_exact_url(monkeypatch):
    openphish_list("https://docs.google.com/forms/d/evil/viewform")
    mock_http(monkeypatch, lambda request: httpx.Response(500))
    assert (await openphish_result("https://docs.google.com/forms/d/evil/viewform"))[0]["status"] == "hit"
    assert (await openphish_result("https://docs.google.com/forms/d/fine/viewform"))[0]["status"] == "clear"
    assert (await openphish_result("https://www.google.com/"))[0]["status"] == "clear"
    assert (await openphish_result("https://mail.google.com/mail"))[0]["status"] == "clear"


@pytest.mark.asyncio
async def test_a_listing_on_a_free_host_matches_that_site_not_the_platform(monkeypatch):
    openphish_list("https://evil.netlify.app/a")
    mock_http(monkeypatch, lambda request: httpx.Response(500))
    other_page = await openphish_result("https://evil.netlify.app/b")
    assert other_page[0]["status"] == "hit" and other_page[0]["detail"] == "this site is on the list"
    assert (await openphish_result("https://someone-else.netlify.app/"))[0]["status"] == "clear"
    assert (await openphish_result("https://www.netlify.com/"))[0]["status"] == "clear"


# --- OpenPhish: the cached list -----------------------------------------------------------

@pytest.mark.asyncio
async def test_a_fresh_list_is_not_downloaded_again(monkeypatch):
    openphish_list("https://evil.example/x", age_s=60)
    seen = mock_http(monkeypatch, lambda request: httpx.Response(200, text="https://other.example/y\n"))
    assert (await openphish_result("https://evil.example/x"))[0]["status"] == "hit"
    assert seen == []


@pytest.mark.asyncio
async def test_a_stale_list_is_downloaded_and_replaced(monkeypatch):
    openphish_list("https://evil.example/x", age_s=2 * 3600)
    seen = mock_http(monkeypatch, lambda request: httpx.Response(200, text="https://new-evil.example/y\n"))
    assert (await openphish_result("https://new-evil.example/y"))[0]["status"] == "hit"
    assert (await openphish_result("https://evil.example/x"))[0]["status"] == "clear"
    assert [str(r.url) for r in seen] == [feeds.OPENPHISH_FEED]


@pytest.mark.asyncio
async def test_a_failed_download_keeps_the_old_copy(monkeypatch):
    openphish_list("https://evil.example/x", age_s=2 * 3600)
    mock_http(monkeypatch, lambda request: httpx.Response(503))
    assert (await openphish_result("https://evil.example/x"))[0]["status"] == "hit"


@pytest.mark.asyncio
async def test_no_list_and_no_download_is_an_error(monkeypatch):
    mock_http(monkeypatch, lambda request: httpx.Response(503))
    assert (await openphish_result("https://evil.example/x"))[0]["status"] == "error"


# --- combining ----------------------------------------------------------------------------

def test_merge_prefers_a_hit_then_error_then_not_checked_then_clear():
    hit = {"source": "A", "status": "hit", "url": "u", "kind": "phishing", "detail": "phishing"}
    clear = {"source": "A", "status": "clear"}
    error = {"source": "B", "status": "error", "detail": "TimeoutError"}
    not_checked = {"source": "B", "status": "not_checked", "detail": "no key"}
    other_clear = {"source": "C", "status": "clear"}
    merged = merge_results([clear, error, other_clear], [hit, not_checked, other_clear])
    assert merged == [hit, error, other_clear]


def test_failed_answers_for_every_source():
    entries = failed("TimeoutError")
    assert [e["source"] for e in entries] == [SAFE_BROWSING, URLHAUS, OPENPHISH]
    assert {e["status"] for e in entries} == {"error"}
