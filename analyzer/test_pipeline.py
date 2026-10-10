import asyncio

import pytest

import pipeline
from feeds import SOURCES

CLEAR = [{"source": s, "status": "clear"} for s in SOURCES]


def opened(**overrides) -> dict:
    return {
        "loaded": True, "complete": True, "final_url": "https://landing.example/page", "final_status": 200,
        "title": "t", "text": "", "blocked_requests": 0, "has_screenshot": False, "error": None,
        "redirects": [{"status": 302, "url": "https://short.example/x"}, {"status": 200, "url": "https://landing.example/page"}],
        **overrides,
    }


class Fakes:
    """Stand-ins for the page, the feeds and RDAP, recording what the pipeline asked of them."""

    def __init__(self, monkeypatch, page=None, feed_delay=0.0, page_delay=0.0):
        self.events: list[str] = []
        self.feed_calls: list[list[str]] = []
        self.age_calls: list[str] = []
        self.page = page or opened()
        self.feed_delay, self.page_delay = feed_delay, page_delay
        monkeypatch.setattr(pipeline, "open_page", self.open_page)
        monkeypatch.setattr(pipeline, "check_feeds", self.check_feeds)
        monkeypatch.setattr(pipeline, "domain_age", self.domain_age)

    async def open_page(self, url, shot_path):
        self.events.append("page:start")
        await asyncio.sleep(self.page_delay)
        self.events.append("page:done")
        if isinstance(self.page, Exception):
            raise self.page
        return self.page

    async def check_feeds(self, urls, timeout=5.0):
        self.feed_calls.append(list(urls))
        self.events.append(f"feeds:start:{len(self.feed_calls)}")
        await asyncio.sleep(self.feed_delay if len(self.feed_calls) == 1 else 0)
        return CLEAR

    async def domain_age(self, host):
        self.age_calls.append(host)
        return {"domain": host, "registered": None, "age_days": 3, "source": "RDAP", "error": None}


@pytest.mark.asyncio
async def test_feeds_start_while_the_page_is_still_loading(monkeypatch, tmp_path):
    fakes = Fakes(monkeypatch, page_delay=0.05)
    await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    assert fakes.events.index("feeds:start:1") < fakes.events.index("page:done")


@pytest.mark.asyncio
async def test_only_the_urls_not_yet_checked_are_asked_about_afterwards(monkeypatch, tmp_path):
    fakes = Fakes(monkeypatch)
    result = await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    assert fakes.feed_calls == [["https://short.example/x"], ["https://landing.example/page"]]
    assert result.final_url == "https://landing.example/page"
    assert [e["source"] for e in result.feeds] == list(SOURCES)


@pytest.mark.asyncio
async def test_no_second_feed_check_when_nothing_new_was_visited(monkeypatch, tmp_path):
    page = opened(final_url="https://example.com/", redirects=[{"status": 200, "url": "https://example.com/"}])
    fakes = Fakes(monkeypatch, page=page)
    await pipeline.scan("https://example.com", tmp_path / "s.png")  # same address, with and without the slash
    assert fakes.feed_calls == [["https://example.com"]]


@pytest.mark.asyncio
async def test_age_is_asked_about_the_page_we_ended_on(monkeypatch, tmp_path):
    fakes = Fakes(monkeypatch)
    result = await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    assert fakes.age_calls == ["landing.example"]
    assert result.age["age_days"] == 3


@pytest.mark.asyncio
async def test_the_page_we_ended_on_is_judged_against_the_brand_list(monkeypatch, tmp_path):
    page = opened(
        final_url="https://paypa1-secure.top/signin", title="Log in to your PayPal account",
        redirects=[{"status": 200, "url": "https://paypa1-secure.top/signin"}],
    )
    Fakes(monkeypatch, page=page)
    result = await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    found = {(f["type"], f["brand"]) for f in result.brand}
    assert ("lookalike", "PayPal") in found
    assert result.popular is False


@pytest.mark.asyncio
async def test_a_popular_domain_is_flagged_as_such(monkeypatch, tmp_path):
    page = opened(final_url="https://www.google.com/", redirects=[{"status": 200, "url": "https://www.google.com/"}])
    Fakes(monkeypatch, page=page)
    result = await pipeline.scan("https://www.google.com/", tmp_path / "s.png")
    assert result.popular is True
    assert {(f["type"], f["brand"]) for f in result.brand} == {("official", "Google")}


@pytest.mark.asyncio
async def test_a_page_that_never_loaded_is_still_checked_by_url(monkeypatch, tmp_path):
    page = opened(loaded=False, final_url=None, redirects=[], error="net::ERR_NAME_NOT_RESOLVED")
    fakes = Fakes(monkeypatch, page=page)
    result = await pipeline.scan("https://gone.example/x", tmp_path / "s.png")
    assert fakes.feed_calls == [["https://gone.example/x"]]
    assert fakes.age_calls == ["gone.example"]
    assert result.final_url == "https://gone.example/x"


@pytest.mark.asyncio
async def test_a_page_on_a_free_host_skips_rdap(monkeypatch, tmp_path):
    page = opened(final_url="https://evil.netlify.app/", redirects=[{"status": 200, "url": "https://evil.netlify.app/"}])
    fakes = Fakes(monkeypatch, page=page)
    result = await pipeline.scan("https://evil.netlify.app/", tmp_path / "s.png")
    assert fakes.age_calls == []
    assert result.age["error"] == "free hosting platform"


@pytest.mark.asyncio
async def test_slow_feeds_cannot_hold_the_scan_hostage(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "FEED_BUDGET_S", 0.1)
    fakes = Fakes(monkeypatch, feed_delay=5)
    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    assert loop.time() - started < 2
    assert result.opened["loaded"] is True  # the page result is intact
    assert {e["status"] for e in result.feeds} == {"error"}
    assert fakes.age_calls  # and the rest still ran


@pytest.mark.asyncio
async def test_a_crashing_page_does_not_leave_the_feed_check_running(monkeypatch, tmp_path):
    cancelled = []

    async def feeds(urls, timeout=5.0):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    Fakes(monkeypatch, page=RuntimeError("browser crashed"))
    monkeypatch.setattr(pipeline, "check_feeds", feeds)
    with pytest.raises(RuntimeError):
        await pipeline.scan("https://short.example/x", tmp_path / "s.png")
    await asyncio.sleep(0)
    assert cancelled == [True]
