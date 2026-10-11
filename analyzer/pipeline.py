"""One scan: open the page, and gather what can be learned about the link while it loads."""
import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from access import judge_access
from brands import check_brand
from defang import defang_text
from enrich import domain_age, registered_domain
from feeds import check_feeds, failed, merge_results
from interstitials import find_platform_warning
from platforms import is_free_host, is_popular
from sandbox import open_page
from score import access_view, age_view, brand_view, feeds_view, fields_view, warning_view

Emit = Callable[[str, dict], None]  # emit(kind, data): one live event; see events.py

FEED_BUDGET_S = 3.0  # most a scan waits on threat feeds once the page itself is done


@dataclass
class Scan:
    url: str  # what was asked for
    final_url: str  # where the browser ended up (the url itself if it never loaded)
    opened: dict  # sandbox.open_page's result
    feeds: list[dict]  # feeds.check_feeds entries, merged over the original url and the redirect chain
    age: dict  # enrich.domain_age's result
    brand: list[dict]  # brands.check_brand findings for the page we ended on
    popular: bool  # one of the 10,000 most visited domains (and not someone's page on a platform)
    fields: list[dict]  # forms.sensitive_fields: what the page's visible inputs ask for
    warning: str | None  # interstitials.find_platform_warning: the host's own phishing-warning page
    access: dict | None  # access.judge_access: None when the sandbox saw the page normally


def _url_key(url: str) -> str:
    """So https://example.com and https://example.com/ count as the same URL."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}:{parts.port or ''}{parts.path or '/'}?{parts.query}"


def unchecked_chain(original: str, opened: dict) -> list[str]:
    """Redirect hops and the final URL that the check on the original URL did not cover."""
    chain = [hop["url"] for hop in opened["redirects"]]
    if opened["final_url"]:
        chain.append(opened["final_url"])
    seen = {_url_key(original)}
    fresh = []
    for url in chain:
        if _url_key(url) not in seen:
            seen.add(_url_key(url))
            fresh.append(url)
    return fresh


async def _wait_for_feeds(task: asyncio.Task) -> list[dict]:
    try:
        return await asyncio.wait_for(asyncio.shield(task), FEED_BUDGET_S)
    except TimeoutError:
        task.cancel()
        return failed("TimeoutError")


async def _age(host: str) -> dict:
    if is_free_host(host):  # the platform's age says nothing about one person's page on it
        return {"domain": host, "registered": None, "age_days": None, "source": "RDAP", "error": "free hosting platform"}
    return await domain_age(host)


def _checked(emit: Emit | None, check: str, view: tuple[str, str]) -> None:
    """Announce one finished check: its name, whether it flagged anything, and one plain sentence."""
    if emit:
        emit("check_done", {"check": check, "outcome": view[0], "detail": defang_text(view[1])})


async def scan(url: str, shot_path: Path, emit: Emit | None = None) -> Scan:
    feeds_task = asyncio.create_task(check_feeds([url]))  # runs while the page loads
    try:
        opened = await open_page(url, shot_path)
    except BaseException:
        feeds_task.cancel()
        raise
    access = judge_access(opened)
    _checked(emit, "page_opened", access_view(access))
    if emit and opened["has_screenshot"]:
        emit("screenshot_ready", {"screenshot_url": f"/shots/{shot_path.stem}.png"})
    first_feeds = await _wait_for_feeds(feeds_task)

    final_url = opened["final_url"] or url
    later_urls = unchecked_chain(url, opened)

    async def later_feeds() -> list[dict]:
        found = await check_feeds(later_urls, timeout=FEED_BUDGET_S) if later_urls else []
        _checked(emit, "threat_feeds", feeds_view(merge_results(first_feeds, found)))
        return found

    async def age_of(host: str) -> dict:
        found = await _age(host)
        _checked(emit, "domain_age", age_view(found))
        return found

    final_host = urlsplit(final_url).hostname or ""
    chain_feeds, age = await asyncio.gather(later_feeds(), age_of(final_host))
    brand = check_brand(final_url, opened["title"] or "", opened["text"] or "")
    fields = opened.get("sensitive_fields", [])
    warning = find_platform_warning(opened["title"], opened["text"])
    _checked(emit, "brand_match", brand_view(brand))
    _checked(emit, "sensitive_form", fields_view(fields))
    _checked(emit, "platform_warning", warning_view(warning))
    return Scan(
        url=url, final_url=final_url, opened=opened, feeds=merge_results(first_feeds, chain_feeds), age=age,
        brand=brand, popular=is_popular(final_host, registered_domain(final_host)),
        fields=fields, warning=warning, access=access,
    )
