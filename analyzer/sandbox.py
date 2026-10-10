"""Opens one URL in a throwaway phone-sized Chromium and reports what rendered.

The browser only observes: it never clicks, types, submits or downloads. Every request is
checked with netguard.is_public, and every document redirect is vetted one hop at a time
(Chromium follows redirects without asking the route handler again).

Known limits, covered at deploy time by the egress firewall: DNS rebinding (the browser
resolves a name again after we checked it) and redirects on images and scripts.
"""
import asyncio
import logging
from pathlib import Path
from urllib.parse import urljoin

from playwright.async_api import async_playwright

from netguard import is_public

MAX_CONCURRENT = 3
MAX_REDIRECTS = 10
NAVIGATION_BUDGET_S = 15  # the whole navigation; reads after it add a few seconds
FIRST_RESPONSE_S = 10
DOM_READY_S = 8
SETTLE_MS = 1500  # let script-heavy pages finish drawing
READ_TIMEOUT_S = 4
TEXT_LIMIT = 3000

log = logging.getLogger("tripwire.sandbox")
_slots = asyncio.Semaphore(MAX_CONCURRENT)


def _blank_result() -> dict:
    return {
        "loaded": False,  # some document arrived
        "complete": False,  # ...and domcontentloaded fired
        "final_url": None,
        "final_status": None,
        "title": None,
        "text": "",
        "redirects": [],  # main-frame responses: {"status", "url"}
        "blocked_requests": 0,
        "has_screenshot": False,
        "error": None,
    }


async def _install_guards(ctx, page, result: dict) -> None:
    hops = 0

    async def refuse(route) -> None:
        result["blocked_requests"] += 1
        await route.abort()

    async def vet_document(route) -> None:
        nonlocal hops
        response = await route.fetch(max_redirects=0)
        location = response.headers.get("location")
        if 300 <= response.status < 400 and location:
            hops += 1
            target = urljoin(route.request.url, location)
            if hops > MAX_REDIRECTS or not await asyncio.to_thread(is_public, target):
                return await refuse(route)
        await route.fulfill(response=response)

    async def guard(route) -> None:
        try:
            if not await asyncio.to_thread(is_public, route.request.url):
                await refuse(route)
            elif route.request.resource_type == "document":
                await vet_document(route)
            else:
                await route.continue_()
        except Exception as exc:  # a failed fetch must end the request, never leave it hanging
            log.warning("request ended early: %s", type(exc).__name__)
            try:
                await route.abort()
            except Exception:
                pass

    def record_navigation(response) -> None:
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            result["redirects"].append({"status": response.status, "url": response.url})

    await ctx.route("**/*", guard)
    await ctx.route_web_socket("**/*", lambda ws: ws.close())  # observe only: no live channels
    page.on("response", record_navigation)


def _ms_left(deadline: float, cap_s: float) -> float:
    return max(500.0, min(cap_s, deadline - asyncio.get_running_loop().time()) * 1000)


async def _navigate(page, url: str, result: dict, deadline: float) -> None:
    try:
        await page.goto(url, wait_until="commit", timeout=_ms_left(deadline, FIRST_RESPONSE_S))
    except Exception as exc:
        result["error"] = str(exc).splitlines()[0][:200]  # no document arrived at all
        return
    result["loaded"] = True
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=_ms_left(deadline, DOM_READY_S))
        result["complete"] = True
    except Exception:
        pass  # a slow page: read whatever has rendered
    await page.wait_for_timeout(SETTLE_MS)


async def _read(coro, default=None):
    """One read of the page. A failure keeps the others alive."""
    try:
        return await asyncio.wait_for(coro, READ_TIMEOUT_S)
    except Exception as exc:
        log.warning("read failed: %s", type(exc).__name__)
        return default


async def _read_page(page, result: dict, shot_path: Path) -> None:
    result["final_url"] = page.url
    await _read(page.screenshot(path=str(shot_path), timeout=READ_TIMEOUT_S * 1000))
    result["has_screenshot"] = shot_path.is_file()
    result["title"] = await _read(page.title())
    result["text"] = (await _read(page.inner_text("body"), ""))[:TEXT_LIMIT]


async def _close(page, ctx, browser) -> None:
    # Handlers still in flight would raise "context disposed" if the context closed under them.
    try:
        await ctx.unroute_all(behavior="ignoreErrors")
    except Exception as exc:
        log.warning("unroute failed: %s", type(exc).__name__)
    for name, closable in (("page", page), ("context", ctx), ("browser", browser)):
        try:
            await closable.close()
        except Exception as exc:
            log.warning("closing %s failed: %s", name, type(exc).__name__)


async def open_page(url: str, shot_path: Path) -> dict:
    """Open url as an iPhone, screenshot whatever rendered, and return what was seen."""
    result = _blank_result()
    if not await asyncio.to_thread(is_public, url):
        result["error"] = "blocked: not a public http(s) address"
        return result

    async with _slots:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            ctx = await browser.new_context(
                **pw.devices["iPhone 13"], accept_downloads=False, service_workers="block"
            )
            page = await ctx.new_page()
            try:
                await _install_guards(ctx, page, result)
                deadline = asyncio.get_running_loop().time() + NAVIGATION_BUDGET_S
                await _navigate(page, url, result, deadline)
                if result["redirects"]:  # the last main-frame response is the page we ended on
                    result["final_status"] = result["redirects"][-1]["status"]
                if result["loaded"]:
                    await _read_page(page, result, shot_path)
            finally:
                await _close(page, ctx, browser)
    return result
