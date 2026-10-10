"""Opens one URL in a throwaway phone-sized Chromium and reports what rendered.

The browser only observes: it never clicks, types, submits or downloads. Every request is
checked with netguard.is_public. Page and iframe redirects are never followed by the browser
itself, because requests that follow a redirect are not routed and so could not be checked:
each hop is answered by the guard and the next one starts as a new, routed request.

Known limits, covered at deploy time by the egress firewall: DNS rebinding (the browser
resolves a name again after we checked it) and redirects on images, scripts and other
subresources (only their first address is checked).
"""
import asyncio
import html
import logging
from pathlib import Path
from urllib.parse import urljoin

from playwright.async_api import async_playwright

from forms import READ_FIELDS_JS, sensitive_fields
from netguard import NOT_PUBLIC, is_public, refusal_reason

MAX_CONCURRENT = 3
MAX_FRAMES = 8
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
        "sensitive_fields": [],  # forms.sensitive_fields: visible inputs asking for a password, card...
        "redirects": [],  # main-frame responses: {"status", "url"}
        "blocked_requests": 0,
        "has_screenshot": False,
        "error": None,
    }


def _refresh_page(target: str) -> str:
    """A page whose only content is "go to target": the browser then makes a new, routed request."""
    return f'<!doctype html><meta http-equiv="refresh" content="0;url={html.escape(target, quote=True)}">'


async def _install_guards(ctx, page, result: dict, nav: dict) -> None:
    """nav carries the redirect state between the guard and _navigate:
    "driving" is True while _navigate is walking the first chain, and "redirect_to" is the vetted
    target of the hop it should open next."""
    hops = 0
    stand_ins: set[str] = set()  # addresses we answered ourselves, not with the server's response

    async def end_navigation(route) -> None:
        """Answer a page or iframe request with "no content": the navigation ends and whatever was
        on screen stays. Aborting instead would make Chromium load its own error page a moment
        later, replacing the page and interrupting any navigation that comes next."""
        stand_ins.add(route.request.url)
        await route.fulfill(status=204)

    async def refuse(route) -> None:
        result["blocked_requests"] += 1
        if route.request.resource_type == "document":
            await end_navigation(route)
        else:
            await route.abort()

    async def vet_document(route) -> None:
        """The browser must never follow a redirect by itself: once it does, the hops that follow
        are not routed, so nothing would check them. Each redirect is answered here instead, and
        the next hop starts as a new request that comes back through this guard."""
        nonlocal hops
        request = route.request
        response = await route.fetch(max_redirects=0)
        location = response.headers.get("location")
        if not (300 <= response.status < 400 and location):
            return await route.fulfill(response=response)

        main_frame = request.frame == page.main_frame
        if main_frame:  # the browser never sees this response, so the hop is recorded here
            result["redirects"].append({"status": response.status, "url": request.url})
        hops += 1
        target = urljoin(request.url, location)
        if hops > MAX_REDIRECTS or not await asyncio.to_thread(is_public, target):
            return await refuse(route)
        if main_frame and nav["driving"]:
            nav["redirect_to"] = target  # _navigate opens it as the next navigation
            return await end_navigation(route)
        # An iframe, or the page redirecting itself after it loaded: hand back a page that goes there.
        stand_ins.add(request.url)
        await route.fulfill(status=200, content_type="text/html", body=_refresh_page(target))

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
        if response.url in stand_ins:
            return  # our own refresh page; the real redirect was recorded when it was answered
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            result["redirects"].append({"status": response.status, "url": response.url})

    await ctx.route("**/*", guard)
    await ctx.route_web_socket("**/*", lambda ws: ws.close())  # observe only: no live channels
    page.on("response", record_navigation)


def _ms_left(deadline: float, cap_s: float) -> float:
    return max(500.0, min(cap_s, deadline - asyncio.get_running_loop().time()) * 1000)


async def _navigate(page, url: str, result: dict, deadline: float, nav: dict) -> None:
    """Walk the redirect chain one navigation at a time, then wait for the page to settle."""
    nav["driving"] = True
    try:
        while True:
            nav["redirect_to"] = None
            try:
                await page.goto(url, wait_until="commit", timeout=_ms_left(deadline, FIRST_RESPONSE_S))
                break
            except Exception as exc:
                if not nav["redirect_to"]:  # not a redirect we stopped on purpose: no document arrived
                    result["error"] = str(exc).splitlines()[0][:200]
                    return
                url = nav["redirect_to"]  # vetted by the guard, which also caps the number of hops
    finally:
        nav["driving"] = False
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
    # Login and payment forms often sit in an iframe, so every frame is asked (attributes only).
    per_frame = await asyncio.gather(*(_read(frame.evaluate(READ_FIELDS_JS), []) for frame in page.frames[:MAX_FRAMES]))
    result["sensitive_fields"] = sensitive_fields([field for fields in per_frame for field in fields or []])


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
        reason = await asyncio.to_thread(refusal_reason, url)
        result["error"] = f"blocked: {reason or NOT_PUBLIC}"  # no browser is launched for these
        return result

    async with _slots:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            ctx = await browser.new_context(
                **pw.devices["iPhone 13"], accept_downloads=False, service_workers="block"
            )
            page = await ctx.new_page()
            try:
                nav = {"driving": False, "redirect_to": None}
                await _install_guards(ctx, page, result, nav)
                deadline = asyncio.get_running_loop().time() + NAVIGATION_BUDGET_S
                await _navigate(page, url, result, deadline, nav)
                if result["redirects"]:  # the last main-frame response is the page we ended on
                    result["final_status"] = result["redirects"][-1]["status"]
                if result["loaded"]:
                    await _read_page(page, result, shot_path)
            finally:
                await _close(page, ctx, browser)
    return result
