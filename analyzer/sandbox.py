"""Opens one URL in a throwaway phone-sized Chromium and reports what rendered.

The browser only observes: it never clicks, types, submits or downloads. It makes every request
itself, so a site sees a real browser, and two checks keep it to public addresses: the first
address of every request (netguard.is_public), and every redirect a page or iframe is answered
with, before the browser follows it (see _install_guards).

Known limits, covered at deploy time by the egress firewall: DNS rebinding (the browser
resolves a name again after we checked it) and redirects on images, scripts and other
subresources (only their first address is checked).
"""
import asyncio
import logging
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from forms import READ_FIELDS_JS, sensitive_fields
from netguard import NOT_PUBLIC, is_public, refusal_reason

MAX_CONCURRENT = 3
MAX_FRAMES = 16  # frames beyond this are not read; pages with that many are almost always advertising
MIN_FRAME_WIDTH, MIN_FRAME_HEIGHT = 60, 20  # css px; an embedded frame smaller than a text box holds no form
MAX_REDIRECTS = 10
NAVIGATION_BUDGET_S = 15  # the whole navigation; reads after it add a few seconds
FIRST_RESPONSE_S = 10
DOM_READY_S = 8
SETTLE_MS = 1500  # let script-heavy pages finish drawing
READ_TIMEOUT_S = 4
READ_RETRY_S = 0.5
CLOSE_TIMEOUT_S = 3  # closing the browser; a stuck page must not hold a browser slot
END_CHECKS_S = 1  # how long teardown waits for the checks it cancelled
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
        "read_errors": [],  # reads that failed: {"what": "screenshot|title|text|fields", "frame": host or None}
        "redirects": [],  # main-frame responses: {"status", "url"}
        "blocked_requests": 0,
        "has_screenshot": False,
        "error": None,
    }


async def _install_guards(ctx, page, result: dict, guard: dict) -> None:
    """Two checks, so that the browser makes every request itself (as a real browser, which sites
    with bot protection insist on) and still never reaches an address we have not vetted.

    1. Request stage, through Playwright's routing: the first address of every request.
    2. Response stage, through a DevTools session: every redirect a page or iframe is answered
       with. Playwright does not route the requests that follow a redirect, so this is the only
       place the next hop can be vetted before the browser goes there.

    guard["blocked"] is set to the reason when the page itself was stopped from going somewhere;
    guard["tasks"] holds every check in flight, so teardown can end them and leave nothing pending.
    """
    hops = 0
    cdp = await ctx.new_cdp_session(page)
    main_frame_id = (await cdp.send("Page.getFrameTree"))["frameTree"]["frame"]["id"]
    guard["cdp"], guard["main_frame_id"] = cdp, main_frame_id  # also used to read a page that resists scripts

    async def check_request(route) -> None:
        request = route.request
        this = asyncio.current_task()  # Playwright's task for this request; ended by _close if still running
        guard["tasks"].add(this)
        try:
            if await asyncio.to_thread(is_public, request.url):
                return await route.continue_()
            result["blocked_requests"] += 1
            if request.resource_type != "document":
                return await route.abort()
            if request.frame == page.main_frame:
                guard["blocked"] = await asyncio.to_thread(refusal_reason, request.url) or NOT_PUBLIC
            # "No content" ends the navigation and leaves what was on screen. Aborting would make
            # Chromium replace the page with its own error page.
            await route.fulfill(status=204)
        except Exception as exc:  # the request must end, never hang
            if not guard["closing"]:  # at teardown the browser is going away under every request: not news
                log.warning("request ended early: %s", type(exc).__name__)
            try:
                await route.abort()
            except Exception:
                pass
        finally:
            guard["tasks"].discard(this)

    async def refusal(target: str) -> str | None:
        """Why the browser may not be sent to target, or None if it may."""
        if await asyncio.to_thread(is_public, target):
            return None
        return await asyncio.to_thread(refusal_reason, target) or NOT_PUBLIC

    async def check_response(paused: dict) -> None:
        nonlocal hops
        request_id = paused["requestId"]
        try:
            status = paused.get("responseStatusCode") or 0
            location = next((h["value"] for h in paused.get("responseHeaders", []) if h["name"].lower() == "location"), None)
            if 300 <= status < 400 and location:
                hops += 1
                target = urljoin(paused["request"]["url"], location)
                reason = "too many redirects" if hops > MAX_REDIRECTS else await refusal(target)
                if reason:
                    result["blocked_requests"] += 1
                    if paused.get("frameId") == main_frame_id:
                        guard["blocked"] = reason
                    # Failing the request is the only thing that stops the browser here: answering
                    # the redirect with another response does not, it follows the redirect anyway.
                    return await cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            await cdp.send("Fetch.continueRequest", {"requestId": request_id})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # fail closed: a response we could not vet does not get through
            if not guard["closing"]:
                log.warning("response check ended early: %s", type(exc).__name__)
            try:
                await cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:
                pass

    def on_paused(paused: dict) -> None:
        task = asyncio.ensure_future(check_response(paused))
        guard["tasks"].add(task)
        task.add_done_callback(guard["tasks"].discard)

    def record_navigation(response) -> None:
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            result["redirects"].append({"status": response.status, "url": response.url})

    await ctx.route("**/*", check_request)
    await ctx.route_web_socket("**/*", lambda ws: ws.close())  # observe only: no live channels
    cdp.on("Fetch.requestPaused", on_paused)
    await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"}]})
    page.on("response", record_navigation)


def _ms_left(deadline: float, cap_s: float) -> float:
    return max(500.0, min(cap_s, deadline - asyncio.get_running_loop().time()) * 1000)


def _is_web_page(url: str) -> bool:
    return url.startswith(("http://", "https://"))


async def _navigate(page, url: str, result: dict, deadline: float, guard: dict) -> None:
    """Open the page and wait for it to settle. Sets loaded once a document arrives."""
    try:
        await page.goto(url, wait_until="commit", timeout=_ms_left(deadline, FIRST_RESPONSE_S))
    except Exception as exc:  # no document arrived: we stopped it, or the site did
        result["error"] = f"blocked: {guard['blocked']}" if guard["blocked"] else str(exc).splitlines()[0][:200]
        return
    result["loaded"] = True
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=_ms_left(deadline, DOM_READY_S))
        result["complete"] = True
    except Exception:
        pass  # a slow page: read whatever has rendered
    await page.wait_for_timeout(SETTLE_MS)
    if not _is_web_page(page.url):
        # The page sent itself somewhere we stopped (or to nowhere), and Chromium is now showing its
        # own error page. There is no page of the site's left to read.
        result["loaded"] = result["complete"] = False
        result["error"] = f"blocked: {guard['blocked'] or NOT_PUBLIC}"


class _FrameNotRead(Exception):
    """An embedded frame whose content was not there to read. host is where it comes from, or ""."""

    def __init__(self, host: str):
        super().__init__(host)
        self.host = host


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


async def _in_isolated_world(guard: dict, function_source: str):
    """Run a function against the page's DOM in a world of our own, through DevTools.

    Playwright's evaluate turns its argument into a function with the page's own eval, and a page can
    replace eval (americanexpress.com throws "eval is disabled"). An isolated world shares the DOM
    but has untouched globals, so the page cannot interfere with what we read.
    """
    cdp = guard["cdp"]
    world = await cdp.send("Page.createIsolatedWorld", {"frameId": guard["main_frame_id"], "worldName": "tripwire-read"})
    answer = await cdp.send("Runtime.evaluate", {
        "expression": f"({function_source})()", "contextId": world["executionContextId"], "returnByValue": True,
    })
    if "exceptionDetails" in answer:
        raise RuntimeError("the isolated read failed")
    return answer["result"].get("value")


async def _frame_fields(page, frame, guard: dict | None = None) -> list[dict]:
    """The frame's visible input fields. Raises _FrameNotRead for an embedded frame that has not
    loaded: asking such a frame still "works" (it answers from an empty placeholder document), so
    without this a login form in a slow frame would read as no form at all."""
    if frame == page.main_frame:
        try:
            return await frame.evaluate(READ_FIELDS_JS)
        except (TimeoutError, PlaywrightTimeoutError):
            raise
        except Exception:
            if not guard or not guard.get("cdp"):
                raise
            return await _in_isolated_world(guard, READ_FIELDS_JS) or []
    element = await frame.frame_element()
    box = await element.bounding_box() if await element.is_visible() else None
    if not box or box["width"] < MIN_FRAME_WIDTH or box["height"] < MIN_FRAME_HEIGHT:
        # Hidden or pixel-sized: advertising and tracking frames. Nobody can type into one, so it is
        # neither read nor missed (real pages carry several, and they are often slow or blocked).
        return []
    if not _is_web_page(frame.url):  # nothing has arrived in it yet: what is it meant to show?
        src = await element.get_attribute("src") or ""
        target = urljoin(page.url, src) if src else ""
        # A frame we refused ourselves (a private address) is blocked, not unread.
        if _is_web_page(target) and await asyncio.to_thread(is_public, target):
            raise _FrameNotRead(_host(target))
        return await frame.evaluate(READ_FIELDS_JS)  # about:blank, srcdoc and the like
    fields = await frame.evaluate(READ_FIELDS_JS)
    if await frame.evaluate("() => document.readyState") == "loading":
        raise _FrameNotRead(_host(frame.url))  # still arriving: a form further down has not been seen
    return fields


async def _read_page(page, result: dict, shot_path: Path, guard: dict | None = None) -> None:
    """Read whatever rendered, all at once, so a stalled page costs one timeout and not four.

    A read that fails is NOT the same as an empty page, so each failure is recorded in
    result["read_errors"] as {"what", "frame"} (frame is None for the page itself, else the host of
    the embedded frame, "" if it has no address yet). The scorer treats a page it could not read as
    one it could not inspect.
    """
    result["final_url"] = page.url

    async def attempt(make):
        """One read, tried again once if it fails at once: a page that is navigating at that instant
        throws its script context away, and a moment later it can be read."""
        try:
            return await make()
        except (TimeoutError, PlaywrightTimeoutError, _FrameNotRead):
            raise
        except Exception:
            await asyncio.sleep(READ_RETRY_S)
            return await make()

    async def read(what: str, make, frame: str | None = None):
        """make() starts the read. Returns its value, or None after recording why not."""
        started = time.monotonic()
        try:
            return await asyncio.wait_for(attempt(make), READ_TIMEOUT_S)
        except Exception as exc:
            if isinstance(exc, _FrameNotRead):
                frame = exc.host
            log.warning("read of %s%s failed after %.1fs: %s", what, f" in a frame from {frame}" if frame else "",
                        time.monotonic() - started, type(exc).__name__)
            # A frame that was removed while we asked is not unreadable content; a slow or unloaded one is.
            if frame is None or isinstance(exc, (TimeoutError, PlaywrightTimeoutError, _FrameNotRead)):
                result["read_errors"].append({"what": what, "frame": frame})
            return None

    def frame_read(frame):
        return read("fields", lambda: _frame_fields(page, frame, guard), None if frame == page.main_frame else _host(frame.url))

    frames = page.frames[:MAX_FRAMES]  # login and payment forms often sit in an iframe, so every frame is asked
    _, title, text, *per_frame = await asyncio.gather(
        read("screenshot", lambda: page.screenshot(path=str(shot_path), timeout=READ_TIMEOUT_S * 1000)),
        read("title", page.title),
        read("text", lambda: page.inner_text("body")),
        *(frame_read(frame) for frame in frames),
    )
    result["has_screenshot"] = shot_path.is_file()
    result["title"] = title
    result["text"] = (text or "")[:TEXT_LIMIT]
    result["sensitive_fields"] = sensitive_fields([field for fields in per_frame for field in fields or []])


async def _close(browser, guard: dict) -> None:
    """Throw the browser away without waiting on the page, and leave no work behind.

    A page whose script never yields blocks page.close() and context.close() until the script ends,
    which would hold one of the few browser slots (and the user's wait) for as long as the page likes.
    Closing the browser asks its main process to exit, and every step is capped; whatever is still
    alive afterwards is killed when the Playwright driver shuts down at the end of open_page.
    """
    # Checks still in flight (a DNS lookup, a paused response) have nothing left to protect. End them
    # here: a task still waiting when the driver shuts down is never resumed, and Python reports it
    # as "Task was destroyed but it is pending".
    guard["closing"] = True
    in_flight = list(guard["tasks"])
    for task in in_flight:
        task.cancel()
    if in_flight:
        await asyncio.wait(in_flight, timeout=END_CHECKS_S)
    # No unroute_all here: it waits on the page, and giving up on it part way leaves its own task
    # pending. The checks are already ended above, which is all it was for.
    try:
        await asyncio.wait_for(browser.close(), CLOSE_TIMEOUT_S)
    except Exception as exc:
        log.warning("closing the browser failed (%s); the driver will end it", type(exc).__name__)


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
            guard = {"blocked": None, "tasks": set(), "closing": False}
            try:
                await _install_guards(ctx, page, result, guard)
                deadline = asyncio.get_running_loop().time() + NAVIGATION_BUDGET_S
                await _navigate(page, url, result, deadline, guard)
                if result["redirects"]:  # the last main-frame response is the page we ended on
                    result["final_status"] = result["redirects"][-1]["status"]
                if result["loaded"]:
                    await _read_page(page, result, shot_path, guard)
            finally:
                await _close(browser, guard)
    return result
