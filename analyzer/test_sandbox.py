import asyncio
import gc
import inspect
import logging
import socket
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

import sandbox

HTML = {"Content-Type": "text/html"}


class Late:
    """A route body that arrives after `seconds`: a slow frame, not a stalled one."""

    def __init__(self, seconds: float, body: bytes):
        self.seconds, self.body = seconds, body


@asynccontextmanager
async def serve(routes):
    """A local server. routes maps a path to (status, headers, body), or to a function of the request
    headers that returns one; a body of None stalls forever, and Late(seconds, body) arrives late.
    Yields (port, hits) where hits lists every path the server was asked for."""
    hits = []

    async def handle(reader, writer):
        path = (await reader.readline()).decode().split(" ")[1]
        request_headers = {}
        while line := (await reader.readline()).strip():
            name, _, value = line.decode().partition(":")
            request_headers[name.strip().lower()] = value.strip()
        hits.append(path)
        route = routes.get(path, (404, HTML, b"not found"))
        status, headers, body = route(request_headers) if callable(route) else route
        if isinstance(body, Late):
            await asyncio.sleep(body.seconds)
            body = body.body
        length = 100 if body is None else len(body)
        head = f"HTTP/1.1 {status} X\r\nContent-Length: {length}\r\nConnection: close\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        writer.write(head.encode() + (body or b""))
        await writer.drain()
        if body is None:
            await asyncio.sleep(30)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], hits
    finally:
        server.close()
        server.close_clients()


@pytest.fixture
def allow_only_loopback_ip(monkeypatch):
    """Let the sandbox reach the test server (127.0.0.1) but nothing else, not even 'localhost'."""
    monkeypatch.setattr(sandbox, "is_public", lambda url: urlparse(url).hostname == "127.0.0.1")


def page(body: str, title: str = "Test page") -> bytes:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>".encode()


@pytest.mark.asyncio
async def test_page_is_opened_read_and_screenshotted(allow_only_loopback_ip, tmp_path):
    shot = tmp_path / "shot.png"
    async with serve({"/": (200, HTML, page("<h1>hello there</h1>"))}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", shot)
    assert result["loaded"] and result["complete"]
    assert result["final_status"] == 200
    assert result["title"] == "Test page"
    assert "hello there" in result["text"]
    assert result["has_screenshot"] and shot.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert result["blocked_requests"] == 0


FORM = """
<form>
  <label for="u">Email</label><input id="u" name="username" value="someone@example.com">
  <label for="p">Password</label><input id="p" name="pw" type="password" value="hunter2-typed-by-nobody">
  <label for="f1">Card number</label><input id="f1" name="f1" value="4111111111111111">
  <input name="csrf" type="hidden" value="tok">
  <input name="old_password" type="password" style="display:none">
  <div style="visibility:hidden"><input name="ssn"></div>
</form>"""


@pytest.mark.asyncio
async def test_visible_sensitive_fields_are_reported_by_kind_and_never_by_value(allow_only_loopback_ip, tmp_path):
    async with serve({"/": (200, HTML, page(FORM))}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    found = result["sensitive_fields"]
    assert [(f["kind"], f["name"]) for f in found] == [("password", "pw"), ("card", "f1")]  # hidden ones are left out
    assert all(set(f) == {"kind", "type", "name", "id"} for f in found)
    assert "hunter2" not in str(found) and "4111" not in str(found)


@pytest.mark.asyncio
async def test_fields_inside_an_iframe_are_found(allow_only_loopback_ip, tmp_path):
    routes = {
        "/": (200, HTML, page('<p>Pay here</p><iframe src="/pay" width="300" height="200"></iframe>')),
        "/pay": (200, HTML, page('<input name="cvv" placeholder="CVV">')),
    }
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert [f["kind"] for f in result["sensitive_fields"]] == ["card"]


@pytest.mark.asyncio
async def test_a_page_that_read_fine_has_no_read_errors(allow_only_loopback_ip, tmp_path):
    async with serve({"/": (200, HTML, page("<h1>Hello</h1>" + FORM))}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["read_errors"] == []


@pytest.mark.asyncio
async def test_a_stalled_iframe_is_recorded_as_unread_not_as_having_no_form(allow_only_loopback_ip, tmp_path):
    """The hole this closes: the form inside a frame that never answered used to read as 'no fields'."""
    routes = {
        "/": (200, HTML, page('<h1>Welcome</h1><iframe src="/slow" width="300" height="200"></iframe>')),
        "/slow": (200, HTML, None),  # headers, then silence
    }
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["loaded"] is True and "Welcome" in result["text"]
    assert result["sensitive_fields"] == []
    assert result["read_errors"] == [{"what": "fields", "frame": "127.0.0.1"}]  # named by where it comes from


@pytest.mark.asyncio
async def test_a_frame_still_arriving_is_unread_too(allow_only_loopback_ip, tmp_path):
    """The frame's document started but stalled half way: a form further down was never seen."""
    async def half_then_stall(reader, writer):
        await reader.readline()
        while (await reader.readline()).strip():
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5000\r\n\r\n<html><body><p>top of the frame</p>")
        await writer.drain()
        await asyncio.sleep(30)

    slow = await asyncio.start_server(half_then_stall, "127.0.0.1", 0)
    slow_port = slow.sockets[0].getsockname()[1]
    try:
        body = page(f'<h1>Welcome</h1><iframe src="http://127.0.0.1:{slow_port}/" width="300" height="200"></iframe>')
        async with serve({"/": (200, HTML, body)}) as (port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    finally:
        slow.close()
        slow.close_clients()
    assert "Welcome" in result["text"]
    assert {"what": "fields", "frame": "127.0.0.1"} in result["read_errors"]


@pytest.mark.asyncio
@pytest.mark.parametrize("style", [
    'style="display:none"', 'width="1" height="1"', 'width="0" height="0"', 'style="visibility:hidden"',
    'style="position:absolute;left:-9999px;width:2px;height:2px"',
])
async def test_a_hidden_or_pixel_sized_frame_is_neither_read_nor_missed(allow_only_loopback_ip, tmp_path, style):
    """Advertising and tracking frames: real sites carry several, they are slow or blocked, and nobody
    can type into one. Treating them as unread turned Amazon and Wells Fargo into 'couldn't check'."""
    routes = {
        "/": (200, HTML, page(f'<h1>Welcome</h1><iframe src="/slow" {style}></iframe><iframe src="/form" {style}></iframe>')),
        "/slow": (200, HTML, None),  # never arrives
        "/form": (200, HTML, page('<input type="password" name="pw">')),  # a form nobody can see
    }
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["read_errors"] == []
    assert result["sensitive_fields"] == []


@pytest.mark.asyncio
async def test_a_page_that_disables_eval_is_still_read(allow_only_loopback_ip, tmp_path):
    """americanexpress.com does this. Playwright's evaluate relies on the page's eval, so the form scan
    failed there every time; it now runs in a world the page cannot tamper with."""
    body = page('<script>window.eval = () => { throw new Error("eval is disabled") }</script>'
                '<h1>Log in</h1><input type="password" name="pw"><input name="cvv" placeholder="CVV">')
    async with serve({"/": (200, HTML, body)}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert [f["kind"] for f in result["sensitive_fields"]] == ["password", "card"]
    assert result["read_errors"] == []
    assert "Log in" in result["text"]


@pytest.mark.asyncio
async def test_a_frame_that_is_styled_away_a_moment_after_it_appears_is_not_unread(allow_only_loopback_ip, tmp_path):
    """Chat widgets and consent frames are inserted unstyled (visible, 300x150, still loading) and
    hidden by the site's own script a moment later. On a slow machine that moment is long enough to
    be caught mid-way; this is what turned citi.com and medicare.gov into 'couldn't check'."""
    body = page('<h1>Welcome</h1><script>'
                'const f = document.createElement("iframe"); f.src = "/widget"; document.body.appendChild(f);'
                'setTimeout(() => { f.style.display = "none"; }, 2000);'
                '</script>')
    routes = {"/": (200, HTML, body), "/widget": (200, HTML, Late(3.5, page("chat")))}
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["read_errors"] == []
    assert "Welcome" in result["text"]


@pytest.mark.asyncio
async def test_a_login_form_in_a_slow_visible_frame_is_read_when_it_arrives(allow_only_loopback_ip, tmp_path):
    """The patience is for reading, not for excusing: a visible frame that holds a form is waited for
    and read, so a slow login frame is not mistaken for no form."""
    body = page('<h1>Sign in</h1><iframe src="/login" width="320" height="220"></iframe>')
    login = page('<input type="password" name="pw"><input name="cvv" placeholder="CVV">')
    routes = {"/": (200, HTML, body), "/login": (200, HTML, Late(1.0, login))}
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert [f["kind"] for f in result["sensitive_fields"]] == ["password", "card"]
    assert result["read_errors"] == []


@pytest.mark.asyncio
async def test_a_visible_frame_that_never_arrives_is_still_unread_after_the_wait(allow_only_loopback_ip, tmp_path):
    body = page('<h1>Sign in</h1><iframe src="/login" width="320" height="220"></iframe>')
    async with serve({"/": (200, HTML, body), "/login": (200, HTML, None)}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["read_errors"] == [{"what": "fields", "frame": "127.0.0.1"}]


def _stub_frame(url: str, state: str = "loading"):
    """An embedded frame that is visible, 300x150, and never gets past its loading state."""
    async def evaluate(script):
        return state if "readyState" in script else []

    async def bounding_box():
        return {"width": 300, "height": 150}

    async def is_visible():
        return True

    async def get_attribute(name):
        return url if name == "src" else ""

    element = SimpleNamespace(bounding_box=bounding_box, is_visible=is_visible, get_attribute=get_attribute)

    async def frame_element():
        return element

    return SimpleNamespace(url=url, evaluate=evaluate, frame_element=frame_element)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://4468676.fls.doubleclick.net/activityi;src=4468676",
    "https://apps.use2.us-gov-pure.cloud/messenger/messenger.html",
    "https://citi.demdex.net/dest5.html",
])
async def test_advertising_analytics_and_chat_frames_are_not_counted_when_they_stay_slow(monkeypatch, url):
    monkeypatch.setattr(sandbox, "FRAME_WAIT_S", 0.2)
    main = SimpleNamespace(url="https://bank.example/")
    page_stub = SimpleNamespace(main_frame=main, url="https://bank.example/")
    assert await sandbox._frame_fields(page_stub, _stub_frame(url)) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://login.evil.example/signin",
    "https://paypal-secure.top/form",
    "https://evil.doubleclick.net.attacker.top/x",  # a lookalike of an ad host is not an ad host
    "https://doubleclick.net.evil.example/x",
])
async def test_any_other_slow_visible_frame_is_unread(monkeypatch, url):
    monkeypatch.setattr(sandbox, "FRAME_WAIT_S", 0.2)
    main = SimpleNamespace(url="https://bank.example/")
    page_stub = SimpleNamespace(main_frame=main, url="https://bank.example/")
    with pytest.raises(sandbox._FrameNotRead):
        await sandbox._frame_fields(page_stub, _stub_frame(url))


@pytest.mark.asyncio
async def test_a_read_that_fails_at_once_is_tried_again(tmp_path):
    """A page navigating at the instant we ask throws its script context away; a moment later it reads."""
    calls = {"text": 0}

    async def text_after_a_hiccup(selector):
        calls["text"] += 1
        if calls["text"] == 1:
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
        return "the page, read on the second try"

    async def nothing(*args, **kwargs):
        return None

    async def no_fields(script):
        return []

    main_frame = SimpleNamespace(url="https://page.example/", evaluate=no_fields)
    stub = SimpleNamespace(url="https://page.example/", screenshot=nothing, title=nothing, inner_text=text_after_a_hiccup,
                           frames=[main_frame], main_frame=main_frame)
    result = {"read_errors": [], "final_url": None}
    await sandbox._read_page(stub, result, tmp_path / "s.png")
    assert result["text"] == "the page, read on the second try"
    assert result["read_errors"] == []
    assert calls["text"] == 2


@pytest.mark.asyncio
async def test_a_read_that_keeps_failing_is_recorded_not_retried_forever(tmp_path):
    calls = {"text": 0}

    async def always_broken(selector):
        calls["text"] += 1
        raise RuntimeError("Execution context was destroyed")

    async def nothing(*args, **kwargs):
        return None

    async def no_fields(script):
        return []

    main_frame = SimpleNamespace(url="https://page.example/", evaluate=no_fields)
    stub = SimpleNamespace(url="https://page.example/", screenshot=nothing, title=nothing, inner_text=always_broken,
                           frames=[main_frame], main_frame=main_frame)
    result = {"read_errors": [], "final_url": None}
    await sandbox._read_page(stub, result, tmp_path / "s.png")
    assert calls["text"] == 2
    assert {"what": "text", "frame": None} in result["read_errors"]


@pytest.mark.asyncio
async def test_an_empty_or_inline_frame_is_not_called_unread(allow_only_loopback_ip, tmp_path):
    body = page('<h1>Hi</h1><iframe></iframe><iframe src="about:blank"></iframe>'
                '<iframe srcdoc="<input type=password name=pw>" width="200" height="80"></iframe>')
    async with serve({"/": (200, HTML, body)}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["read_errors"] == []
    assert [f["kind"] for f in result["sensitive_fields"]] == ["password"]  # the inline frame's form is read


@pytest.mark.asyncio
async def test_a_frame_we_refused_ourselves_is_blocked_not_unread(allow_only_loopback_ip, tmp_path):
    async with serve({}) as (secret_port, secret_hits):
        body = page(f'<h1>Hi</h1><iframe src="http://localhost:{secret_port}/admin"></iframe>')
        async with serve({"/": (200, HTML, body)}) as (port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert secret_hits == []
    assert result["blocked_requests"] >= 1
    assert result["read_errors"] == []


@pytest.mark.asyncio
async def test_a_page_that_never_gives_the_thread_back_cannot_hold_a_browser_slot(allow_only_loopback_ip, tmp_path):
    """Closing a page waits for its script. A page that blocks for a minute used to hold the scan,
    and one of three browser slots, for a minute."""
    body = page("<h1>Sign in</h1><script>setTimeout(() => { const t = Date.now(); while (Date.now() - t < 60000); }, 300)</script>")
    async with serve({"/": (200, HTML, body)}) as (port, _):
        started = asyncio.get_running_loop().time()
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
        took = asyncio.get_running_loop().time() - started
    assert took < 14, f"took {took:.1f}s"
    assert {e["what"] for e in result["read_errors"]} == {"screenshot", "title", "text", "fields"}
    assert result["has_screenshot"] is False
    assert result["loaded"] is True


@pytest.mark.parametrize("value,expected", [
    (None, 3), ("", 3), ("2", 2), ("1", 1), ("6", 6), (" 4 ", 4),
    ("0", 3), ("-1", 3), ("7", 3), ("99", 3), ("two", 3), ("2.5", 3),
])
def test_the_number_of_browsers_comes_from_the_environment_within_limits(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("TRIPWIRE_BROWSERS", raising=False)
    else:
        monkeypatch.setenv("TRIPWIRE_BROWSERS", value)
    assert sandbox._browsers_from_env() == expected


def _leftover_task_reports(caplog) -> list[str]:
    gc.collect()  # a pending task that was dropped is reported when it is collected
    return [r.getMessage() for r in caplog.records if "Task was destroyed" in r.getMessage() or "never retrieved" in r.getMessage()]


@pytest.mark.asyncio
async def test_requests_that_arrive_while_the_browser_is_closing_leave_nothing_pending(monkeypatch, tmp_path, caplog):
    """A busy page keeps requesting right up to the end. Each request that arrived after teardown
    took its snapshot of in-flight work started a check nobody was left to finish: 24 'Task was
    destroyed but it is pending' reports over 6 scans before the fix, none after."""
    def slow_lookup(url):
        time.sleep(0.25)  # a DNS lookup in a worker thread
        return urlparse(url).hostname == "127.0.0.1"

    monkeypatch.setattr(sandbox, "is_public", slow_lookup)
    caplog.set_level(logging.DEBUG)
    body = page('<h1>x</h1><script>setInterval(() => { for (let i = 0; i < 4; i++) '
                'new Image().src = "/p" + Math.random(); }, 20)</script>')
    for _ in range(3):
        async with serve({"/": (200, HTML, body)}) as (port, _):
            await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    await asyncio.sleep(0.8)
    assert _leftover_task_reports(caplog) == []


@pytest.mark.asyncio
async def test_a_request_that_arrives_after_teardown_began_is_refused_not_checked():
    calls = []

    class FakeRoute:
        request = SimpleNamespace(url="http://127.0.0.1/late", resource_type="image", frame=None)

        async def abort(self):
            calls.append("abort")

        async def continue_(self):
            calls.append("continue")

        async def fulfill(self, **kwargs):
            calls.append("fulfill")

    handlers = {}

    class FakeContext:
        async def route(self, pattern, handler):
            handlers["request"] = handler

        async def route_web_socket(self, *args):
            pass

        async def new_cdp_session(self, page):
            class Session:
                async def send(self, method, params=None):
                    return {"frameTree": {"frame": {"id": "main"}}}

                def on(self, *args):
                    pass

            return Session()

    class FakePage:
        main_frame = object()

        def on(self, *args):
            pass

    guard = {"blocked": None, "tasks": set(), "closing": False}
    await sandbox._install_guards(FakeContext(), FakePage(), {"blocked_requests": 0, "redirects": []}, guard)
    guard["closing"] = True
    await handlers["request"](FakeRoute())
    assert calls == ["abort"]  # never continued, never given a lookup
    assert guard["tasks"] == set()


def test_the_sandbox_never_fetches_a_document_itself():
    """route.fetch is Playwright's own HTTP client, not the browser. Sites with bot protection can
    tell: some answer it 403 while serving the real browser (coinbase.com), others never answer it
    (pnc.com), and a fetch still waiting when a scan ends leaves 'Task was destroyed but it is
    pending' behind. Redirects are vetted at the response stage instead (see _install_guards)."""
    source = inspect.getsource(sandbox)
    code = "\n".join(line.split("#")[0] for line in source.splitlines() if not line.strip().startswith(('"""', "#")))
    assert ".fetch(" not in code


@pytest.mark.asyncio
@pytest.mark.parametrize("body,stalled", [
    ('<iframe src="/slow"></iframe><script src="/slow.js"></script><p>content</p>', ("/slow", "/slow.js")),
    ("<p>x</p><script>setTimeout(() => { const t = Date.now(); while (Date.now() - t < 30000); }, 200)</script>", ()),
    ("".join(f'<img src="/img{i}.png">' for i in range(12)) + "<p>content</p>", tuple(f"/img{i}.png" for i in range(12))),
])
async def test_a_scan_that_ends_with_work_in_flight_ends_quietly(monkeypatch, tmp_path, caplog, body, stalled):
    """Requests still arriving, and checks still running, when a scan ends: nothing is left pending
    and teardown is not reported as if requests had failed."""
    def slow_lookup(url):
        time.sleep(0.3)  # runs in a worker thread, like a real DNS lookup
        return urlparse(url).hostname == "127.0.0.1"

    monkeypatch.setattr(sandbox, "is_public", slow_lookup)
    caplog.set_level(logging.DEBUG)
    routes = {"/": (200, HTML, page(body)), **{path: (200, HTML, None) for path in stalled}}
    async with serve(routes) as (port, _):
        await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    await asyncio.sleep(0.6)  # let anything the scan left behind show itself
    assert _leftover_task_reports(caplog) == []
    assert [r.getMessage() for r in caplog.records if "ended early" in r.getMessage()] == []


@pytest.mark.asyncio
async def test_reads_are_made_together_so_stalls_do_not_add_up(tmp_path):
    """Four reads that each hang cost one timeout, not four."""
    async def hang(*args, **kwargs):
        await asyncio.sleep(30)

    frame = SimpleNamespace(url="https://frame.example/x", evaluate=hang, frame_element=hang)
    main_frame = SimpleNamespace(url="https://page.example/", evaluate=hang)
    page_stub = SimpleNamespace(url="https://page.example/", screenshot=hang, title=hang, inner_text=hang,
                                frames=[main_frame, frame], main_frame=main_frame)
    result = {"read_errors": [], "final_url": None}
    started = asyncio.get_running_loop().time()
    await sandbox._read_page(page_stub, result, tmp_path / "s.png")
    took = asyncio.get_running_loop().time() - started
    assert took < sandbox.READ_TIMEOUT_S + 1.5, f"took {took:.1f}s"
    failed = {(e["what"], e["frame"]) for e in result["read_errors"]}
    assert failed == {
        ("fields", None), ("fields", "frame.example"), ("screenshot", None), ("text", None), ("title", None),
    }
    assert result["title"] is None and result["text"] == "" and result["sensitive_fields"] == []


@pytest.mark.asyncio
async def test_a_page_that_is_still_navigating_does_not_end_the_scan(allow_only_loopback_ip, tmp_path):
    body = page("<h1>Just a moment</h1><script>setTimeout(() => location.reload(), 250)</script>")
    async with serve({"/": (200, HTML, body)}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["loaded"] is True
    assert result["text"] or result["read_errors"], "either it was read or the failure was recorded"


@pytest.mark.asyncio
async def test_a_page_without_forms_has_no_sensitive_fields(allow_only_loopback_ip, tmp_path):
    async with serve({"/": (200, HTML, page('<input name="q" placeholder="Search">'))}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["sensitive_fields"] == []


@pytest.mark.asyncio
async def test_the_page_is_never_typed_into_or_submitted(allow_only_loopback_ip, tmp_path):
    """The form posts to /submit and a script reports any input event; neither may ever be requested."""
    body = page("""
      <form action="/submit" method="post"><input name="pw" type="password"><button>Go</button></form>
      <script>
        for (const type of ['input', 'change', 'keydown', 'click', 'submit'])
          document.addEventListener(type, () => fetch('/touched?' + type), true);
      </script>""")
    async with serve({"/": (200, HTML, body)}) as (port, hits):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["sensitive_fields"][0]["kind"] == "password"
    assert not any(hit.startswith(("/submit", "/touched")) for hit in hits), hits


@pytest.mark.asyncio
async def test_public_redirect_chain_is_recorded(allow_only_loopback_ip, tmp_path):
    routes = {
        "/a": (302, {"Location": "/b"}, b""),
        "/b": (301, {"Location": "/c"}, b""),
        "/c": (200, HTML, page("end of the line")),
    }
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/a", tmp_path / "s.png")
    assert [hop["status"] for hop in result["redirects"]] == [302, 301, 200]
    assert result["final_url"].endswith("/c")
    assert "end of the line" in result["text"]


@pytest.mark.asyncio
async def test_redirect_to_a_private_address_is_never_requested(allow_only_loopback_ip, tmp_path):
    async with serve({}) as (port, hits):
        routes_target = f"http://localhost:{port}/secret"  # 'localhost' is not allowed by the fixture
        async with serve({"/r": (302, {"Location": routes_target}, b"")}) as (entry_port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{entry_port}/r", tmp_path / "s.png")
    assert hits == []  # the secret server was never contacted
    assert result["blocked_requests"] >= 1
    assert result["loaded"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("public_hops", [1, 2, 4])
async def test_a_private_address_at_the_end_of_a_longer_chain_is_never_requested(allow_only_loopback_ip, tmp_path, public_hops):
    """Every hop is vetted, not just the first: public -> public -> ... -> private must stop before the last."""
    async with serve({}) as (secret_port, secret_hits):
        routes = {f"/h{i}": (302, {"Location": f"/h{i + 1}"}, b"") for i in range(public_hops)}
        routes[f"/h{public_hops}"] = (302, {"Location": f"http://localhost:{secret_port}/secret"}, b"")
        async with serve(routes) as (port, hits):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/h0", tmp_path / "s.png")
    assert secret_hits == [], "the private address was contacted"
    assert hits == [f"/h{i}" for i in range(public_hops + 1)]  # each public hop was fetched exactly once
    assert result["blocked_requests"] >= 1
    assert result["loaded"] is False


@pytest.mark.asyncio
async def test_a_chain_longer_than_the_limit_is_stopped(allow_only_loopback_ip, tmp_path):
    routes = {f"/h{i}": (302, {"Location": f"/h{i + 1}"}, b"") for i in range(30)}
    async with serve(routes) as (port, hits):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/h0", tmp_path / "s.png")
    assert len(hits) == sandbox.MAX_REDIRECTS + 1
    assert result["loaded"] is False and result["blocked_requests"] == 1


@pytest.mark.asyncio
async def test_cookies_set_on_a_redirect_reach_the_next_hop(allow_only_loopback_ip, tmp_path):
    """Sign-in flows set a cookie on one hop and require it on the next."""
    def landing(headers):
        ok = "session=abc" in headers.get("cookie", "")
        return (200, HTML, page("welcome back" if ok else "cookies are disabled"))

    routes = {"/start": (302, {"Location": "/landing", "Set-Cookie": "session=abc; Path=/"}, b""), "/landing": landing}
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/start", tmp_path / "s.png")
    assert "welcome back" in result["text"]
    assert result["final_url"].endswith("/landing")


@pytest.mark.asyncio
async def test_a_page_that_redirects_itself_after_loading_is_followed_and_still_vetted(allow_only_loopback_ip, tmp_path):
    async with serve({}) as (secret_port, secret_hits):
        routes = {
            "/": (200, HTML, page('<p>one moment</p><script>location.href = "/go"</script>')),
            "/go": (302, {"Location": "/landed"}, b""),
            "/landed": (200, HTML, page('<p>the real page</p><script>location.href = "/trap"</script>')),
            "/trap": (302, {"Location": f"http://localhost:{secret_port}/secret"}, b""),
        }
        async with serve(routes) as (port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert secret_hits == [], "the private address was contacted"
    assert result["blocked_requests"] >= 1
    assert [hop["url"].rsplit("/", 1)[-1] for hop in result["redirects"]][:3] == ["", "go", "landed"]  # the public part was followed
    # Stopping the browser there leaves it on its own error page, so there is no page of the site's to
    # read: the scan says so instead of describing an error page.
    assert result["loaded"] is False
    assert result["error"] == "blocked: not a public address"
    assert result["text"] == "" and result["has_screenshot"] is False


@pytest.mark.asyncio
async def test_a_private_address_reached_by_an_iframe_redirect_chain_is_never_requested(allow_only_loopback_ip, tmp_path):
    async with serve({}) as (secret_port, secret_hits):
        routes = {
            "/": (200, HTML, page('<p>outer</p><iframe src="/f0"></iframe>')),
            "/f0": (302, {"Location": "/f1"}, b""),
            "/f1": (302, {"Location": f"http://localhost:{secret_port}/secret"}, b""),
        }
        async with serve(routes) as (port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert secret_hits == [], "the private address was contacted"
    assert result["loaded"] is True
    assert result["blocked_requests"] >= 1


@pytest.mark.asyncio
async def test_private_subresource_is_blocked(allow_only_loopback_ip, tmp_path):
    async with serve({}) as (secret_port, secret_hits):
        body = page(f'<p>page</p><img src="http://localhost:{secret_port}/pixel.png">')
        async with serve({"/": (200, HTML, body)}) as (port, _):
            result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["loaded"] is True
    assert secret_hits == []
    assert result["blocked_requests"] >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8001/", "file:///etc/passwd"])
async def test_non_public_urls_are_refused_without_launching_a_browser(monkeypatch, tmp_path, url):
    def no_browser():
        raise AssertionError("a browser was launched")

    monkeypatch.setattr(sandbox, "async_playwright", no_browser)
    result = await sandbox.open_page(url, tmp_path / "s.png")
    assert result["loaded"] is False
    assert result["error"].startswith("blocked")
    assert not (tmp_path / "s.png").exists()


@pytest.mark.asyncio
async def test_a_name_that_does_not_resolve_is_reported_as_such_without_a_browser(monkeypatch, tmp_path):
    def no_browser():
        raise AssertionError("a browser was launched")

    def no_such_host(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(sandbox, "async_playwright", no_browser)
    monkeypatch.setattr(socket, "getaddrinfo", no_such_host)
    result = await sandbox.open_page("https://taken-down-scam.example/pay", tmp_path / "s.png")
    assert result["loaded"] is False
    assert result["error"] == "blocked: the name does not resolve"


@pytest.mark.asyncio
async def test_unreachable_host_reports_not_loaded(allow_only_loopback_ip, tmp_path):
    result = await sandbox.open_page("http://127.0.0.1:1/", tmp_path / "s.png")
    assert result["loaded"] is False
    assert result["error"]
    assert result["final_status"] is None


@pytest.mark.asyncio
async def test_download_is_not_saved_and_does_not_crash(allow_only_loopback_ip, tmp_path):
    headers = {"Content-Type": "application/octet-stream", "Content-Disposition": "attachment; filename=x.bin"}
    async with serve({"/f": (200, headers, b"MZ" + b"\x00" * 64)}) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/f", tmp_path / "s.png")
    assert result["has_screenshot"] is False
    assert list(tmp_path.glob("*.bin")) == []


@pytest.mark.asyncio
async def test_page_that_never_finishes_still_yields_what_rendered(allow_only_loopback_ip, tmp_path):
    body = page("<h1>Visible content</h1><script src='/slow.js'></script>", title="Half loaded")
    routes = {"/": (200, HTML, body), "/slow.js": (200, {"Content-Type": "text/javascript"}, None)}
    async with serve(routes) as (port, _):
        result = await sandbox.open_page(f"http://127.0.0.1:{port}/", tmp_path / "s.png")
    assert result["loaded"] is True
    assert result["complete"] is False
    assert result["title"] == "Half loaded"
    assert "Visible content" in result["text"]
    assert result["has_screenshot"]


@pytest.mark.network
@pytest.mark.asyncio
async def test_example_com_opens(tmp_path):
    result = await sandbox.open_page("https://example.com", tmp_path / "s.png")
    assert result["loaded"], result["error"]
    assert result["title"] == "Example Domain"
    assert result["has_screenshot"]
