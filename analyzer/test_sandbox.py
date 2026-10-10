import asyncio
import socket
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import pytest

import sandbox

HTML = {"Content-Type": "text/html"}


@asynccontextmanager
async def serve(routes):
    """A local server. routes maps a path to (status, headers, body), or to a function of the request
    headers that returns one; a body of None stalls forever.
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
    assert "the real page" in result["text"]
    assert result["final_url"].endswith("/landed")
    assert [hop["status"] for hop in result["redirects"]] == [200, 302, 200, 302]
    assert result["blocked_requests"] >= 1


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
