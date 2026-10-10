import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import pytest

import sandbox

HTML = {"Content-Type": "text/html"}


@asynccontextmanager
async def serve(routes):
    """A local server. routes maps a path to (status, headers, body); a body of None stalls forever.
    Yields (port, hits) where hits lists every path the server was asked for."""
    hits = []

    async def handle(reader, writer):
        path = (await reader.readline()).decode().split(" ")[1]
        while (await reader.readline()).strip():
            pass
        hits.append(path)
        status, headers, body = routes.get(path, (404, HTML, b"not found"))
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
