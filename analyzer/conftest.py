"""Safety nets for every test: none of them may reach a live feed, RDAP, or use a real API key."""
import pytest

import enrich
import feeds
import gemini
import og


@pytest.fixture(autouse=True)
def isolate_from_the_outside_world(request, monkeypatch, tmp_path):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    # No test draws a preview picture with a real browser unless it asks to (test_og.py keeps the real one).
    async def fake_png(page_html: str) -> bytes:
        return bytes.fromhex("89504e470d0a1a0a") + bytes(16)

    monkeypatch.setattr(og, "render_png", fake_png)
    monkeypatch.setattr(feeds, "OPENPHISH_PATH", tmp_path / "openphish.txt")
    monkeypatch.setattr(feeds, "_openphish_cache", {"stamp": None, "parsed": None})
    if request.node.get_closest_marker("network"):
        return

    def no_network(*args, **kwargs):
        raise AssertionError("this test tried to use the network; give it a mock transport")

    monkeypatch.setattr(feeds, "_client", no_network)
    monkeypatch.setattr(enrich, "_client", no_network)
    monkeypatch.setattr(gemini, "_client", no_network)
