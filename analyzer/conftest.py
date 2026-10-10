"""Safety nets for every test: none of them may reach a live feed, RDAP, or use a real API key."""
import pytest

import enrich
import feeds


@pytest.fixture(autouse=True)
def isolate_from_the_outside_world(request, monkeypatch, tmp_path):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.setattr(feeds, "OPENPHISH_PATH", tmp_path / "openphish.txt")
    monkeypatch.setattr(feeds, "_openphish_cache", {"stamp": None, "parsed": None})
    if request.node.get_closest_marker("network"):
        return

    def no_network(*args, **kwargs):
        raise AssertionError("this test tried to use the network; give it a mock transport")

    monkeypatch.setattr(feeds, "_client", no_network)
    monkeypatch.setattr(enrich, "_client", no_network)
