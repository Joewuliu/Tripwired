import re

import pytest
from fastapi.testclient import TestClient

import main
import pipeline
import sandbox
from contract import AnalysisResult

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PAGE = {
    "loaded": True, "complete": True, "final_url": "https://evil-login.example.com/signin",
    "final_status": 200, "title": "Sign in to paypal.com", "text": "", "blocked_requests": 0,
    "redirects": [{"status": 302, "url": "http://short.example/x"},
                  {"status": 200, "url": "https://evil-login.example.com/signin"}],
    "has_screenshot": True, "error": None,
}
ALL_CLEAR = [
    {"source": "Google Safe Browsing", "status": "clear"},
    {"source": "URLhaus", "status": "clear"},
    {"source": "OpenPhish", "status": "clear"},
]
YOUNG = {"domain": "example.com", "registered": "2026-10-08T00:00:00Z", "age_days": 2, "source": "RDAP", "error": None}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    return TestClient(main.app)


def fake_world(monkeypatch, feeds=None, age=None, **page):
    """A fake page, fake feeds and fake RDAP behind the real pipeline."""

    async def open_page(url, shot_path):
        if page.get("has_screenshot", True):
            shot_path.write_bytes(PNG)
        return {**PAGE, **page}

    async def check_feeds(urls, timeout=5.0):
        return feeds if feeds is not None else ALL_CLEAR

    async def domain_age(host):
        return age or YOUNG

    monkeypatch.setattr(pipeline, "open_page", open_page)
    monkeypatch.setattr(pipeline, "check_feeds", check_feeds)
    monkeypatch.setattr(pipeline, "domain_age", domain_age)


def test_health(client):
    assert client.get("/health").json() == {"ok": True}


def test_analyze_returns_defanged_result_and_a_fetchable_screenshot(client, monkeypatch):
    fake_world(monkeypatch)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()

    AnalysisResult.model_validate(body)  # the response is exactly the shared contract
    assert body["verdict"] == "unscored" and body["score"] is None
    assert body["evidence"] == [] and body["points_table"] == [] and body["brand_match"] is None
    assert re.fullmatch(r"[a-f0-9]{12}", body["id"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["created_at"])
    assert body["loaded"] is True and body["final_status"] == 200
    assert body["url_defanged"] == "hxxps://short[.]example/x"
    assert body["final_url_defanged"] == "hxxps://evil-login[.]example[.]com/signin"
    assert body["redirects_defanged"][0] == {"status": 302, "url": "hxxp://short[.]example/x"}
    assert body["title"] == "Sign in to paypal[.]com"
    assert "http://" not in str(body) and "https://" not in str(body)

    shot = client.get(body["screenshot_url"])
    assert shot.status_code == 200 and shot.headers["content-type"] == "image/png"
    assert shot.content == PNG


def test_observations_say_what_the_feeds_and_rdap_found(client, monkeypatch):
    fake_world(monkeypatch)
    lines = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()["observations"]
    assert "Not listed by Google Safe Browsing, URLhaus or OpenPhish" in lines
    assert "Registered 2 days ago, from RDAP" in lines


def test_brand_findings_appear_in_the_observations_defanged(client, monkeypatch):
    fake_world(
        monkeypatch, final_url="https://paypa1.com/login", title="Log in",
        redirects=[{"status": 200, "url": "https://paypa1.com/login"}],
    )
    body = client.post("/analyze", json={"urls": ["https://paypa1.com/login"]}).json()
    assert "Domain imitates PayPal: paypa1[.]com spells \"paypal\" with look-alike characters (look-alike check)" in body["observations"]
    assert "paypa1.com" not in str(body)


def test_an_official_page_is_reported_as_official(client, monkeypatch):
    fake_world(
        monkeypatch, final_url="https://www.chase.com/", title="Chase",
        redirects=[{"status": 200, "url": "https://www.chase.com/"}],
    )
    lines = client.post("/analyze", json={"urls": ["https://www.chase.com/"]}).json()["observations"]
    assert "Registered domain is official for Chase (brand list)" in lines
    assert not any("imitates" in line or "not an official site" in line for line in lines)


def test_a_listing_is_reported_by_name(client, monkeypatch):
    hit = [{"source": "OpenPhish", "status": "hit", "url": "https://evil-login.example.com/signin",
            "kind": "phishing", "detail": "exact URL is on the list"}]
    fake_world(monkeypatch, feeds=hit)
    lines = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()["observations"]
    assert "Listed as phishing by OpenPhish" in lines


def test_a_missing_key_is_shown_as_not_checked(client, monkeypatch):
    feeds = [
        {"source": "Google Safe Browsing", "status": "not_checked", "detail": "SAFE_BROWSING_API_KEY is not set"},
        {"source": "URLhaus", "status": "not_checked", "detail": "URLHAUS_AUTH_KEY is not set"},
        {"source": "OpenPhish", "status": "clear"},
    ]
    fake_world(monkeypatch, feeds=feeds)
    lines = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()["observations"]
    assert "Google Safe Browsing was not checked (no API key is set)" in lines
    assert "URLhaus was not checked (no API key is set)" in lines
    assert "Not listed by OpenPhish" in lines


def test_a_page_that_did_not_load_is_couldnt_check_but_feeds_and_age_still_report(client, monkeypatch):
    fake_world(
        monkeypatch, loaded=False, complete=False, final_url=None, final_status=None, has_screenshot=False,
        redirects=[], error="net::ERR_NAME_NOT_RESOLVED at https://gone.example/",
    )
    body = client.post("/analyze", json={"urls": ["https://gone.example/"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["screenshot_url"] is None
    assert "Registered 2 days ago, from RDAP" in body["observations"]
    assert "https://" not in str(body)


def test_private_address_is_refused_without_launching_a_browser(client, monkeypatch):
    def no_browser():
        raise AssertionError("a browser was launched")

    monkeypatch.setattr(sandbox, "async_playwright", no_browser)
    body = client.post("/analyze", json={"urls": ["http://169.254.169.254/latest/meta-data/"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["loaded"] is False
    assert body["screenshot_url"] is None


@pytest.mark.parametrize("payload", [{}, {"urls": []}, {"urls": [""]}, {"urls": ["x" * 3000]}, {"urls": "https://a.test"}])
def test_bad_requests_are_rejected(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


@pytest.mark.parametrize("scan_id", ["abcdef012345", "..%2F..%2Fetc", "not-hex-chars", "ABCDEF012345", "abc"])
def test_unknown_or_malformed_screenshot_ids_are_404(client, scan_id):
    assert client.get(f"/shots/{scan_id}.png").status_code == 404
