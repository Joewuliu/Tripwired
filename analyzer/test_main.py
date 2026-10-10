import re

import pytest
from fastapi.testclient import TestClient

import main
import pipeline
import sandbox
from contract import AnalysisResult

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PAGE = {
    "loaded": True, "complete": True, "final_url": "https://evil-login.some-small-shop.top/signin",
    "final_status": 200, "title": "Sign in to paypal.com", "text": "Sign in to continue", "blocked_requests": 0,
    "redirects": [{"status": 302, "url": "http://short.example/x"},
                  {"status": 200, "url": "https://evil-login.some-small-shop.top/signin"}],
    "has_screenshot": True, "error": None, "sensitive_fields": [],
}
ALL_CLEAR = [
    {"source": "Google Safe Browsing", "status": "clear"},
    {"source": "URLhaus", "status": "clear"},
    {"source": "OpenPhish", "status": "clear"},
]
YOUNG = {"domain": "some-small-shop.top", "registered": "2026-10-08T00:00:00Z", "age_days": 2, "source": "RDAP", "error": None}
OLD = {**YOUNG, "registered": "1996-01-01T00:00:00Z", "age_days": 11000}


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
    assert body["verdict"] == "suspicious" and body["score"] == 30  # a two-day-old domain, nothing else
    assert body["headline"] == "Suspicious: Registered 2 days ago, from RDAP"
    assert [(e["id"], e["points"], e["source"]) for e in body["evidence"]] == [
        ("domain_under_7_days", 30, "RDAP"),
        ("feeds_clear", 0, "Google Safe Browsing, URLhaus, OpenPhish"),
        ("brand_mention", 0, "Brand list"),
    ]
    assert body["points_table"] and {r["id"] for r in body["points_table"]} >= {"known_threat_feed", "official_domain"}
    assert body["brand_match"] is None
    assert re.fullmatch(r"[a-f0-9]{12}", body["id"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["created_at"])
    assert body["loaded"] is True and body["final_status"] == 200
    assert body["url_defanged"] == "hxxps://short[.]example/x"
    assert body["final_url_defanged"] == "hxxps://evil-login[.]some-small-shop[.]top/signin"
    assert body["redirects_defanged"][0] == {"status": 302, "url": "hxxp://short[.]example/x"}
    assert body["title"] == "Sign in to paypal[.]com"
    assert "http://" not in str(body) and "https://" not in str(body)

    shot = client.get(body["screenshot_url"])
    assert shot.status_code == 200 and shot.headers["content-type"] == "image/png"
    assert shot.content == PNG


def test_every_scan_is_kept_and_served_back_unchanged(client, monkeypatch, tmp_path):
    fake_world(monkeypatch, age=OLD, title="A shop", text="Welcome")
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    stored = client.get(f"/api/report/{body['id']}")
    assert stored.status_code == 200
    assert stored.json() == body  # the report is the scan result, nothing added or lost
    assert (tmp_path / "reports" / f"{body['id']}.json").is_file()


def test_a_report_is_served_for_every_verdict(client, monkeypatch):
    for kwargs in (dict(feeds=[{"source": "OpenPhish", "status": "hit", "url": "u", "kind": "phishing", "detail": "x"}]),
                   dict(final_status=403, title="Error", text="Forbidden")):
        fake_world(monkeypatch, age=OLD, **kwargs)
        body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
        assert client.get(f"/api/report/{body['id']}").json()["verdict"] == body["verdict"]


def test_the_analysis_survives_a_report_that_cannot_be_saved(client, monkeypatch):
    def disk_full(directory, result):
        raise OSError("no space left on device")

    fake_world(monkeypatch, age=OLD, title="A shop", text="Welcome")
    monkeypatch.setattr(main, "save_report", disk_full)
    response = client.post("/analyze", json={"urls": ["https://short.example/x"]})
    assert response.status_code == 200
    assert response.json()["verdict"] == "no_red_flags"
    assert client.get(f"/api/report/{response.json()['id']}").status_code == 404


@pytest.mark.parametrize("report_id", ["000000000000", "not-an-id", "ABCDEF012345", "..%2F..%2Fetc%2Fpasswd", "abc"])
def test_an_unknown_or_malformed_report_is_404(client, report_id):
    assert client.get(f"/api/report/{report_id}").status_code == 404


def test_a_report_can_only_be_read_never_written_through_the_api(client, monkeypatch):
    """The proxy forwards /api/report/* to the analyzer as is, so the route itself must be read-only."""
    fake_world(monkeypatch, age=OLD, title="A shop", text="Welcome")
    report_id = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()["id"]
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)(f"/api/report/{report_id}").status_code == 405, method
    assert client.get(f"/api/report/{report_id}").status_code == 200


def test_the_private_address_refusal_is_kept_too(client, monkeypatch):
    def no_browser():
        raise AssertionError("a browser was launched")

    monkeypatch.setattr(sandbox, "async_playwright", no_browser)
    body = client.post("/analyze", json={"urls": ["http://169.254.169.254/latest/meta-data/"]}).json()
    assert client.get(f"/api/report/{body['id']}").json()["verdict"] == "couldnt_check"


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
    assert body["brand_match"] == {
        "brand": "PayPal", "official_domain_defanged": "paypal[.]com", "real_screenshot_url": None, "similarity": None,
    }
    assert "paypa1.com" not in str(body)


def test_an_official_page_is_reported_as_official_and_not_flagged(client, monkeypatch):
    fake_world(
        monkeypatch, final_url="https://www.chase.com/", title="Chase", age=OLD,
        redirects=[{"status": 200, "url": "https://www.chase.com/"}],
    )
    body = client.post("/analyze", json={"urls": ["https://www.chase.com/"]}).json()
    assert body["verdict"] == "no_red_flags" and body["score"] == 0
    assert body["headline"] == "No red flags found. That is not a guarantee."
    assert "Registered domain is official for Chase (brand list)" in body["observations"]
    assert not any("imitates" in line or "not an official site" in line for line in body["observations"])


def test_a_clean_page_is_no_red_flags_and_never_called_safe(client, monkeypatch):
    fake_world(monkeypatch, age=OLD, title="A shop", text="Welcome")
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    assert (body["verdict"], body["score"]) == ("no_red_flags", 0)
    assert not re.search(r"\bsafe", (body["headline"] + " ".join(body["observations"])).lower().replace("google safe browsing", ""))


def test_a_listed_page_is_dangerous_whatever_else_is_true(client, monkeypatch):
    hit = [{"source": "OpenPhish", "status": "hit", "url": "u", "kind": "phishing", "detail": "exact URL is on the list"}]
    fake_world(monkeypatch, feeds=hit, age=OLD, title="A shop", text="Welcome")
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    assert (body["verdict"], body["score"]) == ("dangerous", 60)
    assert body["headline"] == "Dangerous: Listed as phishing by OpenPhish"


@pytest.mark.parametrize("overrides", [
    dict(final_status=403, title="Error", text="Forbidden"),  # refused us
    dict(title="Just a moment...", text="Verifying you are human. This may take a few seconds."),  # human check
    dict(title="", text=""),  # blank
    dict(final_status=404, title="Not found", text="Nothing here"),  # gone
])
def test_a_page_we_could_not_see_is_never_no_red_flags(client, monkeypatch, overrides):
    fake_world(monkeypatch, age=OLD, **overrides)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["headline"].startswith("Couldn't get a proper look at this link.")


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
        redirects=[], error="net::ERR_NAME_NOT_RESOLVED at https://gone.example/", age=OLD,
    )
    body = client.post("/analyze", json={"urls": ["https://gone.example/"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["screenshot_url"] is None
    assert body["observations"][0] == "The address does not resolve (DNS lookup)"
    assert "Registered 30 years ago, from RDAP" in body["observations"]
    assert "https://" not in str(body) and "ERR_NAME" not in str(body)  # no raw browser error reaches a user


def test_what_the_page_asks_for_and_how_it_answered_are_reported(client, monkeypatch):
    fake_world(
        monkeypatch, final_status=403, title="Sign in", text="Enter your details",
        sensitive_fields=[{"kind": "password", "type": "password", "name": "pw", "id": ""},
                          {"kind": "card", "type": "text", "name": "cc", "id": ""}],
    )
    lines = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()["observations"]
    assert "Page asks for a password and card details (page scan)" in lines
    assert "The site refused the sandbox's phone browser (HTTP 403)" in lines


def test_a_hosts_own_warning_page_is_reported(client, monkeypatch):
    fake_world(monkeypatch, title="Suspected phishing site | Cloudflare", text="This website has been reported")
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    assert "The hosting provider has already flagged this page as dangerous (Cloudflare phishing warning)" in body["observations"]
    assert body["verdict"] == "dangerous"


def test_private_address_is_refused_without_launching_a_browser(client, monkeypatch):
    def no_browser():
        raise AssertionError("a browser was launched")

    monkeypatch.setattr(sandbox, "async_playwright", no_browser)
    body = client.post("/analyze", json={"urls": ["http://169.254.169.254/latest/meta-data/"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["loaded"] is False
    assert body["screenshot_url"] is None
    assert body["observations"][0] == "Not a public web address, so it was not opened"


@pytest.mark.parametrize("payload", [{}, {"urls": []}, {"urls": [""]}, {"urls": ["x" * 3000]}, {"urls": "https://a.test"}])
def test_bad_requests_are_rejected(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


@pytest.mark.parametrize("scan_id", ["abcdef012345", "..%2F..%2Fetc", "not-hex-chars", "ABCDEF012345", "abc"])
def test_unknown_or_malformed_screenshot_ids_are_404(client, scan_id):
    assert client.get(f"/shots/{scan_id}.png").status_code == 404
