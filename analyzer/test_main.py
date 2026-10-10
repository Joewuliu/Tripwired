import re

import pytest
from fastapi.testclient import TestClient

import main
import sandbox
from contract import AnalysisResult

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    return TestClient(main.app)


def fake_open_page(**overrides):
    async def open_page(url, shot_path):
        shot_path.write_bytes(PNG)
        return {
            "loaded": True, "complete": True, "final_url": "https://evil-login.example.com/signin",
            "final_status": 200, "title": "Sign in to paypal.com", "text": "", "blocked_requests": 0,
            "redirects": [{"status": 302, "url": "http://short.example/x"},
                          {"status": 200, "url": "https://evil-login.example.com/signin"}],
            "has_screenshot": True, "error": None, **overrides,
        }

    return open_page


def test_health(client):
    assert client.get("/health").json() == {"ok": True}


def test_analyze_returns_defanged_result_and_a_fetchable_screenshot(client, monkeypatch):
    monkeypatch.setattr(main, "open_page", fake_open_page())
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


def test_a_page_that_did_not_load_is_couldnt_check(client, monkeypatch):
    monkeypatch.setattr(
        main, "open_page",
        fake_open_page(loaded=False, complete=False, final_url=None, final_status=None, has_screenshot=False,
                       redirects=[], error="net::ERR_NAME_NOT_RESOLVED at https://gone.example/"),
    )
    body = client.post("/analyze", json={"urls": ["https://gone.example/"]}).json()
    assert body["verdict"] == "couldnt_check"
    assert body["screenshot_url"] is None
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
