"""The link-preview picture and the page that points preview programs at it."""
import re
import struct

import pytest

import main
import og
from contract import AnalysisResult
from test_main import OLD, client, fake_world  # noqa: F401  (fixtures and the fake page world)
from test_reports import SAMPLE

REAL_RENDER = og.render_png  # conftest swaps this for a stand-in before every test
PNG_HEAD = bytes.fromhex("89504e470d0a1a0a")


def report(**overrides) -> AnalysisResult:
    return AnalysisResult.model_validate({**SAMPLE, **overrides})


VERDICTS = ["dangerous", "suspicious", "no_red_flags", "couldnt_check"]


@pytest.mark.parametrize("verdict", VERDICTS)
def test_the_picture_says_the_verdict_in_words_and_what_to_do(verdict):
    page = og.og_html(report(verdict=verdict, headline="Something plain."), font=None)
    assert f'<div class="badge">{og.LABEL[verdict].replace(chr(39), "&#x27;")}</div>' in page
    assert og.ACTION[verdict].replace("'", "&#x27;") in page
    assert "Phish Finder" in page
    tone, fill = og.TONE[verdict]
    assert tone in page and fill in page


def test_nothing_on_the_picture_says_safe_and_the_clean_colour_is_not_green():
    words = " ".join([*og.LABEL.values(), *og.ACTION.values()])
    assert not re.search(r"\bsafe", words, re.IGNORECASE)
    for colour in og.TONE["no_red_flags"]:
        r, g, b = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
        assert b >= g, colour  # aqua or blue


def test_the_headline_loses_its_verdict_word_because_the_badge_says_it():
    assert og.headline_body(report(headline="Dangerous: Security services have already reported this link as a scam.")) == (
        "Security services have already reported this link as a scam."
    )
    assert og.headline_body(report(verdict="no_red_flags", headline="No red flags found. That is not a guarantee.")) == (
        "No red flags found. That is not a guarantee."
    )


def test_a_couldnt_check_leads_with_its_reason_on_the_picture_and_in_the_preview_text():
    stuck = report(
        verdict="couldnt_check",
        headline="Couldn't get a proper look at this link. Don't enter anything until you verify it another way.",
        observations=["That web address doesn't exist, or no longer works.", "This website was created 30 years ago."],
    )
    assert og.headline_body(stuck) == "That web address doesn't exist, or no longer works."
    assert "That web address doesn&#x27;t exist, or no longer works." in og.og_html(stuck, font=None)
    assert 'og:description" content="That web address doesn&#x27;t exist' in og.share_html(stuck, "https://phish.example")


def test_every_word_is_escaped_so_a_headline_cannot_add_markup_or_load_anything():
    hostile = 'Dangerous: </div><script src="https://evil.example/x.js"></script><img src=x onerror=alert(1)>'
    page = og.og_html(report(headline=hostile), font=None)
    assert "<script" not in page and "<img src=x" not in page
    assert "&lt;script" in page
    assert "https://evil.example" not in page.replace("&quot;https://evil.example", "")  # only as escaped text
    stub = og.share_html(report(headline=hostile), "https://phish.example")
    assert "<script" not in stub and 'content="&lt;/div&gt;' in stub


def test_the_picture_embeds_the_screenshot_and_the_font_and_links_to_nothing(tmp_path):
    shot = tmp_path / "shot.png"
    shot.write_bytes(PNG_HEAD + bytes(8))
    page = og.og_html(report(), shot)
    assert 'src="data:image/png;base64,' in page
    assert "url('data:font/ttf;base64," in page  # the wordmark's font ships with the analyzer
    assert not re.search(r"""(src|href)=["']https?:""", page)
    assert "No picture of this page" in og.og_html(report(), None, font=None)


@pytest.mark.asyncio
async def test_a_real_browser_draws_a_1200_by_630_png_with_no_network(tmp_path):
    page = og.og_html(report(headline="Dangerous: The web address uses the name E-ZPass, but it isn't their real website."))
    png = await REAL_RENDER(page)
    assert png[:8] == PNG_HEAD
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (1200, 630)
    assert len(png) > 20_000  # a drawn picture, not a blank one


# --- made once, kept, served -------------------------------------------------------------------


def test_a_scan_gets_its_picture_and_it_is_drawn_only_once(client, monkeypatch, tmp_path):  # noqa: F811
    drawn = []

    async def counting(page_html: str) -> bytes:
        drawn.append(page_html)
        return PNG_HEAD + bytes(32)

    monkeypatch.setattr(og, "render_png", counting)
    fake_world(monkeypatch)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    first = client.get(f"/og/{body['id']}.png")
    assert first.status_code == 200 and first.headers["content-type"] == "image/png"
    assert first.content.startswith(PNG_HEAD)
    assert "max-age" in first.headers["cache-control"]
    assert client.get(f"/og/{body['id']}.png").status_code == 200
    assert len(drawn) == 1
    assert (tmp_path / "og" / f"{body['id']}.png").is_file()
    assert "Suspicious" in drawn[0] and "data:image/png;base64," in drawn[0]  # the scan's own screenshot is on it


def test_no_report_no_picture_and_a_bad_id_never_reaches_the_disk(client):  # noqa: F811
    assert client.get("/og/000000000000.png").status_code == 404
    for bad in ["..%2F..%2Fsecret", "ABCDEF123456", "abc", "5a3c0de1f2b4.json"]:
        assert client.get(f"/og/{bad}.png").status_code == 404, bad
    assert client.post("/og/000000000000.png").status_code == 405  # read-only


def test_a_picture_that_cannot_be_drawn_is_a_404_and_the_scan_is_unharmed(client, monkeypatch):  # noqa: F811
    async def broken(page_html: str) -> bytes:
        raise RuntimeError("no browser")

    monkeypatch.setattr(og, "render_png", broken)
    fake_world(monkeypatch)
    response = client.post("/analyze", json={"urls": ["https://short.example/x"]})
    assert response.status_code == 200 and response.json()["verdict"] == "suspicious"
    assert client.get(f"/og/{response.json()['id']}.png").status_code == 404
    assert client.get(f"/api/report/{response.json()['id']}").status_code == 200


# --- the page preview programs are given ---------------------------------------------------------


def test_the_share_page_has_the_tags_a_preview_reads(client, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    headers = {"X-Forwarded-Host": "phish.example", "X-Forwarded-Proto": "https"}
    page = client.get(f"/share/{body['id']}", headers=headers)
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    text = page.text
    assert '<meta property="og:title" content="Phish Finder: Suspicious">' in text
    assert f'<meta property="og:image" content="https://phish.example/og/{body["id"]}.png">' in text
    assert f'<meta property="og:url" content="https://phish.example/r/{body["id"]}">' in text
    assert '<meta property="og:image:width" content="1200">' in text
    assert '<meta name="twitter:card" content="summary_large_image">' in text
    assert "This website was only created 2 days ago." in text
    assert "http://" not in text and "short.example" not in text  # nothing about the scanned address


def test_the_share_page_ignores_a_host_that_is_not_a_host(client, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"]}).json()
    page = client.get(f"/share/{body['id']}", headers={"X-Forwarded-Host": 'evil.example"><script>'})
    assert "<script" not in page.text and "evil.example" not in page.text
    assert f'content="/og/{body["id"]}.png"' in page.text
    assert client.get("/share/000000000000").status_code == 404


def test_the_origin_is_https_unless_plain_http_was_really_used():
    assert og.public_origin("1-2-3-4.sslip.io", "https") == "https://1-2-3-4.sslip.io"
    assert og.public_origin("127.0.0.1:8002", "http") == "http://127.0.0.1:8002"
    assert og.public_origin("a.example", None) == "https://a.example"
    for bad in [None, "", "a b", "a/b", "evil.example\r\nX: y", "x" * 300]:
        assert og.public_origin(bad, "https") == ""


def test_the_main_module_uses_the_same_data_folder_for_pictures(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    assert og.og_path(main.DATA_DIR, "5a3c0de1f2b4") == tmp_path / "og" / "5a3c0de1f2b4.png"
