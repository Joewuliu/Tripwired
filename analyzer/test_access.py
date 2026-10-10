import re

import pytest

from access import judge_access


def page(**overrides) -> dict:
    return {"loaded": True, "complete": True, "final_status": 200, "title": "A shop", "text": "Welcome to the shop " * 5,
            "error": None, "read_errors": [], **overrides}


def kind(**overrides):
    result = judge_access(page(**overrides))
    return result and result["kind"]


def test_a_normal_page_has_nothing_to_report():
    assert judge_access(page()) is None


@pytest.mark.parametrize("error", ["blocked: not a public address", "blocked: not an http(s) address"])
def test_our_own_refusal_is_not_held_against_the_site(error):
    assert kind(loaded=False, error=error) == "not_public"


@pytest.mark.parametrize("error", [
    "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://gone.example/",  # the browser found out
    "blocked: the name does not resolve",  # the address guard found out first
])
def test_a_name_that_does_not_resolve(error):
    assert kind(loaded=False, error=error) == "unresolved"


@pytest.mark.parametrize("error", ["Page.goto: net::ERR_CONNECTION_REFUSED at x", "Page.goto: Timeout 10000ms exceeded.", ""])
def test_other_failures_to_load_are_unreachable(error):
    assert kind(loaded=False, error=error) == "unreachable"


@pytest.mark.parametrize("code", ["ERR_HTTP2_PROTOCOL_ERROR", "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_EMPTY_RESPONSE"])
def test_a_site_that_cuts_the_connection_refused_us(code):
    """What pnc.com does to a browser it takes for automated: the site is there, it would not talk to us."""
    result = judge_access(page(loaded=False, error=f"Page.goto: net::{code} at https://www.bank.example/"))
    assert result == {"kind": "refused", "detail": "it dropped the connection"}


@pytest.mark.parametrize("status", [404, 410])
def test_gone(status):
    result = judge_access(page(final_status=status, title="Not found", text="Nothing here"))
    assert result == {"kind": "gone", "detail": f"HTTP {status}"}


@pytest.mark.parametrize("status", [401, 403, 429, 451, 503])
def test_refused(status):
    assert judge_access(page(final_status=status, title="Error", text="No.")) == {"kind": "refused", "detail": f"HTTP {status}"}


@pytest.mark.parametrize("title,text", [
    ("Just a moment...", "Verifying you are human. This may take a few seconds."),
    ("Attention Required! | Cloudflare", "Sorry, you have been blocked"),
    ("Access Denied", "Access Denied You don't have permission to access this page on this server."),
    ("", "Please verify you are a human to continue"),
    ("", "Press & Hold to confirm you are a human (and not a bot)."),
])
def test_bot_checks_are_recognised_whatever_the_status(title, text):
    assert kind(title=title, text=text) == "bot_check"
    assert kind(title=title, text=text, final_status=403) == "bot_check"


def test_a_long_article_that_mentions_a_bot_check_is_an_ordinary_page():
    text = "Many sites ask visitors to verify you are human. " + "Here is why that matters for accessibility. " * 40
    assert judge_access(page(text=text)) is None


PAGE_BUSY = [{"what": "text", "frame": None}, {"what": "fields", "frame": None}]


def test_a_page_that_could_not_be_read_is_unreadable_never_blank():
    """Both reads failing used to look exactly like an empty page and be reported as 'showed nothing'."""
    result = judge_access(page(title="", text="", read_errors=PAGE_BUSY))
    assert result == {"kind": "unreadable", "detail": "the page was too busy or slow to be read"}


def test_the_forms_read_failing_alone_makes_the_page_unreadable():
    assert kind(read_errors=[{"what": "fields", "frame": None}]) == "unreadable"


def test_a_slow_embedded_frame_is_named():
    result = judge_access(page(read_errors=[{"what": "fields", "frame": "challenges.example"}]))
    assert result["kind"] == "unreadable"
    assert "challenges.example" in result["detail"]


def test_several_frames_are_listed_once_each_and_capped():
    errors = [{"what": "fields", "frame": f"ad{i % 5}.example"} for i in range(9)]
    detail = judge_access(page(read_errors=errors))["detail"]
    assert re.findall(r"ad\d\.example", detail) == ["ad0.example", "ad1.example", "ad2.example"]  # three, once each


def test_a_frame_that_had_no_address_yet_is_still_unreadable():
    result = judge_access(page(read_errors=[{"what": "fields", "frame": ""}]))
    assert result == {"kind": "unreadable", "detail": "an embedded frame that had not finished loading was too slow to read"}


@pytest.mark.parametrize("what", ["screenshot", "title"])
def test_a_missing_picture_or_title_does_not_make_a_page_unreadable(what):
    assert judge_access(page(read_errors=[{"what": what, "frame": None}])) is None


def test_a_wall_is_still_a_wall_when_other_reads_also_failed():
    result = judge_access(page(title="Just a moment...", text="Verifying you are human.", read_errors=PAGE_BUSY))
    assert result["kind"] == "bot_check"


def test_a_finished_page_with_nothing_on_it_is_blank():
    assert kind(title="", text="   ") == "blank"
    assert kind(title=None, text="") == "blank"


def test_a_page_still_loading_is_not_called_blank():
    assert judge_access(page(complete=False, title="", text="")) is None


def test_a_page_with_only_a_title_is_not_blank():
    assert judge_access(page(title="Sign in", text="")) is None
