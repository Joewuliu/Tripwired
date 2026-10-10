import pytest

from access import judge_access


def page(**overrides) -> dict:
    return {"loaded": True, "complete": True, "final_status": 200, "title": "A shop", "text": "Welcome to the shop " * 5,
            "error": None, **overrides}


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


def test_a_finished_page_with_nothing_on_it_is_blank():
    assert kind(title="", text="   ") == "blank"
    assert kind(title=None, text="") == "blank"


def test_a_page_still_loading_is_not_called_blank():
    assert judge_access(page(complete=False, title="", text="")) is None


def test_a_page_with_only_a_title_is_not_blank():
    assert judge_access(page(title="Sign in", text="")) is None
