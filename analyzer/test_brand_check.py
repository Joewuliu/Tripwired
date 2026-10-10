import pytest

from brands import check_brand
from enrich import registered_domain
from platforms import is_popular


def kinds(url: str, title: str = "", text: str = "") -> set[tuple[str, str]]:
    return {(f["type"], f["brand"]) for f in check_brand(url, title, text)}


# --- the two cases the plan names -----------------------------------------------------------

def test_paypa1_is_a_lookalike():
    assert ("lookalike", "PayPal") in kinds("https://paypa1.com/login")


def test_chase_is_official():
    assert kinds("https://chase.com") == {("official", "Chase")}


# --- catching imitations ---------------------------------------------------------------------

@pytest.mark.parametrize("url,brand", [
    ("https://chasee.com", "Chase"),  # one stray character
    ("https://paypa1-secure.top/signin", "PayPal"),  # disguised name inside a longer one
    ("https://faceb00k.com/", "Facebook"),
    ("https://discorcl.com/nitro", "Discord"),
    ("https://coinbasse.com/", "Coinbase"),
    ("https://docusing.com/sign", "DocuSign"),
    ("https://robiox.com.gr/", "Roblox"),
    ("https://paypa1.netlify.app/login", "PayPal"),  # on a free host, the user's part still counts
])
def test_lookalike_domains(url, brand):
    assert ("lookalike", brand) in kinds(url)


def test_cyrillic_letters_are_a_lookalike_and_so_is_their_punycode_form():
    spoof = "рaypal.com"  # Cyrillic er in place of a Latin p
    assert ("lookalike", "PayPal") in kinds(f"https://{spoof}/login")
    assert ("lookalike", "PayPal") in kinds("https://" + spoof.encode("idna").decode() + "/login")


def test_a_disguised_domain_is_never_official():
    findings = kinds("https://robiox.com.gr/")
    assert ("official", "Roblox") not in findings


@pytest.mark.parametrize("url,brand", [
    ("https://chase-secure.top/", "Chase"),
    ("https://chasesecure.com/", "Chase"),  # the spec's example: short name plus a scam word
    ("https://secure-chase.top/", "Chase"),
    ("https://loginpaypal.net/", "PayPal"),
    ("https://usps-redelivery.top/track", "USPS"),
    ("https://apple.com.account-verify.top/", "Apple"),  # the brand as a subdomain of someone else's domain
    ("https://paypal.github.io/login", "PayPal"),
    ("https://paypal.vercel.app/signin", "PayPal"),
    ("https://some-small-shop.top/netflix/login", "Netflix"),  # in the path
    ("https://continue-with-apple.top/", "Apple"),  # the social-login exception never applies to an address
])
def test_the_brand_name_in_the_address_is_impersonation(url, brand):
    findings = kinds(url)
    assert ("impersonation", brand) in findings
    assert ("official", brand) not in findings


def test_a_name_in_the_path_is_impersonation_not_a_mention_too():
    assert kinds("https://some-small-shop.top/netflix/login", text="Netflix") == {("impersonation", "Netflix")}


def test_a_shared_host_is_judged_by_its_path_and_its_content():
    assert ("impersonation", "Steam") in kinds("https://sites.google.com/view/steam-gift")
    assert ("mention", "PayPal") in kinds("https://docs.google.com/forms/x", title="PayPal login")


# --- official sites --------------------------------------------------------------------------

@pytest.mark.parametrize("url,brand", [
    ("https://www.paypal.com/signin", "PayPal"),
    ("https://secure.chase.com", "Chase"),
    ("https://www.ezpassnj.com", "E-ZPass"),
    # where txtag.org sends people today; its /discover/ path is not the card company
    ("https://www.txdot.gov/discover/toll-roads-managed-lanes.html", "TxTag"),
    ("https://www.ncdot.gov", "NC DMV"),
    ("https://www.google.co.uk/", "Google"),
    ("https://www.youtube.com/", "Google"),
    ("https://www.amazon.co.uk/", "Amazon"),  # regional sites of a brand
    ("https://www.amazon.sg/", "Amazon"),  # ...including ones outside the top ten thousand
    ("https://www.discover.com/", "Discover"),  # not a Discord look-alike
    ("https://www.usps.com/", "USPS"),  # not a UPS look-alike
])
def test_official_domains_report_only_official(url, brand):
    assert kinds(url) == {("official", brand)}


def test_an_official_site_still_reports_what_it_says_about_other_brands():
    assert kinds("https://www.microsoft.com", text="Works great with Apple devices") == {
        ("official", "Microsoft"),
        ("mention", "Apple"),
    }
    assert kinds("https://www.usps.com/", text="Ship with UPS or FedEx") == {
        ("official", "USPS"),
        ("mention", "UPS"),
        ("mention", "FedEx"),
    }


def test_a_brand_name_on_a_hosting_platform_is_never_official():
    for url in ("https://paypal.github.io/", "https://paypal.vercel.app/", "https://chase.netlify.app/"):
        assert not any(kind == "official" for kind, _ in kinds(url)), url


# --- not crying wolf -------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://some-small-shop.top",
    "https://some-small-shop.top/purchase",  # "chase" inside another word
    "https://some-small-shop.top/discovery-channel",  # a long keyword is only matched inside a word in the domain
    "https://some-small-shop.top/applesauce-recipes",  # a path needs the whole word
    "https://purchases-by-mail.top/",  # likewise in the domain, for a short keyword
])
def test_ordinary_addresses_have_no_findings(url):
    assert kinds(url) == set(), url


def test_a_popular_domain_is_not_judged_by_its_address_at_all():
    assert is_popular("www.wikipedia.org", registered_domain("www.wikipedia.org"))
    assert kinds("https://www.wikipedia.org/wiki/Apple") == set()


def test_the_platform_name_in_a_free_hosting_address_is_not_an_imitation():
    for url in ("https://my-bucket.s3.amazonaws.com/index.html", "https://d111.cloudfront.net/x", "https://github.io/"):
        assert kinds(url) == set(), url


@pytest.mark.parametrize("url", [
    "https://login.microsoftonline.com/",  # contains "microsoft"
    "https://www.adobelogin.com/",  # a real brand's own login domain that is not on our list
    "https://www.chess.com/",  # one letter from "chase"
])
def test_a_top_ten_thousand_domain_is_never_an_imitation(url):
    host = url.split("/")[2]
    assert is_popular(host, registered_domain(host)), f"{host} should be in the popular list for this test"
    assert kinds(url) == set()


@pytest.mark.parametrize("url", [
    "https://docs.google.com/forms/d/e/abc/viewform",
    "https://sites.google.com/view/anything",
    "https://drive.google.com/file/d/abc/view",
    "https://forms.gle/abc",
])
def test_a_shared_host_is_neither_official_nor_impersonating_by_its_own_name(url):
    assert kinds(url) == set()


@pytest.mark.parametrize("url", ["https://55a.com/", "https://upss.com/", "https://x7.example.com/"])
def test_short_names_are_not_chased_through_digits_and_stray_letters(url):
    assert kinds(url) == set()


# --- what the page says ----------------------------------------------------------------------

def test_a_title_naming_a_brand_on_an_unrelated_domain_is_only_a_mention():
    assert kinds("https://example.com", title="Netflix: update billing") == {("mention", "Netflix")}


@pytest.mark.parametrize("text", [
    "Continue with Apple", "Sign in with Google", "Log in with Facebook", "Login with Facebook",
    "Sign up with Apple", "Sign-in with Apple", "Continue with an Apple account", "Sign in using Google",
    "Connect with Facebook", "Username Password Sign in Continue with Google Continue with Apple",
])
def test_social_login_buttons_are_not_mentions(text):
    assert kinds("https://example.com/login", text=text) == set()
    assert kinds("https://example.com/login", title=text) == set()


@pytest.mark.parametrize("text,brand", [
    ("Sign in with your PayPal account", "PayPal"),  # "your" makes it the page speaking
    ("Continue to Apple", "Apple"),
    ("Continue with Apple. Apple makes phones.", "Apple"),  # a second, ordinary mention still counts
    ("Log in to your Netflix account", "Netflix"),
    ("We accept Apple Pay", "Apple"),
])
def test_other_mentions_still_count(text, brand):
    assert ("mention", brand) in kinds("https://example.com/", text=text)


def test_a_social_login_phrase_only_hides_the_brand_right_after_it():
    assert kinds("https://example.com/", text="Sign in with Apple or your PayPal account") == {("mention", "PayPal")}


def test_findings_have_the_documented_shape():
    for finding in check_brand("https://paypa1.com/login", "PayPal", "Sign in"):
        assert set(finding) == {"type", "brand", "detail"}
        assert finding["type"] in {"official", "impersonation", "lookalike", "mention"}
