from types import SimpleNamespace

import pytest

from observations import (
    describe,
    describe_access,
    describe_age,
    describe_brand,
    describe_feeds,
    describe_fields,
    describe_warning,
)

ALL_CLEAR = [
    {"source": "Google Safe Browsing", "status": "clear"},
    {"source": "URLhaus", "status": "clear"},
    {"source": "OpenPhish", "status": "clear"},
]


def age(days=None, error=None):
    return {"domain": "x.top", "registered": None, "age_days": days, "source": "RDAP", "error": error}


def test_all_clear_is_one_line_naming_the_sources():
    assert describe_feeds(ALL_CLEAR) == ["Not listed by Google Safe Browsing, URLhaus or OpenPhish"]


def test_a_hit_names_its_source_and_kind_once():
    feeds = [
        {"source": "OpenPhish", "status": "hit", "url": "u1", "kind": "phishing", "detail": "x"},
        {"source": "OpenPhish", "status": "hit", "url": "u2", "kind": "phishing", "detail": "x"},
        {"source": "Google Safe Browsing", "status": "clear"},
    ]
    assert describe_feeds(feeds) == ["Listed as phishing by OpenPhish", "Not listed by Google Safe Browsing"]


def test_missing_keys_and_failures_are_said_plainly():
    feeds = [
        {"source": "Google Safe Browsing", "status": "not_checked", "detail": "SAFE_BROWSING_API_KEY is not set"},
        {"source": "URLhaus", "status": "error", "detail": "TimeoutError"},
        {"source": "OpenPhish", "status": "clear"},
    ]
    assert describe_feeds(feeds) == [
        "Google Safe Browsing was not checked (no API key is set)",
        "URLhaus could not be checked right now",
        "Not listed by OpenPhish",
    ]


def test_age_wording():
    assert describe_age(age(0)) == ["Registered today, from RDAP"]
    assert describe_age(age(1)) == ["Registered 1 day ago, from RDAP"]
    assert describe_age(age(2)) == ["Registered 2 days ago, from RDAP"]
    assert describe_age(age(400)) == ["Registered 13 months ago, from RDAP"]
    assert describe_age(age(2000)) == ["Registered 5 years ago, from RDAP"]


def test_age_unknown_and_free_hosting():
    assert describe_age(age(error="HTTPStatusError")) == ["Domain age could not be found (RDAP)"]
    assert "free hosting platform" in describe_age(age(error="free hosting platform"))[0]


def scan(**overrides):
    """Something shaped like pipeline.Scan, with nothing found unless overridden."""
    defaults = dict(feeds=ALL_CLEAR, age=age(3), brand=[], popular=False, fields=[], warning=None, access=None)
    return SimpleNamespace(**{**defaults, **overrides})


def test_describe_puts_feeds_before_age():
    lines = describe(scan())
    assert lines[0].startswith("Not listed by") and lines[-1] == "Registered 3 days ago, from RDAP"


def test_fields_are_described_by_what_they_ask_for():
    fields = [{"kind": k, "type": "", "name": "", "id": ""} for k in ("card", "password", "card")]
    assert describe_fields(fields) == ["Page asks for a password and card details (page scan)"]
    assert describe_fields([{"kind": "ssn", "type": "", "name": "", "id": ""}]) == ["Page asks for a Social Security number (page scan)"]
    assert describe_fields([]) == []


def test_a_platform_warning_names_whose_warning_it_is():
    assert describe_warning("Cloudflare phishing warning") == [
        "The hosting provider has already flagged this page as dangerous (Cloudflare phishing warning)"
    ]
    assert describe_warning(None) == []


@pytest.mark.parametrize("access,line", [
    ({"kind": "not_public", "detail": "not a public web address"}, "Not a public web address, so it was not opened"),
    ({"kind": "unresolved", "detail": "x"}, "The address does not resolve (DNS lookup)"),
    ({"kind": "unreachable", "detail": "x"}, "The page did not load (browser)"),
    ({"kind": "gone", "detail": "HTTP 404"}, "The page is gone (HTTP 404)"),
    ({"kind": "refused", "detail": "HTTP 403"}, "The site refused the sandbox's phone browser (HTTP 403)"),
    ({"kind": "bot_check", "detail": "Cloudflare challenge"},
     "The site showed a human-verification or access-denied page instead of its content (Cloudflare challenge)"),
    ({"kind": "blank", "detail": "x"}, "The page opened but showed nothing (page scan)"),
])
def test_access_wording(access, line):
    assert describe_access(access) == [line]


def test_normal_access_says_nothing():
    assert describe_access(None) == []


def test_what_we_could_not_see_comes_first():
    lines = describe(scan(
        access={"kind": "refused", "detail": "HTTP 403"}, warning="Cloudflare phishing warning",
        brand=[{"type": "mention", "brand": "PayPal", "detail": ""}],
        fields=[{"kind": "password", "type": "", "name": "", "id": ""}],
    ))
    assert [line.split(" (")[0] for line in lines[:4]] == [
        "The site refused the sandbox's phone browser",
        "The hosting provider has already flagged this page as dangerous",
        "Page text names PayPal",
        "Page asks for a password",
    ]


def finding(kind, brand, detail=""):
    return {"type": kind, "brand": brand, "detail": detail}


def test_brand_lines_say_what_was_found_and_name_the_source():
    lines = describe_brand([
        finding("official", "Chase"),
        finding("impersonation", "PayPal", '"paypal" in domain'),
        finding("impersonation", "Apple", '"apple" in domain'),
        finding("impersonation", "Netflix", '"netflix" in path'),
        finding("lookalike", "Roblox", "robiox.com.gr resembles roblox.com"),
        finding("mention", "Google"),
        finding("mention", "eBay"),
    ])
    assert lines == [
        "Registered domain is official for Chase (brand list)",
        "Web address uses the name PayPal and Apple but is not an official site (brand list)",
        "Web address path names Netflix, but this is not an official site (brand list)",
        "Domain imitates Roblox: robiox[.]com[.]gr resembles roblox[.]com (look-alike check)",
        "Page text names Google and eBay (brand list)",
    ]


def test_three_names_are_joined_with_a_comma_and_and():
    lines = describe_brand([finding("mention", n) for n in ("Apple", "Google", "eBay")])
    assert lines == ["Page text names Apple, Google and eBay (brand list)"]


def test_no_brand_findings_say_nothing():
    assert describe_brand([]) == []


def test_describe_orders_brand_then_feeds_then_age_then_popularity():
    lines = describe(scan(age=age(2000), brand=[finding("official", "Google")], popular=True))
    assert lines[0].startswith("Registered domain is official for Google")
    assert lines[1].startswith("Not listed by")
    assert lines[2] == "Registered 5 years ago, from RDAP"
    assert lines[3] == "Domain is one of the 10,000 most visited on the web (Tranco list)"


def test_no_line_contains_a_live_link():
    feeds = [{"source": "OpenPhish", "status": "hit", "url": "https://evil.example/x", "kind": "phishing", "detail": "x"}]
    assert all("http" not in line for line in describe(scan(feeds=feeds)))
