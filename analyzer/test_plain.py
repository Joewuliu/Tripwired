"""The plain lines: every finding the scorer can produce reads as everyday words."""
import re

import pytest

from contract import Evidence
from plain import plain_line, plain_lines

JARGON = re.compile(r"RDAP|DNS|sandbox|\(page scan\)|\(brand list\)|\(look-alike|page text\)|Tranco|API key|phishing|\bsafe\b|redirect|domain", re.I)


def item(rule_id: str, label: str, points: int = 0) -> Evidence:
    return Evidence(id=rule_id, label=label, points=points, source="x")


CASES = [
    (item("known_threat_feed", "Listed as phishing by OpenPhish", 60), "Security services have already reported this link as a scam."),
    (item("known_threat_feed:URLhaus", "Listed as malware by URLhaus", 0), "Security services have already reported this link as a scam."),
    (item("platform_warning", "The hosting provider has already flagged this page as dangerous (Cloudflare phishing warning)", 60),
     "The website's own host has already warned that this page is dangerous."),
    (item("impersonation", "Web address uses the name E-ZPass but is not an official site (brand list)", 35),
     "The web address uses the name E-ZPass, but it isn't their real website."),
    (item("impersonation_path", "Web address path names Apple, but this is not an official site (brand list)", 35),
     "The link uses the name Apple, but it isn't their real website."),
    (item("lookalike", 'Domain imitates PayPal: paypa1[.]com spells "paypal" with look-alike characters (look-alike check)', 25),
     "The web address is spelled to look like PayPal's, but it isn't."),
    (item("domain_under_7_days", "Registered 2 days ago, from RDAP", 30), "This website was only created 2 days ago."),
    (item("domain_under_30_days", "Registered 3 months ago, from RDAP", 20), "This website was only created 3 months ago."),
    (item("domain_age", "Registered 30 years ago, from RDAP"), "This website was created 30 years ago."),
    (item("sensitive_fields", "Page asks for a password and card details (page scan)", 10), "The page asks for a password and card details."),
    (item("brand_with_sensitive_fields", "Page names E-ZPass and asks for sensitive information (page text)", 25),
     "The page uses the E-ZPass name and asks for private details."),
    (item("young_with_sensitive_fields", "Newly created website asks for sensitive information (RDAP, page scan)", 15),
     "A brand-new website is asking for private details."),
    (item("free_host_credentials", "Page asks for sensitive information on a free hosting platform (host list, page scan)", 30),
     "The page asks for private details on a free website that anyone can set up."),
    (item("brand_mention", "Page text names PayPal (brand list)", 0), "The page mentions PayPal."),
    (item("official_domain", "Registered domain is official for Chase (brand list)", -40), "This is the official website of Chase."),
    (item("feeds_clear", "Not listed by Google Safe Browsing, URLhaus or OpenPhish"), "It isn't on any list of known scam websites."),
    (item("popular_domain", "Domain is one of the 10,000 most visited on the web (Tranco list)", -25),
     "This is one of the most visited websites in the world."),
    (item("feed_error:URLhaus", "URLhaus could not be checked right now"), "One of the scam-list checks couldn't be done right now."),
    (item("not_opened", "The address does not resolve (DNS lookup)"), "That web address doesn't exist, or no longer works."),
    (item("hides_from_sandbox", "The site refused the sandbox's phone browser (HTTP 403)", 10), "The website blocked my check."),
    (item("hides_from_sandbox", "The site showed a human-verification or access-denied page instead of its content (HTTP 403)", 10),
     "The website asked to prove I'm a person, which I can't do."),
    (item("not_opened", "Not a public web address, so it was not opened"), "That isn't an ordinary public web address, so I didn't open it."),
]


@pytest.mark.parametrize(("finding", "expected"), CASES)
def test_each_finding_reads_in_everyday_words(finding, expected):
    assert plain_line(finding) == expected
    assert not JARGON.search(expected), expected


def test_findings_that_would_only_clutter_a_message_are_left_out():
    assert plain_line(item("impersonation_path", "Web address path names Apple; not counted without a form (brand list)", 0)) is None
    assert plain_line(item("domain_age", "Domain age could not be found (RDAP)")) is None
    assert plain_lines([item("domain_age", "Domain age could not be found (RDAP)")]) == []


def test_lines_keep_the_scorers_order_and_never_repeat():
    two = [item("known_threat_feed", "Listed as phishing by OpenPhish", 60), item("known_threat_feed:URLhaus", "Listed as malware by URLhaus")]
    assert plain_lines(two) == ["Security services have already reported this link as a scam."]


def test_a_finding_this_file_does_not_know_still_loses_its_source_in_brackets():
    assert plain_line(item("something_new", "the page does a new thing (page scan)")) == "The page does a new thing."
