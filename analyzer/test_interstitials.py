import pytest

from interstitials import find_platform_warning


@pytest.mark.parametrize("title,text,label", [
    ("Suspected phishing site | Cloudflare", "", "Cloudflare phishing warning"),
    ("Warning", "Suspected Phishing\n\nThis website has been reported for potential phishing.", "Cloudflare phishing warning"),
    ("", "Warning  Suspected Malware. This website has been reported for potentially distributing malware.", "Cloudflare malware warning"),
    ("", "This site has been reported as unsafe. Microsoft recommends you don't continue to this site. "
         "It has been reported to Microsoft for containing phishing threats", "Microsoft SmartScreen"),
    ("", "Deceptive site ahead. Attackers on evil.example may trick you into doing something dangerous "
         "like installing software", "Chrome Safe Browsing"),
])
def test_warning_pages_are_recognised(title, text, label):
    assert find_platform_warning(title, text) == label


def test_curly_apostrophes_and_odd_spacing_do_not_hide_a_warning():
    text = "This site has been reported as unsafe.\n\n  Microsoft recommends you don’t continue.  It has been reported to Microsoft for containing phishing threats"
    assert find_platform_warning(None, text) == "Microsoft SmartScreen"


@pytest.mark.parametrize("title,text", [
    ("Example Domain", "This domain is for use in documentation examples."),
    ("How to spot phishing", "If you see the words suspected phishing in an email, be careful."),  # one phrase, no follow-up
    ("News", "A reader asked what 'deceptive site ahead' means when Chrome shows it."),
    ("Cloudflare blog", "Our systems flagged a suspected malware campaign last week."),
    ("", ""),
    (None, None),
])
def test_ordinary_pages_and_articles_that_quote_a_phrase_are_not_warnings(title, text):
    assert find_platform_warning(title, text) is None
