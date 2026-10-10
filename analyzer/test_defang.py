from defang import defang, defang_text


def test_defang_url():
    assert defang("https://ezpass-pay.top/login?a=1") == "hxxps://ezpass-pay[.]top/login?a=1"
    assert defang("http://paypa1.com") == "hxxp://paypa1[.]com"


def test_defang_text_defangs_links_and_leaves_sentences():
    out = defang_text("Visit https://evil.example.com/pay now or go to usps-track.top/x. Thanks, Mr. Smith.")
    assert "https://" not in out
    assert "hxxps://evil[.]example[.]com/pay" in out
    assert "usps-track[.]top/x" in out
    assert "Mr. Smith" in out


def test_defang_text_handles_bare_domains_and_ports():
    assert defang_text("login at secure-chase.top:8443/a") == "login at secure-chase[.]top:8443/a"


def test_defang_text_leaves_plain_text_alone():
    assert defang_text("Example Domain") == "Example Domain"
