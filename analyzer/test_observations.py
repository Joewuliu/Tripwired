from observations import describe, describe_age, describe_feeds

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


def test_describe_puts_feeds_before_age():
    lines = describe(ALL_CLEAR, age(3))
    assert lines[0].startswith("Not listed by") and lines[-1] == "Registered 3 days ago, from RDAP"


def test_no_line_contains_a_live_link():
    feeds = [{"source": "OpenPhish", "status": "hit", "url": "https://evil.example/x", "kind": "phishing", "detail": "x"}]
    assert all("http" not in line for line in describe(feeds, age(3)))
