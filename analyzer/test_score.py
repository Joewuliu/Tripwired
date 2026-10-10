import re
from types import SimpleNamespace

import pytest

from score import DANGEROUS_AT, RULES, SUSPICIOUS_AT, WEIGHTS, judge

CLEAR = [{"source": s, "status": "clear"} for s in ("Google Safe Browsing", "URLhaus", "OpenPhish")]
OLD = {"domain": "x.top", "registered": None, "age_days": 4000, "source": "RDAP", "error": None}


def listed(source="OpenPhish", kind="phishing"):
    return {"source": source, "status": "hit", "url": "u", "kind": kind, "detail": kind}


def field(kind):
    return {"kind": kind, "type": "text", "name": kind, "id": ""}


def brand(kind, name, detail=""):
    return {"type": kind, "brand": name, "detail": detail}


def scan(**overrides):
    """A page that opened normally on an old, unremarkable domain, until a test says otherwise."""
    defaults = dict(
        final_url="https://some-shop.example/", feeds=CLEAR, age=OLD, brand=[], popular=False, fields=[],
        warning=None, access=None,
        opened={"loaded": True, "complete": True, "has_screenshot": True, "text": "Welcome to the shop"},
    )
    return SimpleNamespace(**{**defaults, **overrides})


def ids(judgement, points_only=True):
    return [e.id for e in judgement.evidence if e.points != 0 or not points_only]


# --- the plain cases ----------------------------------------------------------------------

def test_an_ordinary_page_has_no_red_flags():
    result = judge(scan())
    assert (result.verdict, result.score) == ("no_red_flags", 0)
    assert result.headline == "No red flags found. That is not a guarantee."


def test_the_thresholds_are_the_spec_ones():
    assert (DANGEROUS_AT, SUSPICIOUS_AT) == (60, 30)


def test_a_listing_alone_is_dangerous_and_counted_once_however_many_feeds_agree():
    result = judge(scan(feeds=[listed("OpenPhish"), listed("Google Safe Browsing"), listed("URLhaus", "malware")]))
    assert (result.verdict, result.score) == ("dangerous", 60)
    assert result.headline == "Dangerous: Listed as phishing by OpenPhish"
    assert "Listed as phishing by Google Safe Browsing" in result.observations  # every source is still named
    assert sum(e.points for e in result.evidence if e.id.startswith("known_threat_feed")) == 60


def test_a_hosts_own_warning_page_is_dangerous():
    result = judge(scan(warning="Cloudflare phishing warning"))
    assert result.verdict == "dangerous" and result.score == 60
    assert "Cloudflare phishing warning" in result.headline


def test_a_young_domain_with_a_brand_and_a_login_form_is_dangerous():
    result = judge(scan(
        age={**OLD, "age_days": 2}, brand=[brand("impersonation", "PayPal", '"paypal" in domain')],
        fields=[field("password")],
    ))
    assert result.verdict == "dangerous"
    assert set(ids(result)) == {"impersonation", "domain_under_7_days", "sensitive_fields",
                                "brand_with_sensitive_fields", "young_with_sensitive_fields"}
    assert result.score == 35 + 30 + 10 + 25 + 15


def test_an_imitation_alone_is_suspicious():
    result = judge(scan(brand=[brand("impersonation", "Chase", '"chase" in domain')]))
    assert (result.verdict, result.score) == ("suspicious", 35)
    assert result.headline.startswith("Suspicious: Web address uses the name Chase")


def test_a_lookalike_alone_is_not_enough_for_suspicious():
    result = judge(scan(brand=[brand("lookalike", "PayPal", "paypa1.com spells \"paypal\" with look-alike characters")]))
    assert (result.verdict, result.score) == ("no_red_flags", 25)


@pytest.mark.parametrize("days,rule", [(0, "domain_under_7_days"), (6, "domain_under_7_days"),
                                       (7, "domain_under_30_days"), (29, "domain_under_30_days")])
def test_domain_age_bands(days, rule):
    result = judge(scan(age={**OLD, "age_days": days}))
    assert ids(result) == [rule]
    assert result.score == WEIGHTS[rule]


@pytest.mark.parametrize("days", [30, 365, 4000])
def test_an_older_domain_adds_nothing(days):
    assert judge(scan(age={**OLD, "age_days": days})).score == 0


# --- sensitive fields build up -------------------------------------------------------------

def test_a_login_form_alone_is_small():
    result = judge(scan(fields=[field("password")]))
    assert (result.verdict, result.score) == ("no_red_flags", 10)
    assert "Page asks for a password (page scan)" in result.observations


def test_a_brand_only_mentioned_in_the_text_still_builds_up_with_a_form():
    result = judge(scan(brand=[brand("mention", "PayPal", '"paypal" in title')], fields=[field("password")]))
    assert result.score == 10 + 25
    assert result.verdict == "suspicious"


def test_a_mention_alone_is_worth_nothing():
    assert judge(scan(brand=[brand("mention", "PayPal", '"paypal" in text')])).score == 0


def test_a_form_on_a_free_host_builds_up_and_many_fields_more():
    base = dict(final_url="https://someone.netlify.app/login")
    assert judge(scan(**base, fields=[field("password")])).score == 10 + 30
    many = judge(scan(**base, fields=[field("password"), field("card"), field("otp")]))
    assert many.score == 10 + 30 + 10


def test_a_banks_own_login_form_is_not_held_against_it():
    result = judge(scan(
        final_url="https://www.chase.com/", brand=[brand("official", "Chase")], fields=[field("password"), field("otp")],
    ))
    assert result.verdict == "no_red_flags"
    assert result.score == 0
    sensitive = next(e for e in result.evidence if e.id == "sensitive_fields")
    assert sensitive.points == 0  # shown, never counted


# --- discounts that must not hide anything --------------------------------------------------

def test_an_official_domain_is_discounted_but_never_below_zero():
    result = judge(scan(final_url="https://www.chase.com/", brand=[brand("official", "Chase")]))
    assert (result.verdict, result.score) == ("no_red_flags", 0)
    assert next(e for e in result.evidence if e.id == "official_domain").points == -40


def test_a_listing_withholds_the_official_discount():
    result = judge(scan(final_url="https://www.chase.com/", brand=[brand("official", "Chase")], feeds=[listed()]))
    assert result.verdict == "dangerous"
    assert next(e for e in result.evidence if e.id == "official_domain").points == 0


def test_a_popular_domain_is_discounted():
    result = judge(scan(popular=True, age={**OLD, "age_days": 20}))  # 20 under-30 days - 25 popular
    assert result.score == 0
    assert next(e for e in result.evidence if e.id == "popular_domain").points == -25


def test_a_listing_or_warning_withholds_the_popularity_discount():
    for overrides in ({"feeds": [listed()]}, {"warning": "Cloudflare phishing warning"}):
        result = judge(scan(popular=True, **overrides))
        assert result.verdict == "dangerous" and result.score == 60
        assert "popular_domain" not in [e.id for e in result.evidence]


def test_a_popular_domain_is_never_discounted_next_to_an_imitation():
    result = judge(scan(popular=True, brand=[brand("impersonation", "Chase", '"chase" in domain')]))
    assert "popular_domain" not in [e.id for e in result.evidence]
    assert result.score == 35


def test_official_and_popular_is_discounted_once():
    result = judge(scan(popular=True, brand=[brand("official", "Chase")], final_url="https://www.chase.com/"))
    assert [e.points for e in result.evidence if e.id in ("official_domain", "popular_domain")] == [-40, 0]


# --- a page we could not see is never "no red flags" -----------------------------------------

@pytest.mark.parametrize("kind,detail,loaded", [
    ("refused", "HTTP 403", True),
    ("bot_check", "Cloudflare challenge", True),
    ("blank", "nothing was shown", True),
    ("gone", "HTTP 404", True),
    ("unreachable", "no page arrived", False),
    ("unresolved", "the name does not resolve", False),
    ("not_public", "not a public web address", False),
])
def test_a_page_we_could_not_inspect_is_couldnt_check(kind, detail, loaded):
    result = judge(scan(access={"kind": kind, "detail": detail}, opened={"loaded": loaded, "complete": loaded}))
    assert result.verdict == "couldnt_check"
    assert result.headline.startswith("Couldn't get a proper look at this link.")


def test_refused_alone_is_weak_evidence():
    result = judge(scan(access={"kind": "refused", "detail": "HTTP 403"}))
    assert result.score == 10
    assert result.verdict == "couldnt_check"


def test_our_own_refusal_adds_no_points():
    result = judge(scan(access={"kind": "not_public", "detail": "x"}, opened={"loaded": False}))
    assert result.score == 0 and result.verdict == "couldnt_check"


def test_a_real_banks_refusal_is_couldnt_check_not_clear():
    result = judge(scan(
        final_url="https://www.paypal.com/signin", brand=[brand("official", "PayPal")], popular=True,
        access={"kind": "refused", "detail": "HTTP 403"},
    ))
    assert result.verdict == "couldnt_check"


def test_a_listing_still_wins_on_a_page_we_could_not_see():
    result = judge(scan(feeds=[listed()], access={"kind": "gone", "detail": "HTTP 404"}))
    assert result.verdict == "dangerous"


def test_a_brand_new_domain_that_has_vanished_is_suspicious():
    result = judge(scan(age={**OLD, "age_days": 1}, access={"kind": "unresolved", "detail": "x"}, opened={"loaded": False}))
    assert result.verdict == "suspicious" and result.score == 30 + 10


def test_a_page_that_never_finished_and_shows_nothing_is_couldnt_check():
    result = judge(scan(opened={"loaded": True, "complete": False, "has_screenshot": False, "text": ""}))
    assert result.verdict == "couldnt_check"


def test_a_page_that_never_finished_but_showed_content_is_judged_normally():
    result = judge(scan(opened={"loaded": True, "complete": False, "has_screenshot": True, "text": "Half a shop"}))
    assert result.verdict == "no_red_flags"


# --- the output ----------------------------------------------------------------------------

def test_the_word_safe_never_appears_in_anything_a_person_reads():
    cases = [
        scan(), scan(feeds=[listed()]), scan(access={"kind": "blank", "detail": "x"}),
        scan(brand=[brand("impersonation", "Chase", '"chase" in domain')]),
    ]
    for case in cases:
        result = judge(case)
        text = " ".join([result.headline, *result.observations, *(e.label for e in result.evidence)]).lower()
        text = text.replace("google safe browsing", "")  # a product name, not a claim
        assert not re.search(r"\bsafe", text), text  # not "safe", "safely", "safety"


def test_observations_are_the_evidence_sentences_most_important_first():
    result = judge(scan(feeds=[listed()], age={**OLD, "age_days": 3}, brand=[brand("official", "Chase")]))
    assert result.observations == [e.label for e in result.evidence]
    points = [e.points for e in result.evidence]
    positives = [p for p in points if p > 0]
    assert positives == sorted(positives, reverse=True)
    assert points.index(min(points)) > points.index(max(points))  # discounts after risk


def test_every_evidence_item_names_its_source():
    result = judge(scan(feeds=[listed(), *CLEAR], age={**OLD, "age_days": 3}, fields=[field("card")],
                        brand=[brand("impersonation", "Chase", '"chase" in domain'), brand("mention", "Apple")]))
    assert result.evidence and all(e.source.strip() for e in result.evidence)
    assert len({e.id for e in result.evidence}) == len(result.evidence), "ids are unique (the report keys on them)"


def test_the_points_table_is_the_whole_table_in_use():
    table = judge(scan()).points_table
    assert [(r.id, r.points) for r in table] == [(i, p) for i, _, p in RULES]
    assert {r.id for r in table} >= {"known_threat_feed", "impersonation", "official_domain", "popular_domain"}
    assert all(r.label for r in table)


def test_a_missing_key_is_shown_not_hidden():
    feeds = [{"source": "Google Safe Browsing", "status": "not_checked", "detail": "k"}, *CLEAR[1:]]
    result = judge(scan(feeds=feeds))
    assert "Google Safe Browsing was not checked (no API key is set)" in result.observations
    assert result.verdict == "no_red_flags"  # an absent key is not a finding, and is said out loud


def test_lookalike_detail_is_defanged():
    result = judge(scan(brand=[brand("lookalike", "PayPal", "paypa1.com spells \"paypal\" with look-alike characters")]))
    line = next(o for o in result.observations if o.startswith("Domain imitates"))
    assert "paypa1[.]com" in line and "paypa1.com" not in line
