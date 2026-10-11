"""scripts/accuracy.py: defanging, the counts, and the "Without blocklists" recompute. No network."""
import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import defang as analyzer_defang
import score
from score import judge

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "accuracy.py"
spec = importlib.util.spec_from_file_location("accuracy", SCRIPT)
accuracy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accuracy)

CLEAR = [{"source": s, "status": "clear"} for s in ("Google Safe Browsing", "URLhaus", "OpenPhish")]
OLD = {"domain": "x.top", "registered": None, "age_days": 4000, "source": "RDAP", "error": None}
YOUNG = {**OLD, "age_days": 2}


def listed(source="OpenPhish"):
    return {"source": source, "status": "hit", "url": "u", "kind": "phishing", "detail": "exact URL is on the list"}


def brand(kind, name, detail=""):
    return {"type": kind, "brand": name, "detail": detail}


def field(kind):
    return {"kind": kind, "type": "text", "name": kind, "id": ""}


def scan(**overrides):
    defaults = dict(
        final_url="https://some-shop.example/", feeds=CLEAR, age=OLD, brand=[], popular=False, fields=[],
        warning=None, access=None,
        opened={"loaded": True, "complete": True, "has_screenshot": True, "text": "Welcome to the shop"},
    )
    return SimpleNamespace(**{**defaults, **overrides})


def as_answer(judgement) -> dict:
    """What POST /analyze returns of a judgement, as far as the script reads it."""
    return {
        "verdict": judgement.verdict,
        "score": judgement.score,
        "evidence": [e.model_dump() for e in judgement.evidence],
        "points_table": [r.model_dump() for r in judgement.points_table],
        "explained_by": "template",
    }


# --- defanging -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://www.wellsfargo.com", "http://short.example/x?y=1", "https://evil-login.some-small-shop.top:8443/a/b.html#frag"],
)
def test_a_url_is_defanged_the_same_way_the_analyzer_does_it(url):
    assert accuracy.defang(url) == analyzer_defang.defang(url)
    assert "://" in accuracy.defang(url) and not re.search(r"https?://", accuracy.defang(url))
    assert "." not in accuracy.defang(url).replace("[.]", "")


def test_free_text_is_defanged_and_ordinary_sentences_are_left_alone():
    text = "Domain imitates PayPal: paypa1.com and see https://evil.example/login. Mr. Smith agrees."
    assert accuracy.defang_text(text) == analyzer_defang.defang_text(text)
    assert "paypa1[.]com" in accuracy.defang_text(text) and "Mr. Smith" in accuracy.defang_text(text)


PROPER_NOUN = "Google Safe Browsing"


def without_the_proper_noun(text: str) -> str:
    """The one place the word "safe" may appear in a written file."""
    return text.replace(PROPER_NOUN, "")


def test_the_word_safe_never_survives_scrubbing_except_inside_the_proper_noun():
    assert accuracy.scrub("Not listed by Google Safe Browsing, URLhaus or OpenPhish") == (
        "Not listed by Google Safe Browsing, URLhaus or OpenPhish"
    )
    assert accuracy.scrub("Listed as phishing by Google Safe Browsing") == "Listed as phishing by Google Safe Browsing"
    for text in ["This site is safe.", "SAFELY done", "unsafe link", "safety first", "Safe Browsing alone"]:
        assert not re.search(r"safe", accuracy.scrub(text), re.IGNORECASE), text
    # next to the proper noun, our own use of the word is still removed
    assert accuracy.scrub("Google Safe Browsing says this site is safe") == "Google Safe Browsing says this site is (word removed)"


def test_scrubbing_leaves_no_live_address():
    assert "https://" not in accuracy.scrub("go to https://evil.example/x now")


# --- the script's constants stay the scorer's -----------------------------------------------------------


def test_the_thresholds_and_rule_lists_are_the_scorers():
    assert (accuracy.DANGEROUS_AT, accuracy.SUSPICIOUS_AT) == (score.DANGEROUS_AT, score.SUSPICIOUS_AT)
    assert accuracy._PATH_CORROBORATORS == score._CORROBORATES_PATH - {"known_threat_feed"}
    assert accuracy._UNSEEN == score._REASON_IDS
    assert accuracy.FEED_RULE in score.WEIGHTS


# --- "Without blocklists": from the same evidence, equal to the scorer re-judging without feeds -------------


def exact_without_feeds(s):
    """What the analyzer's own re-judge says: the same scan with every feed hit removed."""
    bare = judge(SimpleNamespace(**{**vars(s), "feeds": []}))
    return bare.score, bare.verdict


SCENARIOS = {
    "listed alone": scan(feeds=[listed()]),
    "listed and clean-looking": scan(feeds=[listed(), listed("URLhaus")], age=OLD),
    "listed, young, with a form": scan(
        feeds=[listed()], age=YOUNG, fields=[field("password")], brand=[brand("impersonation", "PayPal", '"paypal" in domain')]),
    "young with brand and form, no listing": scan(
        age=YOUNG, brand=[brand("impersonation", "PayPal", '"paypal" in domain')], fields=[field("password")]),
    "official bank, listed": scan(final_url="https://www.chase.com/", brand=[brand("official", "Chase")], feeds=[listed()]),
    "official bank, clean": scan(final_url="https://www.chase.com/", brand=[brand("official", "Chase")]),
    "official bank, listed and host-warned": scan(
        final_url="https://www.chase.com/", brand=[brand("official", "Chase")], feeds=[listed()], warning="Cloudflare phishing warning"),
    "brand only in the path, listed": scan(
        final_url="https://some-shop.example/apple/login", brand=[brand("impersonation", "Apple", '"apple" in path')], feeds=[listed()]),
    "brand only in the path, listed, and a form": scan(
        final_url="https://some-shop.example/apple/login", brand=[brand("impersonation", "Apple", '"apple" in path')],
        feeds=[listed()], fields=[field("password")]),
    "brand only in the path, nothing else": scan(
        final_url="https://some-shop.example/apple/login", brand=[brand("impersonation", "Apple", '"apple" in path')]),
    "host warning page only": scan(warning="Cloudflare phishing warning"),
    "listed but the page was refused": scan(
        feeds=[listed()], access={"kind": "refused", "detail": "HTTP 403"}),
    "refused, not listed": scan(access={"kind": "refused", "detail": "HTTP 403"}),
    "gone, listed, old domain": scan(feeds=[listed()], access={"kind": "gone", "detail": "HTTP 404"}),
    "unreadable part, listed": scan(feeds=[listed()], access={"kind": "unreadable", "detail": "a frame was too slow"}),
    "lookalike, listed": scan(feeds=[listed()], brand=[brand("lookalike", "PayPal", "paypa1.com")]),
    "free host, form, listed": scan(
        final_url="https://x.vercel.app/", feeds=[listed()], fields=[field("password")], age={**OLD, "age_days": None, "error": "free hosting platform"}),
}


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_the_recompute_from_evidence_equals_rejudging_the_scan_without_feeds(name):
    s = SCENARIOS[name]
    answer = as_answer(judge(s))
    got = accuracy.without_blocklists(answer["evidence"], answer["points_table"])
    assert got == exact_without_feeds(s), name


def test_a_page_that_only_a_feed_flagged_is_no_red_flags_without_it():
    answer = as_answer(judge(scan(feeds=[listed()])))
    assert (answer["verdict"], answer["score"]) == ("dangerous", 60)
    assert accuracy.without_blocklists(answer["evidence"], answer["points_table"]) == (0, "no_red_flags")


def test_what_the_sandbox_found_on_its_own_still_counts():
    s = scan(feeds=[listed()], age=YOUNG, fields=[field("password")], brand=[brand("impersonation", "PayPal", '"paypal" in domain')])
    answer = as_answer(judge(s))
    score_without, verdict = accuracy.without_blocklists(answer["evidence"], answer["points_table"])
    assert verdict == "dangerous" and score_without == answer["score"] - 60


def test_an_unseen_page_stays_couldnt_check_when_the_feed_points_come_out():
    answer = as_answer(judge(scan(feeds=[listed()], access={"kind": "unresolved", "detail": ""})))
    assert accuracy.without_blocklists(answer["evidence"], answer["points_table"])[1] == "couldnt_check"


def test_the_one_thing_it_cannot_give_back_is_a_popular_sites_discount():
    """A listing keeps the popular-domain discount out of the evidence, so it cannot be restored."""
    s = scan(feeds=[listed()], popular=True)
    answer = as_answer(judge(s))
    assert not any(e["id"] == "popular_domain" for e in answer["evidence"])
    ours = accuracy.without_blocklists(answer["evidence"], answer["points_table"])
    exact = exact_without_feeds(s)
    assert ours[0] >= exact[0]  # never lower: it can only err towards flagging more


def test_a_fixed_example_end_to_end():
    evidence = [
        {"id": "known_threat_feed", "label": "Listed as phishing by OpenPhish", "points": 60, "source": "OpenPhish"},
        {"id": "domain_under_7_days", "label": "Registered 2 days ago, from RDAP", "points": 30, "source": "RDAP"},
        {"id": "feeds_clear", "label": "Not listed by Google Safe Browsing", "points": 0, "source": "x"},
    ]
    table = [{"id": "known_threat_feed", "label": "", "points": 60}, {"id": "official_domain", "label": "", "points": -40}]
    assert accuracy.without_blocklists(evidence, table) == (30, "suspicious")
    assert accuracy.verdict_for(29, False) == "no_red_flags" and accuracy.verdict_for(29, True) == "couldnt_check"
    assert accuracy.verdict_for(60, True) == "dangerous"


# --- the counts --------------------------------------------------------------------------------------------


def row(n, label, verdict, without=None, seconds=10.0, signals=("a", "b"), gemini=False, error=None):
    return {
        "n": n, "label": label, "url": f"hxxps://site{n}[.]example/", "verdict": verdict, "score": 0 if verdict != "error" else None,
        "without": without or verdict, "signals": list(signals), "seconds": seconds, "gemini": gemini, "error": error,
    }


ROWS = [
    row(1, "scam", "dangerous", without="no_red_flags", seconds=8.0, gemini=True),
    row(2, "scam", "suspicious", without="suspicious", seconds=12.0),
    row(3, "scam", "no_red_flags", without="no_red_flags", seconds=9.0),  # a miss
    row(4, "scam", "couldnt_check", seconds=30.0, signals=("That web address doesn't exist, or no longer works.",)),
    row(5, "legit", "no_red_flags", seconds=7.0),
    row(6, "legit", "no_red_flags", seconds=11.0, gemini=True),
    row(7, "legit", "suspicious", seconds=13.0),  # a false alarm
    row(8, "legit", "couldnt_check", seconds=14.0, signals=("The website blocked my check.",)),
    row(9, "scam", "error", seconds=90.0, error="URLError: could not reach the analyzer or it timed out"),
]


def test_couldnt_check_and_errors_are_listed_but_counted_as_neither_right_nor_wrong():
    s = accuracy.summarize(ROWS)
    assert (s["scams_flagged"], s["scams_counted"]) == (2, 3)  # 1, 2 flagged; 3 missed; 4 and 9 excluded
    assert (s["legit_clear"], s["legit_counted"]) == (2, 3)  # 5, 6 clear; 7 a false alarm; 8 excluded
    assert [r["n"] for r in s["couldnt_check"]] == [4, 8]
    assert [r["n"] for r in s["errors"]] == [9]


def test_without_blocklists_uses_the_same_denominator_as_the_main_count():
    s = accuracy.summarize(ROWS)
    assert (s["scams_flagged_without"], s["scams_counted"]) == (1, 3)  # only #2 is still flagged without feeds


def test_the_median_time_leaves_out_runs_that_never_answered():
    s = accuracy.summarize(ROWS)
    assert s["median_seconds"] == 11.5  # the eight answered runs: 7 8 9 11 12 13 14 30; the 90 s error is left out
    assert s["gemini_worded"] == 2 and s["total"] == 9


def test_an_empty_run_has_no_median_and_no_division():
    s = accuracy.summarize([])
    assert s["median_seconds"] is None and s["scams_counted"] == 0


# --- the files -----------------------------------------------------------------------------------------------


def make_answer(verdict="dangerous", url="https://ezpass-pay.top/pay"):
    return as_answer(judge(scan(feeds=[listed()], final_url=url)))


def test_rows_come_from_an_answer_and_a_failure_is_a_row_not_a_crash():
    ok = accuracy.make_row(1, "scam", "https://ezpass-pay.top/pay?x=1", make_answer(), 8.04)
    assert (ok["verdict"], ok["score"], ok["without"], ok["seconds"]) == ("dangerous", 60, "no_red_flags", 8.0)
    assert ok["url"] == "hxxps://ezpass-pay[.]top/pay?x=1"
    assert ok["signals"][0] == "Listed as phishing by OpenPhish"
    failed = accuracy.make_row(2, "scam", "https://x.example", None, 90, "Timeout: x")
    assert (failed["verdict"], failed["without"]) == ("error", "error")


def test_markdown_and_csv_carry_every_row_defanged_and_never_say_safe():
    rows = [
        accuracy.make_row(1, "scam", "https://ezpass-pay.top/pay", make_answer(), 8.0),
        accuracy.make_row(2, "legit", "https://www.wellsfargo.com", as_answer(judge(scan())), 5.5),
        accuracy.make_row(3, "scam", "https://gone.example/x", as_answer(judge(scan(access={"kind": "unresolved", "detail": ""}))), 3.0),
    ]
    summary = accuracy.summarize(rows)
    from datetime import datetime, timezone

    md = accuracy.to_markdown(rows, summary, datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc), accuracy.notes_for(summary, 0, 0, 0))
    out = accuracy.to_csv(rows)
    for text in (md, out):
        assert not re.search(r"https?://", text), "a live address got into a file"
        assert not re.search(r"safe", without_the_proper_noun(text), re.IGNORECASE), "the word safe got into a file"
        assert "hxxps://ezpass-pay[.]top/pay" in text
    assert "| # | Label | URL | Verdict | Score | Without blocklists | Top 2 signals | Seconds |" in md
    assert "Scams flagged Dangerous or Suspicious: **1/1**" in md  # the gone link is not counted
    assert 'Legit sites with "No red flags found": **1/1**' in md
    assert "Couldn't check, not counted as right or wrong: #3 Scam link" in md
    assert "Median time per check: **5.5 s**" in md
    assert out.splitlines()[0] == ",".join(accuracy.CSV_FIELDS)
    assert len(out.splitlines()) == 4


def test_pipes_in_a_cell_cannot_break_the_table():
    r = row(1, "scam", "dangerous", signals=("a | b", "c"))
    r["url"] = "hxxps://a[.]example/x|y"
    from datetime import datetime, timezone

    md = accuracy.to_markdown([r], accuracy.summarize([r]), datetime.now(timezone.utc), [])
    line = next(l for l in md.splitlines() if l.startswith("| 1 |"))
    assert line.count(" | ") == 7 and "a \\| b" in line


# --- inputs and the run -------------------------------------------------------------------------------------------


def test_the_default_list_is_the_five_legit_sites():
    found = accuracy.parse_urls_file(accuracy.URLS_FILE.read_text(encoding="utf-8"))
    assert found == [("legit", u) for u in (
        "https://www.wellsfargo.com", "https://www.amazon.com", "https://www.unc.edu", "https://www.usps.com", "https://www.apple.com")]


def test_a_bad_line_in_the_list_is_refused_with_its_number():
    with pytest.raises(SystemExit, match="line 2"):
        accuracy.parse_urls_file("legit,https://a.example\nmaybe,https://b.example\n")
    with pytest.raises(SystemExit):
        accuracy.parse_urls_file("scam,not-a-url\n")


def test_fresh_links_are_one_per_host_and_never_repeat_the_list():
    found = accuracy.pick_fresh(
        ["https://a.example/1", "https://a.example/2", "ftp://c.example/x", "https://b.example/1", "https://listed.example/"],
        count=3, skip={"https://listed.example/"},
    )
    assert found == ["https://a.example/1", "https://b.example/1"]


def test_it_refuses_to_run_without_the_eval_flag(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SOMETHING=1\n")
    with pytest.raises(SystemExit, match="Refusing to run"):
        accuracy.require_eval_ok(env={}, env_path=env_file)
    accuracy.require_eval_ok(env={"TRIPWIRE_EVAL_OK": "1"}, env_path=env_file)
    env_file.write_text("TRIPWIRE_EVAL_OK=1\n")
    accuracy.require_eval_ok(env={}, env_path=env_file)


def test_a_whole_run_writes_both_files_stops_at_max_and_pauses_between_links(tmp_path, monkeypatch):
    listing = tmp_path / "urls.txt"
    listing.write_text("".join(f"legit,https://site{i}.example\n" for i in range(1, 6)) + "scam,https://bad.example/x\n")
    asked, naps = [], []

    def fake_analyze(base, url):
        asked.append(url)
        return as_answer(judge(scan(feeds=[listed()]))) if "bad" in url else {**as_answer(judge(scan())), "explained_by": "gemini"}

    monkeypatch.setattr(accuracy, "analyze", fake_analyze)
    monkeypatch.setattr(accuracy.time, "sleep", lambda s: naps.append(s))
    monkeypatch.setattr(accuracy, "fresh_scams", lambda n, skip, key: [f"https://fresh{i}.example/" for i in range(n)])
    out = tmp_path / "docs"
    accuracy.main(
        ["--urls", str(listing), "--fresh", "3", "--max", "7", "--pause", "1.5", "--out-dir", str(out)],
        env={"TRIPWIRE_EVAL_OK": "1"},
    )
    assert len(asked) == 7  # 6 listed + 3 fresh = 9; stops at --max
    assert asked[:6][-1] == "https://bad.example/x" and asked[6] == "https://fresh0.example/"
    assert naps == [1.5] * 6  # a pause between links, none after the last
    md = (out / "accuracy.md").read_text(encoding="utf-8")
    assert "Answers worded by Gemini in this run: 6 of 7" in md
    assert "2 more links were listed than the limit allowed" in md
    assert (out / "accuracy.csv").read_text(encoding="utf-8").count("\n") == 8
    written = md + (out / "accuracy.csv").read_text(encoding="utf-8")
    assert not re.search(r"https?://|safe", without_the_proper_noun(written), re.IGNORECASE)
    assert PROPER_NOUN in written  # the product name is kept as it is where an evidence line names it


def test_the_default_limit_is_fifteen_links():
    assert accuracy.parse_args([]).max == 15
    assert accuracy.parse_args([]).analyzer.startswith("http://")
