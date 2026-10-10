import random
from types import SimpleNamespace

import pytest

import live_check
from live_check import (
    BENIGN_PATH,
    format_row,
    load_urls,
    outcome,
    require_eval_ok,
    sample,
    summary,
    tally,
)


def row(label, verdict, no_feeds=None, score=0, url="https://evil.example/login", reasons=()):
    return {"label": label, "url": url, "verdict": verdict, "score": score, "verdict_no_feeds": no_feeds or verdict,
            "score_no_feeds": 0, "seconds": 3.2, "reasons": list(reasons)}


# --- it must never run where live phishing is not allowed ----------------------------------

@pytest.mark.parametrize("env", [{}, {"TRIPWIRE_EVAL_OK": "0"}, {"TRIPWIRE_EVAL_OK": ""}, {"TRIPWIRE_EVAL_OK": "true"}])
def test_it_refuses_without_the_vm_switch(env):
    with pytest.raises(SystemExit) as stop:
        require_eval_ok(env)
    assert "Never run it on a laptop" in str(stop.value)


def test_it_runs_only_with_exactly_one():
    require_eval_ok({"TRIPWIRE_EVAL_OK": "1"})  # does not raise


def test_main_refuses_before_opening_anything(monkeypatch):
    async def must_not_run(*args, **kwargs):
        raise AssertionError("something was opened")

    monkeypatch.setattr(live_check, "scan", must_not_run)
    monkeypatch.setattr(live_check.feeds, "refresh_openphish", must_not_run)
    with pytest.raises(SystemExit):
        live_check.main(["--phish", "5"], env={})


def test_every_name_it_uses_from_other_modules_exists():
    """The VM is the only place this runs for real, so a typo here must not wait until then."""
    for module, name in [(live_check.feeds, "refresh_openphish"), (live_check.feeds, "OPENPHISH_PATH"),
                         (live_check, "scan"), (live_check, "judge"), (live_check, "defang"), (live_check, "load_root_env")]:
        assert hasattr(module, name), f"{module.__name__}.{name}"


# --- input ---------------------------------------------------------------------------------

def test_load_urls_skips_comments_blanks_and_duplicates(tmp_path):
    path = tmp_path / "urls.txt"
    path.write_text("# a comment\n\nhttps://a.example/\n  https://b.example/  \nhttps://a.example/\n", encoding="utf-8")
    assert load_urls(path) == ["https://a.example/", "https://b.example/"]


def test_the_known_good_list_is_usable():
    urls = load_urls(BENIGN_PATH)
    assert len(urls) >= 40
    assert all(u.startswith("https://") for u in urls)
    assert len(set(urls)) == len(urls)


def test_sampling_is_repeatable_with_a_seed_and_never_larger_than_the_list():
    pool = [f"https://s{i}.example/" for i in range(50)]
    assert sample(pool, 5, random.Random(7)) == sample(pool, 5, random.Random(7))
    assert len(sample(pool, 5, random.Random(7))) == 5
    assert sample(pool, 500, random.Random(1)) == pool
    assert sample(pool, 0, random.Random(1)) == []


# --- the tally --------------------------------------------------------------------------------

def test_what_each_verdict_means_for_the_tally():
    assert [outcome(v) for v in ("dangerous", "suspicious", "no_red_flags", "couldnt_check", "error")] == [
        "flagged", "flagged", "clear", "undecided", "undecided",
    ]


def test_summary_counts_misses_and_false_alarms_separately():
    rows = [
        row("phish", "dangerous", no_feeds="suspicious"),
        row("phish", "dangerous", no_feeds="no_red_flags"),
        row("phish", "couldnt_check"),
        row("benign", "no_red_flags"),
        row("benign", "suspicious"),
        row("benign", "couldnt_check"),
    ]
    assert tally(rows, "phish", "verdict") == {"flagged": 2, "clear": 0, "undecided": 1}
    assert tally(rows, "phish", "verdict_no_feeds") == {"flagged": 1, "clear": 1, "undecided": 1}
    text = "\n".join(summary(rows))
    assert "phishing links: 3" in text and "known-good links: 3" in text
    assert "1 flagged (FALSE ALARMS)" in text
    assert "1 said no red flags (MISSED)" in text


def test_summary_counts_scans_a_person_would_have_given_up_on():
    rows = [{**row("benign", "no_red_flags"), "seconds": 4.0}, {**row("benign", "no_red_flags"), "seconds": 19.5}]
    assert "1 of 2 took longer than 15 seconds" in "\n".join(summary(rows))
    assert "longer than 15" not in "\n".join(summary([row("phish", "dangerous")]))


def test_the_check_runs_as_many_at_once_as_the_sandbox_allows():
    assert live_check.CONCURRENCY == live_check.sandbox.MAX_CONCURRENT


def test_summary_says_how_often_a_page_could_not_be_fully_read():
    rows = [row("phish", "dangerous"), {**row("benign", "couldnt_check"), "unread": True},
            {**row("benign", "no_red_flags"), "unread": False}]
    assert "1 of 3 had a part that was too slow to read (phishing 0, known-good 1)" in "\n".join(summary(rows))
    assert "too slow to read" not in "\n".join(summary([row("phish", "dangerous")]))


def test_every_printed_line_is_defanged():
    lines = format_row(1, row("phish", "dangerous", score=120, url="https://paypa1-login.top/signin?a=1",
                             reasons=["Listed as phishing by OpenPhish", "Redirects to https://evil.example/x"]))
    blob = "\n".join(lines)
    assert "http://" not in blob and "https://" not in blob
    assert "hxxps://paypa1-login[.]top/signin?a=1" in blob
    assert "dangerous" in blob and "120" in blob
