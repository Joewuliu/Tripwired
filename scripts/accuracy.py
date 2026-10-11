#!/usr/bin/env python3
"""A small accuracy check for the Devpost write-up. VM ONLY.

    cd ~/tripwire && python3 scripts/accuracy.py                 # the five legit sites in accuracy_urls.txt
    cd ~/tripwire && python3 scripts/accuracy.py --fresh 10      # plus 10 recent scams from OpenPhish and URLhaus
    cd ~/tripwire && python3 scripts/accuracy.py --fresh 10 --max 20

Each URL goes through the analyzer's POST /analyze, the same call the gateway makes for a phone text,
over the Docker network. Nothing goes through iMessage and nothing is opened here: the analyzer's
sandbox opens the page, behind the egress firewall. Scams are live phishing pages, so this refuses
to run unless TRIPWIRE_EVAL_OK=1 is set (in the VM's .env, or the environment).

It writes docs/accuracy.md and docs/accuracy.csv. Every address in them is defanged, and neither says
a site is "safe": the clean verdict is "No red flags found". (The product name "Google Safe Browsing"
is a proper noun and is kept as it is.)

Standard library only, so it runs on the VM's own python3 with nothing installed.
"""
import argparse
import csv
import io
import json
import os
import re
import statistics
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ANALYZER = "http://172.30.0.10:8001"  # the analyzer's fixed address in docker-compose.yml
URLS_FILE = Path(__file__).resolve().parent / "accuracy_urls.txt"
DEFAULT_MAX = 15
DEFAULT_PAUSE_S = 3.0
SCAN_TIMEOUT_S = 90  # the analyzer's own worst case is about 30 s

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# The scorer's thresholds (analyzer/score.py). test_accuracy.py fails if these drift from it.
DANGEROUS_AT = 60
SUSPICIOUS_AT = 30

WORDS = {
    "dangerous": "Dangerous",
    "suspicious": "Suspicious",
    "no_red_flags": "No red flags found",
    "couldnt_check": "Couldn't check",
    "error": "Not run (error)",
}
FLAGGED = ("dangerous", "suspicious")
LABELS = ("scam", "legit")


# --- defanging: nothing written to a file is a live link ------------------------------------------

_HOSTLIKE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?", re.IGNORECASE)
_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)


def defang(url: str) -> str:
    """hxxps://paypa1[.]com/login: readable, not clickable."""
    return _SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", url).replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defang every link-looking token in free text and leave ordinary sentences alone."""
    text = _SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", text)
    return _HOSTLIKE.sub(lambda m: m.group(0).replace(".", "[.]"), text)


# "safe" in any form, except inside the proper noun "Google Safe Browsing".
_SAFE_WORD = re.compile(r"(?<!Google )safe\w*", re.IGNORECASE)


def scrub(text: str) -> str:
    """Last line of defence for what reaches a file: a defanged address, and not the word "safe"
    in our own wording. The proper noun "Google Safe Browsing" is left as it is."""
    return _SAFE_WORD.sub("(word removed)", defang_text(text))


# --- the "Without blocklists" verdict, from the same evidence ---------------------------------------

FEED_RULE = "known_threat_feed"
# What makes a brand named only in the URL path worth points (analyzer/score.py), minus the feed.
_PATH_CORROBORATORS = frozenset({
    "platform_warning", "lookalike", "sensitive_fields", "brand_with_sensitive_fields",
    "young_with_sensitive_fields", "free_host_credentials", "domain_under_7_days", "domain_under_30_days",
})
# The evidence ids that mean the sandbox could not see the page: its verdict is then couldn't check.
_UNSEEN = frozenset({"hides_from_sandbox", "not_opened", "not_read", "not_finished"})


def verdict_for(score: int, unseen: bool) -> str:
    if score >= DANGEROUS_AT:
        return "dangerous"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "couldnt_check" if unseen else "no_red_flags"


def without_blocklists(evidence: list[dict], points_table: list[dict]) -> tuple[int, str]:
    """What the score and verdict would have been had no threat feed listed the page.

    From the evidence of the one scan, no second scan: threat-feed points come out, and the two things
    that only depended on a feed hit are put back as the scorer would have had them:
      - an official-domain discount that a listing had withheld (unless the host's own warning page,
        which is page evidence and stays, would have withheld it anyway);
      - a brand named only in the address path, which had counted only because the listing
        corroborated it, goes back to worth nothing unless something else corroborates it.
    The popular-domain discount, which a listing keeps out of the evidence altogether, cannot be
    restored from it: a popular site that was also listed scores higher here than it would have.
    """
    weights = {rule["id"]: rule["points"] for rule in points_table}
    ids = {item["id"].split(":")[0] for item in evidence}
    host_warned = "platform_warning" in ids
    corroborated = any(
        item["id"].split(":")[0] in _PATH_CORROBORATORS and item["points"] > 0 for item in evidence
    )
    score = 0
    for item in evidence:
        rule, points = item["id"].split(":")[0], item["points"]
        if rule == FEED_RULE:
            continue
        if rule == "official_domain" and points == 0 and weights.get(rule, 0) < 0 and not host_warned:
            points = weights[rule]
        if rule == "impersonation_path" and points > 0 and not corroborated:
            points = 0
        score += points
    score = max(0, score)
    return score, verdict_for(score, bool(ids & _UNSEEN))


# --- turning an answer into a row ---------------------------------------------------------------------

def top_signals(evidence: list[dict], count: int = 2) -> list[str]:
    """The first findings the scorer put in its order (what adds risk first, biggest first; for a
    couldn't-check, why). Wording is the evidence's own, scrubbed."""
    return [scrub(item["label"]) for item in evidence[:count]]


def make_row(index: int, label: str, url: str, answer: dict | None, seconds: float, error: str | None = None) -> dict:
    row = {
        "n": index, "label": label, "url": defang(url), "verdict": "error", "score": None,
        "without": "error", "signals": [], "seconds": round(seconds, 1), "gemini": False, "error": error,
    }
    if answer is None:
        return row
    evidence = answer.get("evidence", [])
    _, without = without_blocklists(evidence, answer.get("points_table", []))
    row.update(
        verdict=answer.get("verdict", "error"), score=answer.get("score"), without=without,
        signals=top_signals(evidence), gemini=answer.get("explained_by") == "gemini",
    )
    return row


def summarize(rows: list[dict]) -> dict:
    """The counts under the table. A couldn't-check, and a link that could not be run at all, is
    listed but counts as neither right nor wrong."""
    scams = [r for r in rows if r["label"] == "scam"]
    legit = [r for r in rows if r["label"] == "legit"]
    counted_scams = [r for r in scams if r["verdict"] in (*FLAGGED, "no_red_flags")]
    counted_legit = [r for r in legit if r["verdict"] in (*FLAGGED, "no_red_flags")]
    times = [r["seconds"] for r in rows if r["verdict"] != "error"]
    return {
        "total": len(rows),
        "scams_flagged": sum(r["verdict"] in FLAGGED for r in counted_scams),
        "scams_counted": len(counted_scams),
        "scams_flagged_without": sum(r["without"] in FLAGGED for r in counted_scams),
        "legit_clear": sum(r["verdict"] == "no_red_flags" for r in counted_legit),
        "legit_counted": len(counted_legit),
        "couldnt_check": [r for r in rows if r["verdict"] == "couldnt_check"],
        "errors": [r for r in rows if r["verdict"] == "error"],
        "median_seconds": round(statistics.median(times), 1) if times else None,
        "gemini_worded": sum(r["gemini"] for r in rows),
    }


# --- the two files ---------------------------------------------------------------------------------------

def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(rows: list[dict], summary: dict, when: datetime, notes: list[str]) -> str:
    out = [
        "# Accuracy check",
        "",
        f"Run {when.strftime('%Y-%m-%d %H:%M UTC')} on the deployed Phish Finder, {summary['total']} links, "
        "one at a time, through the same analyzer call a phone text uses. "
        "Scams are recent live phishing links; legit sites are well-known ones. Every address is defanged.",
        "",
        "| # | Label | URL | Verdict | Score | Without blocklists | Top 2 signals | Seconds |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        signals = "; ".join(r["signals"]) if r["signals"] else (r["error"] or "")
        out.append(
            f"| {r['n']} | {r['label']} | `{_cell(r['url'])}` | {WORDS.get(r['verdict'], r['verdict'])} | "
            f"{'' if r['score'] is None else r['score']} | {WORDS.get(r['without'], r['without'])} | "
            f"{_cell(scrub(signals))} | {r['seconds']} |"
        )
    out += ["", f"- Scams flagged Dangerous or Suspicious: **{summary['scams_flagged']}/{summary['scams_counted']}**"]
    out.append(
        f"- Legit sites with \"No red flags found\": **{summary['legit_clear']}/{summary['legit_counted']}**"
    )
    out.append(
        f"- Scams still flagged without blocklists: **{summary['scams_flagged_without']}/{summary['scams_counted']}** "
        "(what the sandbox and the domain checks catch by themselves)"
    )
    median = summary["median_seconds"]
    out.append(f"- Median time per check: **{'n/a' if median is None else f'{median} s'}**")
    for r in summary["couldnt_check"]:
        what = "Scam link" if r["label"] == "scam" else "Legit site"
        reason = scrub(r["signals"][0]) if r["signals"] else "no reason given"
        out.append(f"- Couldn't check, not counted as right or wrong: #{r['n']} {what} `{_cell(r['url'])}`: {reason}")
    for r in summary["errors"]:
        out.append(f"- Could not be run, not counted: #{r['n']} `{_cell(r['url'])}`: {scrub(r['error'] or 'no answer')}")
    out += ["", "## Notes", ""] + [f"- {scrub(note)}" for note in notes]
    return "\n".join(out) + "\n"


CSV_FIELDS = ["n", "label", "url", "verdict", "score", "without_blocklists", "top_signal_1", "top_signal_2", "seconds"]


def to_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_FIELDS)
    for r in rows:
        signals = [scrub(s) for s in r["signals"]] + ["", ""]
        writer.writerow([
            r["n"], r["label"], r["url"], WORDS.get(r["verdict"], r["verdict"]), "" if r["score"] is None else r["score"],
            WORDS.get(r["without"], r["without"]), signals[0], signals[1], r["seconds"],
        ])
    return buffer.getvalue()


def notes_for(summary: dict, fresh_wanted: int, fresh_got: int, skipped: int) -> list[str]:
    notes = [
        "Verdict and score come from the points table. Gemini only words the explanation: the analyzer has no "
        "per-request way to switch it off, so it stayed on. "
        f"Answers worded by Gemini in this run: {summary['gemini_worded']} of {summary['total']} "
        "(one call is attempted per scan when a key is set; a call that failed or was rejected leaves the plain "
        "wording and is not visible here).",
        "\"Without blocklists\" is computed from the same scan's evidence, not a second scan: threat-feed points are "
        "removed, a discount a listing had withheld is restored, and a brand named only in the address counts only "
        "if something else supports it. A popular site that was also listed is not given back its popularity discount.",
        "Scam links are recent: many are already gone when opened. Those show as Couldn't check, and a scam is "
        "caught then only through a feed listing or a brand in its address.",
    ]
    if fresh_wanted:
        notes.append(f"Fresh scams requested: {fresh_wanted}; got {fresh_got} from OpenPhish and URLhaus.")
    if skipped:
        notes.append(f"{skipped} more links were listed than the limit allowed and were not run (--max).")
    return notes


# --- inputs -----------------------------------------------------------------------------------------------

def parse_urls_file(text: str) -> list[tuple[str, str]]:
    """label,url per line; blank lines and #-comments ignored; a line that is not scam/legit is an error."""
    found: list[tuple[str, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        label, _, url = line.partition(",")
        label, url = label.strip().lower(), url.strip()
        if label not in LABELS or not re.match(r"https?://\S+$", url, re.IGNORECASE):
            raise SystemExit(f"accuracy_urls.txt line {number}: expected 'scam,https://…' or 'legit,https://…'")
        found.append((label, url))
    return list(dict.fromkeys(found))


def _fetch(url: str, headers: dict | None = None, timeout: float = 20) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "phish-finder-accuracy/1", **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed, https feed addresses)
        return response.read()


def read_env_value(name: str, env_path: Path = ROOT / ".env", env=os.environ) -> str:
    """One value from the environment or the repo-root .env (nothing else of it is read or printed)."""
    if env.get(name):
        return env[name]
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip("\"'")
    except OSError:
        pass
    return ""


def pick_fresh(candidates: list[str], count: int, skip: set[str]) -> list[str]:
    """Up to `count` http(s) links, at most one per host, none already in the list."""
    seen_hosts: set[str] = set()
    picked: list[str] = []
    for url in candidates:
        match = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
        if not match or url in skip or match.group(1).lower() in seen_hosts:
            continue
        seen_hosts.add(match.group(1).lower())
        picked.append(url)
        if len(picked) == count:
            break
    return picked


def fresh_scams(count: int, skip: set[str], key: str) -> list[str]:
    """Recent scam links, half from OpenPhish and half from URLhaus (all from OpenPhish if there is
    no URLhaus key or it does not answer). Never opened here; they are only handed to the analyzer."""
    from_urlhaus: list[str] = []
    if key:
        try:
            data = json.loads(_fetch(URLHAUS_RECENT, {"Auth-Key": key}))
            online = [u for u in data.get("urls", []) if u.get("url_status") == "online" and u.get("url")]
            from_urlhaus = [u["url"] for u in online]
        except Exception as exc:  # the feed is a convenience: a run without it is still a run
            print(f"URLhaus: not used ({type(exc).__name__})", file=sys.stderr)
    else:
        print("URLhaus: not used (no URLHAUS_AUTH_KEY in .env)", file=sys.stderr)
    try:
        from_openphish = [l.strip() for l in _fetch(OPENPHISH_FEED).decode("utf-8", "ignore").splitlines() if l.strip()]
    except Exception as exc:
        print(f"OpenPhish: not used ({type(exc).__name__})", file=sys.stderr)
        from_openphish = []
    want_haus = count // 2 if from_urlhaus else 0
    haus = pick_fresh(from_urlhaus, want_haus, skip)
    phish = pick_fresh(from_openphish, count - len(haus), skip | set(haus))
    if len(haus) + len(phish) < count:  # one source came up short: top up from the other
        haus += pick_fresh(from_urlhaus, count - len(haus) - len(phish), skip | set(haus) | set(phish))
    return phish + haus


# --- running ----------------------------------------------------------------------------------------------

def analyze(base: str, url: str) -> dict:
    request = urllib.request.Request(
        f"{base.rstrip('/')}/analyze",
        data=json.dumps({"urls": [url]}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=SCAN_TIMEOUT_S) as response:  # noqa: S310 (the internal analyzer)
        return json.loads(response.read())


def require_eval_ok(env=os.environ, env_path: Path = ROOT / ".env") -> None:
    if read_env_value("TRIPWIRE_EVAL_OK", env_path, env) != "1":
        raise SystemExit(
            "Refusing to run: this opens live phishing pages through the analyzer.\n"
            "Run it only on the VM, where the egress firewall is installed and TRIPWIRE_EVAL_OK=1 is set in\n"
            ".env (see deploy/DEPLOY.md). Never run it on a laptop."
        )


def run(jobs: list[tuple[str, str]], base: str, pause_s: float, report=print) -> list[dict]:
    rows: list[dict] = []
    for index, (label, url) in enumerate(jobs, 1):
        started = time.monotonic()
        try:
            answer, error = analyze(base, url), None
        except Exception as exc:  # one bad link must not end the run
            answer, error = None, f"{type(exc).__name__}: could not reach the analyzer or it timed out"
        row = make_row(index, label, url, answer, time.monotonic() - started, error)
        rows.append(row)
        report(f"{index:2d}. {label:5s} {WORDS.get(row['verdict'], row['verdict']):20s} "
               f"without blocklists: {WORDS.get(row['without'], row['without']):20s} {row['seconds']:5.1f}s  {row['url'][:70]}")
        if index < len(jobs):
            time.sleep(pause_s)
    return rows


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run links through the analyzer and write docs/accuracy.md and .csv.")
    parser.add_argument("--fresh", type=int, default=0, metavar="N", help="add N recent scam links from OpenPhish and URLhaus")
    parser.add_argument("--max", type=int, default=DEFAULT_MAX, help=f"most links to run (default {DEFAULT_MAX})")
    parser.add_argument("--pause", type=float, default=DEFAULT_PAUSE_S, help="seconds between links")
    parser.add_argument("--urls", type=Path, default=URLS_FILE, help="the label,url file")
    parser.add_argument("--analyzer", default=os.environ.get("ANALYZER_URL") or DEFAULT_ANALYZER)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "docs")
    args = parser.parse_args(argv)
    if args.fresh < 0 or args.max < 1:
        parser.error("--fresh must be 0 or more and --max at least 1")
    return args


def main(argv: list[str] | None = None, env=os.environ) -> None:
    args = parse_args(argv)
    require_eval_ok(env)  # before anything is fetched or sent
    listed = parse_urls_file(args.urls.read_text(encoding="utf-8"))
    fresh: list[str] = []
    if args.fresh:
        fresh = fresh_scams(args.fresh, {url for _, url in listed}, read_env_value("URLHAUS_AUTH_KEY", env=env))
    everything = listed + [("scam", url) for url in fresh]
    jobs, skipped = everything[: args.max], max(0, len(everything) - args.max)
    print(f"Running {len(jobs)} links one at a time through {args.analyzer} ({skipped} not run: --max {args.max}).")
    print("Gemini stays on: the analyzer has no per-request switch. Verdicts come from the points table.")
    rows: list[dict] = []
    try:
        rows = run(jobs, args.analyzer, args.pause)
    except KeyboardInterrupt:
        print("\nInterrupted: writing what finished.")
    if not rows:
        raise SystemExit("Nothing finished, nothing written.")
    summary = summarize(rows)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    when = datetime.now(timezone.utc)
    (args.out_dir / "accuracy.md").write_text(
        to_markdown(rows, summary, when, notes_for(summary, args.fresh, len(fresh), skipped)), encoding="utf-8"
    )
    (args.out_dir / "accuracy.csv").write_text(to_csv(rows), encoding="utf-8", newline="")
    print(f"\nScams flagged Dangerous or Suspicious: {summary['scams_flagged']}/{summary['scams_counted']}")
    print(f"Legit sites with No red flags found: {summary['legit_clear']}/{summary['legit_counted']}")
    print(f"Scams still flagged without blocklists: {summary['scams_flagged_without']}/{summary['scams_counted']}")
    print(f"Median time per check: {summary['median_seconds']} s   Gemini-worded answers: {summary['gemini_worded']}")
    print(f"Wrote {args.out_dir / 'accuracy.md'} and {args.out_dir / 'accuracy.csv'}")


if __name__ == "__main__":
    main()
