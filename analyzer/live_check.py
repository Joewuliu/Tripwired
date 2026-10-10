"""Run live phishing links and known-good links through the real pipeline and print what Tripwire says.

VM ONLY. This OPENS LIVE PHISHING PAGES. It refuses to run unless TRIPWIRE_EVAL_OK=1, which belongs
only in the VM's .env, where the analyzer sits behind the egress firewall (deploy/DEPLOY.md).

    docker compose exec analyzer python live_check.py --phish 5 --benign 5
    docker compose exec analyzer python live_check.py --list 5       # fresh links to forward by phone

Each link is scored twice from the same evidence: with every signal, and with threat-feed hits
removed. The second run is the honest measure of the page and domain signals, because the phishing
links come from OpenPhish and the pipeline also asks OpenPhish. Everything printed is defanged.
"""
import argparse
import asyncio
import dataclasses
import os
import random
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

import feeds
from defang import defang
from env import load_root_env
from pipeline import scan
from score import judge

CONCURRENCY = 3
BENIGN_PATH = Path(__file__).resolve().parent / "data" / "benign.txt"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FLAGGED = {"dangerous", "suspicious"}


def require_eval_ok(env=os.environ) -> None:
    if env.get("TRIPWIRE_EVAL_OK") != "1":
        raise SystemExit(
            "Refusing to run: live_check.py opens live phishing pages.\n"
            "Run it only on the VM, where the egress firewall is installed and TRIPWIRE_EVAL_OK=1 is set in\n"
            ".env (see deploy/DEPLOY.md). Never run it on a laptop."
        )


def load_urls(path: Path) -> list[str]:
    """One URL per line; blank lines and #-comments are ignored; duplicates dropped."""
    lines = (line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines())
    return list(dict.fromkeys(line for line in lines if line and not line.startswith("#")))


def sample(urls: list[str], n: int, rng: random.Random) -> list[str]:
    if n <= 0:
        return []
    return rng.sample(urls, n) if n < len(urls) else list(urls)


def outcome(verdict: str) -> str:
    """flagged, clear, or undecided (couldn't check): the three things a verdict can mean for a tally."""
    if verdict in FLAGGED:
        return "flagged"
    return "clear" if verdict == "no_red_flags" else "undecided"


def tally(rows: list[dict], label: str, key: str) -> dict[str, int]:
    counts = {"flagged": 0, "clear": 0, "undecided": 0}
    for row in rows:
        if row["label"] == label:
            counts[outcome(row[key])] += 1
    return counts


def summary(rows: list[dict]) -> list[str]:
    phish_all, phish_bare = tally(rows, "phish", "verdict"), tally(rows, "phish", "verdict_no_feeds")
    benign = tally(rows, "benign", "verdict")
    n_phish = sum(r["label"] == "phish" for r in rows)
    n_benign = sum(r["label"] == "benign" for r in rows)
    lines = [
        f"phishing links: {n_phish}",
        f"  with every signal : {phish_all['flagged']} flagged, {phish_all['clear']} said no red flags (MISSED), "
        f"{phish_all['undecided']} couldn't check",
        f"  feed hits removed : {phish_bare['flagged']} flagged, {phish_bare['clear']} said no red flags (MISSED), "
        f"{phish_bare['undecided']} couldn't check",
        f"known-good links: {n_benign}",
        f"  {benign['flagged']} flagged (FALSE ALARMS), {benign['clear']} no red flags, "
        f"{benign['undecided']} couldn't check",
    ]
    unread = [r for r in rows if r.get("unread")]
    if unread:  # a page we could not fully read is never cleared; this says how often that happens
        lines.append(
            f"{len(unread)} of {len(rows)} had a part that was too slow to read "
            f"(phishing {sum(r['label'] == 'phish' for r in unread)}, known-good {sum(r['label'] == 'benign' for r in unread)})"
        )
    return lines


def format_row(index: int, row: dict) -> list[str]:
    head = (
        f"{index:2d}. {row['label']:6s} {row['verdict']:13s} score {row['score']:3d}   "
        f"feeds removed: {row['verdict_no_feeds']:13s} {row['score_no_feeds']:3d}   {row['seconds']:4.1f}s"
    )
    lines = [head, f"      {defang(row['url'])[:110]}"]
    lines += [f"      - {defang(text) if '://' in text else text}" for text in row["reasons"]]
    return lines


async def _check(index: int, url: str, label: str, shots: Path, gate: asyncio.Semaphore) -> dict:
    async with gate:
        started = time.monotonic()
        try:
            result = await scan(url, shots / f"{index:02d}.png")
            full = judge(result)
            bare = judge(dataclasses.replace(result, feeds=[]))  # the same evidence, feed hits removed
        except Exception as exc:  # one bad link must not end the run
            return {"label": label, "url": url, "verdict": "error", "score": 0, "verdict_no_feeds": "error",
                    "score_no_feeds": 0, "seconds": time.monotonic() - started, "unread": False,
                    "reasons": [f"error: {type(exc).__name__}"]}
        return {
            "label": label, "url": url, "verdict": full.verdict, "score": full.score,
            "verdict_no_feeds": bare.verdict, "score_no_feeds": bare.score,
            "seconds": time.monotonic() - started, "reasons": full.observations[:3],
            "unread": any(item.id == "not_read" for item in full.evidence),  # a page or frame was too slow to read
        }


async def run(phish: list[str], benign: list[str], shots: Path) -> list[dict]:
    gate = asyncio.Semaphore(CONCURRENCY)
    items = [(u, "phish") for u in phish] + [(u, "benign") for u in benign]
    tasks = [_check(i, url, label, shots, gate) for i, (url, label) in enumerate(items, 1)]
    rows = []
    for finished in asyncio.as_completed(tasks):
        row = await finished
        rows.append(row)
        print(f"[{len(rows)}/{len(items)}] {row['label']:6s} {row['verdict']:13s} {defang(row['url'])[:90]}",
              file=sys.stderr, flush=True)
    return sorted(rows, key=lambda r: (r["label"] != "phish", r["url"]))


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run live phishing links and known-good links through Tripwire.")
    parser.add_argument("--phish", type=int, default=5, help="phishing links to take from OpenPhish")
    parser.add_argument("--benign", type=int, default=5, help="known-good links to take from data/benign.txt")
    parser.add_argument("--seed", type=int, default=None, help="repeat the same sample")
    parser.add_argument("--list", type=int, default=0, metavar="N",
                        help="only print N fresh phishing links (NOT defanged: paste into the Tripwire chat, never open)")
    args = parser.parse_args(argv)
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(2**32)
    return args


async def _main(args: argparse.Namespace) -> None:
    try:
        await feeds.refresh_openphish()
    except Exception as exc:
        raise SystemExit(f"Could not download the OpenPhish list and there is no saved copy: {type(exc).__name__}")
    pool = load_urls(feeds.OPENPHISH_PATH)
    rng = random.Random(args.seed)

    if args.list:
        print("LIVE PHISHING LINKS. Do not open them. Forward them to the Tripwire number.\n")
        print("\n".join(sample(pool, args.list, rng)))
        return

    phish, benign = sample(pool, args.phish, rng), sample(load_urls(BENIGN_PATH), args.benign, rng)
    shots = DATA_DIR / "live" / f"{datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
    shots.mkdir(parents=True)
    print(f"Checking {len(phish)} phishing and {len(benign)} known-good links (seed {args.seed}).\n", file=sys.stderr)
    rows = await run(phish, benign, shots)

    print()
    for i, row in enumerate(rows, 1):
        print("\n".join(format_row(i, row)))
    print("\n== Summary ==")
    print("\n".join(summary(rows)))
    print(f"\nScreenshots: {shots}   (repeat this exact sample with --seed {args.seed})")


def main(argv: list[str] | None = None, env=os.environ) -> None:
    require_eval_ok(env)  # before anything else: nothing is opened without it
    load_root_env()
    asyncio.run(_main(parse_args(argv)))


if __name__ == "__main__":
    main()
