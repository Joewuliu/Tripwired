"""Plain-English lines about what the checks found. Each names where it came from."""
from defang import defang_text
from feeds import SOURCES


def _joined(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


def describe_feeds(feeds: list[dict]) -> list[str]:
    lines, clear = [], []
    hit_sources = []
    for entry in feeds:
        source, status = entry["source"], entry["status"]
        if status == "hit" and source not in hit_sources:
            hit_sources.append(source)
            lines.append(f"Listed as {entry['kind']} by {source}")
        elif status == "not_checked":
            lines.append(f"{source} was not checked (no API key is set)")
        elif status == "error":
            lines.append(f"{source} could not be checked right now")
        elif status == "clear":
            clear.append(source)
    if clear:
        ordered = [s for s in SOURCES if s in clear]
        lines.append(f"Not listed by {_joined(ordered)}")
    return lines


def _how_long(days: int) -> str:
    if days == 0:
        return "today"
    if days < 60:
        return f"{days} day{'' if days == 1 else 's'} ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


def describe_age(age: dict) -> list[str]:
    if age.get("age_days") is not None:
        return [f"Registered {_how_long(age['age_days'])}, from RDAP"]
    if age.get("error") == "free hosting platform":
        return ["On a free hosting platform, so the domain's age says nothing about this page"]
    return ["Domain age could not be found (RDAP)"]


def _names(brands: list[str]) -> str:
    return brands[0] if len(brands) == 1 else ", ".join(brands[:-1]) + " and " + brands[-1]


def describe_brand(findings: list[dict]) -> list[str]:
    def brands(kind: str, detail_ends: str | None = None) -> list[str]:
        return [
            f["brand"] for f in findings
            if f["type"] == kind and (detail_ends is None or f["detail"].endswith(detail_ends))
        ]

    lines = []
    if official := brands("official"):
        lines.append(f"Registered domain is official for {_names(official)} (brand list)")
    if named := brands("impersonation", "in domain"):
        lines.append(f"Web address uses the name {_names(named)} but is not an official site (brand list)")
    if in_path := brands("impersonation", "in path"):
        lines.append(f"Web address path names {_names(in_path)}, but this is not an official site (brand list)")
    for finding in findings:
        if finding["type"] == "lookalike":
            lines.append(f"Domain imitates {finding['brand']}: {defang_text(finding['detail'])} (look-alike check)")
    if mentioned := brands("mention"):
        lines.append(f"Page text names {_names(mentioned)} (brand list)")
    return lines


def describe(feeds: list[dict], age: dict, brand: list[dict] | None = None, popular: bool = False) -> list[str]:
    lines = describe_brand(brand or []) + describe_feeds(feeds) + describe_age(age)
    if popular:
        lines.append("Domain is one of the 10,000 most visited on the web (Tranco list)")
    return lines
