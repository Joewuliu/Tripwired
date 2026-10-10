"""Plain-English lines about what the checks found. Each names where it came from."""
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


def describe(feeds: list[dict], age: dict) -> list[str]:
    return describe_feeds(feeds) + describe_age(age)
