import re

# A hostname with at least one dot and a letters-only ending, plus an optional port/path.
_HOSTLIKE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?", re.IGNORECASE)
_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)


def defang(url: str) -> str:
    """hxxps://paypa1[.]com/login: readable, not clickable. For values that are known URLs."""
    return _SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", url).replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defang every link-looking token in free text and leave ordinary sentences alone."""
    text = _SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", text)
    return _HOSTLIKE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
