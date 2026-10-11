"""Plain wording for a finding, for the replies and the top of a report.

The evidence table keeps its precise sentences, with the source of each ("Registered 2 days ago,
from RDAP"): that is the show-your-work part of a report. The short lines a person reads first use
these instead: everyday words, no source names, no "(page scan)". They are the wording used when
Gemini is not (it is asked for the same register). They add no points and decide nothing.

Nothing here says a page is safe. Findings that would only clutter a short message (a source that
was unavailable, an age that could not be found) return None and are left out of the short lines.
"""
import re

from contract import Evidence


def _group(pattern: str, label: str) -> str | None:
    found = re.search(pattern, label)
    return found.group(1) if found else None


def _first_sentence_case(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


# What the sandbox could not see: the start of the scorer's sentence -> the plain reason.
_ACCESS_PLAIN = (
    ("Not a public web address", "That isn't an ordinary public web address, so I didn't open it."),
    ("The address does not resolve", "That web address doesn't exist, or no longer works."),
    ("The page did not load", "The page wouldn't open."),
    ("The page is gone", "The page has been taken down."),
    ("The site refused the sandbox", "The website blocked my check."),
    ("The site showed a human-verification", "The website asked to prove I'm a person, which I can't do."),
    ("The page opened but showed nothing", "The page opened but it was empty."),
    ("Part of the page could not be read", "I could only read part of the page."),
    ("The page had not finished loading", "The page was too slow to finish loading."),
)


def plain_line(item: Evidence) -> str | None:
    """One short, plain sentence for a finding, or None when it is not worth a line."""
    rule = item.id.split(":")[0]
    label = item.label

    if rule == "known_threat_feed":
        return "Security services have already reported this link as a scam."
    if rule == "platform_warning":
        return "The website's own host has already warned that this page is dangerous."
    if rule == "impersonation":
        name = _group(r"uses the name (.+?) but", label)
        return f"The web address uses the name {name}, but it isn't their real website." if name else None
    if rule == "impersonation_path":
        if item.points <= 0:
            return None
        name = _group(r"names (.+?), but", label)
        return f"The link uses the name {name}, but it isn't their real website." if name else None
    if rule == "lookalike":
        name = _group(r"imitates (.+?):", label)
        return f"The web address is spelled to look like {name}'s, but it isn't." if name else None
    if rule in ("domain_under_7_days", "domain_under_30_days"):
        when = _group(r"Registered (.+?), from", label)
        return f"This website was only created {when}." if when else None
    if rule == "sensitive_fields":
        asked = _group(r"asks for (.+?) \(", label)
        return f"The page asks for {asked}." if asked else None
    if rule == "brand_with_sensitive_fields":
        name = _group(r"Page names (.+?) and", label)
        return f"The page uses the {name} name and asks for private details." if name else None
    if rule == "young_with_sensitive_fields":
        return "A brand-new website is asking for private details."
    if rule == "free_host_credentials":
        return "The page asks for private details on a free website that anyone can set up."
    if rule == "free_host_many_fields":
        return "The page asks for several private details at once."
    if rule == "brand_mention":
        name = _group(r"names (.+?) \(", label)
        return f"The page mentions {name}." if name else None
    if rule == "official_domain":
        name = _group(r"official for (.+?) \(", label)
        return f"This is the official website of {name}." if name else None
    if rule == "feeds_clear":
        return "It isn't on any list of known scam websites."
    if rule == "popular_domain":
        return "This is one of the most visited websites in the world."
    if rule == "domain_age":
        when = _group(r"Registered (.+?), from", label)
        return f"This website was created {when}." if when else None
    if rule == "partial_page":
        return "The page was slow, so I only checked part of it."
    if rule.startswith("feed_error") or rule.startswith("feed_not_checked"):
        return "One of the scam-list checks couldn't be done right now."
    if rule in ("hides_from_sandbox", "not_opened", "not_read", "not_finished"):
        for start, sentence in _ACCESS_PLAIN:
            if label.startswith(start):
                return sentence
        return "I couldn't get a proper look at the page."
    # Anything new: its own sentence, with the source in brackets taken off the end.
    stripped = re.sub(r"\s*\([^)]*\)\s*$", "", label).strip()
    return _first_sentence_case(stripped).rstrip(".") + "." if stripped else None


def plain_lines(evidence: list[Evidence]) -> list[str]:
    """The plain line for each finding, in the scorer's order, without gaps or repeats."""
    lines: list[str] = []
    for item in evidence:
        line = plain_line(item)
        if line and line not in lines:
            lines.append(line)
    return lines
