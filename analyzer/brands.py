"""Does this address or page name a well-known brand it does not belong to?

check_brand returns findings {"type", "brand", "detail"}, at most one per brand:

  official       the registered domain is one the brand owns
  impersonation  the brand's name appears in the address (host or path)
  lookalike      the address spells the brand with look-alike characters or one stray character
                 (paypa1.com, chasee.com, a Cyrillic "а" in place of "a")
  mention        the brand is named only in the page title or text (weaker: plenty of honest pages
                 mention PayPal or Apple)

The rules that keep honest pages out of trouble:
  - a shared host (docs.google.com) is never official, and its own name is not impersonation;
  - on a free-hosting platform only the user's part of the name counts (bucket.s3.amazonaws.com is
    not an Amazon imitation, paypal.github.io is a PayPal one);
  - a domain among the 10,000 most visited is never an imitation (microsoftonline.com, amazon.co.uk);
  - a brand's own site is not an imitation of a similarly named brand (discover.com is not Discord,
    usps.com is not UPS);
  - "Sign in with Google" is a button for another service, not a page claiming to be Google.
"""
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from confusable_homoglyphs import confusables
from rapidfuzz import fuzz

from enrich import main_label, registered_domain
from platforms import FREE_HOSTING_PLATFORMS, is_free_host, is_popular, is_shared_host

LOOKALIKE_RATIO = 80  # 0-100; "chasee" vs "chase" is 91, "robiox" vs "roblox" is 83
MIN_LABEL = 4  # shorter labels are too ambiguous to call look-alikes
MIN_SUBSTRING_KEYWORD = 6  # shorter keywords ("chase" in "purchase") must be whole words
# Words scam domains glue to a short brand name: chasesecure.com, loginpaypal.net
AFFIXES = ("secure", "login", "signin", "verify", "verification", "account", "support", "service", "services",
           "update", "alert", "alerts", "online", "payment", "billing", "official", "portal", "customer",
           "auth", "confirm", "recover", "unlock")

BRANDS: list[dict] = json.loads((Path(__file__).parent / "data" / "brands.json").read_text(encoding="utf-8"))

_DIGIT_LOOKALIKES = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})

# "Sign in with Apple", "Continue with Google": a button for another service. Only a brand
# directly after the phrase is skipped: "sign in with your PayPal account", a real phishing line,
# still counts.
_SOCIAL_LOGIN = re.compile(r"(?:(?:sign|log) ?(?:in|up)|login|signup|continue|connect) (?:with|using|via)(?: an?)?$")


def _words(text: str) -> str:
    """Lowercase alphanumeric words joined by single spaces, padded so ' kw ' finds whole words."""
    return " " + " ".join(re.findall(r"[a-z0-9]+", text.lower())) + " "


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _deconfuse(text: str) -> str:
    """Swap digits and non-ASCII look-alikes for the ASCII letter they imitate: paypa1 -> paypal."""
    out = []
    for ch in text.lower():
        if ch.isascii():
            out.append(ch)
            continue
        groups = confusables.is_confusable(ch, greedy=True) or []
        imitated = [h["c"] for g in groups for h in g["homoglyphs"] if h["c"].isascii() and h["c"].isalpha()]
        out.append(imitated[0].lower() if imitated else ch)
    return "".join(out).translate(_DIGIT_LOOKALIKES)


def _hostname(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    try:
        return host.encode("ascii").decode("idna")  # decode xn-- punycode
    except UnicodeError:
        return host


def _users_part(host: str) -> str:
    """paypal.github.io -> paypal; bucket.s3.amazonaws.com -> bucket.s3; github.io -> "" ."""
    labels = host.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in FREE_HOSTING_PLATFORMS:
            return ".".join(labels[:i])
    return host


def _in_social_login_only(needle: str, words: str) -> bool:
    """True if every occurrence sits straight after a social-login phrase."""
    start = words.find(needle)
    if start == -1:
        return False
    while start != -1:
        if not _SOCIAL_LOGIN.search(words[:start]):
            return False
        start = words.find(needle, start + 1)
    return True


def _in_text(keyword: str, words: str) -> bool:
    needle = _words(keyword)
    return needle in words and not _in_social_login_only(needle, words)


def _in_host(keyword: str, host: str, label: str) -> bool:
    """A whole word of the host; a long keyword also inside a word; a short one when the domain's
    own name is the keyword plus a scam word (chasesecure)."""
    if _words(keyword) in _words(host):
        return True
    squashed = _squash(keyword)
    if len(squashed) >= MIN_SUBSTRING_KEYWORD:
        return squashed in _squash(host)
    bare = _squash(label)
    return any(bare in (squashed + affix, affix + squashed) for affix in AFFIXES)


def _address_finding(brand: dict, subject: dict) -> dict | None:
    """impersonation (the name itself) beats lookalike (the name disguised)."""
    host, path = subject["match_host"], subject["path_words"]
    # address_keywords are names too common in ordinary text to count in a page ("ledger" is also an
    # accounting book), but telling in a web address.
    keywords = [*brand["keywords"], *brand.get("address_keywords", [])]
    for keyword in keywords:
        if host and _in_host(keyword, host, subject["label"]):
            return {"type": "impersonation", "brand": brand["brand"], "detail": f'"{keyword}" in domain'}
        if _words(keyword) in path:
            return {"type": "impersonation", "brand": brand["brand"], "detail": f'"{keyword}" in path'}
    if subject["shared"]:
        return None
    # Look-alike checks need a name long enough to be unambiguous: "55a.com" is not "ssa", and
    # "upss.com" is not a disguised "ups".
    for keyword in keywords:  # the same check once the characters are un-disguised
        if len(_squash(keyword)) >= MIN_LABEL and _in_host(keyword, subject["plain_host"], subject["plain_label"]):
            return {"type": "lookalike", "brand": brand["brand"],
                    "detail": f'{subject["host"]} spells "{keyword}" with look-alike characters'}
    label = subject["plain_label"]
    if len(label) >= MIN_LABEL:
        for official in brand["official_domains"]:
            official_label = main_label(official)
            if len(official_label) >= MIN_LABEL and fuzz.ratio(label, official_label) >= LOOKALIKE_RATIO:
                return {"type": "lookalike", "brand": brand["brand"],
                        "detail": f'{subject["host"]} resembles {official}'}
    return None


def check_brand(url: str, page_title: str = "", page_text: str = "") -> list[dict]:
    host = _hostname(url)
    domain = registered_domain(host)
    shared = is_shared_host(host)
    free = is_free_host(host) and not shared
    match_host = "" if shared else (_users_part(host) if free else host)
    label = match_host.split(".")[-1] if free else main_label(host)
    subject = {
        "host": host,
        "shared": shared,
        "match_host": match_host,
        "label": label,
        "path_words": _words(urlparse(url).path),
        "plain_host": _deconfuse(match_host),
        "plain_label": _deconfuse(label),
    }
    # An imitation cannot be a top-10,000 domain; regional and affiliate sites of real brands are.
    judge_address = not is_popular(host, domain)
    owned_by = [] if shared else [b["brand"] for b in BRANDS if domain in b["official_domains"]]
    title_words, content_words = _words(page_title), _words(f"{page_title}\n{page_text}")

    findings = []
    for brand in BRANDS:
        name = brand["brand"]
        if name in owned_by:
            findings.append({"type": "official", "brand": name, "detail": f"{domain} is an official domain"})
            continue
        # A brand's own site is not an imitation of another brand: only the address of an unowned
        # page is judged. What any page says about a brand still counts as a mention.
        found = _address_finding(brand, subject) if judge_address and not owned_by else None
        if found:
            findings.append(found)
            continue
        keyword = next((k for k in brand["keywords"] if _in_text(k, content_words)), None)
        if keyword:
            place = "title" if _in_text(keyword, title_words) else "text"
            findings.append({"type": "mention", "brand": name, "detail": f'"{keyword}" in {place}'})
    return findings
