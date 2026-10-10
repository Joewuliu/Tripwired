"""Evidence and the verdict. The verdict is arithmetic over a table you can read; no model decides it.

judge(scan) turns everything a scan learned into a list of findings, each with its points, a
plain-English sentence and the source it came from, then adds the points up.

  60 or more      dangerous
  30 to 59        suspicious
  under 30        no red flags found... but only if we actually got to see the page.
                  A page we could not inspect (refused us, human-check wall, blank, gone,
                  did not load) is "couldn't check", never "no red flags".

The wording never says "safe". Tune the numbers in RULES; the report page shows this same table.
"""
from dataclasses import dataclass
from urllib.parse import urlsplit

from contract import Evidence, PointsRule
from defang import defang_text
from feeds import SOURCES
from forms import kinds_asked_for
from platforms import is_free_host

# id, what the rule means (shown in the report's table), points.
RULES: list[tuple[str, str, int]] = [
    ("known_threat_feed", "Listed as malicious by a threat feed (counted once)", 60),
    ("platform_warning", "The hosting provider or browser vendor has flagged the page as dangerous", 60),
    ("impersonation", "Names a brand on a domain that is not the brand's", 35),
    ("impersonation_path", "Names a brand only in the address path, together with a form, a young domain or another signal", 35),
    ("domain_under_7_days", "Domain registered under 7 days ago", 30),
    ("free_host_credentials", "Asks for sensitive details on a free hosting platform", 30),
    ("lookalike", "Lookalike domain (paypa1, chasee)", 25),
    ("brand_with_sensitive_fields", "Names a brand and asks for sensitive details", 25),
    ("domain_under_30_days", "Domain registered under 30 days ago", 20),
    ("young_with_sensitive_fields", "New domain (under 30 days) that asks for sensitive details", 15),
    ("sensitive_fields", "Asks for a password, card number, SSN or one-time code", 10),
    ("free_host_many_fields", "Three or more sensitive fields on a free hosting platform", 10),
    ("hides_from_sandbox", "Hides from phones or bots, or no longer resolves", 10),
    ("popular_domain", "One of the 10,000 most visited domains", -25),
    ("official_domain", "Official brand domain, on no threat feed", -40),
]
WEIGHTS = {rule_id: points for rule_id, _, points in RULES}
MANY_FIELDS = 3
DANGEROUS_AT = 60
SUSPICIOUS_AT = 30

# Why we could not see a page, and which of those count as the page hiding from us. Our own
# refusal to open a private address says nothing about the site.
HIDES = {"unresolved", "unreachable", "gone", "refused", "bot_check", "blank"}

_REASON_IDS = {"hides_from_sandbox", "not_opened", "not_read", "not_finished"}  # the evidence ids _access can give

COULDNT_CHECK = "Couldn't get a proper look at this link. Don't enter anything until you verify it another way."
NO_RED_FLAGS = "No red flags found. That is not a guarantee."

_ASKS_FOR = {
    "password": "a password",
    "card": "card details",
    "ssn": "a Social Security number",
    "bank": "bank account details",
    "otp": "a one-time code",
    "pin": "a PIN",
    "seed": "a wallet recovery phrase",
}

_ACCESS = {  # kind -> (sentence, source)
    "not_public": ("Not a public web address, so it was not opened", "Address check"),
    "unresolved": ("The address does not resolve (DNS lookup)", "DNS lookup"),
    "unreachable": ("The page did not load (browser)", "Sandbox"),
    "gone": ("The page is gone ({detail})", "Sandbox"),
    "refused": ("The site refused the sandbox's phone browser ({detail})", "Sandbox"),
    "bot_check": ("The site showed a human-verification or access-denied page instead of its content ({detail})", "Sandbox"),
    "blank": ("The page opened but showed nothing (page scan)", "Sandbox page scan"),
    # Not held against the site (it may just be heavy), but never reported as a clean page either.
    "unreadable": ("Part of the page could not be read: {detail} (page scan)", "Sandbox page scan"),
    "unfinished": ("The page had not finished loading when its time was up, and {detail} (page scan)", "Sandbox page scan"),
}
_NOT_COUNTED = {"unreadable": "not_read", "unfinished": "not_finished"}  # shown, worth nothing


@dataclass(frozen=True)
class Judgement:
    verdict: str  # dangerous | suspicious | no_red_flags | couldnt_check
    score: int
    headline: str
    observations: list[str]  # the evidence sentences, most important first
    evidence: list[Evidence]
    points_table: list[PointsRule]


def _item(rule_id: str, label: str, source: str, points: int | None = None) -> Evidence:
    return Evidence(id=rule_id, label=label, points=WEIGHTS.get(rule_id, 0) if points is None else points, source=source)


def _names(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _or(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " or " + items[-1]


def _how_long(days: int) -> str:
    if days == 0:
        return "today"
    if days < 60:
        return f"{days} day{'' if days == 1 else 's'} ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


# --- one function per kind of finding ---------------------------------------------------------

def _access(access: dict | None) -> list[Evidence]:
    if not access:
        return []
    sentence, source = _ACCESS[access["kind"]]
    rule_id = _NOT_COUNTED.get(access["kind"]) or ("hides_from_sandbox" if access["kind"] in HIDES else "not_opened")
    return [_item(rule_id, defang_text(sentence.format(detail=access["detail"])), source)]  # a frame's host is a link


def _partial(scan) -> list[Evidence]:
    """A page still loading when its time was up, but seen well enough to judge: say it was partial."""
    if scan.access is not None or scan.opened.get("complete", True):
        return []
    return [_item("partial_page", "The page was slow to finish loading, so only part of it was checked (page scan)",
                  "Sandbox page scan", 0)]


def _warning(warning: str | None) -> list[Evidence]:
    if not warning:
        return []
    label = f"The hosting provider has already flagged this page as dangerous ({warning})"
    return [_item("platform_warning", label, "Host warning page")]


def _feeds(feeds: list[dict]) -> list[Evidence]:
    items, hit_sources, clear = [], [], []
    for entry in feeds:
        source, status = entry["source"], entry["status"]
        if status == "hit":
            if source in hit_sources:
                continue
            hit_sources.append(source)
            first = len(hit_sources) == 1  # the points count once however many feeds list the link
            items.append(_item(
                "known_threat_feed" if first else f"known_threat_feed:{source}",
                f"Listed as {entry['kind']} by {source}", source, WEIGHTS["known_threat_feed"] if first else 0,
            ))
        elif status == "not_checked":
            items.append(_item(f"feed_not_checked:{source}", f"{source} was not checked (no API key is set)", source))
        elif status == "error":
            items.append(_item(f"feed_error:{source}", f"{source} could not be checked right now", source))
        elif status == "clear":
            clear.append(source)
    if clear:
        ordered = [s for s in SOURCES if s in clear]
        items.append(_item("feeds_clear", f"Not listed by {_or(ordered)}", ", ".join(ordered)))
    return items


def _age(age: dict) -> list[Evidence]:
    days = age.get("age_days")
    if days is None:
        if age.get("error") == "free hosting platform":
            return [_item("domain_age", "On a free hosting platform, so the domain's age says nothing about this page", "Host list")]
        return [_item("domain_age", "Domain age could not be found (RDAP)", "RDAP")]
    label = f"Registered {_how_long(days)}, from RDAP"
    if days < 7:
        return [_item("domain_under_7_days", label, "RDAP")]
    if days < 30:
        return [_item("domain_under_30_days", label, "RDAP")]
    return [_item("domain_age", label, "RDAP")]


def _brands(findings: list[dict], official: bool) -> list[Evidence]:
    def named(kind: str, detail_ends: str | None = None) -> list[str]:
        return [f["brand"] for f in findings
                if f["type"] == kind and (detail_ends is None or f["detail"].endswith(detail_ends))]

    items = []
    if owners := named("official"):
        items.append(_item("official_domain", f"Registered domain is official for {_names(owners)} (brand list)", "Brand list", 0))
    if official:
        return items + _mentions(named("mention"))
    in_domain = named("impersonation", "in domain")
    if in_domain:  # a brand named in the path alone is handled by _path_evidence, once the rest is known
        items.append(_item("impersonation", f"Web address uses the name {_names(in_domain)} but is not an official site (brand list)", "Brand list"))
    lookalikes = [f for f in findings if f["type"] == "lookalike"]
    for i, finding in enumerate(lookalikes):
        label = f"Domain imitates {finding['brand']}: {defang_text(finding['detail'])} (look-alike check)"
        items.append(_item("lookalike" if i == 0 else f"lookalike:{finding['brand']}", label, "Look-alike check",
                           WEIGHTS["lookalike"] if i == 0 else 0))
    return items + _mentions(named("mention"))


# Signals that make a brand's name in the URL path worth points. A path on its own is weak: honest
# sites have /discover, /apple, /medicare, /facebook, and the name says nothing about who runs the
# site. Next to something that already points the same way it is evidence. Deliberately not here:
# hides_from_sandbox (refused alone is weak), a free host with nothing else, or a mention.
_CORROBORATES_PATH = frozenset({
    "known_threat_feed", "platform_warning", "lookalike", "sensitive_fields", "brand_with_sensitive_fields",
    "young_with_sensitive_fields", "free_host_credentials", "domain_under_7_days", "domain_under_30_days",
})


def _path_evidence(findings: list[dict], official: bool, so_far: list[Evidence]) -> list[Evidence]:
    """A brand named only in the URL path: 0 points alone, full points with a corroborating signal."""
    in_path = [f["brand"] for f in findings if f["type"] == "impersonation" and f["detail"].endswith("in path")]
    if official or not in_path:
        return []
    names = _names(list(dict.fromkeys(in_path)))
    if any(e.id == "impersonation" for e in so_far):  # already named in the domain: one finding, one set of points
        return [_item("impersonation_path", f"Web address path also names {names} (brand list)", "Brand list", 0)]
    if any(e.id in _CORROBORATES_PATH and e.points > 0 for e in so_far):
        return [_item("impersonation_path",
                      f"Web address path names {names}, but this is not an official site (brand list)", "Brand list")]
    return [_item("impersonation_path",
                  f"Web address path names {names}; not counted without a form, a young domain or another signal (brand list)",
                  "Brand list", 0)]


def _mentions(brands: list[str]) -> list[Evidence]:
    return [_item("brand_mention", f"Page text names {_names(brands)} (brand list)", "Brand list")] if brands else []


def _fields(fields: list[dict], brand_names: list[str], age_days: int | None, free_host: bool, official: bool) -> list[Evidence]:
    asked = [_ASKS_FOR[kind] for kind in kinds_asked_for(fields)]
    if not asked:
        return []
    label = f"Page asks for {_names(asked)} (page scan)"
    if official:  # a bank's own login page asks for a password: that is what it is for
        return [_item("sensitive_fields", label, "Sandbox page scan", 0)]
    items = [_item("sensitive_fields", label, "Sandbox page scan")]
    if brand_names:
        items.append(_item("brand_with_sensitive_fields",
                           f"Page names {_names(brand_names)} and asks for sensitive information (page text)", "Brand list, page scan"))
    if age_days is not None and age_days < 30:
        items.append(_item("young_with_sensitive_fields",
                           "Newly created website asks for sensitive information (RDAP, page scan)", "RDAP, page scan"))
    if free_host:
        items.append(_item("free_host_credentials",
                           "Page asks for sensitive information on a free hosting platform (host list, page scan)", "Host list, page scan"))
        if len(fields) >= MANY_FIELDS:
            items.append(_item("free_host_many_fields",
                               f"The form on that free host has {len(fields)} sensitive fields (page scan)", "Sandbox page scan"))
    return items


# --- putting it together ----------------------------------------------------------------------

def _uninspected(scan) -> bool:
    """True when we saw too little of the page to say anything reassuring about it.

    access.judge_access is the only judge of that. There is deliberately no second test here: a page
    could then be "couldn't check" with no evidence line saying why (it happened, on usps.com).
    """
    return scan.access is not None


def _order(item: Evidence) -> tuple[int, int]:
    """What adds risk first, biggest first; then discounts; then what merely informs. Stable inside a group."""
    if item.points > 0:
        return (0, -item.points)
    return (1, item.points) if item.points < 0 else (2, 0)


def _headline(verdict: str, evidence: list[Evidence]) -> str:
    if verdict == "couldnt_check":
        return COULDNT_CHECK
    if verdict == "no_red_flags":
        return NO_RED_FLAGS
    top = next((e.label for e in evidence if e.points > 0), "")
    return f"{'Dangerous' if verdict == 'dangerous' else 'Suspicious'}: {top}"


def judge(scan) -> Judgement:
    """scan is a pipeline.Scan: feeds, age, brand, popular, fields, warning, access, opened, final_url."""
    host = urlsplit(scan.final_url).hostname or ""
    official = any(f["type"] == "official" for f in scan.brand)
    listed = any(e["status"] == "hit" for e in scan.feeds)
    age_days = (scan.age or {}).get("age_days")
    named = [f["brand"] for f in scan.brand if f["type"] in ("impersonation", "mention")]

    items = (
        _access(scan.access)
        + _partial(scan)
        + _warning(scan.warning)
        + _feeds(scan.feeds)
        + _brands(scan.brand, official)
        + _fields(scan.fields, list(dict.fromkeys(named)), age_days, is_free_host(host), official)
        + _age(scan.age or {})
    )
    items += _path_evidence(scan.brand, official, items)  # needs the rest, to see what corroborates it
    # An official domain is discounted only when nothing serious points the other way.
    serious = listed or bool(scan.warning)
    items = [
        _item("official_domain", e.label, e.source, 0 if serious else WEIGHTS["official_domain"]) if e.id == "official_domain" else e
        for e in items
    ]
    if scan.popular and not serious:
        # Already discounted as official? Then this only informs. Never discounted next to an imitation.
        imitation = any(e.id.startswith(("impersonation", "lookalike")) and e.points > 0 for e in items)
        if not imitation:
            items.append(_item(
                "popular_domain", "Domain is one of the 10,000 most visited on the web (Tranco list)", "Tranco list",
                0 if official else WEIGHTS["popular_domain"],
            ))

    items.sort(key=_order)
    points = max(0, sum(e.points for e in items))
    uninspected = _uninspected(scan)
    if points >= DANGEROUS_AT:
        verdict = "dangerous"
    elif points >= SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "couldnt_check" if uninspected else "no_red_flags"
    if verdict == "couldnt_check":
        # Why we could not check is the point of the message: it leads, ahead of any discount, so a
        # phone reply (three bullets) and the report both open with it.
        items.sort(key=lambda e: e.id not in _REASON_IDS)

    return Judgement(
        verdict=verdict,
        score=points,
        headline=_headline(verdict, items),
        observations=[e.label for e in items],
        evidence=items,
        points_table=[PointsRule(id=i, label=label, points=p) for i, label, p in RULES],
    )
