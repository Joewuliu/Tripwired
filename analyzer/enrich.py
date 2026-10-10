"""Facts about a domain that come from outside the page: its registered name and its age."""
from datetime import datetime, timezone

import httpx
import tldextract

RDAP_URL = "https://rdap.org/domain/{}"
RDAP_TIMEOUT_S = 5.0

# The suffix list is bundled: no network fetch, the same answer every run.
# With private domains on, evil.github.io is its own registered domain instead of sharing github.io.
_with_platforms = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
# RDAP only knows ICANN-level domains: evil.github.io has no record, github.io does.
_icann_only = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(hostname: str) -> str:
    """login.secure-chase.top -> secure-chase.top; evil.github.io -> evil.github.io; "" if none."""
    return _with_platforms(hostname).top_domain_under_public_suffix


def rdap_domain(hostname: str) -> str:
    """The domain RDAP has a record for: evil.github.io -> github.io; "" if none."""
    return _icann_only(hostname).top_domain_under_public_suffix


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=RDAP_TIMEOUT_S, follow_redirects=True)


def _registration_date(rdap: dict) -> str | None:
    for event in rdap.get("events", []):
        if event.get("eventAction") == "registration":
            return event.get("eventDate")
    return None


def _age_in_days(iso_date: str) -> int:
    registered = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
    if registered.tzinfo is None:
        registered = registered.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - registered).days)


async def domain_age(hostname: str) -> dict:
    """How old the domain is, from RDAP. Never raises: a failure is reported in "error".

    Returns {"domain", "registered", "age_days", "source", "error"}; age_days is None when unknown.
    """
    name = rdap_domain(hostname)
    result = {"domain": name or hostname, "registered": None, "age_days": None, "source": "RDAP", "error": None}
    if not name:
        result["error"] = "no registered domain"
        return result
    try:
        async with _client() as client:
            response = await client.get(RDAP_URL.format(name))
            response.raise_for_status()
        registered = _registration_date(response.json())
        if registered is None:
            result["error"] = "no registration date in the record"
            return result
        result["registered"] = registered
        result["age_days"] = _age_in_days(registered)
    except Exception as exc:  # only the class name is kept: messages can carry addresses
        result["error"] = type(exc).__name__
    return result
