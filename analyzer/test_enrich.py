from datetime import datetime, timedelta, timezone

import httpx
import pytest

import enrich
from enrich import domain_age, rdap_domain, registered_domain


@pytest.mark.parametrize(
    "host, registered, rdap",
    [
        ("login.secure-chase.top", "secure-chase.top", "secure-chase.top"),
        ("foo.co.uk", "foo.co.uk", "foo.co.uk"),
        ("evil.github.io", "evil.github.io", "github.io"),  # someone's own site on a platform
        ("a.b.pages.dev", "b.pages.dev", "pages.dev"),
        ("docs.google.com", "google.com", "google.com"),
        ("93.184.216.34", "", ""),
        ("localhost", "", ""),
    ],
)
def test_registered_domains(host, registered, rdap):
    assert registered_domain(host) == registered
    assert rdap_domain(host) == rdap


def rdap_client(monkeypatch, handler):
    seen = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return handler(request)

    monkeypatch.setattr(
        enrich, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True)
    )
    return seen


def record(days_ago: int) -> dict:
    when = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=1)
    return {"events": [{"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": when.strftime("%Y-%m-%dT%H:%M:%SZ")}]}


@pytest.mark.asyncio
async def test_age_comes_from_the_registration_event(monkeypatch):
    seen = rdap_client(monkeypatch, lambda request: httpx.Response(200, json=record(3)))
    result = await domain_age("login.secure-chase.top")
    assert result["age_days"] == 3
    assert result["domain"] == "secure-chase.top"
    assert result["source"] == "RDAP" and result["error"] is None
    assert seen == ["https://rdap.org/domain/secure-chase.top"]


@pytest.mark.asyncio
async def test_a_date_without_a_timezone_is_read_as_utc(monkeypatch):
    when = (datetime.now(timezone.utc) - timedelta(days=10, hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
    rdap_client(monkeypatch, lambda request: httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": when}]}))
    assert (await domain_age("example.top"))["age_days"] == 10


@pytest.mark.asyncio
async def test_redirects_to_the_registry_are_followed(monkeypatch):
    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(302, headers={"location": "https://registry.example/rdap/domain/example.top"})
        return httpx.Response(200, json=record(400))

    rdap_client(monkeypatch, handler)
    assert (await domain_age("example.top"))["age_days"] == 400


@pytest.mark.asyncio
async def test_no_registration_event_is_reported_not_raised(monkeypatch):
    rdap_client(monkeypatch, lambda request: httpx.Response(200, json={"events": []}))
    result = await domain_age("example.top")
    assert result["age_days"] is None and result["error"]


@pytest.mark.asyncio
async def test_a_missing_record_is_reported(monkeypatch):
    rdap_client(monkeypatch, lambda request: httpx.Response(404))
    result = await domain_age("nothing-here.top")
    assert result["age_days"] is None and result["error"] == "HTTPStatusError"


@pytest.mark.asyncio
async def test_a_network_failure_is_reported_without_the_message(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("could not reach https://rdap.org/secret-path")

    rdap_client(monkeypatch, handler)
    result = await domain_age("example.top")
    assert result["error"] == "ConnectError"
    assert "secret-path" not in str(result)


@pytest.mark.asyncio
async def test_an_ip_address_has_no_domain_to_look_up():
    result = await domain_age("93.184.216.34")  # the network is blocked in tests: any request would fail the check below
    assert result["error"] == "no registered domain"
    assert result["age_days"] is None
