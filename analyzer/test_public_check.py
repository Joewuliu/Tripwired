import pytest

import main
from public_check import RateLimiter, normalize
from test_main import client, fake_world  # noqa: F401  (fixtures and the fake page world)


@pytest.mark.parametrize(
    ("typed", "scanned"),
    [
        ("https://example.com/login", "https://example.com/login"),
        ("  http://example.com  ", "http://example.com"),
        ("example.com/login?x=1", "https://example.com/login?x=1"),
        ("HTTPS://Example.com", "HTTPS://Example.com"),
        ("example.com:8443/a", "https://example.com:8443/a"),
    ],
)
def test_a_web_address_is_accepted_and_given_a_scheme(typed, scanned):
    assert normalize(typed) == scanned


@pytest.mark.parametrize(
    "typed",
    [
        "", "   ", "hello", "two words.com", "javascript:alert(1)", "mailto:a@b.com", "file:///etc/passwd",
        "ftp://example.com/x", "data:text/html,hi", "http://", "https://nodots", "see https://a.com and more",
    ],
)
def test_anything_else_is_refused_before_the_sandbox(typed):
    assert normalize(typed) is None


def test_the_limiter_counts_each_visitor_and_everyone_and_recovers():
    limiter = RateLimiter(per_visitor=2, overall=3, window_s=100)
    assert limiter.take("a", now=0) is None
    assert limiter.take("a", now=1) is None
    assert limiter.take("a", now=2) == pytest.approx(98)  # a's third check waits for the first to age out
    assert limiter.take("b", now=3) is None  # a different visitor is not held up by a
    assert limiter.take("c", now=4) == pytest.approx(96)  # the overall budget of 3 is spent
    assert limiter.take("a", now=101) is None  # a's first check has aged out of the window


def test_the_route_returns_only_the_report_id_and_the_report_is_stored(client, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    body = client.post("/api/check", json={"url": "short.example/x"}).json()
    assert list(body) == ["id"]
    stored = client.get(f"/api/report/{body['id']}")
    assert stored.status_code == 200 and stored.json()["url_defanged"] == "hxxps://short[.]example/x"


def test_the_route_refuses_what_is_not_a_web_address_without_scanning(client, monkeypatch):  # noqa: F811
    async def never(*args, **kwargs):
        raise AssertionError("the sandbox must not be reached")

    monkeypatch.setattr(main, "scan", never)
    for bad in ["javascript:alert(1)", "not a link", "file:///etc/passwd"]:
        assert client.post("/api/check", json={"url": bad}).status_code == 422


def test_the_route_is_rate_limited_per_visitor_with_retry_after(client, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    monkeypatch.setattr(main, "_public_limit", RateLimiter(per_visitor=1, overall=10))
    mine = {"X-Forwarded-For": "203.0.113.7"}
    assert client.post("/api/check", json={"url": "short.example"}, headers=mine).status_code == 200
    again = client.post("/api/check", json={"url": "short.example"}, headers=mine)
    assert again.status_code == 429 and int(again.headers["retry-after"]) > 0
    other = {"X-Forwarded-For": "198.51.100.9"}
    assert client.post("/api/check", json={"url": "short.example"}, headers=other).status_code == 200


def test_a_visitor_cannot_choose_their_own_bucket_with_a_spoofed_header(client, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    monkeypatch.setattr(main, "_public_limit", RateLimiter(per_visitor=1, overall=10))
    # Caddy appends the address it saw as the last entry; anything before it is the visitor's own.
    first = {"X-Forwarded-For": "1.1.1.1, 203.0.113.7"}
    second = {"X-Forwarded-For": "2.2.2.2, 203.0.113.7"}
    assert client.post("/api/check", json={"url": "short.example"}, headers=first).status_code == 200
    assert client.post("/api/check", json={"url": "short.example"}, headers=second).status_code == 429
