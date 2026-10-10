import socket

import pytest

from netguard import NOT_PUBLIC, NOT_WEB, UNRESOLVED, is_public, refusal_reason


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://localhost:8001/analyze",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://100.64.0.1",  # carrier-grade NAT
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",  # IPv4 loopback wrapped in IPv6
        "http://[fd00::1]/",
        "http://2130706433/",  # 127.0.0.1 written as one number
        "file:///etc/passwd",
        "ftp://example.com/file",
        "javascript:alert(1)",
        "data:text/html,hi",
        "http://",
        "not a url",
        "http://[::1",  # malformed
    ],
)
def test_non_public_or_unusable_urls_are_refused(url):
    assert is_public(url) is False


def test_public_ip_literal_is_allowed():
    assert is_public("https://93.184.216.34/") is True


def test_name_resolving_to_a_public_address_is_allowed(monkeypatch):
    answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answer)
    assert is_public("https://example.test/") is True


def test_name_resolving_to_a_public_and_a_private_address_is_refused(monkeypatch):
    answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answer)
    assert is_public("https://rebind.test/") is False


def test_name_that_does_not_resolve_is_refused(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert is_public("https://nowhere.test/") is False
    assert refusal_reason("https://nowhere.test/") == UNRESOLVED


@pytest.mark.parametrize("url,reason", [
    ("https://93.184.216.34/", None),
    ("http://127.0.0.1/", NOT_PUBLIC),
    ("http://169.254.169.254/latest/meta-data/", NOT_PUBLIC),
    ("http://[::ffff:10.0.0.1]/", NOT_PUBLIC),
    ("file:///etc/passwd", NOT_WEB),
    ("javascript:alert(1)", NOT_WEB),
    ("http://", NOT_WEB),
    ("http://[::1", NOT_WEB),
])
def test_the_reason_for_a_refusal_is_told_apart(url, reason):
    assert refusal_reason(url) == reason


def test_a_mixed_public_and_private_answer_is_not_public(monkeypatch):
    answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.9", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answer)
    assert refusal_reason("https://rebind.test/") == NOT_PUBLIC
