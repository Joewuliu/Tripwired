import pytest

from platforms import is_free_host, is_shared_host


@pytest.mark.parametrize(
    "host", ["docs.google.com", "DOCS.GOOGLE.COM", "docs.google.com.", "bit.ly", "forms.gle", "storage.googleapis.com"]
)
def test_shared_hosts(host):
    assert is_shared_host(host) and is_free_host(host)


@pytest.mark.parametrize(
    "host", ["evil.netlify.app", "a.b.pages.dev", "someone.github.io", "bucket.s3.amazonaws.com", "github.io"]
)
def test_free_hosting_platforms_and_their_subdomains(host):
    assert is_free_host(host)
    assert not is_shared_host(host)


@pytest.mark.parametrize(
    "host", ["example.com", "secure-chase.top", "google.com", "netlify.app.evil.top", "notgithub.io", "mail.google.com"]
)
def test_ordinary_hosts_are_neither(host):
    assert not is_free_host(host)
    assert not is_shared_host(host)
