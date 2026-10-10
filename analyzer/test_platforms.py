import pytest

from enrich import rdap_domain, registered_domain
from platforms import POPULAR_DOMAINS, is_free_host, is_popular, is_shared_host


def test_the_popular_list_is_the_top_ten_thousand():
    assert len(POPULAR_DOMAINS) == 10_000
    assert {"google.com", "wikipedia.org"} <= POPULAR_DOMAINS
    assert all(d == d.lower() and not d.startswith("#") for d in POPULAR_DOMAINS)


@pytest.mark.parametrize("host", ["www.google.com", "login.microsoftonline.com", "en.wikipedia.org"])
def test_popular_domains(host):
    assert is_popular(host, registered_domain(host))


@pytest.mark.parametrize("host", ["some-small-shop.top", "paypa1.com", "evil.github.io", "github.io", "evil.netlify.app"])
def test_unpopular_and_platform_hosted_pages_are_not_popular(host):
    """A platform may be in the top ten thousand; its users' pages are not."""
    assert not is_popular(host, registered_domain(host))


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


@pytest.mark.parametrize("host", ["paypal-login.my.id", "tokoku.web.id", "shop.biz.id"])
def test_a_cheap_registry_namespace_is_a_registered_domain_not_free_hosting(host):
    """my.id is a public suffix in the ICANN list (like co.uk): each name under it is somebody's own
    registered domain, with its own RDAP record and age. It must not be treated as a hosting platform."""
    assert not is_free_host(host)
    assert registered_domain(host) == host
    assert rdap_domain(host) == host  # RDAP is asked about the name itself, so its age can be found


@pytest.mark.parametrize(
    "host", ["example.com", "secure-chase.top", "google.com", "netlify.app.evil.top", "notgithub.io", "mail.google.com"]
)
def test_ordinary_hosts_are_neither(host):
    assert not is_free_host(host)
    assert not is_shared_host(host)
