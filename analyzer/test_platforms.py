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


@pytest.mark.parametrize("host", [
    # reported from the VM check: reported square.site's own 7-year age for one person's page
    "visit-ledgr-helps.square.site", "square.site",
    # site builders, app hosts, tunnels and storage that were missing
    "shop.myshopify.com", "someone.squarespace.com", "blog.wordpress.com", "evil.wpcomstaging.com", "x.jimdosite.com",
    "trezorio-xearn.gitbook.io", "evil.azurewebsites.net", "app.railway.app", "x.deno.dev", "abc.ngrok-free.app",
    "abc.trycloudflare.com", "bucket.blob.core.windows.net", "site.web.core.windows.net", "x.digitaloceanspaces.com",
    "contoso.sharepoint.com", "free.infinityfreeapp.com",
    # already covered, kept here so they stay covered
    "x.backblazeb2.com", "x.wixsite.com", "x.weebly.com", "x.webflow.io",
])
def test_site_builders_app_hosts_and_storage_are_free_hosting(host):
    assert is_free_host(host)
    assert not is_popular(host, registered_domain(host))  # the platform is popular; its users' pages are not


@pytest.mark.parametrize("host", ["linktr.ee", "bio.link", "beacons.ai", "forms.office.com", "form.jotform.com", "1drv.ms"])
def test_one_host_many_pages_is_a_shared_host(host):
    assert is_shared_host(host) and is_free_host(host)


def test_no_platform_is_also_a_brands_official_domain():
    """An official brand domain that is also a place anyone can publish would whitelist scams."""
    import json
    from pathlib import Path

    from platforms import FREE_HOSTING_PLATFORMS, SHARED_HOSTS

    brands = json.loads((Path(__file__).parent / "data" / "brands.json").read_text(encoding="utf-8"))
    official = {d for b in brands for d in b["official_domains"]}
    assert not official & (FREE_HOSTING_PLATFORMS | SHARED_HOSTS)


def test_the_platform_lists_are_clean():
    from platforms import FREE_HOSTING_PLATFORMS, SHARED_HOSTS

    for entry in FREE_HOSTING_PLATFORMS | SHARED_HOSTS:
        assert entry == entry.lower().strip() and not entry.startswith(".") and "/" not in entry and " " not in entry, entry
        assert "." in entry, entry


@pytest.mark.parametrize("host", ["s.amazon-adsystem.com", "4468676.fls.doubleclick.net", "citi.demdex.net",
                                  "apps.use2.us-gov-pure.cloud", "www.googletagmanager.com", "cdn.cookielaw.org"])
def test_advertising_analytics_consent_and_chat_hosts_are_not_form_hosts(host):
    from platforms import is_non_form_frame_host

    assert is_non_form_frame_host(host)


@pytest.mark.parametrize("host", ["login.evil.example", "doubleclick.net.attacker.top", "notdoubleclick.net",
                                  "form.jotform.com", "contoso.sharepoint.com", "someone.netlify.app", "docs.google.com"])
def test_nothing_that_can_hold_a_form_is_listed_as_a_non_form_host(host):
    from platforms import is_non_form_frame_host

    assert not is_non_form_frame_host(host)


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
