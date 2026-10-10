"""Hosts where anyone can publish a page, and the most visited domains on the web.

A threat-feed listing for one page on such a host says nothing about the rest of the host, so
feeds.py matches these by exact URL only. brands.py uses the same lists: a shared host is never an
official site, and a popular domain is not treated as imitating a brand.
"""
from pathlib import Path

# Hostnames that serve anyone's content, or redirect anyone's links, but are not in the public
# suffix list: docs.google.com would otherwise count as google.com.
SHARED_HOSTS = frozenset({
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "storage.googleapis.com",
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "rb.gy", "cutt.ly", "lnkd.in",
    # link-in-bio pages, shared files and form builders: one host, many people's pages (by path)
    "linktr.ee", "bio.link", "beacons.ai", "forms.office.com", "onedrive.live.com", "1drv.ms", "page.link",
    "form.jotform.com",
})

# Free hosting, site builders and storage endpoints: a hostname equal to one of these, or under one,
# is somebody's own page on a platform.
#
# Not for cheap registry namespaces such as my.id, web.id or biz.id (Indonesia): those are public
# suffixes in the ICANN list, so name.my.id is a domain somebody registered. It has its own RDAP
# record, and its age is exactly the evidence wanted for a throwaway domain; listing it here would
# throw that away and score it as a page on someone else's platform.
FREE_HOSTING_PLATFORMS = frozenset({
    # Cloudflare
    "pages.dev", "workers.dev", "r2.dev",
    # app and site hosts
    "vercel.app", "netlify.app", "webflow.io", "framer.website", "framer.app", "godaddysites.com",
    "replit.app", "replit.dev", "repl.co", "wasmer.app", "github.io", "gitlab.io", "firebaseapp.com",
    "web.app", "appspot.com", "herokuapp.com", "onrender.com", "fly.dev", "surge.sh", "glitch.me",
    "azurestaticapps.net", "bubbleapps.io",
    # site builders
    "weebly.com", "wixsite.com", "000webhostapp.com", "blogspot.com", "notion.site", "carrd.co",
    "tiiny.site", "mystrikingly.com", "canva.site",
    "square.site", "squarespace.com", "myshopify.com", "wixstudio.io", "editorx.io", "wordpress.com",
    "wpcomstaging.com", "site123.me", "jimdosite.com", "jimdofree.com", "weeblysite.com", "webnode.page",
    "webnode.com", "strikingly.com", "gitbook.io",
    # app hosts, free web hosting and tunnels
    "azurewebsites.net", "railway.app", "deno.dev", "pythonanywhere.com", "infinityfreeapp.com", "epizy.com",
    "ngrok-free.app", "ngrok.app", "ngrok.io", "trycloudflare.com", "loca.lt",
    # storage, CDN and file-sharing endpoints
    "backblazeb2.com", "storage.googleapis.com", "googleusercontent.com", "dropboxusercontent.com",
    "cloudfront.net", "amazonaws.com", "ipfs.io", "dweb.link",
    "blob.core.windows.net", "web.core.windows.net", "digitaloceanspaces.com", "firebasestorage.googleapis.com",
    "sharepoint.com",
})


# Advertising, analytics, consent and chat-widget infrastructure. A visible embedded frame from one of
# these that is still loading when a page is read is not counted as "could not read": they are the
# slow frames on nearly every large commercial site, and none of them is where a site puts its own
# login or payment form. Kept short and to vendors that serve widgets, never user content: a form
# builder, a file host or a site builder does not belong here. Matched on the host and its subdomains.
NON_FORM_FRAME_HOSTS = frozenset({
    # advertising and measurement
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagmanager.com",
    "google-analytics.com", "adsrvr.org", "amazon-adsystem.com", "criteo.com", "criteo.net", "taboola.com",
    "outbrain.com", "scorecardresearch.com", "quantserve.com", "everesttech.net", "demdex.net", "omtrdc.net",
    "adobedtm.com", "tiqcdn.com", "tealiumiq.com", "hotjar.com", "clarity.ms", "fullstory.com", "newrelic.com",
    # consent banners
    "onetrust.com", "cookielaw.org", "trustarc.com", "consensu.org",
    # chat widgets
    "pure.cloud", "us-gov-pure.cloud", "mypurecloud.com", "genesys.com", "intercom.io", "intercomcdn.com", "drift.com", "driftt.com", "livechatinc.com",
    "zdassets.com", "salesforceliveagent.com", "my.salesforce-sites.com",
})

POPULAR_DOMAINS_PATH = Path(__file__).resolve().parent / "data" / "popular_domains.txt"


def load_popular_domains(path: Path = POPULAR_DOMAINS_PATH) -> frozenset[str]:
    """One registered domain per line; '#' lines are comments."""
    lines = (line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))


POPULAR_DOMAINS = load_popular_domains()


def _clean(hostname: str) -> str:
    return hostname.lower().rstrip(".")


def is_shared_host(hostname: str) -> bool:
    return _clean(hostname) in SHARED_HOSTS


def is_free_host(hostname: str) -> bool:
    """True for a shared host, or a hostname that is (or sits under) a free hosting platform."""
    host = _clean(hostname)
    if host in SHARED_HOSTS:
        return True
    labels = host.split(".")
    return any(".".join(labels[i:]) in FREE_HOSTING_PLATFORMS for i in range(len(labels)))


def is_non_form_frame_host(hostname: str) -> bool:
    """True for a host (or a subdomain of one) in NON_FORM_FRAME_HOSTS: ad, analytics, consent or chat."""
    labels = _clean(hostname).split(".")
    return any(".".join(labels[i:]) in NON_FORM_FRAME_HOSTS for i in range(len(labels)))


def is_popular(hostname: str, registered: str) -> bool:
    """A top-10,000 domain, unless the host is somebody's page on a platform: the platform is
    popular, its users are not."""
    return registered.lower() in POPULAR_DOMAINS and not is_free_host(hostname)
