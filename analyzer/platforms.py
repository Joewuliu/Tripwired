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
})

# Free hosting, site builders and storage endpoints: a hostname equal to one of these, or under one,
# is somebody's own page on a platform.
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
    # storage, CDN and file-sharing endpoints
    "backblazeb2.com", "storage.googleapis.com", "googleusercontent.com", "dropboxusercontent.com",
    "cloudfront.net", "amazonaws.com", "ipfs.io", "dweb.link",
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


def is_popular(hostname: str, registered: str) -> bool:
    """A top-10,000 domain, unless the host is somebody's page on a platform: the platform is
    popular, its users are not."""
    return registered.lower() in POPULAR_DOMAINS and not is_free_host(hostname)
