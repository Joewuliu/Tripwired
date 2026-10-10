"""Hosts where anyone can publish a page.

A threat-feed listing for one page on such a host says nothing about the rest of the host, so
feeds.py matches these by exact URL only. (Later steps also use these lists for the brand check.)
"""

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
