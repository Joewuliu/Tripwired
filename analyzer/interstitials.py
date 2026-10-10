"""Warning pages that a hosting provider, CDN or browser vendor shows INSTEAD of a site it has flagged.

A page like that is evidence from the page itself, not from a threat feed. Each pattern needs the
distinctive heading and its follow-up sentence together (or the vendor's own page title), so an
article that merely quotes one sentence does not match. Matched case-insensitively against the
page title plus text, with whitespace collapsed.

The wording comes from public descriptions of these pages (vendor support articles and community
reports). None was reproduced here by opening a flagged page, so treat the list as a start:
  Cloudflare           the "Suspected Phishing" and "Suspected Malware" interstitials
  Microsoft SmartScreen "This site has been reported as unsafe"
  Chrome Safe Browsing "Deceptive site ahead". Chrome draws it as browser chrome, not page content,
                       so the sandbox will rarely see it; kept for completeness.
Not covered, for lack of reliable wording: Vercel, Netlify, GitHub Pages, Wix, Weebly, Google Sites.
"""
import re

PLATFORM_WARNING_PATTERNS = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in (
    ("Cloudflare phishing warning",
     r"suspected phishing site \| cloudflare"
     r"|suspected phishing\W{0,12}this website has been reported for potential phishing"),
    ("Cloudflare malware warning",
     r"suspected malware site \| cloudflare"
     r"|suspected malware\W{0,12}this website has been reported for potentially distributing malware"),
    ("Microsoft SmartScreen",
     r"this site has been reported as unsafe.{0,160}reported to microsoft for containing phishing"),
    ("Chrome Safe Browsing",
     r"deceptive site ahead.{0,60}attackers on .{0,80}may trick you into doing something dangerous"),
)]


def find_platform_warning(title: str | None, text: str | None) -> str | None:
    """The name of the warning page this is ("Cloudflare phishing warning"), or None."""
    haystack = re.sub(r"\s+", " ", f"{title or ''} {text or ''}").replace("’", "'").strip()
    for label, pattern in PLATFORM_WARNING_PATTERNS:
        if pattern.search(haystack):
            return label
    return None
