"""Did the sandbox actually get to see the page?

judge_access returns None when the page opened normally, otherwise {"kind", "detail"}:

  not_public   we refused to open it: not a public http(s) address (says nothing about the site)
  unresolved   the name does not resolve
  unreachable  no page arrived for another reason (refused, timed out, blocked redirect)
  gone         the server says the page is gone (404, 410)
  refused      the server refused the sandbox's phone browser (401, 403, 429, 451, 503)
  bot_check    a "verify you are human" or access-denied page instead of the content
  unreadable   the page, or a frame in it, was too slow to read: whatever it asks for we did not see
  unfinished   the page was still loading when its time was up, and too little of it was seen
  blank        the page finished loading and showed nothing at all (only claimed when it was read)

Every one of these ends as "couldn't check" when nothing else scores 30, and every one carries a
sentence saying why: score.py gives the verdict no other way to be uninspected.

A page that hides from automated visitors, or vanishes soon after it is sent, is mild evidence on
its own. More importantly, in every one of these cases we did not see the real page, so a later
step must never report "no red flags" on the strength of it.
"""
import re

from netguard import UNRESOLVED

_CONNECTION_DROPPED = ("ERR_HTTP2_PROTOCOL_ERROR", "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_EMPTY_RESPONSE")
GONE_STATUSES = {404, 410}
REFUSED_STATUSES = {401, 403, 429, 451, 503}
SHORT_PAGE_CHARS = 700  # a wall of this kind is a short page; a long article that quotes one is not

_BOT_CHECKS = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in (
    ("Cloudflare challenge", r"just a moment\.\.\.|checking your browser before accessing"
                             r"|verifying you are human|needs to review the security of your connection"),
    ("Cloudflare block", r"attention required! \| cloudflare|sorry, you have been blocked"),
    ("access denied", r"access denied.{0,80}you don't have permission to access"),
    ("human check", r"verify (that )?you are (a )?human|i'm not a robot|press (&|and) hold to confirm"
                    r"|complete the security check|are you a robot"),
)]


def _bot_check(title: str, text: str) -> str | None:
    if len(text) > SHORT_PAGE_CHARS:
        return None
    haystack = re.sub(r"\s+", " ", f"{title} {text}").replace("’", "'")
    return next((label for label, pattern in _BOT_CHECKS if pattern.search(haystack)), None)


def judge_access(opened: dict) -> dict | None:
    """opened is sandbox.open_page's result."""
    error = opened.get("error") or ""
    status = opened.get("final_status")
    if not opened.get("loaded"):
        if "ERR_NAME_NOT_RESOLVED" in error or (error.startswith("blocked:") and UNRESOLVED in error):
            return {"kind": "unresolved", "detail": UNRESOLVED}
        if error.startswith("blocked:"):  # our own refusal: a private address or a non-web scheme
            return {"kind": "not_public", "detail": "not a public web address"}
        if any(code in error for code in _CONNECTION_DROPPED):
            # The server answered by cutting the connection: what sites with bot protection do to a
            # browser they take for automated (pnc.com, usaa.com). It is there; it would not talk to us.
            return {"kind": "refused", "detail": "it dropped the connection"}
        return {"kind": "unreachable", "detail": "no page arrived"}
    if status in GONE_STATUSES:
        return {"kind": "gone", "detail": f"HTTP {status}"}

    title, text = opened.get("title") or "", opened.get("text") or ""
    wall = _bot_check(title, text)
    if wall:
        return {"kind": "bot_check", "detail": wall}
    if status in REFUSED_STATUSES:
        return {"kind": "refused", "detail": f"HTTP {status}"}
    unread = _unread(opened.get("read_errors") or [])
    if unread:
        return {"kind": "unreadable", "detail": unread}
    if not opened.get("complete", True):
        # The page was still arriving when its time was up. What was seen is partial: a form further
        # down the document may not have been parsed. With a screenshot and some text it is judged as
        # seen; without either, there is too little to say anything about it.
        if not text.strip():
            return {"kind": "unfinished", "detail": "no text had arrived"}
        if not opened.get("has_screenshot", True):
            return {"kind": "unfinished", "detail": "no screenshot could be taken"}
        return None
    if not text.strip() and not title.strip():
        return {"kind": "blank", "detail": "nothing was shown"}
    return None


def _unread(read_errors: list[dict]) -> str | None:
    """A read that failed is not an empty page: say what we could not read, or None if all that
    matters was read. A missing screenshot or title costs the user a picture, not the verdict."""
    page_failed = {e["what"] for e in read_errors if e.get("frame") is None}
    if page_failed & {"text", "fields"}:
        return "the page was too busy or slow to be read"
    in_frames = [e["frame"] for e in read_errors if e.get("frame") is not None]
    if not in_frames:
        return None
    hosts = list(dict.fromkeys(host for host in in_frames if host))  # "" is a frame with no address yet
    if hosts:
        return f"an embedded frame from {', '.join(hosts[:3])} was too slow to read"
    return "an embedded frame that had not finished loading was too slow to read"
