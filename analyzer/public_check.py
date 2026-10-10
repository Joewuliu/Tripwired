"""The narrow public route behind the report site's paste-a-link box.

`POST /analyze` is never public. This is a separate door that takes one address as text, makes it a
web address or refuses it, and is rate-limited per visitor and overall. The per-sender limit proper
(by phone number) is its own step; this one only keeps the box from being used as a free scanner.
"""
import time
from collections import deque

PER_VISITOR = 10  # checks per window from one address
OVERALL = 60  # checks per window from everyone using the box
WINDOW_S = 3600.0
MAX_VISITORS = 5000  # bound on remembered visitors; the oldest are dropped first

ALLOWED = ("http://", "https://")


def normalize(text: str) -> str | None:
    """The address to scan, or None when the text is not one web address.

    "example.com/login" becomes "https://example.com/login". Other schemes (javascript:, file:,
    ftp:) and anything with whitespace in it are refused here, before the sandbox sees them.
    """
    candidate = text.strip()
    if not candidate or any(ch.isspace() for ch in candidate):
        return None
    lowered = candidate.lower()
    if "://" not in lowered:
        first = lowered.split("/", 1)[0]
        if ":" in first and not first.rsplit(":", 1)[1].isdigit():
            return None  # "javascript:alert(1)", "mailto:x@y": a scheme, not a host and port
        candidate = "https://" + candidate
    elif not lowered.startswith(ALLOWED):
        return None
    host = candidate.split("://", 1)[1].split("/", 1)[0]
    return candidate if "." in host else None


class RateLimiter:
    """Sliding window, in memory. Good enough for one process on one VM."""

    def __init__(self, per_visitor: int = PER_VISITOR, overall: int = OVERALL, window_s: float = WINDOW_S):
        self.per_visitor = per_visitor
        self.overall = overall
        self.window_s = window_s
        self._visitors: dict[str, deque[float]] = {}
        self._all: deque[float] = deque()

    def _trim(self, hits: deque[float], now: float) -> None:
        while hits and now - hits[0] >= self.window_s:
            hits.popleft()

    def take(self, visitor: str, now: float | None = None) -> float | None:
        """Count one check. None means allowed; otherwise the seconds until it would be."""
        now = time.monotonic() if now is None else now
        self._trim(self._all, now)
        hits = self._visitors.setdefault(visitor, deque())
        self._trim(hits, now)
        if len(hits) >= self.per_visitor:
            return max(1.0, self.window_s - (now - hits[0]))
        if len(self._all) >= self.overall:
            return max(1.0, self.window_s - (now - self._all[0]))
        hits.append(now)
        self._all.append(now)
        self._forget_idle(now)
        return None

    def _forget_idle(self, now: float) -> None:
        if len(self._visitors) <= MAX_VISITORS:
            return
        for key in [k for k, hits in self._visitors.items() if not hits or now - hits[-1] >= self.window_s]:
            del self._visitors[key]
        while len(self._visitors) > MAX_VISITORS:  # still full of active visitors: drop the oldest
            del self._visitors[next(iter(self._visitors))]
