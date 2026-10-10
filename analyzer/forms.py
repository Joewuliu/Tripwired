"""Which of a page's form fields ask for something sensitive.

The sandbox reads each visible input's attributes and label (never its value, and it never types).
This module decides what a field is asking for from those words alone.
"""
import re

# Read-only: reports attributes of visible inputs in one frame and touches nothing.
READ_FIELDS_JS = """() => [...document.querySelectorAll('input, textarea, select')]
    .filter(el => {
        if (el.type === 'hidden') return false;
        const box = el.getBoundingClientRect(), style = getComputedStyle(el);
        return box.width > 0 && box.height > 0 && style.visibility !== 'hidden'
            && style.display !== 'none' && style.opacity !== '0';
    })
    .slice(0, 100)
    .map(el => ({
        type: el.type || '',
        name: el.name || '',
        id: el.id || '',
        placeholder: el.placeholder || '',
        autocomplete: el.getAttribute('autocomplete') || '',
        ariaLabel: el.getAttribute('aria-label') || '',
        label: (el.labels && el.labels[0] ? el.labels[0].innerText : '').slice(0, 80),
    }))"""

KINDS = ("password", "card", "ssn", "bank", "otp", "pin")  # also the order they are reported in

_NOT_TYPED_INTO = {"radio", "checkbox", "submit", "button", "reset", "image", "file", "range", "color"}

_AUTOCOMPLETE = {
    "current-password": "password", "new-password": "password",
    "cc-number": "card", "cc-csc": "card", "cc-exp": "card", "cc-exp-month": "card", "cc-exp-year": "card",
    "one-time-code": "otp",
}

# Matched against name, id, placeholder, aria-label and label text, after lowercasing, splitting
# camelCase and turning _ and - into spaces. Short tokens need word boundaries ("classname" has
# "ssn", "spinner" has "pin"). First match wins, so the more specific kinds come first.
_PATTERNS = [(kind, re.compile(pattern)) for kind, pattern in (
    ("card", r"card ?(number|no\b|num)|\bcc ?(number|num)|credit card|debit card|\bcvv\d?\b|\bcvc\d?\b"
             r"|security code|expir(y|ation)|\bexp ?(date|month|year)"),
    ("ssn", r"\bssn\b|social security"),
    ("bank", r"routing ?(number|no\b|num)|account ?(number|no\b|num)|\biban\b|sort code"),
    ("otp", r"\botp\b|one ?time ?(code|pass|pin)|verification code|auth(entication)? code|\b2fa\b|sms code"),
    ("pin", r"\bpin\b(?! ?code)"),
    ("password", r"pass ?word|passcode|passwd|\bpwd\b"),
)]


def _normalize(text: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.sub(r"[_\-]+", " ", text).lower()


def classify(field: dict) -> str | None:
    """What a field asks for ("password", "card", ...), or None for an ordinary field."""
    if field.get("type", "").lower() in _NOT_TYPED_INTO:
        return None  # a "One time / Monthly" radio button is not a one-time code
    for token in field.get("autocomplete", "").lower().split():
        if token in _AUTOCOMPLETE:
            return _AUTOCOMPLETE[token]
    if field.get("type") == "password":
        return "password"
    words = _normalize(" ".join(field.get(key, "") for key in ("name", "id", "placeholder", "ariaLabel", "label")))
    return next((kind for kind, pattern in _PATTERNS if pattern.search(words)), None)


def sensitive_fields(fields: list[dict]) -> list[dict]:
    """The sensitive ones, as {"kind", "type", "name", "id"}: identifiers only, no page text."""
    found = []
    for field in fields:
        kind = classify(field)
        if kind:
            found.append({"kind": kind, "type": field.get("type", ""), "name": field.get("name", ""), "id": field.get("id", "")})
    return found


def kinds_asked_for(found: list[dict]) -> list[str]:
    """The distinct kinds, in a fixed order: ["password", "card"]."""
    present = {f["kind"] for f in found}
    return [kind for kind in KINDS if kind in present]
