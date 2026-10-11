"""The one place that talks to Gemini.

Gemini never decides a verdict or a point. It is asked for plain words (explain.py) and for the
links in a picture (vision.py), always for structured JSON, and everything it returns is checked by
the caller before it is used. Every failure (no key, an error, too slow, unreadable answer) comes
back as None, so a caller always has the plain fallback.
"""
import asyncio
import json
import logging
import os

import httpx

log = logging.getLogger("tripwire.gemini")

DEFAULT_MODEL = "gemini-2.5-flash"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout)


def api_key() -> str:
    return os.environ.get("GEMINI_API_KEY", "").strip()


def model_name() -> str:
    return os.environ.get("GEMINI_MODEL", "").strip() or DEFAULT_MODEL


def configured() -> bool:
    return bool(api_key())


async def generate_json(system: str, parts: list[dict], schema: dict, timeout_s: float) -> dict | None:
    """One structured answer, or None. `parts` are Gemini content parts (text or inline_data).

    The system instruction is ours; `parts` carry the untrusted material and are only ever data.
    The key goes in a header and is never logged; a failure logs its kind and HTTP status only.
    """
    key = api_key()
    if not key:
        return None
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024,
            "responseMimeType": "application/json",
            "responseSchema": schema,
        },
    }
    try:
        async with _client(timeout_s) as client:
            response = await asyncio.wait_for(
                client.post(ENDPOINT.format(model=model_name()), json=body, headers={"x-goog-api-key": key}),
                timeout=timeout_s,
            )
        if response.status_code != 200:
            log.warning("gemini answered HTTP %s", response.status_code)
            return None
        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        answer = json.loads(text)
        return answer if isinstance(answer, dict) else None
    except Exception as exc:  # slow, offline, blocked, or a shape we do not know: fall back
        log.warning("gemini unavailable: %s", type(exc).__name__)
        return None
