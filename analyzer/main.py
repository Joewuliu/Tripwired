import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, StringConstraints

from brands import BRANDS
from contract import AnalysisResult, BrandMatch, Hop
from defang import defang, defang_text
from env import load_root_env
from events import Sender, bus, sender_from
from explain import explain
from pipeline import scan
from public_check import RateLimiter, normalize
from reports import load_report, save_report
from score import judge
from vision import MAX_BYTES, decode, read_links

load_root_env()  # API keys for the threat feeds live in the repo-root .env

log = logging.getLogger("tripwire.main")

PORT = 8001
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SCAN_ID = re.compile(r"[a-f0-9]{12}")

app = FastAPI(title="Tripwire analyzer")
_public_limit = RateLimiter()


def _reports_dir() -> Path:
    return DATA_DIR / "reports"


class SenderRef(BaseModel):
    """Who asked, as the gateway keeps it: a salted hash and the last four digits. Used only to label
    live events with a mask; it is never written to a report."""

    hash: str = Field(pattern=r"^[0-9a-f]{16}$")
    last4: str | None = Field(default=None, pattern=r"^[0-9]{4}$")


class AnalyzeRequest(BaseModel):
    urls: list[Annotated[str, StringConstraints(min_length=1, max_length=2048)]] = Field(min_length=1)
    sender: SenderRef | None = None


def _brand_match(brand_findings: list[dict]) -> BrandMatch | None:
    """The brand a page imitates, for the fake-versus-real comparison (screenshots come later)."""
    imitated = next((f for f in brand_findings if f["type"] in ("impersonation", "lookalike")), None)
    if not imitated:
        return None
    official = next((b["official_domains"][0] for b in BRANDS if b["brand"] == imitated["brand"]), "")
    return BrandMatch(
        brand=imitated["brand"], official_domain_defanged=defang(official), real_screenshot_url=None, similarity=None
    )


async def _wording(judgement) -> tuple[str, list[str], str]:
    """The headline and lines to show. Gemini may reword them; it cannot touch the verdict, the score
    or the evidence, and anything it gets wrong leaves the template wording as it was."""
    explained = await explain(judgement.verdict, judgement.evidence)
    if explained is None:
        return judgement.headline, judgement.observations, "template"
    if judgement.verdict in ("dangerous", "suspicious"):
        label = "Dangerous" if judgement.verdict == "dangerous" else "Suspicious"
        return f"{label}: {explained.headline}", explained.lines, "gemini"
    # The fixed headline of the clean and couldn't-check verdicts stays ours. A couldn't-check always
    # leads with its reason, as the scorer ordered it.
    lines = explained.lines
    if judgement.verdict == "couldnt_check" and judgement.evidence:
        reason = judgement.evidence[0].label
        lines = [reason, *[line for line in lines if line != reason][:2]]
    return judgement.headline, lines, "gemini"


async def _scan_and_store(url: str, sender: Sender | None = None, source: str = "web") -> AnalysisResult:
    scan_id = secrets.token_hex(6)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    def emit(kind: str, data: dict) -> None:
        bus.publish(scan_id, kind, data, sender)

    emit("scan_started", {"url": defang(url), "source": source})
    try:
        result = await scan(url, DATA_DIR / f"{scan_id}.png", emit)
        opened = result.opened
        judgement = judge(result)
        headline, observations, explained_by = await _wording(judgement)
    except BaseException:
        emit("scan_failed", {"detail": "The scan did not finish"})
        raise
    analysis = AnalysisResult(
        id=scan_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        verdict=judgement.verdict,
        score=judgement.score,
        headline=headline,
        observations=observations,
        explained_by=explained_by,
        evidence=judgement.evidence,
        points_table=judgement.points_table,
        brand_match=_brand_match(result.brand),
        url_defanged=defang(url),
        final_url_defanged=defang(opened["final_url"]) if opened["final_url"] else None,
        redirects_defanged=[Hop(status=hop["status"], url=defang(hop["url"])) for hop in opened["redirects"]],
        title=defang_text(opened["title"]) if opened["title"] else None,
        loaded=opened["loaded"],
        complete=opened["complete"],
        final_status=opened["final_status"],
        blocked_requests=opened["blocked_requests"],
        screenshot_url=f"/shots/{scan_id}.png" if opened["has_screenshot"] else None,
    )
    try:
        save_report(_reports_dir(), analysis)
    except Exception as exc:  # a full disk must cost the report link, not the verdict
        log.error("report %s was not saved: %s", scan_id, type(exc).__name__)
    emit("verdict", {
        "verdict": analysis.verdict, "score": analysis.score, "headline": defang_text(analysis.headline),
        "explained_by": analysis.explained_by, "report_path": f"/r/{scan_id}",
    })
    return analysis


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest) -> AnalysisResult:
    sender = sender_from(request.sender.model_dump()) if request.sender else None
    return await _scan_and_store(request.urls[0], sender, "imessage")


class CheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class CheckResponse(BaseModel):
    id: str


def _visitor(request: Request) -> str:
    """Who is asking. Caddy is the only way in and sets X-Forwarded-For; its last entry is the one
    Caddy itself saw, so a visitor cannot pick their own bucket by sending the header."""
    forwarded = request.headers.get("x-forwarded-for", "")
    last = forwarded.split(",")[-1].strip()
    return last or (request.client.host if request.client else "unknown")


@app.post("/api/check", response_model=CheckResponse)
async def check(body: CheckRequest, request: Request) -> CheckResponse:
    """The public paste-a-link route: one address in, the report id out (the page then opens
    /r/<id>). Narrow on purpose: it returns nothing but the id and is rate-limited."""
    url = normalize(body.url)
    if url is None:
        raise HTTPException(status_code=422, detail="not a web address")
    wait = _public_limit.take(_visitor(request))
    if wait is not None:
        raise HTTPException(status_code=429, headers={"Retry-After": str(int(wait) + 1)})
    result = await _scan_and_store(url)
    return CheckResponse(id=result.id)


class ReadImageRequest(BaseModel):
    mime_type: str = Field(max_length=64)
    data_base64: str = Field(max_length=(MAX_BYTES * 4) // 3 + 16)


class ReadImageResponse(BaseModel):
    status: Literal["ok", "unavailable"]  # "unavailable": no key, an error, or too slow
    urls: list[str]  # addresses found, as the picture shows them; the gateway then asks /analyze


@app.post("/read-image", response_model=ReadImageResponse)
async def read_image(request: ReadImageRequest) -> ReadImageResponse:
    """Internal: the gateway reaches it over the private network and Caddy answers 404. Finds the link
    in a screenshot or a QR photo. It decides nothing: the link is scanned like any other."""
    data = decode(request.data_base64)
    if data is None:
        raise HTTPException(status_code=422, detail="not base64")
    reading = await read_links(data, request.mime_type)
    return ReadImageResponse(status=reading.status, urls=reading.urls)


class ReplySent(BaseModel):
    scan: str = Field(pattern=r"^[a-f0-9]{12}$")
    sender: SenderRef | None = None


@app.post("/internal/reply-sent", status_code=204)
async def reply_sent(body: ReplySent) -> None:
    """Internal (private network only; Caddy answers 404): the gateway says the reply went out."""
    sender = sender_from(body.sender.model_dump()) if body.sender else None
    bus.publish(body.scan, "reply_sent", {"delivered": True}, sender)


class GuardianAlerted(BaseModel):
    scan: str = Field(pattern=r"^[a-f0-9]{12}$")
    guardian: SenderRef
    sender: SenderRef | None = None


@app.post("/internal/guardian-alerted", status_code=204)
async def guardian_alerted(body: GuardianAlerted) -> None:
    """Internal (private network only; Caddy answers 404): family mode told a guardian about this
    scan's Dangerous verdict. The stream shows the guardian as a mask, like every sender."""
    sender = sender_from(body.sender.model_dump()) if body.sender else None
    guardian = sender_from(body.guardian.model_dump())
    if guardian is not None:
        bus.publish(body.scan, "guardian_alerted", {"guardian": guardian.mask}, sender)


def _last_event_id(request: Request) -> int | None:
    raw = request.headers.get("last-event-id") or request.query_params.get("since") or ""
    return int(raw) if raw.isdigit() else None


@app.get("/events")
async def events(request: Request) -> StreamingResponse:
    """Server-Sent Events: one event per step of every scan, defanged and with masked senders.
    Read-only. A new connection gets the recent events first; reconnecting with Last-Event-ID (the
    browser does this by itself) or ?since=<id> gets what was missed."""
    if not bus.has_room():
        raise HTTPException(status_code=503, detail="too many viewers")
    stream = bus.stream(_last_event_id(request), request.is_disconnected)
    headers = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
    return StreamingResponse(stream, media_type="text/event-stream", headers=headers)


@app.get("/api/report/{report_id}", response_model=AnalysisResult)
async def report(report_id: str) -> AnalysisResult:
    stored = load_report(_reports_dir(), report_id)
    if stored is None:
        raise HTTPException(status_code=404)
    return stored


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.get("/shots/{scan_id}.png")
async def shot(scan_id: str) -> FileResponse:
    path = DATA_DIR / f"{scan_id}.png"
    if not SCAN_ID.fullmatch(scan_id) or not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type="image/png")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=PORT)
