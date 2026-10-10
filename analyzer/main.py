import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, StringConstraints

from brands import BRANDS
from contract import AnalysisResult, BrandMatch, Hop
from defang import defang, defang_text
from env import load_root_env
from pipeline import scan
from public_check import RateLimiter, normalize
from reports import load_report, save_report
from score import judge

load_root_env()  # API keys for the threat feeds live in the repo-root .env

log = logging.getLogger("tripwire.main")

PORT = 8001
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SCAN_ID = re.compile(r"[a-f0-9]{12}")

app = FastAPI(title="Tripwire analyzer")
_public_limit = RateLimiter()


def _reports_dir() -> Path:
    return DATA_DIR / "reports"


class AnalyzeRequest(BaseModel):
    urls: list[Annotated[str, StringConstraints(min_length=1, max_length=2048)]] = Field(min_length=1)


def _brand_match(brand_findings: list[dict]) -> BrandMatch | None:
    """The brand a page imitates, for the fake-versus-real comparison (screenshots come later)."""
    imitated = next((f for f in brand_findings if f["type"] in ("impersonation", "lookalike")), None)
    if not imitated:
        return None
    official = next((b["official_domains"][0] for b in BRANDS if b["brand"] == imitated["brand"]), "")
    return BrandMatch(
        brand=imitated["brand"], official_domain_defanged=defang(official), real_screenshot_url=None, similarity=None
    )


async def _scan_and_store(url: str) -> AnalysisResult:
    scan_id = secrets.token_hex(6)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    result = await scan(url, DATA_DIR / f"{scan_id}.png")
    opened = result.opened
    judgement = judge(result)
    analysis = AnalysisResult(
        id=scan_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        verdict=judgement.verdict,
        score=judgement.score,
        headline=judgement.headline,
        observations=judgement.observations,
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
    return analysis


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest) -> AnalysisResult:
    return await _scan_and_store(request.urls[0])


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
