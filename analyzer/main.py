import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, StringConstraints

from contract import AnalysisResult, Hop
from defang import defang, defang_text
from env import load_root_env
from observations import describe
from pipeline import scan

load_root_env()  # API keys for the threat feeds live in the repo-root .env

PORT = 8001
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SCAN_ID = re.compile(r"[a-f0-9]{12}")

app = FastAPI(title="Tripwire analyzer")


class AnalyzeRequest(BaseModel):
    urls: list[Annotated[str, StringConstraints(min_length=1, max_length=2048)]] = Field(min_length=1)


def _summary(opened: dict) -> tuple[str, str, list[str]]:
    """(verdict, headline, observations). Placeholder until scoring exists: nothing is judged yet."""
    if not opened["loaded"]:  # why it did not load is said by the access line in observations.describe
        return "couldnt_check", "Couldn't open this link safely. Don't enter anything until you verify it another way.", []
    seen = [f"Opened in the sandbox and ended on {defang(opened['final_url'] or '')}"]
    if not opened["complete"]:
        seen.append("The page was slow to finish loading, so only part of it was captured")
    return "unscored", "Opened in the sandbox. No verdict yet: scoring is not wired up.", seen


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest) -> AnalysisResult:
    url = request.urls[0]
    scan_id = secrets.token_hex(6)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    result = await scan(url, DATA_DIR / f"{scan_id}.png")
    opened = result.opened
    verdict, headline, observations = _summary(opened)
    return AnalysisResult(
        id=scan_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        verdict=verdict,
        score=None,
        headline=headline,
        observations=observations + describe(result),
        evidence=[],  # filled in by the scoring step
        points_table=[],
        brand_match=None,
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
