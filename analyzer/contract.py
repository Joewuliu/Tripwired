"""The result of one scan, as every consumer sees it (gateway, report page, card, dashboard).

This is the shared contract. The web side has the same shape in web/src/contract.ts, and both are
checked against the one example in web/src/sample/report.sample.json. Change it deliberately: edit
this file, the TypeScript file and the sample together, and tell whoever builds the other lanes.

Every URL in it is already defanged. `verdict` is decided by the points table, never by an LLM.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict

# There is no "safe": the clean verdict is "no red flags found". "couldnt_check" is for a page the
# sandbox could not inspect (it refused us, showed a human-check wall, was blank, gone, or did not load).
Verdict = Literal["dangerous", "suspicious", "no_red_flags", "couldnt_check"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Model):
    """One finding that moved (or deliberately did not move) the score."""

    id: str  # stable signal name, e.g. "domain_under_7_days"
    label: str  # the plain-English sentence shown to people
    points: int  # signed; 0 for something worth showing that adds nothing
    source: str  # where it came from: "RDAP", "Google Safe Browsing", "Sandbox page scan"


class PointsRule(_Model):
    """One row of the points table in use, so the report can show how the verdict is reached."""

    id: str
    label: str
    points: int


class Hop(_Model):
    status: int
    url: str  # defanged


class BrandMatch(_Model):
    """The brand a page imitates, for the fake-versus-real comparison."""

    brand: str
    official_domain_defanged: str
    real_screenshot_url: str | None  # a screenshot of the brand's real page, when we have one
    similarity: float | None  # 0..1, shown on the report; worth no points unless the evaluation says so


class AnalysisResult(_Model):
    id: str  # 12 hex characters; also the screenshot file name
    created_at: str  # ISO 8601, UTC
    verdict: Verdict
    score: int  # the points the evidence adds up to, never below 0
    headline: str
    observations: list[str]  # plain lines saying why, most important first; consumers show up to three
    explained_by: Literal["template", "gemini"] = "template"  # who wrote headline and observations; never the verdict
    evidence: list[Evidence]  # every finding with its points and source, in the same order
    points_table: list[PointsRule]  # the whole table in use, so a report can show how the verdict is reached
    brand_match: BrandMatch | None
    url_defanged: str  # what was asked for
    final_url_defanged: str | None  # where the browser ended up
    redirects_defanged: list[Hop]
    title: str | None
    loaded: bool  # some document arrived
    complete: bool  # ...and finished loading
    final_status: int | None
    blocked_requests: int  # requests the sandbox refused (private addresses and the like)
    screenshot_url: str | None  # path on the analyzer, e.g. /shots/<id>.png
