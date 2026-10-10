"""The result of one scan, as every consumer sees it (gateway, report page, card, dashboard).

This is the shared contract. The web side has the same shape in web/src/contract.ts, and both are
checked against the one example in web/src/sample/report.sample.json. Change it deliberately: edit
this file, the TypeScript file and the sample together, and tell whoever builds the other lanes.

Every URL in it is already defanged. `verdict` is decided by the points table, never by an LLM.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict

# "unscored" exists only until the scoring step lands: the page was opened, nothing was judged.
Verdict = Literal["dangerous", "suspicious", "no_red_flags", "couldnt_check", "unscored"]


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
    score: int | None  # None while verdict is "unscored"
    headline: str
    observations: list[str]  # the plain-English lines under the headline; consumers show up to three
    evidence: list[Evidence]
    points_table: list[PointsRule]
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
