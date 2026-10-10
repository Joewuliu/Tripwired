import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from contract import AnalysisResult
from score import judge

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "web" / "src" / "sample" / "report.sample.json"

# The scan the example report describes: a two-day-old toll-payment lookalike that asks for a card.
GOLDEN_SCAN = SimpleNamespace(
    final_url="https://ezpass-toll-pay.example/pay",
    feeds=[{"source": s, "status": "clear"} for s in ("Google Safe Browsing", "URLhaus", "OpenPhish")],
    age={"domain": "ezpass-toll-pay.example", "registered": None, "age_days": 2, "source": "RDAP", "error": None},
    brand=[{"type": "impersonation", "brand": "E-ZPass", "detail": '"ezpass" in domain'}],
    popular=False,
    fields=[{"kind": "card", "type": "text", "name": "card_number", "id": ""},
            {"kind": "card", "type": "text", "name": "cvv", "id": ""}],
    warning=None,
    access=None,
    opened={"loaded": True, "complete": True, "has_screenshot": True, "text": "Unpaid toll balance"},
)


@pytest.fixture
def sample() -> dict:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_the_shared_sample_is_a_valid_result(sample):
    AnalysisResult.model_validate(sample)


def test_the_sample_has_every_field_and_nothing_else(sample):
    """Round trip: no field is missing from the sample, and none is unknown to the contract."""
    assert AnalysisResult.model_validate(sample).model_dump(mode="json") == sample


def test_the_sample_is_what_the_scorer_really_says_about_its_scenario(sample):
    """The example report cannot drift from the rules: change a weight and this fails until the
    sample is regenerated."""
    result = judge(GOLDEN_SCAN)
    assert sample["verdict"] == result.verdict == "dangerous"
    assert sample["score"] == result.score
    assert sample["headline"] == result.headline
    assert sample["observations"] == result.observations
    assert sample["evidence"] == [e.model_dump() for e in result.evidence]
    assert sample["points_table"] == [r.model_dump() for r in result.points_table]
    assert sample["score"] == sum(e["points"] for e in sample["evidence"])


def test_the_sample_follows_the_house_rules(sample):
    blob = json.dumps(sample)
    assert "http://" not in blob and "https://" not in blob, "URLs in a result are defanged"
    assert "safe" not in blob.lower().replace("google safe browsing", "")


def test_unknown_verdicts_and_fields_are_rejected(sample):
    for bad in ("safe", "unscored"):
        with pytest.raises(ValidationError):
            AnalysisResult.model_validate({**sample, "verdict": bad})
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({**sample, "surprise": 1})
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({**sample, "score": None})
