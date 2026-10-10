import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from contract import AnalysisResult

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "web" / "src" / "sample" / "report.sample.json"


@pytest.fixture
def sample() -> dict:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_the_shared_sample_is_a_valid_result(sample):
    AnalysisResult.model_validate(sample)


def test_the_sample_has_every_field_and_nothing_else(sample):
    """Round trip: no field is missing from the sample, and none is unknown to the contract."""
    assert AnalysisResult.model_validate(sample).model_dump(mode="json") == sample


def test_the_sample_follows_the_house_rules(sample):
    assert sample["verdict"] != "safe"
    blob = json.dumps(sample)
    assert "http://" not in blob and "https://" not in blob, "URLs in a result are defanged"


def test_unknown_verdicts_and_fields_are_rejected(sample):
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({**sample, "verdict": "safe"})
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({**sample, "surprise": 1})
