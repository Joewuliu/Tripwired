import json

import pytest

from contract import AnalysisResult
from reports import is_report_id, load_report, save_report

SAMPLE = {
    "id": "5a3c0de1f2b4", "created_at": "2026-10-10T17:42:00Z", "verdict": "dangerous", "score": 90,
    "headline": "Dangerous: Listed as phishing by OpenPhish", "observations": ["Listed as phishing by OpenPhish"],
    "evidence": [{"id": "known_threat_feed", "label": "Listed as phishing by OpenPhish", "points": 60, "source": "OpenPhish"}],
    "points_table": [{"id": "known_threat_feed", "label": "Listed as malicious by a threat feed", "points": 60}],
    "brand_match": None, "url_defanged": "hxxps://evil[.]example/x", "final_url_defanged": "hxxps://evil[.]example/x",
    "redirects_defanged": [{"status": 200, "url": "hxxps://evil[.]example/x"}], "title": "Sign in",
    "loaded": True, "complete": True, "final_status": 200, "blocked_requests": 0, "screenshot_url": "/shots/5a3c0de1f2b4.png",
}


def result(**overrides) -> AnalysisResult:
    return AnalysisResult.model_validate({**SAMPLE, **overrides})


def test_a_saved_report_comes_back_exactly(tmp_path):
    save_report(tmp_path, result())
    assert load_report(tmp_path, "5a3c0de1f2b4") == result()


def test_the_directory_is_created_on_demand(tmp_path):
    save_report(tmp_path / "data" / "reports", result())
    assert (tmp_path / "data" / "reports" / "5a3c0de1f2b4.json").is_file()


def test_saving_leaves_no_temporary_files(tmp_path):
    for i in range(3):
        save_report(tmp_path, result(id=f"{i:012x}"))
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"{i:012x}.json" for i in range(3)]


def test_a_failed_write_leaves_neither_a_report_nor_a_temporary_file(tmp_path, monkeypatch):
    def refuse(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(type(tmp_path), "write_text", refuse)
    with pytest.raises(OSError):
        save_report(tmp_path, result())
    assert list(tmp_path.iterdir()) == []


def test_saving_the_same_id_again_replaces_it(tmp_path):
    save_report(tmp_path, result(headline="first"))
    save_report(tmp_path, result(headline="second"))
    assert load_report(tmp_path, "5a3c0de1f2b4").headline == "second"


@pytest.mark.parametrize("report_id", ["", "abc", "5A3C0DE1F2B4", "5a3c0de1f2b4a", "../secret", "..%2Fsecret",
                                       "5a3c0de1f2b4/../x", "5a3c0de1f2b4.json", "zzzzzzzzzzzz"])
def test_a_malformed_id_is_never_looked_up(tmp_path, report_id):
    (tmp_path / "secret.json").write_text(json.dumps(SAMPLE))
    assert is_report_id(report_id) is False
    assert load_report(tmp_path, report_id) is None


def test_an_id_that_would_escape_the_directory_reads_nothing(tmp_path):
    inner = tmp_path / "reports"
    inner.mkdir()
    (tmp_path / "5a3c0de1f2b4.json").write_text(json.dumps(SAMPLE))  # one level up
    assert load_report(inner, "../5a3c0de1f2b4") is None


def test_an_unknown_report_is_none(tmp_path):
    assert load_report(tmp_path, "000000000000") is None


@pytest.mark.parametrize("content", ["", "not json", "[]", "{}", json.dumps({**SAMPLE, "verdict": "safe"}),
                                     json.dumps({**SAMPLE, "extra": 1})])
def test_a_corrupt_or_outdated_file_is_none_not_an_error(tmp_path, content):
    (tmp_path / "5a3c0de1f2b4.json").write_text(content, encoding="utf-8")
    assert load_report(tmp_path, "5a3c0de1f2b4") is None


def test_a_report_with_a_bad_id_is_not_written(tmp_path):
    with pytest.raises(ValueError):
        save_report(tmp_path, result(id="../../etc/x"))
    assert list(tmp_path.iterdir()) == []


def test_nothing_about_who_asked_is_kept(tmp_path):
    save_report(tmp_path, result())
    text = (tmp_path / "5a3c0de1f2b4.json").read_text(encoding="utf-8")
    assert set(json.loads(text)) == set(SAMPLE)  # exactly the contract, no sender, no raw url, no page text
