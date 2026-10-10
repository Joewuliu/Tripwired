"""Finished scans, kept as one JSON file each so a report link keeps working after the reply is sent.

A report is the same AnalysisResult the scan returned: defanged addresses, the evidence, the points
table. It holds nothing about who asked. Files are written whole or not at all, so a reader never
sees half of one.
"""
import logging
import os
import re
import secrets
from pathlib import Path

from pydantic import ValidationError

from contract import AnalysisResult

log = logging.getLogger("tripwire.reports")

REPORT_ID = re.compile(r"[a-f0-9]{12}")


def is_report_id(value: str) -> bool:
    return REPORT_ID.fullmatch(value) is not None


def save_report(directory: Path, result: AnalysisResult) -> None:
    """Write the report to <directory>/<id>.json atomically. Raises OSError if the disk refuses."""
    if not is_report_id(result.id):
        raise ValueError("not a report id")
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / f"{result.id}.json"
    temp = directory / f".{result.id}.{secrets.token_hex(4)}.tmp"
    try:
        temp.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temp, final)  # atomic on the same filesystem
    finally:
        temp.unlink(missing_ok=True)


def load_report(directory: Path, report_id: str) -> AnalysisResult | None:
    """The stored report, or None if there is none, the id is malformed, or the file is unusable.

    The id is checked before it goes near a path, so nothing outside the directory can be read.
    """
    if not is_report_id(report_id):
        return None
    path = directory / f"{report_id}.json"
    try:
        return AnalysisResult.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValidationError, ValueError) as exc:
        log.warning("report %s is unusable: %s", report_id, type(exc).__name__)
        return None
