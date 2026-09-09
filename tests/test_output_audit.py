import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from shared_lib.formatter import MitreValidator
from shared_lib.schemas import DataSchema, TaskType

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"
OUTPUT_FILES = ["all_records.jsonl", "all_rich_records.jsonl"]

SUSPICIOUS_PHRASES = {
    "machine learning-based": 10,
    "dynamic analysis": 10,
    "fake TLS header": 10,
    "hardcoded key": 15,
    "hard-coded key": 15,
}

VALID_SCHEMA_TYPES = {item.value for item in DataSchema}
VALID_TASK_TYPES = {item.value for item in TaskType}


def _load_jsonl(path: Path) -> list[dict]:
    lines = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                lines.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"Invalid JSON in {path.name} line {i}: {exc}") from exc
    return lines


def _find_invalid_mitre_ids(record: dict, validator: MitreValidator) -> list[str]:
    invalid_ids = []
    if isinstance(record.get("mitre_ids"), list):
        _, invalid = validator.filter_ids([str(mid) for mid in record["mitre_ids"]])
        invalid_ids.extend(invalid)

    output = str(record.get("output", ""))
    found = re.findall(r"T\d{4}(?:\.\d{3})?", output)
    for mid in found:
        ok, _ = validator.validate_id(mid)
        if not ok:
            invalid_ids.append(mid)

    return sorted(set(invalid_ids))


def _count_suspicious_phrases(text: str) -> dict[str, int]:
    normalized = text.lower()
    return {phrase: normalized.count(phrase.lower()) for phrase in SUSPICIOUS_PHRASES}


def test_output_files_exist():
    for filename in OUTPUT_FILES:
        path = OUTPUT_DIR / filename
        if not path.exists():
            pytest.skip(f"Output file {filename} does not exist yet. Skipping output audit tests.")


def test_output_jsonl_validity():
    for filename in OUTPUT_FILES:
        path = OUTPUT_DIR / filename
        if not path.exists():
            pytest.skip(f"Output file {filename} does not exist yet.")
        records = _load_jsonl(path)
        assert records, f"No JSON lines loaded from {filename}"


def test_output_record_structure():
    validator = MitreValidator()
    for filename in OUTPUT_FILES:
        path = OUTPUT_DIR / filename
        if not path.exists():
            pytest.skip(f"Output file {filename} does not exist yet.")
        records = _load_jsonl(path)
        for idx, record in enumerate(records, 1):
            assert "schema_type" in record, f"Missing schema_type in {filename} line {idx}"
            assert record["schema_type"] in VALID_SCHEMA_TYPES, (
                f"Invalid schema_type {record['schema_type']} in {filename} line {idx}"
            )
            assert "task_type" in record, f"Missing task_type in {filename} line {idx}"
            assert record["task_type"] in VALID_TASK_TYPES, (
                f"Invalid task_type {record['task_type']} in {filename} line {idx}"
            )
            assert record.get("source_file"), f"Missing source_file in {filename} line {idx}"
            assert record.get("quality_score") is not None or record.get("quality") is not None, (
                f"Missing quality_score or quality in {filename} line {idx}"
            )
            assert record.get("quality_score", record.get("quality", 0.0)) >= 0.0
            assert record.get("quality_score", record.get("quality", 0.0)) <= 1.0
            invalid_mitre = _find_invalid_mitre_ids(record, validator)
            assert not invalid_mitre, (
                f"Invalid MITRE IDs in {filename} line {idx}: {invalid_mitre}"
            )


def test_output_file_counts():
    path_all = OUTPUT_DIR / "all_records.jsonl"
    path_rich = OUTPUT_DIR / "all_rich_records.jsonl"
    if not path_all.exists() or not path_rich.exists():
        pytest.skip("Output files do not exist yet.")
    all_records = _load_jsonl(path_all)
    all_rich_records = _load_jsonl(path_rich)
    assert len(all_records) >= len(all_rich_records), (
        "Expected all_records.jsonl to contain at least as many entries as all_rich_records.jsonl"
    )


def test_output_hallucination_risk_phrases():
    for filename in OUTPUT_FILES:
        path = OUTPUT_DIR / filename
        if not path.exists():
            pytest.skip(f"Output file {filename} does not exist yet.")
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        counts = _count_suspicious_phrases(raw_text)
        for phrase, threshold in SUSPICIOUS_PHRASES.items():
            assert counts[phrase] <= threshold, (
                f"Suspicious phrase '{phrase}' appears {counts[phrase]} times in {filename}, above threshold {threshold}"
            )
