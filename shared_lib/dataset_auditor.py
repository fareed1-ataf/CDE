# shared_lib/dataset_auditor.py  — Cyber Data Engine v1.0.0
# =============================================================================
# DATASET AUDITOR — Training Data Quality Inspector
#
# Scans generated JSONL files and produces a comprehensive quality report:
#   - Schema distribution (what types of records were generated)
#   - Average quality per schema
#   - Hallucination warning count (MITRE stripped, IOC stripped, grounding fail)
#   - Records below minimum quality threshold
#   - Duplicate detection between records
#   - Output length distribution
#   - Schema fallback rate (how often alpaca fallback was triggered)
#
# Usage:
#   from shared_lib.dataset_auditor import DatasetAuditor
#   auditor = DatasetAuditor()
#   report  = auditor.audit_file("output/results.jsonl")
#   print(report.summary())
# =============================================================================

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("CDE.DatasetAuditor")


# ─────────────────────────────────────────────────────────────────────────────
# Report dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditReport:
    filepath:            str
    total_records:       int = 0
    schema_distribution: dict = field(default_factory=dict)   # schema → count
    quality_by_schema:   dict = field(default_factory=dict)   # schema → avg_quality
    fallback_rate:       float = 0.0     # % records that fell back to alpaca
    hallucination_warnings: int = 0      # records with stripped MITRE/IOC
    low_quality_records: int = 0         # records with quality < threshold
    duplicate_pairs:     int = 0         # identical or near-identical records
    empty_output_records: int = 0        # records with empty output field
    schema_fallback_count: int = 0       # records with schema_fallback marker
    avg_output_length:   float = 0.0     # average output character length
    quality_histogram:   dict = field(default_factory=dict)   # bucket → count
    errors:              list = field(default_factory=list)

    MIN_QUALITY_THRESHOLD: float = 0.35

    def summary(self) -> str:
        """Return a formatted text summary of the audit."""
        lines = [
            f"\n{'='*60}",
            f"📊 DATASET AUDIT REPORT",
            f"   File: {self.filepath}",
            f"{'='*60}",
            f"  Total Records:       {self.total_records}",
            f"  Avg Output Length:   {self.avg_output_length:.0f} chars",
            f"  Fallback Rate:       {self.fallback_rate:.1%}",
            f"  Hallucination Warn:  {self.hallucination_warnings}",
            f"  Low Quality (<0.35): {self.low_quality_records}",
            f"  Empty Outputs:       {self.empty_output_records}",
            f"  Near-Duplicates:     {self.duplicate_pairs}",
            f"",
            f"{'─'*60}",
            f"  Schema Distribution:",
        ]
        for schema, count in sorted(self.schema_distribution.items(), key=lambda x: -x[1]):
            avg_q = self.quality_by_schema.get(schema, 0.0)
            lines.append(f"    {schema:<30} {count:>4} records  avg_q={avg_q:.2f}")

        lines.append(f"")
        lines.append(f"{'─'*60}")
        lines.append(f"  Quality Histogram:")
        for bucket, count in sorted(self.quality_histogram.items()):
            bar = "█" * min(count, 30)
            lines.append(f"    {bucket}  {bar} {count}")

        if self.errors:
            lines.append(f"")
            lines.append(f"{'─'*60}")
            lines.append(f"  Parse Errors: {len(self.errors)}")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return report as JSON-serializable dict for API response."""
        return {
            "filepath":              self.filepath,
            "total_records":         self.total_records,
            "avg_output_length":     round(self.avg_output_length, 1),
            "fallback_rate":         round(self.fallback_rate, 4),
            "hallucination_warnings": self.hallucination_warnings,
            "low_quality_records":   self.low_quality_records,
            "empty_output_records":  self.empty_output_records,
            "duplicate_pairs":       self.duplicate_pairs,
            "schema_distribution":   self.schema_distribution,
            "quality_by_schema":     {k: round(v, 3) for k, v in self.quality_by_schema.items()},
            "quality_histogram":     self.quality_histogram,
            "error_count":           len(self.errors),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Auditor
# ─────────────────────────────────────────────────────────────────────────────

class DatasetAuditor:
    """
    Scans generated JSONL dataset files and produces quality reports.

    Supports both Alpaca-format and Rich-schema JSONL files.
    """

    # Quality histogram buckets
    QUALITY_BUCKETS = [
        (0.00, 0.35, "0.00-0.35 [REJECTED ]"),
        (0.35, 0.50, "0.35-0.50 [LOW      ]"),
        (0.50, 0.65, "0.50-0.65 [FAIR     ]"),
        (0.65, 0.80, "0.65-0.80 [GOOD     ]"),
        (0.80, 1.01, "0.80-1.00 [EXCELLENT]"),
    ]

    # Keys to check for non-empty output
    OUTPUT_KEYS = ["output", "response", "answer", "reasoning", "summary", "code"]

    def audit_file(self, filepath: str) -> AuditReport:
        """
        Audit a single JSONL file and return an AuditReport.

        Args:
            filepath: Path to the JSONL file to audit
        """
        path = Path(filepath)
        report = AuditReport(filepath=str(path))

        if not path.exists():
            report.errors.append(f"File not found: {filepath}")
            return report

        schema_counts:   Counter     = Counter()
        quality_sums:    defaultdict = defaultdict(float)
        quality_counts:  defaultdict = defaultdict(int)
        hist_counts:     Counter     = Counter()
        output_lengths:  list[int]   = []
        seen_outputs:    list[str]   = []
        fallback_count   = 0
        hallucination_warn = 0
        low_quality      = 0
        empty_output     = 0
        duplicate_pairs  = 0

        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    report.errors.append(f"Line {line_num}: {e}")
                    continue

                report.total_records += 1

                # Schema
                schema = (
                    record.get("schema_used")
                    or record.get("task_type")
                    or "unknown"
                )
                is_fallback = "fallback_from:" in str(schema)
                if is_fallback:
                    fallback_count += 1
                schema_counts[schema] += 1

                # Quality
                quality = record.get("quality_score", record.get("quality", 0.0))
                if isinstance(quality, (int, float)):
                    quality_sums[schema]   += quality
                    quality_counts[schema] += 1
                    if quality < AuditReport.MIN_QUALITY_THRESHOLD:
                        low_quality += 1
                    bucket = self._get_bucket(quality)
                    hist_counts[bucket] += 1

                # Output length
                output_text = self._get_output(record)
                if not output_text:
                    empty_output += 1
                else:
                    output_lengths.append(len(output_text))

                # Hallucination warnings (markers left by post_validator)
                if record.get("_mitre_stripped") or record.get("_ioc_stripped"):
                    hallucination_warn += 1
                # Also check for stripped markers in text fields
                if "MITRE_STRIPPED" in str(record) or "IOC_STRIPPED" in str(record):
                    hallucination_warn += 1

                # Near-duplicate detection (simplified Jaccard on output)
                if output_text and len(output_text) > 50:
                    out_tokens = set(re.findall(r'\b\w{4,}\b', output_text.lower()))
                    for prev_tokens in seen_outputs[-20:]:  # check last 20 only
                        if prev_tokens:
                            sim = len(out_tokens & prev_tokens) / max(len(out_tokens | prev_tokens), 1)
                            if sim >= 0.85:
                                duplicate_pairs += 1
                                break
                    seen_outputs.append(out_tokens)

        # Finalize quality averages
        quality_by_schema = {
            schema: round(quality_sums[schema] / quality_counts[schema], 3)
            for schema in quality_counts
            if quality_counts[schema] > 0
        }

        report.schema_distribution    = dict(schema_counts)
        report.quality_by_schema      = quality_by_schema
        report.schema_fallback_count  = fallback_count
        report.fallback_rate          = fallback_count / max(report.total_records, 1)
        report.hallucination_warnings = hallucination_warn
        report.low_quality_records    = low_quality
        report.empty_output_records   = empty_output
        report.duplicate_pairs        = duplicate_pairs
        report.avg_output_length      = (
            sum(output_lengths) / len(output_lengths) if output_lengths else 0.0
        )
        report.quality_histogram = {k: v for k, v in sorted(hist_counts.items())}

        logger.info(
            "Audit complete: %d records, fallback=%.1f%%, warnings=%d",
            report.total_records,
            report.fallback_rate * 100,
            report.hallucination_warnings,
        )
        return report

    def audit_directory(self, dirpath: str, pattern: str = "*.jsonl") -> list[AuditReport]:
        """
        Audit all JSONL files in a directory.

        Args:
            dirpath: Path to directory containing JSONL files
            pattern: Glob pattern for files to include (default: *.jsonl)
        """
        path = Path(dirpath)
        reports = []
        for jsonl_file in sorted(path.glob(pattern)):
            reports.append(self.audit_file(str(jsonl_file)))
        return reports

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _get_output(self, record: dict) -> str:
        """Extract the primary output text from a record."""
        for key in self.OUTPUT_KEYS:
            val = record.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    def _get_bucket(self, quality: float) -> str:
        """Map a quality float to a histogram bucket label."""
        for lo, hi, label in self.QUALITY_BUCKETS:
            if lo <= quality < hi:
                return label
        return "UNKNOWN"
