"""Read-only compliance engine: evaluation loop, finding persistence, CSV telemetry."""

import csv
import json
import os
from dataclasses import dataclass

from config import SNAPSHOT_CSV_PATH
from models import ModelPrompt, SafetyFinding
from validators import ALL_VALIDATORS

CSV_FIELDS = ["prompt_id", "rule_id", "severity", "error_detail", "model_version", "detected_at"]


@dataclass
class EvaluationSummary:
    total_records: int
    passing_records: int
    total_findings: int
    findings_by_rule: dict

    @property
    def passing_metric(self):
        if self.total_records == 0:
            return 100.0
        return round(100.0 * self.passing_records / self.total_records, 2)


def _serialize_payload(record):
    return json.dumps({
        "prompt_text": record.prompt_text,
        "response_text": record.response_text,
        "model_version": record.model_version,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    })


def _append_snapshot_rows(rows):
    file_exists = os.path.exists(SNAPSHOT_CSV_PATH)
    with open(SNAPSHOT_CSV_PATH, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def run_evaluation(session):
    """Stream-parse all model_prompts records through the validation pipeline.

    Source records are never modified; violations are persisted to
    safety_findings and appended to the CSV snapshot.
    """
    total = 0
    passing = 0
    findings_by_rule = {}
    csv_rows = []
    new_findings = []

    already_flagged = {
        row[0] for row in session.query(SafetyFinding.prompt_id).distinct()
    }

    for record in session.query(ModelPrompt).yield_per(50):
        total += 1
        record_violations = []
        for validator in ALL_VALIDATORS:
            record_violations.extend(validator.validate(record))

        if not record_violations:
            passing += 1
            continue

        if record.id in already_flagged:
            continue

        payload = _serialize_payload(record)
        for violation in record_violations:
            findings_by_rule[violation.rule_id] = findings_by_rule.get(violation.rule_id, 0) + 1
            finding = SafetyFinding(
                prompt_id=record.id,
                rule_id=violation.rule_id,
                severity=violation.severity,
                error_detail=violation.error_detail,
                record_payload=payload,
            )
            new_findings.append(finding)

    session.add_all(new_findings)
    session.commit()

    for finding in new_findings:
        source = json.loads(finding.record_payload)
        csv_rows.append({
            "prompt_id": finding.prompt_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "error_detail": finding.error_detail,
            "model_version": source["model_version"],
            "detected_at": finding.detected_at.isoformat() if finding.detected_at else "",
        })
    if csv_rows:
        _append_snapshot_rows(csv_rows)

    return EvaluationSummary(
        total_records=total,
        passing_records=passing,
        total_findings=len(new_findings),
        findings_by_rule=findings_by_rule,
    )
