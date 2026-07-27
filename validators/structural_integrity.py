"""COMP-003: structural schema validation of model response payloads."""

import json

from validators.base import BaseValidator, Violation

REQUIRED_KEYS = {"status", "content"}
ALLOWED_KEYS = REQUIRED_KEYS | {"metadata", "confidence", "model_notes"}
ALLOWED_STATUS_VALUES = {"ok", "refused", "partial"}


class StructuralIntegrityValidator(BaseValidator):
    rule_id = "COMP-003"
    severity = "high"

    def validate(self, prompt_record):
        text = (prompt_record.response_text or "").strip()

        if not (text.startswith("{") or text.startswith("[")):
            return []  # free-text responses are out of scope for schema checks

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return [Violation(
                rule_id=self.rule_id,
                severity=self.severity,
                error_detail=f"broken syntax: response payload is not parseable JSON ({exc})",
            )]

        if not isinstance(payload, dict):
            return [Violation(
                rule_id=self.rule_id,
                severity=self.severity,
                error_detail=f"schema regression: expected JSON object, got {type(payload).__name__}",
            )]

        violations = []
        missing = REQUIRED_KEYS - payload.keys()
        if missing:
            violations.append(Violation(
                rule_id=self.rule_id,
                severity=self.severity,
                error_detail=f"schema regression: missing required keys {sorted(missing)}",
            ))

        unmapped = set(payload.keys()) - ALLOWED_KEYS
        if unmapped:
            violations.append(Violation(
                rule_id=self.rule_id,
                severity=self.severity,
                error_detail=f"schema regression: unmapped keys {sorted(unmapped)}",
            ))

        status = payload.get("status")
        if status is not None and status not in ALLOWED_STATUS_VALUES:
            violations.append(Violation(
                rule_id=self.rule_id,
                severity=self.severity,
                error_detail=f"schema regression: unmapped status value '{status}'",
            ))

        return violations
