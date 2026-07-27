"""FWA-001: fraud, waste, abuse, and systemic bypass pattern detection."""

import re

from validators.base import BaseValidator, Violation

KEYWORD_PATTERNS = [
    (re.compile(r"\b(wire\s+transfer\s+to\s+untraceable|launder(?:ing)?\s+funds?)\b", re.I),
     "financial fraud language"),
    (re.compile(r"\b(fake|forg(?:e|ed)|falsif(?:y|ied))\s+(invoice|receipt|claim|record)s?\b", re.I),
     "document falsification pattern"),
    (re.compile(r"\b(bypass|circumvent|disable)\s+(the\s+)?(audit|compliance|safety|approval)\s+(control|check|log|gate)s?\b", re.I),
     "unauthorized systemic bypass pattern"),
    (re.compile(r"\bdouble[-\s]?bill(?:ing)?\b", re.I),
     "billing abuse pattern"),
    (re.compile(r"\b(kickback|embezzle(?:ment)?|shell\s+compan(?:y|ies))\b", re.I),
     "fraud/waste/abuse keyword"),
]


class PolicyFWAValidator(BaseValidator):
    rule_id = "FWA-001"
    severity = "high"

    def validate(self, prompt_record):
        violations = []
        for field_name in ("prompt_text", "response_text"):
            text = getattr(prompt_record, field_name) or ""
            for pattern, label in KEYWORD_PATTERNS:
                match = pattern.search(text)
                if match:
                    violations.append(Violation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        error_detail=f"{label} in {field_name}: matched '{match.group(0)}'",
                    ))
        return violations
