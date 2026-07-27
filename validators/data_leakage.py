"""LEAK-002: non-public data variable and cryptographic segment leak detection."""

import re

from validators.base import BaseValidator, Violation

LEAK_PATTERNS = [
    (re.compile(r"\b(?:sk|pk|api[_-]?key)[_-][A-Za-z0-9_]{16,}\b"),
     "API key or secret token segment"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "private key material"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS access key identifier"),
    (re.compile(r"\b[A-Fa-f0-9]{64}\b"),
     "raw 256-bit hex segment (possible key/hash leak)"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "SSN-formatted identifier"),
    (re.compile(r"\b(?:INTERNAL_ONLY|CONFIDENTIAL|DO_NOT_DISTRIBUTE)[:_][A-Za-z0-9_]+\b"),
     "non-public data variable marker"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "JWT-structured token"),
]


class DataLeakageValidator(BaseValidator):
    rule_id = "LEAK-002"
    severity = "critical"

    def validate(self, prompt_record):
        violations = []
        text = prompt_record.response_text or ""
        for pattern, label in LEAK_PATTERNS:
            match = pattern.search(text)
            if match:
                snippet = match.group(0)
                redacted = snippet[:8] + "..." if len(snippet) > 8 else snippet
                violations.append(Violation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    error_detail=f"{label} detected in response_text (redacted: {redacted})",
                ))
        return violations
