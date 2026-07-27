"""Shared validator contract."""

from dataclasses import dataclass


@dataclass
class Violation:
    rule_id: str
    severity: str
    error_detail: str


class BaseValidator:
    rule_id = "BASE-000"
    severity = "medium"

    def validate(self, prompt_record):
        """Return a list of Violation objects for the given ModelPrompt record."""
        raise NotImplementedError
