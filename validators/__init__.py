"""Validation pipeline registry."""

from validators.policy_fwa import PolicyFWAValidator
from validators.data_leakage import DataLeakageValidator
from validators.structural_integrity import StructuralIntegrityValidator

ALL_VALIDATORS = [
    PolicyFWAValidator(),
    DataLeakageValidator(),
    StructuralIntegrityValidator(),
]
