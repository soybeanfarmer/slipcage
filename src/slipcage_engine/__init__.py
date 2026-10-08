"""Portable Slipcage experiment contracts; no execution adapters in this release."""

__version__ = "0.1.0a1"

from .specification import (
    ExperimentSpec,
    SpecValidationError,
    load_spec,
    validate_spec_bytes,
)

__all__ = ["ExperimentSpec", "SpecValidationError", "load_spec", "validate_spec_bytes"]
