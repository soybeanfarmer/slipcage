"""Fail-closed v1alpha1 experiment definition validation.

This module parses bounded YAML/JSON *data*. It never executes instructions,
instantiates Kubernetes clients, provisions VMs or dispatches workloads.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

import jsonschema
import yaml

MAX_SPEC_BYTES = 64 * 1024
SCHEMA_NAME = "security-experiment-v1alpha1.schema.json"


class SpecValidationError(ValueError):
    """A document is missing, invalid, unsafe or incompatible."""


class _StrictSafeLoader(yaml.SafeLoader):
    """Reject YAML aliases, merge keys and duplicate/non-string mapping keys."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise SpecValidationError("YAML aliases are not permitted")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise SpecValidationError("Expected a YAML mapping")
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise SpecValidationError("YAML merge keys are not permitted")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise SpecValidationError("All mapping keys must be strings")
            if key in seen:
                raise SpecValidationError("Duplicate mapping key is not permitted")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SpecValidationError("Duplicate JSON key is not permitted")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise SpecValidationError("Non-finite JSON numbers are not permitted")


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    source = resources.files("slipcage_engine").joinpath("schemas", SCHEMA_NAME)
    with source.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    """A validated, canonical v1alpha1 definition; no execution permission."""

    experiment_id: str
    version: str
    profile_id: str
    digest_sha256: str
    canonical_json: bytes


def validate_spec_bytes(document: bytes, *, extension: str) -> ExperimentSpec:
    """Strictly parse YAML/JSON, check the bundled schema and hash canonical data.

    A digest is evidence of exact validated input content, not an authenticated
    approval, signed pack or permission to execute this definition.
    """
    if not isinstance(document, bytes):
        raise SpecValidationError("Experiment document must be bytes")
    if not document or len(document) > MAX_SPEC_BYTES:
        raise SpecValidationError("Experiment document must be 1 to 65536 bytes")
    extension = extension.lower()
    if extension not in (".yaml", ".yml", ".json"):
        raise SpecValidationError("Expected a .json, .yaml or .yml definition")
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecValidationError("Definition is not UTF-8") from exc
    try:
        if extension == ".json":
            value = json.loads(
                text,
                object_pairs_hook=_strict_pairs,
                parse_constant=_reject_constant,
            )
        else:
            value = yaml.load(text, Loader=_StrictSafeLoader)
    except SpecValidationError:
        raise
    except (yaml.YAMLError, ValueError, RecursionError, OverflowError) as exc:
        raise SpecValidationError("Definition has invalid or unsafe syntax") from exc

    errors = sorted(
        _validator().iter_errors(value),
        key=lambda error: (
            tuple(str(x) for x in error.absolute_path),
            str(error.validator),
        ),
    )
    if errors:
        error = errors[0]
        location = "/" + "/".join(str(x) for x in error.absolute_path)
        raise SpecValidationError(
            f"Invalid definition at {location}: {error.validator} constraint"
        )

    # JSON Schema cannot express array-wide uniqueness of one object property.
    ids = [entry["id"] for entry in value["assertions"]]
    if len(ids) != len(set(ids)):
        raise SpecValidationError("Assertion IDs must be unique")

    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return ExperimentSpec(
        experiment_id=value["metadata"]["id"],
        version=value["metadata"]["version"],
        profile_id=value["profile"]["id"],
        digest_sha256=hashlib.sha256(canonical).hexdigest(),
        canonical_json=canonical,
    )


def load_spec(filename: str | Path) -> ExperimentSpec:
    """Read only a bounded regular local file; no network, shell or host mutation."""
    path = Path(filename)
    try:
        if path.is_symlink():
            raise SpecValidationError("Definition path must not be a symlink")
        # Open without following a last-component symlink when supported.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise SpecValidationError("Definition must be a regular file")
            if os.fstat(handle.fileno()).st_size > MAX_SPEC_BYTES:
                raise SpecValidationError("Experiment document exceeds 65536 bytes")
            contents = handle.read(MAX_SPEC_BYTES + 1)
    except SpecValidationError:
        raise
    except OSError as exc:
        raise SpecValidationError("Could not read a regular definition file") from exc
    return validate_spec_bytes(contents, extension=path.suffix)
