"""JSON schema validation for request, result, and audit record."""

import os
import jsonschema

from .schema_io import get_request_schema, get_result_schema, get_audit_schema


def validate_request(obj):
    """Validate object against finance_request schema. Raises jsonschema.ValidationError on failure."""
    jsonschema.validate(obj, get_request_schema())


def validate_result(obj):
    """Validate object against finance_result schema. Raises jsonschema.ValidationError on failure."""
    jsonschema.validate(obj, get_result_schema())


def validate_audit_record(obj):
    """Validate object against audit_record schema. Raises jsonschema.ValidationError on failure."""
    jsonschema.validate(obj, get_audit_schema())


def should_validate_output_schema() -> bool:
    """True when VALIDATE_OUTPUT_SCHEMA env is set to true/1."""
    v = os.environ.get("VALIDATE_OUTPUT_SCHEMA", "").strip().lower()
    return v in ("true", "1", "yes")
