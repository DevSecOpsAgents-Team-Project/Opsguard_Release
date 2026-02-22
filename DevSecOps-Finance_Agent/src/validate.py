"""JSON schema validation for request and result."""

import jsonschema

from .schema_io import get_request_schema, get_result_schema


def validate_request(obj):
    """Validate object against finance_request schema. Raises jsonschema.ValidationError on failure."""
    jsonschema.validate(obj, get_request_schema())


def validate_result(obj):
    """Validate object against finance_result schema. Raises jsonschema.ValidationError on failure."""
    jsonschema.validate(obj, get_result_schema())
