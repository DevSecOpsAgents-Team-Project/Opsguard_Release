"""Load JSON schemas from schemas/ directory."""

import json
from pathlib import Path

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def load_schema(name):
    """Load a JSON schema file by name (without .schema.json).

    Args:
        name: e.g. 'finance_request' or 'finance_result'

    Returns:
        dict schema
    """
    path = _SCHEMAS_DIR / f"{name}.schema.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_request_schema():
    return load_schema("finance_request")


def get_result_schema():
    return load_schema("finance_result")


def get_audit_schema():
    return load_schema("audit_record")
