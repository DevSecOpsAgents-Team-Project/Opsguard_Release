"""Load policy by version from policy/ directory."""

import json
from pathlib import Path

_POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"


def load_policy(policy_version: str) -> dict:
    """Load policy file for given version.

    File rule: policy/policy.<policy_version>.json
    e.g. v1.0 -> policy.v1.0.json

    Args:
        policy_version: e.g. "v1.0"

    Returns:
        Policy dict with policy_version, approved_by, approved_at, currency, pricing_table.

    Raises:
        ValueError: if file not found or policy_version in file does not match.
    """
    safe_name = policy_version.replace("/", "_")
    path = _POLICY_DIR / f"policy.{safe_name}.json"
    if not path.exists():
        raise ValueError(f"Policy not found for version: {policy_version}")
    with open(path, encoding="utf-8") as f:
        policy = json.load(f)
    if policy.get("policy_version") != policy_version:
        raise ValueError(
            f"Policy version mismatch: file has {policy.get('policy_version')}, requested {policy_version}"
        )
    return policy
