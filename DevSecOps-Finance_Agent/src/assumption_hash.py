"""Canonical SHA256 hash of normalized assumptions for reproducibility."""

import hashlib
import json


def assumption_hash(normalized_assumptions: dict) -> str:
    """Compute SHA256 hex (64 chars, lower) of canonical JSON of normalized assumptions.

    Canonical: sort_keys=True, separators=(",", ":"), ensure_ascii=False.
    """
    canonical = json.dumps(
        normalized_assumptions,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest().lower()
