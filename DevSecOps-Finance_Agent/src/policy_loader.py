"""Load policy by version. Supports legacy single-file (v1.0) and bundle+manifest (v1.0.0)."""

import hashlib
import json
from pathlib import Path

_POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest_path: Path | None = None) -> dict:
    """Load policy_manifest.json. Path defaults to policy/policy_manifest.json."""
    path = manifest_path or (_POLICY_DIR / "policy_manifest.json")
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_manifest_hashes(manifest_path: Path | None = None) -> None:
    """Verify each file in manifest has matching SHA256. Raises ValueError on mismatch."""
    manifest = load_manifest(manifest_path)
    path = manifest_path or (_POLICY_DIR / "policy_manifest.json")
    base = path.parent
    for rel, expected in manifest.get("files", {}).items():
        if not expected:
            continue
        full = base / rel
        if not full.exists():
            raise ValueError(f"Policy file missing: {rel}")
        actual = _file_sha256(full)
        if actual != expected:
            raise ValueError(f"Policy file hash mismatch: {rel} (expected {expected[:16]}..., got {actual[:16]}...)")


def compute_manifest_hash(manifest_json: dict) -> str:
    """SHA256 of canonical JSON string of manifest (for audit trail)."""
    canonical = json.dumps(manifest_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy(policy_version: str) -> dict:
    """Load policy for given version.

    - v1.0.0: load from policy/v1.0.0/*.json, validate manifest hashes, return bundle with
      impact_table, likelihood_table, regulation_weights, profile_weights, action_catalog,
      recommendation_constraints, policy_meta, pricing_table, policy_version, policy_hash.
    - v1.0 (legacy): load policy.v1.0.json, return dict with pricing_table etc. for backward compat.
    """
    if policy_version == "v1.0.0":
        return _load_policy_bundle_v1()
    # Legacy: single file
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


def _load_policy_bundle_v1() -> dict:
    manifest_path = _POLICY_DIR / "policy_manifest.json"
    manifest = load_manifest(manifest_path)
    if not manifest or not manifest.get("files"):
        raise ValueError("policy_manifest.json missing or empty")
    validate_manifest_hashes(manifest_path)
    policy_hash = compute_manifest_hash(manifest)
    base = _POLICY_DIR / "v1.0.0"
    bundle = {
        "policy_version": "v1.0.0",
        "policy_hash": policy_hash,
        "impact_table": _load_json(base / "impact_table.json"),
        "likelihood_table": _load_json(base / "likelihood_table.json"),
        "regulation_weights": _load_json(base / "regulation_weights.json"),
        "profile_weights": _load_json(base / "profile_weights.json"),
        "action_catalog": _load_json(base / "action_catalog.json"),
        "recommendation_constraints": _load_json(base / "recommendation_constraints.json"),
        "policy_meta": _load_json(base / "policy_meta.json"),
    }
    meta = bundle["policy_meta"]
    bundle["pricing_table"] = meta.get("pricing_table", {})
    bundle["approved_by"] = meta.get("approved_by", "")
    bundle["approved_at"] = meta.get("approved_at", "")
    bundle["currency"] = meta.get("currency", "USD")
    return bundle


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
