"""
Build policy_manifest.json: compute SHA256 for each policy file and write manifest.
Run from repo root: python scripts/build_manifest.py
"""
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policy"
MANIFEST_PATH = POLICY_DIR / "policy_manifest.json"

VERSION_DIRS = ["v1.0.0"]
MANIFEST_FILES = [
    "impact_table.json",
    "likelihood_table.json",
    "regulation_weights.json",
    "profile_weights.json",
    "action_catalog.json",
    "recommendation_constraints.json",
    "policy_meta.json",
]


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    manifest = {"policy_version": "v1.0.0", "description": "SHA256 of each policy file. Run scripts/build_manifest.py to update.", "files": {}}
    for ver in VERSION_DIRS:
        base = POLICY_DIR / ver
        if not base.exists():
            continue
        for name in MANIFEST_FILES:
            p = base / name
            key = f"{ver}/{name}"
            if p.exists():
                manifest["files"][key] = file_sha256(p)
            else:
                manifest["files"][key] = ""
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print("Updated", MANIFEST_PATH)
    for k, v in manifest["files"].items():
        print(" ", k, v[:16] + "..." if v else "(missing)")


if __name__ == "__main__":
    main()
