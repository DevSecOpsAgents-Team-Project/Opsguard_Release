"""Append audit record to JSONL file."""

import json
from pathlib import Path


def append_audit_record(record: dict, path: str | Path) -> None:
    """Append one JSON line to path. Creates parent dirs if needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
