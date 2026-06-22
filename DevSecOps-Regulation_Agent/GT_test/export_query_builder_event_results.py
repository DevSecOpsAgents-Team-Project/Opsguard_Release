from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
SRC_DIR = REPO_ROOT / "src"

for path in (str(REPO_ROOT), str(SRC_DIR), str(THIS_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from gt_rag_common import finding_from_event  # noqa: E402
from regulation_agent.rag import build_guardduty_rag_query, rerank_retrieved_documents  # noqa: E402


def _load_reg_docs() -> List[Dict[str, Any]]:
    rows = json.loads((REPO_ROOT / "data.json").read_text(encoding="utf-8"))
    return [
        {
            "id": row.get("id"),
            "metadata": row.get("metadata") or {},
            "document": row.get("document", ""),
        }
        for row in rows
    ]


def _iter_event_files(input_dir: Path) -> List[Path]:
    return sorted(p for p in input_dir.glob("*.json") if p.is_file())


def _load_event(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"Unsupported event shape: {path}")
    return obj


def _row_from_event(path: Path, event: Dict[str, Any], reg_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    finding = finding_from_event(event)
    primary_query, query_plan = build_guardduty_rag_query(
        finding=finding,
        runtime_result=event.get("runtime_result") or {},
        candidate_actions=[],
    )
    ranked = rerank_retrieved_documents(primary_query, finding, reg_docs, query_plan=query_plan)
    top5 = ranked[:5]

    top5_ids = [str(row.get("id", "")) for row in top5]
    top5_categories = [str((row.get("metadata") or {}).get("category", "")) for row in top5]
    top5_titles = [str((row.get("metadata") or {}).get("title", "")) for row in top5]

    return {
        "event_file": path.name,
        "finding_type": str(finding.get("type", "")),
        "resource_type": str((finding.get("resource") or {}).get("resourceType", "")),
        "api_name": str((((finding.get("service") or {}).get("action") or {}).get("awsApiCallAction") or {}).get("api", "")),
        "planned_categories": " | ".join(query_plan.get("expected_categories", [])),
        "downweight_categories": " | ".join(query_plan.get("downweight_hints", [])),
        "matched_rules": " | ".join(query_plan.get("matched_rules", [])),
        "security_meanings": " | ".join(query_plan.get("security_meanings", [])),
        "regulatory_phrases": " | ".join(query_plan.get("regulatory_phrases", [])),
        "actual_top5_ids": " | ".join(top5_ids),
        "actual_top5_categories": " | ".join(top5_categories),
        "actual_top5_titles": " | ".join(top5_titles),
        "primary_query": primary_query,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export query-builder results for real event JSON files")
    parser.add_argument(
        "--input-dir",
        default=str(REPO_ROOT / "cases"),
        help="Directory containing event JSON files",
    )
    parser.add_argument(
        "--output",
        default=str(THIS_DIR / "query_builder_event_results_cases.csv"),
        help="Output CSV path",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir).resolve()
    output_path = Path(args.output).resolve()
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    reg_docs = _load_reg_docs()
    rows: List[Dict[str, Any]] = []
    for path in _iter_event_files(input_dir):
        try:
            event = _load_event(path)
            rows.append(_row_from_event(path, event, reg_docs))
        except Exception as exc:
            rows.append(
                {
                    "event_file": path.name,
                    "finding_type": "",
                    "resource_type": "",
                    "api_name": "",
                    "planned_categories": "",
                    "downweight_categories": "",
                    "matched_rules": "",
                    "security_meanings": "",
                    "regulatory_phrases": "",
                    "actual_top5_ids": "",
                    "actual_top5_categories": "",
                    "actual_top5_titles": "",
                    "primary_query": f"ERROR: {exc}",
                }
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "event_file",
                "finding_type",
                "resource_type",
                "api_name",
                "planned_categories",
                "downweight_categories",
                "matched_rules",
                "security_meanings",
                "regulatory_phrases",
                "actual_top5_ids",
                "actual_top5_categories",
                "actual_top5_titles",
                "primary_query",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(output_path)
    print(f"rows={len(rows)}")


if __name__ == "__main__":
    main()
