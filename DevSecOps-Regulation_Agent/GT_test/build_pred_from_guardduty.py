"""
GuardDutyJSON/*.json → regulation_agent.rag (Top-5) → pred_from_rag/caseNN.json

프로덕션 RAG와 동일:
  RETRIEVAL_TOP_K=10 (Chroma) → rerank → RERANK_OUTPUT_TOP_K=5

실행 (프로젝트 루트):
  .venv\\Scripts\\python.exe GT_test\\build_pred_from_guardduty.py

환경변수:
  GT_GUARDDUTY_DIR   입력 (기본 GT_test/GuardDutyJSON)
  GT_PRED_DIR        출력 (기본 GT_test/pred_from_rag)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from gt_rag_common import (
    clause_id_from_row,
    decide_level_for_event,
    ensure_pythonpath,
    finding_from_event,
    load_dotenv,
    run_guardduty_rag,
)

DEFAULT_INPUT = os.path.join(_THIS_DIR, "GuardDutyJSON")
DEFAULT_OUT = os.path.join(_THIS_DIR, "pred_from_rag")


def _normalize_chroma_dir() -> str:
    configured = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_db")
    configured = configured.replace("\\", os.sep)
    if os.path.isabs(configured):
        return configured
    return os.path.abspath(os.path.join(_REPO_ROOT, configured))


def build_pred_payload(
    event: dict,
    fname: str,
    query_text: str,
    where_filter,
    ranked: list,
    clause_ids: list[str],
    selected_level: int,
    route_reasons: list[str],
) -> dict:
    from regulation_agent.rag import RERANK_OUTPUT_TOP_K, RETRIEVAL_TOP_K

    finding = finding_from_event(event)
    regulations = [{"clause_id": cid} for cid in clause_ids]

    detail = []
    for i, row in enumerate(ranked, start=1):
        meta = row.get("metadata") or {}
        detail.append(
            {
                "rank": i,
                "clause_id": clause_id_from_row(row),
                "title": meta.get("title", ""),
                "category": meta.get("category", ""),
            }
        )

    return {
        "sample_id": fname,
        "finding_type": finding.get("type") or event.get("incident_summary", {}).get("title", ""),
        "source": "guardduty_rag",
        "regulations": regulations,
        "selected_level": selected_level,
        "route_reasons": route_reasons,
        "debug_info": {
            "query_text_used": query_text,
            "where_filter_used": where_filter,
            "retrieval_top_k": RETRIEVAL_TOP_K,
            "rerank_output_top_k": RERANK_OUTPUT_TOP_K,
            "regulations_ranked_detail": detail,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run regulation_agent.rag on GuardDutyJSON → evaluator pred JSON (Top-5)"
    )
    parser.add_argument(
        "--input-dir",
        default=os.environ.get("GT_GUARDDUTY_DIR", DEFAULT_INPUT),
    )
    parser.add_argument(
        "--out-dir",
        default=os.environ.get("GT_PRED_DIR", DEFAULT_OUT),
    )
    args = parser.parse_args()

    ensure_pythonpath()
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
    load_dotenv()
    os.environ["CHROMA_PERSIST_DIR"] = _normalize_chroma_dir()

    from regulation_agent.service import _get_collection

    if not os.path.isdir(args.input_dir):
        print(f"입력 폴더 없음: {args.input_dir}")
        raise SystemExit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    collection = _get_collection()
    files = sorted(f for f in os.listdir(args.input_dir) if f.endswith(".json"))
    if not files:
        print(f"JSON 없음: {args.input_dir}")
        raise SystemExit(1)

    for fname in files:
        in_path = os.path.join(args.input_dir, fname)
        with open(in_path, encoding="utf-8") as f:
            event = json.load(f)
        if not isinstance(event, dict):
            print(f"건너뜀: {fname}")
            continue

        query_text, where_filter, ranked, clause_ids = run_guardduty_rag(event, collection)
        selected_level, route_reasons = decide_level_for_event(event)
        pred = build_pred_payload(
            event,
            fname,
            query_text,
            where_filter,
            ranked,
            clause_ids,
            selected_level,
            route_reasons,
        )
        out_path = os.path.join(args.out_dir, fname)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(pred, f, ensure_ascii=False, indent=2)
        print(f"OK  {fname}  Top-5: {', '.join(clause_ids)}")

    print(f"\n완료. {len(files)}건 → {args.out_dir}")


if __name__ == "__main__":
    main()
