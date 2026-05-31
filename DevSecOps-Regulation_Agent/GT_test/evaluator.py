"""
GT vs 예측(pred) 비교 — recall@2, recall@5, MRR, nDCG@5, HN_Error@5, level_correct.

실행 (GT_test 디렉터리 또는 루트):
  python run_rag_eval.py
  python evaluator.py
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

EVAL_TOP_K = int(os.environ.get("EVAL_TOP_K", "5"))


def _pred_clause_ids(pred: dict) -> list[str]:
    regs = pred.get("regulations")
    if isinstance(regs, list) and regs:
        return [str(r.get("clause_id", "")) for r in regs if r.get("clause_id")]
    return []


def _pred_level(pred: dict):
    level = pred.get("escalation_assessment", {}).get("recommended_level")
    if level is None:
        level = pred.get("selected_level")
    return level


def _binary_recall_at_k(relevance_dict: dict, pred_docs_list: list[str], k: int) -> float:
    for doc in pred_docs_list[:k]:
        if relevance_dict.get(doc, 0) > 0:
            return 1.0
    return 0.0


def calculate_metrics(gt: dict, pred: dict, *, eval_top_k: int = EVAL_TOP_K) -> dict:
    pred_docs_list = _pred_clause_ids(pred)[:eval_top_k]
    pred_level = _pred_level(pred)

    relevance_dict = gt.get("grading", {}).get("relevance", {})
    gt_level = gt.get("expected", {}).get("selected_level")
    hard_negatives = set(gt.get("hard_negatives", []))

    gt_docs_list = [doc for doc, rel in relevance_dict.items() if rel > 0]
    top_k_preds = pred_docs_list[:eval_top_k]

    recall_at_2 = _binary_recall_at_k(relevance_dict, pred_docs_list, 2)
    recall_at_5 = _binary_recall_at_k(relevance_dict, pred_docs_list, eval_top_k)

    mrr = 0.0
    for i, doc in enumerate(pred_docs_list):
        if relevance_dict.get(doc, 0) > 0:
            mrr = 1.0 / (i + 1)
            break

    dcg = 0.0
    for i, doc in enumerate(top_k_preds):
        rel = relevance_dict.get(doc, 0)
        dcg += rel / math.log2(i + 2)

    ideal_rels = sorted([rel for rel in relevance_dict.values() if rel > 0], reverse=True)
    idcg = 0.0
    for i, rel in enumerate(ideal_rels[:eval_top_k]):
        idcg += rel / math.log2(i + 2)

    ndcg_at_5 = (dcg / idcg) if idcg > 0 else 0.0

    hn_error_at_5 = 0.0
    for doc in top_k_preds:
        if doc in hard_negatives:
            hn_error_at_5 = 1.0
            break

    if pred_level is None or gt_level is None:
        level_correct = ""
    else:
        level_correct = 1 if str(pred_level) == str(gt_level) else 0

    return {
        "sample_id": gt.get("sample_id", "unknown"),
        "finding_type": gt.get("finding_type", ""),
        "gt_docs": ",".join(gt_docs_list),
        "pred_docs": ",".join(pred_docs_list),
        "gt_level": gt_level if gt_level is not None else "",
        "pred_level": pred_level if pred_level is not None else "",
        "recall@2": round(recall_at_2, 4),
        "recall@5": round(recall_at_5, 4),
        "MRR": round(mrr, 4),
        "nDCG@5": round(ndcg_at_5, 4),
        "HN_Error@5": round(hn_error_at_5, 4),
        "level_correct": level_correct,
    }


def run_evaluation(
    gt_dir: str,
    pred_dir: str,
    output_csv: str,
    *,
    eval_top_k: int = EVAL_TOP_K,
) -> list[dict]:
    gt_dir = os.path.abspath(gt_dir)
    pred_dir = os.path.abspath(pred_dir)

    if not os.path.isdir(gt_dir):
        raise FileNotFoundError(f"GT 폴더 없음: {gt_dir}")

    results: list[dict] = []
    skipped = 0

    for filename in sorted(os.listdir(gt_dir)):
        if not filename.endswith(".json"):
            continue

        gt_path = os.path.join(gt_dir, filename)
        pred_path = os.path.join(pred_dir, filename)

        if not os.path.isfile(pred_path):
            print(f"WARN: no pred for {filename}, skip")
            skipped += 1
            continue

        with open(gt_path, encoding="utf-8") as f:
            gt_data = json.load(f)
        with open(pred_path, encoding="utf-8") as f:
            pred_data = json.load(f)

        metrics = calculate_metrics(gt_data, pred_data, eval_top_k=eval_top_k)
        results.append(metrics)
        print(
            f"OK [{filename}] recall@2={metrics['recall@2']} recall@5={metrics['recall@5']} "
            f"nDCG={metrics['nDCG@5']} level_ok={metrics['level_correct']}"
        )

    if not results:
        print(f"평가된 샘플 없음 (skipped={skipped}). pred_dir={pred_dir}")
        return results

    n = len(results)
    level_vals = [r["level_correct"] for r in results if r["level_correct"] != ""]
    avg_level = (
        round(sum(level_vals) / len(level_vals), 4) if level_vals else ""
    )

    results.append(
        {
            "sample_id": "AVERAGE",
            "finding_type": "-",
            "gt_docs": "-",
            "pred_docs": "-",
            "gt_level": "-",
            "pred_level": "-",
            "recall@2": round(sum(r["recall@2"] for r in results) / n, 4),
            "recall@5": round(sum(r["recall@5"] for r in results) / n, 4),
            "MRR": round(sum(r["MRR"] for r in results) / n, 4),
            "nDCG@5": round(sum(r["nDCG@5"] for r in results) / n, 4),
            "HN_Error@5": round(sum(r["HN_Error@5"] for r in results) / n, 4),
            "level_correct": avg_level,
        }
    )

    keys = [
        "sample_id",
        "finding_type",
        "gt_docs",
        "pred_docs",
        "gt_level",
        "pred_level",
        "recall@2",
        "recall@5",
        "MRR",
        "nDCG@5",
        "HN_Error@5",
        "level_correct",
    ]

    out_path = output_csv if os.path.isabs(output_csv) else os.path.join(_THIS_DIR, output_csv)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        dict_writer.writeheader()
        dict_writer.writerows(results)

    print(f"\nDone. {n} cases, skipped={skipped}")
    print(f"  → {out_path}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare GT labels with predictions")
    parser.add_argument(
        "--gt-dir",
        default=os.environ.get("GT_DIR", "new_gt_files"),
    )
    parser.add_argument(
        "--pred-dir",
        default=os.environ.get("PRED_DIR", "pred_from_rag"),
    )
    parser.add_argument(
        "-o",
        "--output",
        default=os.environ.get("EVAL_OUTPUT", "evaluation_results_rag.csv"),
    )
    parser.add_argument("--top-k", type=int, default=EVAL_TOP_K)
    args = parser.parse_args()

    gt_path = args.gt_dir
    pred_path = args.pred_dir
    if not os.path.isabs(gt_path):
        gt_path = os.path.join(_THIS_DIR, gt_path)
    if not os.path.isabs(pred_path):
        pred_path = os.path.join(_THIS_DIR, pred_path)

    run_evaluation(gt_path, pred_path, args.output, eval_top_k=args.top_k)


if __name__ == "__main__":
    main()
