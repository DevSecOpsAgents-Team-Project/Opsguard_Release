"""
GuardDuty → RAG Top-5 + level_router → pred_from_rag → evaluator.

프로젝트 루트:
  .venv\\Scripts\\python.exe GT_test\\run_rag_eval.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)


def _run(cmd: list[str], cwd: str | None = None) -> None:
    print("$", " ".join(cmd))
    if subprocess.call(cmd, cwd=cwd or _REPO_ROOT) != 0:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="GuardDuty RAG eval pipeline")
    parser.add_argument("--skip-rag", action="store_true", help="pred 생성 생략")
    parser.add_argument("--guardduty-dir", default="GuardDutyJSON")
    parser.add_argument("--gt-dir", default="new_gt_files")
    parser.add_argument("--pred-dir", default="pred_from_rag")
    parser.add_argument("-o", "--output", default="evaluation_results_rag.csv")
    args = parser.parse_args()

    py = sys.executable

    if not args.skip_rag:
        _run(
            [
                py,
                os.path.join(_THIS_DIR, "build_pred_from_guardduty.py"),
                "--input-dir",
                os.path.join(_THIS_DIR, args.guardduty_dir),
                "--out-dir",
                os.path.join(_THIS_DIR, args.pred_dir),
            ],
            cwd=_THIS_DIR,
        )

    _run(
        [
            py,
            os.path.join(_THIS_DIR, "evaluator.py"),
            "--gt-dir",
            args.gt_dir,
            "--pred-dir",
            args.pred_dir,
            "-o",
            args.output,
        ],
        cwd=_THIS_DIR,
    )


if __name__ == "__main__":
    main()
