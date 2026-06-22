from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
SRC_DIR = REPO_ROOT / "src"

for path in (str(REPO_ROOT), str(SRC_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from regulation_agent.rag import build_guardduty_rag_query, rerank_retrieved_documents  # noqa: E402


def _load_rows() -> List[Dict[str, Any]]:
    data = json.loads((REPO_ROOT / "data.json").read_text(encoding="utf-8"))
    return [
        {
            "id": row.get("id"),
            "metadata": row.get("metadata") or {},
            "document": row.get("document", ""),
        }
        for row in data
    ]


REG_DOCS = _load_rows()


def _finding(
    finding_type: str,
    title: str,
    description: str,
    resource_type: str = "AwsResource",
    api_name: str = "",
    severity: float = 5.0,
) -> Dict[str, Any]:
    return {
        "type": finding_type,
        "title": title,
        "description": description,
        "severity": severity,
        "resource": {"resourceType": resource_type},
        "service": {"action": {"awsApiCallAction": {"api": api_name}}},
    }


CASES: List[Dict[str, Any]] = [
    {
        "name": "CEK",
        "finding": _finding(
            "Persistence:KMS/KeyDeletionScheduled",
            "KMS key scheduled for deletion",
            "Encryption control may degrade because key rotation and key management lifecycle are disrupted.",
            resource_type="KMSKey",
            api_name="ScheduleKeyDeletion",
        ),
        "expected": ["CEK", "DSP", "GRC"],
    },
    {
        "name": "DSP",
        "finding": _finding(
            "Impact:S3/AnomalousBehavior.Delete",
            "Suspicious S3 object delete activity",
            "Sensitive data may be deleted or disclosed, requiring data protection and retention review.",
            resource_type="S3Bucket",
            api_name="DeleteObject",
        ),
        "expected": ["DSP", "LOG", "SEF"],
    },
    {
        "name": "GRC",
        "finding": _finding(
            "Policy:Account/ComplianceDrift",
            "Compliance drift and governance exception detected",
            "Risk management, control ownership, and compliance assessment are required for this governance issue.",
            resource_type="AwsAccount",
            api_name="PutAccountPolicy",
        ),
        "expected": ["GRC", "IAM", "AccessControl"],
    },
    {
        "name": "IAM",
        "finding": _finding(
            "PrivilegeEscalation:IAMUser/AnomalousBehavior",
            "User attached an elevated policy and assumed privileged role",
            "Potential least privilege failure and privileged access misuse involving credentials and user account controls.",
            resource_type="IAMUser",
            api_name="AttachUserPolicy",
        ),
        "expected": ["IAM", "AccessControl", "GRC"],
    },
    {
        "name": "AccessControl",
        "finding": _finding(
            "Policy:Account/SharedAdminUsage",
            "Shared administrator account was used without approval",
            "Access control requires permission revoke, administrator separation, and access right management review.",
            resource_type="IAMUser",
            api_name="CreateLoginProfile",
        ),
        "expected": ["AccessControl", "IAM", "GRC"],
    },
    {
        "name": "IncidentResponse",
        "finding": _finding(
            "UnauthorizedAccess:EC2/IntrusionActivity",
            "Intrusion requires containment and response procedure",
            "Incident handling, containment, breach response, and assign responsibility steps are required immediately.",
            resource_type="Instance",
            api_name="RevokeSecurityGroupIngress",
        ),
        "expected": ["IncidentResponse", "SEF", "LOG"],
    },
    {
        "name": "Logging",
        "finding": _finding(
            "Stealth:CloudTrail/LogTampering",
            "Audit trail integrity is at risk",
            "Log retention, evidence preservation, tampering protection, and log file validation are required.",
            resource_type="Trail",
            api_name="DeleteTrail",
        ),
        "expected": ["Logging", "LOG", "SEF"],
    },
    {
        "name": "IVS",
        "finding": _finding(
            "Backdoor:EC2/C&CActivity.B",
            "EC2 instance communicated with command and control infrastructure",
            "Runtime security, host isolation, malware detection, and lateral movement monitoring are required.",
            resource_type="Instance",
            api_name="DescribeInstances",
        ),
        "expected": ["IVS", "SEF", "LOG"],
    },
    {
        "name": "LOG",
        "finding": _finding(
            "Stealth:CloudTrail/LoggingDisabled",
            "CloudTrail logging disabled for production trail",
            "Security monitoring, alerting, event analysis, and anomaly reporting visibility were degraded.",
            resource_type="Trail",
            api_name="StopLogging",
        ),
        "expected": ["LOG", "Logging", "SEF"],
    },
    {
        "name": "SEF",
        "finding": _finding(
            "Policy:Incident/ResponsePlanOutdated",
            "Incident response plan and playbook require update",
            "Event triage, breach notification, response plan maintenance, and incident metrics review are needed.",
            resource_type="AwsAccount",
            api_name="UpdateResponsePlan",
        ),
        "expected": ["SEF", "IncidentResponse", "LOG"],
    },
]


class CategorySearchSmokeTests(unittest.TestCase):
    maxDiff = None

    def test_all_category_probes(self) -> None:
        failures: List[str] = []

        for case in CASES:
            primary_query, query_plan = build_guardduty_rag_query(
                case["finding"],
                runtime_result={},
                candidate_actions=[],
            )
            ranked = rerank_retrieved_documents(
                primary_query,
                case["finding"],
                REG_DOCS,
                query_plan=query_plan,
            )
            top_categories = [str(row.get("metadata", {}).get("category", "")) for row in ranked[:5]]
            primary_expected = case["expected"][0]

            expected_window = top_categories[:5] if case["name"] == "IVS" else top_categories[:2]
            if not top_categories or primary_expected not in expected_window:
                failures.append(
                    f"{case['name']}: expected_in_window={primary_expected} actual_top5={top_categories}"
                )

        if failures:
            self.fail("\n".join(failures))


if __name__ == "__main__":
    unittest.main()
