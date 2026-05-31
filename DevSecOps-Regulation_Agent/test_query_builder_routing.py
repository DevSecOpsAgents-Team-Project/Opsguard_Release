import os
import sys
import unittest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from regulation_agent.rag import (  # noqa: E402
    CATEGORY_DOCUMENT_TERMS,
    build_guardduty_rag_query,
    rerank_retrieved_documents,
)


def _make_finding(
    finding_type: str,
    title: str,
    description: str,
    resource_type: str,
    api_name: str = "",
    severity: float = 5.0,
):
    return {
        "type": finding_type,
        "title": title,
        "description": description,
        "severity": severity,
        "resource": {"resourceType": resource_type},
        "service": {"action": {"awsApiCallAction": {"api": api_name}}},
    }


def _make_retrieved_docs():
    docs = []
    for category, terms in CATEGORY_DOCUMENT_TERMS.items():
        docs.append(
            {
                "id": f"{category}-1",
                "metadata": {"category": category, "title": category},
                "document": " ".join(terms),
            }
        )
    return docs


class QueryBuilderRoutingTests(unittest.TestCase):
    maxDiff = None

    def _rank_categories(self, finding):
        primary_query, query_plan = build_guardduty_rag_query(finding, runtime_result={}, candidate_actions=[])
        ranked = rerank_retrieved_documents(
            primary_query,
            finding,
            _make_retrieved_docs(),
            query_plan=query_plan,
        )
        categories = [row["metadata"]["category"] for row in ranked]
        return primary_query, query_plan, categories

    def test_logging_disabled_prefers_log_logging_sef(self):
        finding = _make_finding(
            "Stealth:CloudTrail/LoggingDisabled",
            "CloudTrail logging disabled for production trail",
            "Audit logging was disabled and security event visibility was reduced.",
            "Trail",
            api_name="StopLogging",
        )
        primary_query, query_plan, categories = self._rank_categories(finding)
        self.assertIn("audit logging disabled", primary_query.lower())
        self.assertEqual(query_plan["expected_categories"][:3], ["LOG", "Logging", "SEF"])
        self.assertEqual(categories[:3], ["LOG", "Logging", "SEF"])
        self.assertGreater(categories.index("IAM"), 2)

    def test_malicious_ip_caller_keeps_iam_but_not_only_iam(self):
        finding = _make_finding(
            "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "IAM user invoked API from a known malicious IP address",
            "Credential misuse should be investigated and incident triage should begin.",
            "IAMUser",
            api_name="ListBuckets",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][:4], ["SEF", "LOG", "IncidentResponse", "IAM"])
        self.assertEqual(categories[:4], ["SEF", "LOG", "IncidentResponse", "IAM"])

    def test_s3_delete_prefers_dsp_log_sef(self):
        finding = _make_finding(
            "Impact:S3/AnomalousBehavior.Delete",
            "Suspicious S3 object delete activity",
            "Potential data deletion and disclosure risk affecting sensitive storage.",
            "S3Bucket",
            api_name="DeleteObject",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][:3], ["DSP", "LOG", "SEF"])
        self.assertEqual(categories[:3], ["DSP", "LOG", "SEF"])
        self.assertGreater(categories.index("IAM"), 2)

    def test_privilege_escalation_prefers_iam_accesscontrol_grc(self):
        finding = _make_finding(
            "PrivilegeEscalation:IAMUser/AnomalousBehavior",
            "User attached an elevated policy and assumed privileged role",
            "Potential least privilege failure and governance approval bypass.",
            "IAMUser",
            api_name="AttachUserPolicy",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][:3], ["IAM", "AccessControl", "GRC"])
        self.assertEqual(categories[:3], ["IAM", "AccessControl", "GRC"])

    def test_malware_c2_prefers_sef_ivs_log(self):
        finding = _make_finding(
            "Backdoor:EC2/C&CActivity.B",
            "EC2 instance communicated with command and control infrastructure",
            "Possible malware or C2 activity requiring host isolation and incident containment.",
            "Instance",
            api_name="DescribeInstances",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][:3], ["SEF", "IVS", "LOG"])
        self.assertEqual(categories[:3], ["IVS", "SEF", "LOG"])
        self.assertGreater(categories.index("IAM"), 2)

    def test_iam_anomalous_behavior_defense_evasion_prefers_log_sef_iam(self):
        finding = _make_finding(
            "DefenseEvasion:IAMUser/AnomalousBehavior",
            "Suspicious IAM API activity suggests defense evasion",
            "Anomalous behavior and suspicious_api_activity require security monitoring and incident triage.",
            "AccessKey",
            api_name="AccessDenied",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][0], "LOG")
        self.assertIn("SEF", query_plan["expected_categories"][:4])
        self.assertIn("IAM", query_plan["expected_categories"][:4])
        self.assertEqual(categories[0], "LOG")
        self.assertIn("SEF", categories[:4])
        self.assertGreater(categories.index("CEK"), 2)

    def test_s3_public_access_policy_prefers_dsp(self):
        finding = _make_finding(
            "Policy:S3/BucketPublicAccessGranted",
            "S3 bucket policy granted public access",
            "Public data exposure and s3_misconfiguration require data protection and disclosure review.",
            "S3Bucket",
            api_name="PutBucketPolicy",
        )
        _, query_plan, categories = self._rank_categories(finding)
        self.assertEqual(query_plan["expected_categories"][:2], ["DSP", "LOG"])
        self.assertEqual(categories[0], "DSP")
        self.assertGreater(categories.index("CEK"), 2)


if __name__ == "__main__":
    unittest.main()
