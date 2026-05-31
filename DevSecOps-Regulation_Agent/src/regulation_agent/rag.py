'''
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# Retrieval pool size (Chroma), then rerank and keep top RERANK_OUTPUT_TOP_K for downstream.
RETRIEVAL_TOP_K = 10
RERANK_OUTPUT_TOP_K = 5


def _safe_get(d: Dict[str, Any], path: List[str], default: Any = "") -> Any:
    cur: Any = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def build_guardduty_rag_query(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
    candidate_actions: Optional[List[str]] = None,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    runtime_result = runtime_result or {}
    candidate_actions = candidate_actions or []

    gd_type = _safe_get(finding, ["type"], "")
    gd_sev = _safe_get(finding, ["severity"], "")
    gd_title = _safe_get(finding, ["title"], "") or _safe_get(finding, ["description"], "")
    gd_desc = _safe_get(finding, ["description"], "")

    resource_type = _safe_get(finding, ["resource", "resourceType"], "")
    instance_id = _safe_get(finding, ["resource", "instanceDetails", "instanceId"], "")
    iam_user = _safe_get(finding, ["resource", "accessKeyDetails", "userName"], "")
    access_key_id = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], "")
    api_name = _safe_get(finding, ["service", "action", "awsApiCallAction", "api"], "")
    remote_ip = _safe_get(
        finding,
        ["service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"],
        "",
    )

    runtime_signals = _to_list(runtime_result.get("key_signals"))[:6]
    runtime_tags = _to_list(runtime_result.get("tags"))[:6]

    parts: List[str] = []
    if gd_title:
        parts.append(str(gd_title)[:160])
    if gd_type:
        parts.append(gd_type)
    if resource_type:
        parts.append(f"resource:{resource_type}")
    if iam_user:
        parts.extend(["iam user", iam_user])
    if access_key_id:
        parts.append("access key")
    if instance_id:
        parts.append("ec2 instance")
    if api_name:
        parts.append(f"api:{api_name}")
    if remote_ip:
        parts.append("remote ip")
    if gd_sev != "":
        parts.append(f"severity:{gd_sev}")

    parts.extend(runtime_tags)
    parts.extend(runtime_signals)

    if candidate_actions:
        parts.append("candidate_actions:")
        parts.extend(candidate_actions[:8])

    if gd_desc:
        parts.append(str(gd_desc)[:180])

    query_text = " | ".join([p for p in parts if p and str(p).strip()])

    where_filter: Optional[Dict[str, Any]] = None
    #lowered = " ".join(parts).lower()
    type_and_resource = " ".join([gd_type, str(resource_type)]).lower()
    if any(k in type_and_resource for k in ["access key", "credential", "iam", "excessive privilege", "privilege escalation"]):
        where_filter = {"category": "IAM"}
        
    elif any(k in type_and_resource for k in ["s3", "bucket", "public access", "storage"]):
        where_filter = {"category": "DSP"}
        
    elif any(k in type_and_resource for k in ["ec2", "instance", "crypto", "mining", "malware", "backdoor"]):
        where_filter = {"category": "IVS"}

    return query_text, where_filter


def _doc_text_for_rerank(row: Dict[str, Any]) -> str:
    meta = row.get("metadata") or {}
    title = str(meta.get("title", "") or "")
    body = str(row.get("document", "") or "")
    return f"{title} {body}".lower()


def _domain_keyword_boost(finding: Dict[str, Any], content_lower: str) -> int:
    """Rule-based bonus aligned with finding type / resource (IAM, S3/DSP, EC2/IVS)."""
    gd_type = str(finding.get("type", "")).lower()
    rt = str(_safe_get(finding, ["resource", "resourceType"], "")).lower()
    tr = f"{gd_type} {rt}"
    score = 0
    if any(k in tr for k in ("access key", "credential", "iam", "privilege", "maliciousipcaller")):
        for kw in ("iam", "authentication", "credential", "identity", "access"):
            if kw in content_lower:
                score += 2
    elif any(k in tr for k in ("s3", "bucket", "storage", "public access")):
        for kw in ("logging", "bucket", "data", "encryption", "access"):
            if kw in content_lower:
                score += 2
    elif any(k in tr for k in ("ec2", "instance", "crypto", "mining", "malware", "backdoor")):
        for kw in ("instance", "runtime", "network", "host", "malware"):
            if kw in content_lower:
                score += 2
    return score


def rerank_retrieved_documents(
    query_text: str,
    finding: Dict[str, Any],
    retrieved: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Rule-based rerank: token overlap with query + domain keyword boosts from finding type.
    Returns all rows sorted by score (desc); caller slices to RERANK_OUTPUT_TOP_K.
    """
    if not retrieved:
        return []

    q_lower = (query_text or "").lower()
    query_tokens = [t for t in re.split(r"[\s|]+", q_lower) if len(t) > 1]

    scored: List[Tuple[int, int, Dict[str, Any]]] = []
    for i, row in enumerate(retrieved):
        content_lower = _doc_text_for_rerank(row)
        score = 0
        for tok in query_tokens:
            if tok and tok in content_lower:
                score += 1

        # Query-conditioned boosts (overlap with user-style example)
        if "iam" in q_lower and "iam" in content_lower:
            score += 2
        if "s3" in q_lower and "log" in content_lower:
            score += 2
        if "ec2" in q_lower and "instance" in content_lower:
            score += 2

        score += _domain_keyword_boost(finding, content_lower)

        scored.append((score, i, row))

    scored.sort(key=lambda x: (-x[0], x[1]))
    out = [r for _, __, r in scored]
    preview = [(r.get("id"), s) for s, _, r in scored[: min(RETRIEVAL_TOP_K, len(scored))]]
    _logger.info("rerank_retrieved_documents: (id, score) top=%s", preview)
    return out


def chroma_retrieve(collection: Any, query_text: str, where_filter: Optional[Dict[str, Any]] = None, top_k: int = RETRIEVAL_TOP_K) -> List[Dict[str, Any]]:
    if not query_text.strip():
        return []
    
    
    #print(f"[RAG DEBUG] query: {query_text[:80]}")  # ← 추가
    #print(f"[RAG DEBUG] where_filter: {where_filter}")  
    
    

    kwargs: Dict[str, Any] = {"query_texts": [query_text], "n_results": top_k}
    if where_filter:
        kwargs["where"] = where_filter

    res = collection.query(**kwargs)
    ids = (res.get("ids") or [[]])[0]
    
    #print(f"[RAG DEBUG] result ids: {ids}")
    
    
    metadatas = (res.get("metadatas") or [[]])[0]
    documents = (res.get("documents") or [[]])[0]

    out: List[Dict[str, Any]] = []
    for i in range(min(len(ids), len(metadatas), len(documents))):
        out.append({"id": ids[i], "metadata": metadatas[i] or {}, "document": documents[i] or ""})
    return out


def build_context_chunks(retrieved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chunks: List[Dict[str, Any]] = []
    for row in retrieved:
        meta = row.get("metadata") or {}
        clause_id = row.get("id") or meta.get("clause_id") or meta.get("id")
        chunks.append(
            {
                "doc_type": meta.get("doc_type", meta.get("framework", "")),
                "doc_version": meta.get("doc_version", ""),
                "clause_id": clause_id,
                "title": meta.get("title", ""),
                "category": meta.get("category", ""),
                "mapping_iso27001": meta.get("mapping_iso27001", []) or [],
                "mapping_iso27017": meta.get("mapping_iso27017", []) or [],
                "content": row.get("document", ""),
            }
        )
    return chunks
'''
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

RETRIEVAL_TOP_K = 10
RERANK_OUTPUT_TOP_K = 5
CATEGORY_NAMES: List[str] = [
    "CEK",
    "DSP",
    "GRC",
    "IAM",
    "AccessControl",
    "IncidentResponse",
    "Logging",
    "IVS",
    "LOG",
    "SEF",
]

CATEGORY_LABELS: Dict[str, str] = {
    "CEK": "Cryptography and Key Management",
    "DSP": "Data Security and Privacy",
    "GRC": "Governance, Risk, and Compliance",
    "IAM": "Identity and Access Management",
    "AccessControl": "ISMS-P 2.4 Access Control",
    "IncidentResponse": "ISMS-P 3.1 Incident Response",
    "Logging": "ISMS-P 4.2 Logging",
    "IVS": "Infrastructure and Virtualization Security",
    "LOG": "Security Logging and Monitoring",
    "SEF": "Security Event and Incident Response",
}

CATEGORY_DOCUMENT_TERMS: Dict[str, List[str]] = {
    "LOG": [
        "logging",
        "monitoring",
        "security-related events",
        "audit logging",
        "event analysis",
        "alerting",
        "anomaly reporting",
        "triage event",
        "analyze log pattern",
    ],
    "Logging": [
        "log retention",
        "log integrity",
        "evidence preservation",
        "tampering or deletion protection",
        "audit trail",
        "enable log file validation",
        "preserve evidence",
        "log_action",
    ],
    "SEF": [
        "incident response",
        "event triage",
        "breach notification",
        "response plan",
        "incident metrics",
        "playbook execution",
        "stakeholder notification",
        "business continuity",
        "incident escalation",
    ],
    "IncidentResponse": [
        "incident handling",
        "containment",
        "network isolation",
        "response procedure",
        "assign responsibility",
        "execute playbook",
        "breach response",
        "intrusion response",
        "initial response",
    ],
    "DSP": [
        "data protection",
        "sensitive data",
        "data retention",
        "data deletion",
        "data disclosure",
        "secure disposal",
        "data classification",
        "privacy compliance",
    ],
    "IAM": [
        "least privilege",
        "privileged access",
        "credential",
        "user account",
        "authentication",
        "identity",
        "segregation of privileged access roles",
        "uniquely identifiable users",
    ],
    "AccessControl": [
        "access control",
        "permission grant",
        "permission revoke",
        "privilege review",
        "shared account restriction",
        "administrator separation",
        "access right management",
    ],
    "IVS": [
        "network security",
        "lateral movement",
        "tls ssl",
        "ingress restriction",
        "workload monitoring",
        "malware detection",
        "runtime security",
        "host isolation",
        "compromised workload",
        "command and control",
    ],
    "GRC": [
        "governance",
        "risk management",
        "compliance assessment",
        "accountability",
        "control ownership",
        "audit program",
        "exception process",
        "non-compliance review",
        "leadership oversight",
    ],
    "CEK": [
        "key management",
        "encryption",
        "key rotation",
        "kms key lifecycle",
        "cryptographic change management",
        "certificate management",
        "decrypt encrypt controls",
    ],
}

EVENT_ROUTING_RULES: List[Dict[str, Any]] = [
    {
        "name": "logging_disabled",
        "patterns": [
            "loggingdisabled",
            "logging disabled",
            "cloudtrail logging disabled",
            "stoplogging",
            "deletetrail",
            "disabletrail",
            "audit log disabled",
            "trail was disabled",
        ],
        "weights": {"LOG": 10, "Logging": 9, "SEF": 7, "IncidentResponse": 5, "IAM": -5},
        "security_meanings": [
            "log collection interruption",
            "audit logging disabled",
            "security event visibility gap",
            "monitoring coverage degradation",
        ],
        "regulatory_phrases": [
            "log monitoring",
            "event analysis",
            "audit trail protection",
            "incident triage readiness",
            "log protection",
            "transaction activity logging",
            "log retention",
        ],
        "preferred_doc_ids": ["ISMSP-4.2.3", "LOG-09", "LOG-11", "GRC-07"],
        "downweight_doc_ids": ["LOG-03", "LOG-05"],
    },
    {
        "name": "grc_compliance_issue",
        "patterns": [
            "compliance drift",
            "governance exception",
            "non-compliance",
            "risk acceptance",
            "control ownership",
            "assessment finding",
            "audit finding",
            "policy exception",
        ],
        "weights": {"GRC": 12, "AccessControl": 4, "IAM": -2, "LOG": 2},
        "security_meanings": [
            "governance control gap",
            "risk management escalation",
            "compliance accountability issue",
        ],
        "regulatory_phrases": [
            "risk management program",
            "control ownership",
            "compliance assessment",
            "exception process",
        ],
    },
    {
        "name": "malicious_ip_caller",
        "patterns": [
            "maliciousipcaller",
            "malicious ip",
            "known malicious ip",
            "unauthorizedaccess:iamuser/maliciousipcaller",
        ],
        "weights": {"SEF": 10, "LOG": 9, "IncidentResponse": 6, "IAM": 4, "AccessControl": 2},
        "security_meanings": [
            "suspicious remote access activity",
            "incident triage required",
            "security event investigation",
            "credential misuse should be assessed",
        ],
        "regulatory_phrases": [
            "event triage",
            "alerting and monitoring",
            "incident response procedure",
            "credential review",
        ],
        "preferred_doc_ids": ["SEF-06", "LOG-03", "LOG-05", "ISMSP-3.1.2"],
    },
    {
        "name": "iam_anomalous_behavior_defense_evasion",
        "patterns": [
            "defenseevasion:iamuser/anomalousbehavior",
            "defense_evasion",
            "suspicious_api_activity",
        ],
        "weights": {"LOG": 10, "SEF": 8, "IAM": 6, "IncidentResponse": 4, "CEK": -8},
        "security_meanings": [
            "defense evasion through suspicious api usage",
            "security monitoring and incident triage are required",
            "credential misuse should be reviewed without assuming cryptographic failure",
        ],
        "regulatory_phrases": [
            "security monitoring and alerting",
            "audit logs monitoring and response",
            "incident triage",
            "least privilege review",
        ],
    },
    {
        "name": "iam_anomalous_behavior_recon_discovery",
        "patterns": [
            "recon:iamuser/anomalousbehavior",
            "recon:iamuser/toripcaller",
            "discovery:iamuser/anomalousbehavior",
            "reconnaissance_activity",
            "discovery_activity",
            "tor_ip_access",
            "suspicious_api_calls",
        ],
        "weights": {"IVS": 11, "IncidentResponse": 10, "LOG": 8, "Logging": 7, "IAM": 6, "CEK": -8},
        "security_meanings": [
            "reconnaissance activity should be investigated",
            "monitoring and log review are required",
            "suspicious access patterns require response procedure",
        ],
        "regulatory_phrases": [
            "network defense",
            "failures and anomalies reporting",
            "log review and anomaly analysis",
            "incident handling",
            "remote access investigation",
        ],
        "preferred_doc_ids": ["LOG-13", "ISMSP-4.2.4", "GRC-02", "IVS-09", "ISMSP-3.1.2", "IAM-13", "IAM-16"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "IAM-09", "LOG-05"],
    },
    {
        "name": "iam_anomalous_behavior_impact_persistence",
        "patterns": [
            "impact:iamuser/anomalousbehavior",
            "persistence:iamuser/anomalousbehavior",
            "impact_activity",
            "persistence_activity",
            "attack_in_progress",
        ],
        "weights": {"SEF": 8, "IncidentResponse": 9, "AccessControl": 8, "IAM": 7, "LOG": 7, "Logging": 5, "CEK": -8},
        "security_meanings": [
            "active compromise or persistence behavior",
            "response procedure and containment may be required",
            "access control review should follow incident handling",
        ],
        "regulatory_phrases": [
            "incident response procedure",
            "event triage and escalation",
            "access right management review",
            "audit logs monitoring and response",
            "transaction activity logging",
            "management of privileged access roles",
        ],
        "preferred_doc_ids": ["ISMSP-3.1.2", "SEF-06", "LOG-05", "ISMSP-2.4.1", "IAM-10"],
        "downweight_doc_ids": ["IAM-09", "IAM-13", "IAM-14"],
    },
    {
        "name": "iam_anomalous_behavior_credential_access",
        "patterns": [
            "credentialaccess:iamuser/anomalousbehavior",
            "credential_access",
            "potential_compromise",
        ],
        "weights": {"IAM": 9, "AccessControl": 10, "DSP": 8, "LOG": 7, "SEF": 3, "CEK": -8},
        "security_meanings": [
            "credential compromise risk",
            "access control and privileged account review required",
            "data protection impact should be assessed",
        ],
        "regulatory_phrases": [
            "least privilege",
            "user account control",
            "user identification and authentication",
            "sensitive data protection",
            "audit logs monitoring and response",
        ],
        "preferred_doc_ids": ["ISMSP-2.4.2", "DSP-17", "LOG-05", "IAM-05", "IAM-16"],
        "downweight_doc_ids": ["IAM-09", "IAM-13", "IAM-14"],
    },
    {
        "name": "iam_anomalous_behavior_exfiltration",
        "patterns": [
            "exfiltration:iamuser/anomalousbehavior",
            "data_exfiltration",
            "data disclosure",
        ],
        "weights": {"DSP": 11, "IncidentResponse": 8, "LOG": 7, "IAM": 5, "SEF": 5, "CEK": -8},
        "security_meanings": [
            "data exfiltration risk from compromised credentials",
            "incident response and disclosure review required",
            "data location and transfer controls should be assessed",
        ],
        "regulatory_phrases": [
            "data location",
            "sensitive data transfer",
            "incident handling",
            "audit logs monitoring and response",
        ],
        "preferred_doc_ids": ["DSP-19", "DSP-10", "ISMSP-3.1.2", "IAM-05", "DSP-17"],
    },
    {
        "name": "incident_response_procedure",
        "patterns": [
            "intrusion activity",
            "incident handling",
            "containment required",
            "breach response",
            "response procedure",
            "assign responsibility",
            "initial response",
            "forensic triage",
        ],
        "weights": {"IncidentResponse": 12, "SEF": 8, "LOG": 5, "IAM": -3},
        "security_meanings": [
            "incident response workflow activation",
            "containment and accountability required",
            "formal response procedure needed",
        ],
        "regulatory_phrases": [
            "incident handling",
            "response procedure",
            "assign responsibility",
            "execute playbook",
        ],
    },
    {
        "name": "s3_exfiltration_delete",
        "patterns": [
            "exfiltration:s3",
            "s3/anomalousbehavior.delete",
            "deleteobject",
            "deletebucket",
            "getobject",
            "putobjectacl",
            "data exfiltration",
            "public access",
        ],
        "weights": {"DSP": 10, "LOG": 7, "SEF": 6, "GRC": 3, "IAM": -3},
        "security_meanings": [
            "sensitive data exposure risk",
            "data deletion or disclosure activity",
            "data protection control failure",
            "investigation and notification workflow may be required",
        ],
        "regulatory_phrases": [
            "data protection",
            "sensitive data handling",
            "data disclosure monitoring",
            "secure disposal and retention",
        ],
    },
    {
        "name": "s3_public_access_policy",
        "patterns": [
            "policy:s3/bucketpublicaccessgranted",
            "policy:s3/bucketanonymousaccessgranted",
            "policy:s3/bucketblockpublicaccessdisabled",
            "bucketpublicaccessgranted",
            "bucketanonymousaccessgranted",
            "bucketblockpublicaccessdisabled",
            "public_access_enabled",
            "s3_misconfiguration",
        ],
        "weights": {"DSP": 12, "LOG": 6, "IncidentResponse": 5, "AccessControl": 4, "IAM": 2, "CEK": -8},
        "security_meanings": [
            "public data exposure or disclosure risk",
            "s3 misconfiguration affects data protection controls",
            "monitoring and incident handling should follow policy drift",
        ],
        "regulatory_phrases": [
            "disclosure notification",
            "sensitive data protection",
            "data retention and deletion",
            "audit trail for policy changes",
        ],
    },
    {
        "name": "s3_malicious_ip_access",
        "patterns": [
            "impact:s3/maliciousipcaller",
            "exfiltration:s3/maliciousipcaller",
            "discovery:s3/maliciousipcaller",
            "malicious_ip",
            "s3_access",
            "data_access_attempt",
        ],
        "weights": {"DSP": 11, "IVS": 9, "IncidentResponse": 8, "LOG": 6, "SEF": 4, "IAM": -2, "CEK": -8},
        "security_meanings": [
            "s3 access from malicious infrastructure",
            "network-based attack and data exposure risk",
            "response procedure and network defense should be activated",
        ],
        "regulatory_phrases": [
            "sensitive data protection",
            "sensitive data transfer",
            "network defense",
            "incident handling",
        ],
        "preferred_doc_ids": ["DSP-17", "DSP-10", "IVS-09", "ISMSP-3.1.2", "LOG-05", "LOG-13"],
        "downweight_doc_ids": ["SEF-03", "SEF-05", "SEF-06"],
    },
    {
        "name": "logging_integrity_issue",
        "patterns": [
            "log tampering",
            "audit trail integrity",
            "evidence preservation",
            "log file validation",
            "delete trail",
            "tampering or deletion",
            "preserve evidence",
        ],
        "weights": {"Logging": 12, "LOG": 8, "SEF": 5, "IncidentResponse": 3, "IAM": -4},
        "security_meanings": [
            "audit trail integrity issue",
            "evidence preservation requirement",
            "logging control degradation",
        ],
        "regulatory_phrases": [
            "log retention",
            "log integrity",
            "tampering or deletion protection",
            "enable log file validation",
        ],
    },
    {
        "name": "privilege_escalation",
        "patterns": [
            "privilegeescalation",
            "privilege escalation",
            "attachuserpolicy",
            "attachrolepolicy",
            "putuserpolicy",
            "putrolepolicy",
            "createloginprofile",
            "admin policy",
        ],
        "weights": {"IAM": 10, "AccessControl": 9, "GRC": 7, "LOG": 3, "SEF": 3},
        "security_meanings": [
            "privileged access misuse",
            "authorization control weakness",
            "least privilege failure",
            "governance and approval breakdown",
        ],
        "regulatory_phrases": [
            "least privilege",
            "privileged access review",
            "role segregation",
            "control ownership",
        ],
        "preferred_doc_ids": ["ISMSP-2.4.1", "IAM-05", "GRC-06", "IAM-10"],
        "downweight_doc_ids": ["IAM-09", "IAM-13", "IAM-14"],
    },
    {
        "name": "malware_c2",
        "patterns": [
            "command and control",
            "c2 activity",
            "c2activity",
            "c&cactivity",
            "malware",
            "backdoor",
            "trojan",
            "bitcoin",
            "crypto mining",
            "ransomware",
        ],
        "weights": {"SEF": 16, "IVS": 13, "LOG": 8, "IncidentResponse": -2, "IAM": -4},
        "security_meanings": [
            "compromised workload behavior",
            "containment and host isolation required",
            "runtime security incident",
            "security monitoring escalation needed",
        ],
        "regulatory_phrases": [
            "network isolation",
            "runtime security monitoring",
            "incident containment",
            "malware detection and triage",
        ],
        "preferred_doc_ids": ["SEF-07", "ISMSP-3.1.2", "GRC-06", "IVS-04", "IVS-09"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "SEF-06", "SEF-03"],
    },
    {
        "name": "encryption_key_issue",
        "patterns": [
            "disablekey",
            "schedulekeydeletion",
            "kms",
            "encryption",
            "decrypt",
            "cryptography",
            "key rotation",
        ],
        "weights": {"CEK": 10, "DSP": 6, "GRC": 5, "LOG": 2, "IAM": -2},
        "security_meanings": [
            "cryptographic control degradation",
            "key management lifecycle issue",
            "data confidentiality risk",
            "compliance and governance review needed",
        ],
        "regulatory_phrases": [
            "key management",
            "encryption control",
            "cryptographic change management",
            "compliance assessment",
        ],
    },
    {
        "name": "instance_credential_exfiltration",
        "patterns": [
            "instancecredentialexfiltration.outsideaws",
            "instancecredentialexfiltration.insideaws",
            "credential_exfiltration",
            "external_ip_usage",
        ],
        "weights": {"DSP": 11, "IncidentResponse": 10, "IVS": 9, "IAM": 4, "LOG": 5, "CEK": -8},
        "security_meanings": [
            "instance credentials may have been exfiltrated",
            "compromised workload and unauthorized access require response",
            "data transfer and credential misuse should be investigated",
        ],
        "regulatory_phrases": [
            "incident handling",
            "network isolation",
            "sensitive data transfer",
            "data location",
            "segmentation and segregation",
            "privileged access review",
        ],
        "preferred_doc_ids": ["DSP-10", "DSP-19", "ISMSP-3.1.2", "IVS-03", "IVS-06", "IAM-10"],
        "downweight_doc_ids": ["IAM-09", "IAM-14"],
    },
    {
        "name": "s3_anomalous_write",
        "patterns": [
            "impact:s3/anomalousbehavior.write",
            "anomalous_write_activity",
            "s3_write_attempt",
        ],
        "weights": {"DSP": 11, "IncidentResponse": 7, "LOG": 5, "AccessControl": 3, "IAM": -2, "CEK": -8},
        "security_meanings": [
            "anomalous data write activity may affect integrity or retention",
            "data lifecycle and response procedures should be reviewed",
        ],
        "regulatory_phrases": [
            "data retention and deletion",
            "sensitive data protection",
            "incident handling",
        ],
        "preferred_doc_ids": ["DSP-16", "DSP-17", "ISMSP-3.1.2", "IAM-05", "DSP-19"],
    },
    {
        "name": "kali_linux_pentest",
        "patterns": [
            "pentest:iamuser/kalilinux",
            "kalilinux",
            "kali linux",
            "pentest",
        ],
        "weights": {"IAM": 9, "AccessControl": 8, "IVS": 7, "LOG": 5, "IncidentResponse": 3, "CEK": -8},
        "security_meanings": [
            "penetration testing host invoked sensitive iam apis",
            "authentication and authorization controls should be reviewed",
            "network defense visibility is required",
        ],
        "regulatory_phrases": [
            "strong authentication",
            "user identification and authentication",
            "least privilege",
            "authorization mechanisms",
            "network defense",
        ],
        "preferred_doc_ids": ["IAM-14", "ISMSP-2.4.2", "IAM-05", "IAM-16", "IVS-09", "LOG-03"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "IAM-09", "IAM-13"],
    },
    {
        "name": "runtime_suspicious_command",
        "patterns": [
            "execution:runtime/suspiciouscommand",
            "suspiciouscommand",
            "runtime",
            "execution",
        ],
        "weights": {"IncidentResponse": 10, "SEF": 9, "IVS": 8, "GRC": 6, "LOG": 3, "IAM": -3},
        "security_meanings": [
            "runtime suspicious command indicates active compromise",
            "containment and breach notification procedures are relevant",
            "hardening controls should be reviewed after response",
        ],
        "regulatory_phrases": [
            "incident response and action",
            "security breach notification",
            "os hardening and base controls",
            "governance responsibility model",
        ],
        "preferred_doc_ids": ["ISMSP-3.1.2", "SEF-07", "IVS-04", "GRC-06"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "LOG-03"],
    },
    {
        "name": "network_port_unusual_behavior",
        "patterns": [
            "behavior:ec2/networkportunusual",
            "networkportunusual",
            "unusual_port",
        ],
        "weights": {"IncidentResponse": 10, "SEF": 8, "GRC": 7, "IVS": 7, "LOG": 4, "IAM": -3},
        "security_meanings": [
            "unusual network port behavior requires incident procedure review",
            "governance responsibility and triage should be established",
        ],
        "regulatory_phrases": [
            "incident response procedure",
            "event triage processes",
            "governance responsibility model",
            "network defense",
        ],
        "preferred_doc_ids": ["ISMSP-3.1.1", "SEF-06", "GRC-06", "IVS-09"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "IVS-04"],
    },
    {
        "name": "traffic_volume_unusual_behavior",
        "patterns": [
            "behavior:ec2/trafficvolumeunusual",
            "trafficvolumeunusual",
        ],
        "weights": {"GRC": 9, "SEF": 8, "IVS": 8, "IncidentResponse": 6, "LOG": 3, "IAM": -3},
        "security_meanings": [
            "unusual traffic volume may indicate program-level security monitoring issue",
            "network defense and incident triage should be coordinated",
        ],
        "regulatory_phrases": [
            "information security program",
            "event triage processes",
            "network defense",
            "incident response and action",
        ],
        "preferred_doc_ids": ["GRC-05", "SEF-06", "IVS-09", "ISMSP-3.1.2"],
        "downweight_doc_ids": ["IVS-03", "IVS-06", "IVS-04"],
    },
]

CATEGORY_KEYWORDS: List[Tuple[str, List[str]]] = [
    (
        "Logging",
        [
            "log retention",
            "retain log",
            "retention",
            "audit trail",
            "tamper",
            "integrity",
            "preservation",
            "보관",
            "무결성",
            "위변조",
            "증적",
        ],
    ),
    (
        "SEF",
        [
            "response plan",
            "playbook",
            "runbook",
            "exercise",
            "drill",
            "tabletop",
            "recovery plan",
            "incident response plan",
            "business continuity",
        ],
    ),
    (
        "IncidentResponse",
        [
            "incident response",
            "incident handling",
            "containment",
            "eradication",
            "escalation",
            "triage",
            "forensic",
            "breach response",
            "침해사고",
            "대응 절차",
            "초동 대응",
        ],
    ),
    (
        "AccessControl",
        [
            "least privilege",
            "permission",
            "permissions",
            "grant",
            "revoke",
            "authorization",
            "role-based",
            "rbac",
            "access control",
            "privileged access",
            "접근권한",
            "권한 부여",
            "권한 회수",
        ],
    ),
    (
        "IAM",
        [
            "iam",
            "credential",
            "credentials",
            "identity",
            "access key",
            "secret key",
            "authentication",
            "federation",
            "role",
        ],
    ),
    (
        "DSP",
        [
            "s3",
            "bucket",
            "storage",
            "data protection",
            "privacy",
            "disposal",
            "retention policy",
            "classification",
            "sensitive data",
        ],
    ),
    (
        "IVS",
        [
            "ec2",
            "instance",
            "runtime",
            "host",
            "network security",
            "malware",
            "backdoor",
            "crypto mining",
            "lateral movement",
            "workload",
        ],
    ),
    (
        "CEK",
        [
            "kms",
            "encryption",
            "cryptography",
            "cipher",
            "key rotation",
            "key management",
            "decrypt",
            "encrypt",
            "certificate",
        ],
    ),
    (
        "GRC",
        [
            "compliance",
            "governance",
            "risk",
            "policy",
            "control framework",
            "audit program",
            "assessment",
            "third-party",
            "exception process",
        ],
    ),
    (
        "LOG",
        [
            "cloudtrail",
            "security monitoring",
            "alerting",
            "monitoring",
            "event logging",
            "detection",
            "siem",
        ],
    ),
]

CATEGORY_EXPANSIONS: Dict[str, List[str]] = {
    "LOG": ["logging", "monitoring", "alerting", "cloudtrail", "event logging", "siem"],
    "IAM": ["identity", "authentication", "access key", "credential", "policy", "federation"],
    "DSP": ["data protection", "privacy", "storage", "sensitive data", "disposal", "classification"],
    "IVS": ["runtime security", "instance", "network security", "host", "malware", "workload"],
    "CEK": ["key management", "encryption", "kms", "cryptography", "certificate", "key rotation"],
    "GRC": ["compliance", "governance", "risk management", "control framework", "audit", "assessment"],
    "SEF": ["incident response plan", "playbook", "runbook", "exercise", "recovery plan", "business continuity"],
    "AccessControl": ["least privilege", "authorization", "permission", "role-based access", "grant", "revoke"],
    "IncidentResponse": ["incident handling", "containment", "eradication", "triage", "forensic", "breach response"],
    "Logging": ["log retention", "audit trail", "integrity", "tamper protection", "evidence preservation", "보안 로그"],
}


def _safe_get(d: Dict[str, Any], path: List[str], default: Any = "") -> Any:
    cur: Any = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _append_unique(target: List[str], values: List[str], limit: Optional[int] = None) -> None:
    seen = set(target)
    for value in values:
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            continue
        target.append(cleaned)
        seen.add(cleaned)
        if limit is not None and len(target) >= limit:
            return


def _normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9가-힣:/._ -]+", " ", text.lower())


def _contains_any(text: str, patterns: List[str]) -> bool:
    return any(pattern in text for pattern in patterns)


def _sort_categories(category_weights: Dict[str, int]) -> List[str]:
    positives = [(cat, score) for cat, score in category_weights.items() if score > 0]
    positives.sort(key=lambda item: (-item[1], item[0]))
    return [cat for cat, _ in positives]


def _finding_summary(finding: Dict[str, Any]) -> Dict[str, str]:
    return {
        "type": str(_safe_get(finding, ["type"], "") or ""),
        "title": str(_safe_get(finding, ["title"], "") or ""),
        "description": str(_safe_get(finding, ["description"], "") or ""),
        "resource_type": str(_safe_get(finding, ["resource", "resourceType"], "") or ""),
        "api_name": str(_safe_get(finding, ["service", "action", "awsApiCallAction", "api"], "") or ""),
        "severity": str(_safe_get(finding, ["severity"], "") or ""),
    }


def _build_guardduty_query_plan(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
    candidate_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    runtime_result = runtime_result or {}
    candidate_actions = candidate_actions or []

    summary = _finding_summary(finding)
    runtime_signals = _to_list(runtime_result.get("key_signals"))[:6]
    runtime_tags = _to_list(runtime_result.get("tags"))[:6]

    source_parts = [
        summary["type"],
        summary["title"],
        summary["description"],
        summary["resource_type"],
        summary["api_name"],
        f"severity {summary['severity']}" if summary["severity"] else "",
    ]
    source_summary = " ".join(part for part in source_parts if part).strip()
    lowered = _normalize_text(" ".join(source_parts + runtime_tags + runtime_signals))

    category_weights: Dict[str, int] = {name: 0 for name in CATEGORY_NAMES}
    security_meanings: List[str] = []
    regulatory_phrases: List[str] = []
    matched_rules: List[str] = []
    preferred_doc_ids: List[str] = []

    detected_category = detect_category(source_summary)
    if detected_category:
        category_weights[detected_category] += 2
        _append_unique(regulatory_phrases, CATEGORY_DOCUMENT_TERMS.get(detected_category, []), limit=10)

    for rule in EVENT_ROUTING_RULES:
        if _contains_any(lowered, rule["patterns"]):
            matched_rules.append(str(rule["name"]))
            for category, score in rule["weights"].items():
                category_weights[category] = category_weights.get(category, 0) + int(score)
            _append_unique(security_meanings, rule.get("security_meanings", []), limit=10)
            _append_unique(regulatory_phrases, rule.get("regulatory_phrases", []), limit=12)
            _append_unique(preferred_doc_ids, rule.get("preferred_doc_ids", []), limit=12)

    if not matched_rules:
        if _contains_any(lowered, ["cloudtrail", "log", "logging", "monitor", "audit"]):
            category_weights["LOG"] += 4
            category_weights["Logging"] += 4
        if _contains_any(lowered, ["incident", "breach", "containment", "triage"]):
            category_weights["SEF"] += 3
            category_weights["IncidentResponse"] += 3
        if _contains_any(lowered, ["s3", "bucket", "object", "data"]):
            category_weights["DSP"] += 4
        if _contains_any(lowered, ["ec2", "instance", "host", "runtime", "network"]):
            category_weights["IVS"] += 4
        if _contains_any(lowered, ["kms", "encryption", "decrypt", "cryptography", "certificate", "schedulekeydeletion", "disablekey"]):
            category_weights["CEK"] += 4
        if _contains_any(lowered, ["privilege", "policy", "role", "permission", "access control"]):
            category_weights["AccessControl"] += 4
            category_weights["IAM"] += 4
        if _contains_any(lowered, ["governance", "compliance", "risk", "assessment"]):
            category_weights["GRC"] += 3

    iam_signal = _contains_any(
        lowered,
        [
            "accesskey",
            "access key",
            "iamuser",
            "iam user",
            "credential",
            "credentials",
            "assumerole",
            "login profile",
            "authentication",
        ],
    )
    non_iam_priority_signal = _contains_any(
        lowered,
        [
            "cloudtrail",
            "log",
            "logging",
            "monitor",
            "incident",
            "breach",
            "triage",
            "s3",
            "bucket",
            "data",
            "malware",
            "command and control",
            "backdoor",
            "governance",
            "compliance",
            "risk",
        ],
    )
    if iam_signal and not non_iam_priority_signal:
        category_weights["IAM"] += 1
        category_weights["AccessControl"] += 1

    crypto_signal = _contains_any(
        lowered,
        [
            "kms",
            "encryption",
            "decrypt",
            "encrypt",
            "cryptography",
            "certificate",
            "key rotation",
            "schedulekeydeletion",
            "disablekey",
        ],
    )
    if not crypto_signal and _contains_any(lowered, ["accesskey", "access key", "secret key"]):
        category_weights["CEK"] -= 6

    if _contains_any(lowered, ["privilege escalation", "privilegeescalation", "admin policy", "attachrolepolicy"]):
        category_weights["IAM"] += 4
        category_weights["AccessControl"] += 4

    if _contains_any(lowered, ["logging disabled", "cloudtrail", "stoplogging", "deletetrail"]):
        category_weights["IAM"] -= 2

    if _contains_any(lowered, ["exfiltration:s3", "deleteobject", "deletebucket", "s3/anomalousbehavior.delete"]):
        category_weights["IAM"] -= 2

    if _contains_any(lowered, ["malware", "command and control", "c2", "backdoor", "crypto mining"]):
        category_weights["IAM"] -= 2

    if _contains_any(lowered, ["cloudtrail", "log", "logging", "monitor"]):
        _append_unique(
            security_meanings,
            ["security monitoring issue", "audit visibility requirement"],
            limit=10,
        )
        _append_unique(
            regulatory_phrases,
            ["log monitoring", "audit trail protection", "event analysis"],
            limit=12,
        )

    expected_categories = _sort_categories(category_weights)[:4]
    downweight_hints = [cat for cat, score in category_weights.items() if score < 0]
    negative_hints = list(downweight_hints)

    if not expected_categories and detected_category:
        expected_categories = [detected_category]

    primary_query_parts: List[str] = []
    _append_unique(
        primary_query_parts,
        [
            f"event summary: {source_summary}" if source_summary else "",
            f"runtime signals: {', '.join(runtime_signals[:4])}" if runtime_signals else "",
            f"runtime tags: {', '.join(runtime_tags[:4])}" if runtime_tags else "",
            f"security meaning: {', '.join(security_meanings[:4])}" if security_meanings else "",
            f"regulatory language: {', '.join(regulatory_phrases[:6])}" if regulatory_phrases else "",
            f"expected categories: {', '.join(expected_categories)}" if expected_categories else "",
            f"downweight categories: {', '.join(downweight_hints)}" if downweight_hints else "",
        ],
    )
    primary_query = " | ".join(primary_query_parts)

    category_queries: Dict[str, str] = {}
    for category in expected_categories:
        cat_terms = CATEGORY_DOCUMENT_TERMS.get(category, [])
        cat_parts: List[str] = []
        _append_unique(
            cat_parts,
            [
                CATEGORY_LABELS.get(category, category),
                f"security meaning: {', '.join(security_meanings[:3])}" if security_meanings else "",
                f"regulatory language: {', '.join(cat_terms[:6])}",
                summary["type"],
                summary["resource_type"],
                summary["api_name"],
            ],
        )
        category_queries[category] = " | ".join(part for part in cat_parts if part)

    return {
        "primary_query": primary_query,
        "category_queries": category_queries,
        "negative_hints": negative_hints,
        "downweight_hints": downweight_hints,
        "expected_categories": expected_categories,
        "category_weights": {cat: score for cat, score in category_weights.items() if score != 0},
        "security_meanings": security_meanings,
        "regulatory_phrases": regulatory_phrases,
        "source_summary": source_summary,
        "matched_rules": matched_rules,
        "preferred_doc_ids": preferred_doc_ids,
    }


# -------------------------
# 🔥 Category (힌트용, 필터 아님)
# -------------------------
def detect_category(text: str) -> Optional[str]:
    text = text.lower()

    for category, keywords in CATEGORY_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            return category

    return None


# -------------------------
# 🔥 Query Builder (핵심)
# -------------------------
def build_guardduty_rag_query(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
    candidate_actions: Optional[List[str]] = None,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    plan = _build_guardduty_query_plan(
        finding=finding,
        runtime_result=runtime_result,
        candidate_actions=candidate_actions,
    )
    return str(plan.get("primary_query", "")), plan


# -------------------------
# 🔥 Rerank (핵심)
# -------------------------
def _doc_text_for_rerank(row: Dict[str, Any]) -> str:
    meta = row.get("metadata") or {}
    return f"{meta.get('title', '')} {row.get('document', '')}".lower()


def rerank_retrieved_documents(
    query_text: str,
    finding: Dict[str, Any],
    retrieved: List[Dict[str, Any]],
    query_plan: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:

    if not retrieved:
        return []

    if query_plan is None:
        query_plan = _build_guardduty_query_plan(finding=finding, runtime_result=None, candidate_actions=None)

    query_sources = [query_text]
    query_sources.extend(list((query_plan.get("category_queries") or {}).values()))
    tokens: List[str] = []
    for source in query_sources:
        tokens.extend([t for t in re.split(r"[|\s,:]+", source.lower()) if len(t) > 2])

    expected_categories = set(query_plan.get("expected_categories") or [])
    expected_order = list(query_plan.get("expected_categories") or [])
    downweight_hints = set(query_plan.get("downweight_hints") or [])
    category_weights = query_plan.get("category_weights") or {}
    regulatory_phrases = [p.lower() for p in (query_plan.get("regulatory_phrases") or [])]
    security_meanings = [p.lower() for p in (query_plan.get("security_meanings") or [])]
    preferred_doc_ids = list(query_plan.get("preferred_doc_ids") or [])
    downweight_doc_ids = set(query_plan.get("downweight_doc_ids") or [])

    scored = []

    for i, row in enumerate(retrieved):
        content = _doc_text_for_rerank(row)
        doc_category = str((row.get("metadata", {}).get("category") or "")).strip()
        doc_category_lower = doc_category.lower()
        doc_id = str(row.get("id") or row.get("metadata", {}).get("clause_id") or "")

        score = 0

        for tok in tokens:
            if tok in content:
                score += 1

        regulatory_hits = sum(1 for phrase in regulatory_phrases[:8] if phrase and phrase in content)
        security_hits = sum(1 for phrase in security_meanings[:6] if phrase and phrase in content)
        score += min(2, regulatory_hits) * 3
        score += min(2, security_hits) * 2

        score += int(row.get("_query_hits", 1)) * 2
        best_rank = int(row.get("_best_rank", i))
        score += max(0, 3 - best_rank)

        weight = int(category_weights.get(doc_category, 0))
        score += weight * 4

        if doc_category in expected_categories:
            score += max(4, 16 - (expected_order.index(doc_category) * 4))

        if doc_category in downweight_hints:
            score -= max(6, abs(weight) * 3)

        if doc_id in preferred_doc_ids:
            score += max(8, 24 - (preferred_doc_ids.index(doc_id) * 2))

        if doc_id in downweight_doc_ids:
            score -= 10

        if doc_category == "IAM" and doc_category not in expected_categories:
            if any(cat in expected_categories for cat in ("LOG", "Logging", "SEF", "IncidentResponse", "DSP", "IVS")):
                score -= 5

        if doc_category in ("AccessControl", "IAM") and any(
            cat in expected_categories for cat in ("LOG", "Logging")
        ) and "privilege" not in query_text.lower():
            score -= 3

        scored.append((score, i, row))

    scored.sort(key=lambda x: (-x[0], x[1]))

    return [r for _, __, r in scored]


# -------------------------
# Retrieve
# -------------------------
def chroma_retrieve(collection, query_text, where_filter=None, top_k=RETRIEVAL_TOP_K):

    if not query_text.strip():
        return []

    query_plan = where_filter if isinstance(where_filter, dict) and "primary_query" in where_filter else None
    raw_where = None
    if isinstance(where_filter, dict) and "where" in where_filter:
        raw_where = where_filter.get("where")

    query_entries: List[Tuple[str, str, int]] = [("primary", query_text, top_k)]
    if query_plan:
        for category in query_plan.get("expected_categories", [])[:4]:
            category_query = (query_plan.get("category_queries") or {}).get(category)
            if category_query:
                query_entries.append((category, category_query, max(3, min(top_k, 5))))

    merged: Dict[str, Dict[str, Any]] = {}
    for source_name, query_value, n_results in query_entries:
        kwargs: Dict[str, Any] = {"query_texts": [query_value], "n_results": n_results}
        if raw_where:
            kwargs["where"] = raw_where

        res = collection.query(**kwargs)
        ids = (res.get("ids") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]

        for i in range(min(len(ids), len(metas), len(docs))):
            doc_id = ids[i]
            if doc_id not in merged:
                merged[doc_id] = {
                    "id": doc_id,
                    "metadata": metas[i] or {},
                    "document": docs[i] or "",
                    "_query_hits": 1,
                    "_query_sources": [source_name],
                    "_best_rank": i,
                }
                continue

            merged[doc_id]["_query_hits"] = int(merged[doc_id].get("_query_hits", 1)) + 1
            merged[doc_id]["_best_rank"] = min(int(merged[doc_id].get("_best_rank", i)), i)
            sources = merged[doc_id].setdefault("_query_sources", [])
            if source_name not in sources:
                sources.append(source_name)

    out = list(merged.values())
    out.sort(key=lambda row: (-int(row.get("_query_hits", 1)), int(row.get("_best_rank", 0)), str(row.get("id", ""))))
    return out


# -------------------------
# Context Builder
# -------------------------
def build_context_chunks(retrieved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chunks = []

    for row in retrieved:
        meta = row.get("metadata") or {}

        chunks.append({
            "doc_type": meta.get("doc_type", ""),
            "clause_id": row.get("id"),
            "title": meta.get("title", ""),
            "category": meta.get("category", ""),
            "content": row.get("document", ""),
        })

    return chunks
