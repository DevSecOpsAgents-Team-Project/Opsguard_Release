from __future__ import annotations

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Chroma는 sqlite3 >= 3.35 필요. Lambda 런타임 기본 sqlite가 낮을 수 있어 pysqlite3로 대체.
try:
    __import__("pysqlite3")
    import sys

    sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")
except ImportError:
    pass

import sqlite3

_logger = logging.getLogger(__name__)
_logger.info("sqlite_version=%s (effective before chromadb import)", sqlite3.sqlite_version)

import chromadb
from chromadb.config import Settings
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import ValidationError

from level_router import decide_response_level
from severity_decision import decide_severity_level_with_xai

from .prompt import SYSTEM_PROMPT
from .chroma_repair import repair_chroma_sqlite
from .rag import (
    RERANK_OUTPUT_TOP_K,
    RETRIEVAL_TOP_K,
    build_context_chunks,
    build_guardduty_rag_query,
    chroma_retrieve,
    rerank_retrieved_documents,
)

load_dotenv()
from .output_contract import (
    finalize_output_contract,
    iter_all_playbook_dicts,
    validate_output_contract,
)
from .schemas import RegulationAgentIntermediate, RegulationAgentOutput

DEFAULT_CANDIDATE_ACTIONS = [
    "disable_access_key",
    "detach_admin_policies",
    "disable_iam_entity",
    "isolate_instance",
    "stop_instance",
    "create_snapshot",
    "backup_instance",
    "block_ip",
    "enable_vpc_flow_logs",
    "block_s3_public_access",
    "enable_s3_bucket_logging",
]

OUTPUT_JSON_SKELETON = {
    "schema_version": "1.2",
    "generated_at": "2026-01-01T00:00:00Z",
    "incident_id": "gd-incident-id",
    "scenario": "CredentialCompromise",
    "incident_summary": {
        "source": "guardduty",
        "title": "string",
        "severity": "5.0",
        "resource": {
            "type": "AccessKey",
            "id": "AKIA...",
            "region": "ap-northeast-2",
            "account_id": "123456789012",
        },
    },
    "executed_level1_actions": ["record_finding"],
    "escalation_assessment": {
        "escalation_needed": True,
        "recommended_level": 2,
        "confidence": 0.8,
        "decision_questions": ["승인 전 어떤 영향 범위를 확인할까요?"],
        "approval_notes": "승인형 조치입니다.",
    },
    "reasoning_bullets": ["규제 근거 기반 판단"],
    "regulations": [
        {
            "framework": "CSA CCM",
            "clause_id": "IVS-01",
            "clause_title": "clause title",
            "relevance": 0.7,
            "excerpt": "retrieved excerpt",
            "why_relevant": "reason",
        }
    ],
    "recommended_actions": [
        {
            "playbook_name": "Credential Containment",
            "description": "Containment actions based on regulation context and related_actions from context_chunks.",
            "level": 2,
            "requires_approval": True,
            "expected_impact": "MEDIUM",
            "actions": [
                {
                    "action_id": "action_from_related_actions",
                    "targets": [{"type": "ResourceType", "id": "actual-resource-id"}],
                },
                {
                    "action_id": "action_from_related_actions",
                    "targets": [{"type": "ResourceType", "id": "actual-resource-id"}],
                },
            ],
        },
        {
            "playbook_name": "Network Isolation and Mitigation",
            "description": "Aggressive isolation actions based on regulation context and related_actions from context_chunks.",
            "level": 3,
            "requires_approval": True,
            "expected_impact": "HIGH",
            "actions": [
                {
                    "action_id": "action_from_related_actions",
                    "targets": [{"type": "ResourceType", "id": "actual-resource-id"}],
                },
                {
                    "action_id": "action_from_related_actions",
                    "targets": [{"type": "ResourceType", "id": "actual-resource-id"}],
                },
            ],
        },
    ],
    "insufficient_context": False,
    "missing_context_requests": [],
}

_collection: Optional[Any] = None
_lambda_runtime_chroma_dir: Optional[str] = None


def _get_effective_chroma_dir() -> str:
    """
    로컬: CHROMA_PERSIST_DIR 또는 ./chroma_db (절대경로).
    Lambda: /var/task/chroma_db 는 읽기 전용이므로 번들을 /tmp/... 로 복사한 뒤 그 경로만 사용.
    """
    global _lambda_runtime_chroma_dir

    default_rel = "./chroma_db"
    env_dir = os.environ.get("CHROMA_PERSIST_DIR", default_rel)

    if not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        out = os.path.abspath(os.path.expanduser(env_dir))
        _logger.info(
            "chroma_dir_resolve: local mode chroma_dir=%s sqlite=%s",
            out,
            os.path.join(out, "chroma.sqlite3"),
        )
        return out

    if _lambda_runtime_chroma_dir is not None:
        d = _lambda_runtime_chroma_dir
        _logger.info(
            "chroma_dir_resolve: lambda cache hit runtime_dir=%s sqlite=%s",
            d,
            os.path.join(d, "chroma.sqlite3"),
        )
        return d

    task_root = os.environ.get("LAMBDA_TASK_ROOT", "/var/task")
    source_dir = os.path.join(task_root, "chroma_db")
    runtime_dir = env_dir if env_dir.startswith("/tmp") else "/tmp/chroma_db"
    if env_dir and not env_dir.startswith("/tmp") and env_dir != default_rel:
        _logger.warning(
            "chroma_dir_resolve: Lambda에서 CHROMA_PERSIST_DIR=%s 는 /var/task 등 쓰기 불가일 수 있어 /tmp/chroma_db 사용",
            env_dir,
        )
    runtime_dir = os.path.abspath(runtime_dir)

    sqlite_path = os.path.join(runtime_dir, "chroma.sqlite3")
    _logger.info(
        "chroma_dir_resolve: lambda bundled_source=%s runtime_dir=%s sqlite_target=%s",
        source_dir,
        runtime_dir,
        sqlite_path,
    )

    if os.path.isfile(sqlite_path):
        _logger.info("chroma_dir_resolve: runtime sqlite already present, skip copy")
    elif os.path.isdir(source_dir):
        parent = os.path.dirname(runtime_dir.rstrip(os.sep)) or "/tmp"
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(runtime_dir):
            shutil.rmtree(runtime_dir)
        shutil.copytree(source_dir, runtime_dir)
        _logger.info("chroma_dir_resolve: copied %s -> %s", source_dir, runtime_dir)
    else:
        _logger.warning(
            "chroma_dir_resolve: bundled chroma missing at %s; mkdir runtime %s",
            source_dir,
            runtime_dir,
        )
        os.makedirs(runtime_dir, exist_ok=True)

    _lambda_runtime_chroma_dir = runtime_dir
    return runtime_dir


def _get_collection() -> Any:
    global _collection
    if _collection is not None:
        return _collection

    chroma_dir = _get_effective_chroma_dir()
    collection_name = os.environ.get("CHROMA_COLLECTION", "csa_ccm_v4")

    sqlite_file = os.path.join(chroma_dir, "chroma.sqlite3")
    _logger.info(
        "chroma_client: chroma_dir=%s chroma_sqlite_path=%s",
        chroma_dir,
        sqlite_file,
    )

    skip_repair = os.environ.get("CHROMA_SKIP_REPAIR", "").lower() in ("1", "true", "yes")
    if skip_repair:
        _logger.info("chroma_client: CHROMA_SKIP_REPAIR=true — skipping repair_chroma_sqlite")
    else:
        # KeyError '_type' 등 구버전 chroma.sqlite3 메타데이터 자동 보정 (쓰기 가능한 경로만)
        repair_chroma_sqlite(chroma_dir)

    api_key = os.environ.get("CHROMA_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing CHROMA_OPENAI_API_KEY or OPENAI_API_KEY")

    # NOTE:
    # chromadb의 OpenAIEmbeddingFunction은 openai 2.x에서 레거시 API(openai.Embedding)를 호출해
    # `APIRemovedInV1...` 류 오류를 유발할 수 있다. 이 프로젝트는 openai==2.x를 사용하므로,
    # OpenAI 공식 클라이언트(OpenAI().embeddings.create)를 사용하는 embedding function을 직접 제공한다.
    class _OpenAIEmbeddingFunction:
        def __init__(self, api_key: str, model_name: str) -> None:
            self._client = OpenAI(api_key=api_key)
            self._model_name = model_name

        def __call__(self, input: Any) -> Any:
            texts = [str(t).replace("\n", " ") for t in (input or [])]
            if not texts:
                return []
            resp = self._client.embeddings.create(model=self._model_name, input=texts)
            data = sorted(resp.data, key=lambda e: e.index)
            return [d.embedding for d in data]

    ef = _OpenAIEmbeddingFunction(api_key=api_key, model_name="text-embedding-3-large")

    client = chromadb.PersistentClient(
        path=chroma_dir,
        settings=Settings(anonymized_telemetry=False),
    )
    _collection = client.get_collection(
        name=collection_name,
        embedding_function=ef
    )
    return _collection

def _safe_get(d: Dict[str, Any], path: List[str], default: Any = "") -> Any:
    cur: Any = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _apply_finding_targets_to_playbooks(result: Dict[str, Any], finding: Dict[str, Any]) -> None:
    """Fill resource IDs / IPs on every playbook present in the response dict."""
    access_key_id = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], "")
    instance_id = _safe_get(finding, ["resource", "instanceDetails", "instanceId"], "")
    bucket_name = ""
    s3_details = finding.get("resource", {}).get("s3BucketDetails", [])
    if isinstance(s3_details, list) and len(s3_details) > 0:
        bucket_name = s3_details[0].get("name", "")
    resource_id = access_key_id or instance_id or bucket_name or finding.get("id", "unknown-resource")

    if result.get("incident_summary", {}).get("resource"):
        result["incident_summary"]["resource"]["id"] = resource_id

    remote_ip = _safe_get(
        finding,
        ["service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"],
        "",
    )
    iam_user = _safe_get(finding, ["resource", "accessKeyDetails", "userName"], "")

    for playbook in iter_all_playbook_dicts(result):
        if bucket_name:
            for action in playbook.get("actions", []) or []:
                for target in action.get("targets", []) or []:
                    if target.get("type") == "S3Bucket":
                        target["id"] = bucket_name
        if remote_ip:
            for action in playbook.get("actions", []) or []:
                if action.get("action_id") == "block_ip":
                    for target in action.get("targets", []) or []:
                        if not target.get("ip"):
                            target["ip"] = remote_ip
                            target["id"] = None
        if iam_user:
            for action in playbook.get("actions", []) or []:
                for target in action.get("targets", []) or []:
                    if target.get("type") in ("AccessKey", "IAMUser") and not target.get("user_name"):
                        target["user_name"] = iam_user

        for action in playbook.get("actions", []) or []:
            aid = action.get("action_id")
            if aid == "disable_access_key" and access_key_id and iam_user:
                targets = action.get("targets") or []
                if not targets:
                    action["targets"] = [
                        {"type": "AccessKey", "id": access_key_id, "user_name": iam_user}
                    ]
                for target in targets:
                    if not target.get("id"):
                        target["id"] = access_key_id
                    if not target.get("user_name"):
                        target["user_name"] = iam_user
            elif aid in ("disable_iam_entity", "detach_admin_policies") and iam_user:
                targets = action.get("targets") or []
                if not targets:
                    action["targets"] = [
                        {"type": "IAMUser", "id": iam_user, "user_name": iam_user}
                    ]
                for target in targets:
                    if not target.get("user_name"):
                        target["user_name"] = iam_user
                    tid = target.get("id")
                    if not tid or str(tid).startswith(("AKIA", "ASIA", "AROA", "AIDA")):
                        target["id"] = iam_user
                    elif not target.get("user_name"):
                        target["user_name"] = str(tid).strip()


def _build_security_event(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding_type = str(finding.get("type", "")).lower()
    resource_type = _safe_get(finding, ["resource", "resourceType"], "Unknown")
    access_key_details = _safe_get(finding, ["resource", "accessKeyDetails"], {})

    if access_key_details:
        exposure = "public"
    elif "internal" in finding_type or "private" in finding_type:
        exposure = "internal"
    else:
        exposure = "internal"

    privilege_impact = any(keyword in finding_type for keyword in ["privilege", "escalation", "admin", "root"])

    severity_score = float(finding.get("severity", 0.0) or 0.0)
    if severity_score >= 7.0:
        data_sensitivity = "high"
    elif severity_score >= 4.0:
        data_sensitivity = "medium"
    else:
        data_sensitivity = "low"

    return {
        "event_type": finding.get("type", "Unknown"),
        "resource_type": resource_type,
        "exposure": exposure,
        "privilege_impact": privilege_impact,
        "data_sensitivity": data_sensitivity,
    }


def _infer_scenario(finding: Dict[str, Any], runtime_result: Dict[str, Any]) -> str:
    text = " ".join(
        [
            str(finding.get("type", "")),
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            " ".join([str(x) for x in runtime_result.get("key_signals", [])]),
            " ".join([str(x) for x in runtime_result.get("tags", [])]),
        ]
    ).lower()

    if any(k in text for k in ["ransom", "trojan", "malware", "backdoor"]):
        return "MalwareOutbreak"
    if any(k in text for k in ["crypto", "mining"]):
        return "CryptoMining"
    if any(k in text for k in ["exfiltration", "leak", "data exfiltration"]):
        return "DataExfiltration"
    if any(k in text for k in ["accesskey", "credential", "iam", "unauthorizedaccess"]):
        return "CredentialCompromise"
    return "SuspiciousActivity"


def _build_incident_input(
    finding: Dict[str, Any],
    executed_level1_actions: List[str],
    candidate_actions: List[str],
    severity_result: Dict[str, Any],
    scenario: str,
) -> Dict[str, Any]:
    resource_type = _safe_get(finding, ["resource", "resourceType"], "Unknown")
    access_key_id = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], "")
    instance_id = _safe_get(finding, ["resource", "instanceDetails", "instanceId"], "")
    resource_id = access_key_id or instance_id or finding.get("id", "unknown-resource")

    return {
        "schema_version": "1.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": finding.get("id", "unknown-incident"),
        "scenario": scenario,
        "incident_summary": {
            "source": "guardduty",
            "title": finding.get("title", finding.get("description", "GuardDuty finding")),
            "severity": str(finding.get("severity", "")),
            "resource": {
                "type": resource_type,
                "id": resource_id,
                "region": finding.get("region", "unknown"),
                "account_id": finding.get("accountId", "unknown"),
            },
        },
        "executed_level1_actions": executed_level1_actions,
        "candidate_actions": candidate_actions,
        "severity_decision_result": severity_result,
    }


def _call_llm_json(payload: Dict[str, Any], model: str) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY")

    client = OpenAI(api_key=api_key)
    user_prompt = (
        "INPUT_JSON:\n"
        f"{json.dumps(payload, ensure_ascii=False)}\n\n"
        "OUTPUT_JSON_SKELETON (keep same keys/shape):\n"
        f"{json.dumps(OUTPUT_JSON_SKELETON, ensure_ascii=False)}\n\n"
        "RULES:\n"
        "- Return only JSON.\n"
        "- Do not add extra keys.\n"
        f"- When insufficient_context is false, regulations array length MUST equal len(context_chunks) in INPUT_JSON (max {RERANK_OUTPUT_TOP_K}), same order as chunks.\n"
        "- recommended_actions must include multiple playbooks when incident scope is broad.\n"
        "- each playbook must include multiple actions where applicable.\n"
        "- playbook_name: short English Title Case phrase (e.g. Credential Containment, Access Review and Remediation); "
        "never generic names like Containment Playbook or Isolation Playbook.\n"
        "- approval_notes, reasoning_bullets, regulations[].why_relevant, justification: write in Korean; "
        "each bullet must mention incident resource/behavior and proposed actions.\n"
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content or ""


def _normalize_recommended_actions_shape(parsed: Dict[str, Any], scenario: str) -> Dict[str, Any]:
    if not parsed.get("scenario"):
        parsed["scenario"] = scenario

    recommended = parsed.get("recommended_actions")
    if not isinstance(recommended, list):
        parsed["recommended_actions"] = []
        return parsed
    if not recommended:
        return parsed

    first = recommended[0]
    if isinstance(first, dict) and "action_id" in first:
        rec_level = parsed.get("escalation_assessment", {}).get("recommended_level", 2)
        playbook_level = rec_level if rec_level in (2, 3) else 2
        recommended = [
            {
                "playbook_name": "Auto Converted Playbook",
                "description": "Converted from legacy action list.",
                "level": playbook_level,
                "requires_approval": True,
                "expected_impact": "MEDIUM",
                "actions": recommended,
            }
        ]

    normalized: List[Dict[str, Any]] = []
    for idx, pb in enumerate(recommended, start=1):
        if not isinstance(pb, dict):
            continue
        if "playbook_name" not in pb:
            pb["playbook_name"] = pb.get("title", f"Playbook {idx}")
        pb.setdefault("playbook_name", f"Playbook {idx}")
        pb.setdefault("description", "Auto normalized playbook.")
        pb.setdefault("requires_approval", True)
        pb.setdefault("expected_impact", "MEDIUM")
        
        # CRITICAL 등 잘못된 값 보정
        if pb.get("expected_impact") not in ("LOW", "MEDIUM", "HIGH"):
            pb["expected_impact"] = "HIGH"

        pb_level = pb.get("level", 2)
        if pb_level not in (2, 3):
            pb_level = 2
            pb["level"] = 2

        actions = pb.get("actions")
        if not isinstance(actions, list):
            pb["actions"] = []
            actions = pb["actions"]

        fixed_actions: List[Dict[str, Any]] = []
        for act in actions:
            if not isinstance(act, dict) or "action_id" not in act:
                continue
            if not isinstance(act.get("targets"), list):
                act["targets"] = []
            fixed_actions.append(
                {
                    "action_id": act["action_id"],
                    "targets": act["targets"],
                }
            )

        if fixed_actions:
            normalized.append(
                {
                    "level": pb_level,
                    "playbook_name": pb["playbook_name"],
                    "description": pb["description"],
                    "actions": fixed_actions,
                    "requires_approval": True,
                    "expected_impact": pb["expected_impact"],
                }
            )

    parsed["recommended_actions"] = normalized
    return parsed


def _playbook_names_for_incident(scenario: str, finding: Dict[str, Any]) -> tuple[str, str]:
    """Short English Title Case names for Level 2 / Level 3 (rule-based path)."""
    rt = str(_safe_get(finding, ["resource", "resourceType"], "")).lower()
    gd = str(finding.get("type", "")).lower()
    if "s3" in rt or "bucket" in gd:
        return ("S3 Bucket Security Enhancement", "Data Compliance Review")
    if scenario == "CredentialCompromise":
        return ("Credential Containment", "Access Review and Remediation")
    if scenario == "CryptoMining":
        return ("Enhanced Monitoring Setup", "Network Isolation and Mitigation")
    if scenario == "MalwareOutbreak":
        return ("Threat Containment and Eradication", "Network Isolation and Mitigation")
    if scenario == "DataExfiltration":
        return ("Data Flow Restrictions", "Incident Isolation and Forensics")
    return ("Targeted Containment", "Expanded Isolation and Review")


def _build_rule_based_playbooks(
    finding: Dict[str, Any],
    candidate_actions: List[str],
    response_targets: Dict[str, Any],
    scenario: str,
) -> List[Dict[str, Any]]:
    access_key = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], None)
    iam_user = _safe_get(finding, ["resource", "accessKeyDetails", "userName"], None)
    source_ip = response_targets.get("source_ip") or _safe_get(
        finding,
        ["service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"],
        None,
    )
    instance_id = response_targets.get("instance_id") or _safe_get(finding, ["resource", "instanceDetails", "instanceId"], None)
    vpc_id = response_targets.get("vpc_id")
    bucket = response_targets.get("bucket")
    log_bucket = response_targets.get("log_bucket")

    l2_actions: List[Dict[str, Any]] = []
    if "disable_access_key" in candidate_actions and access_key:
        l2_actions.append(
            {
                "action_id": "disable_access_key",
                "targets": [{"type": "AccessKey", "id": access_key, "user_name": iam_user}],
            }
        )
    if "block_ip" in candidate_actions and source_ip:
        l2_actions.append({"action_id": "block_ip", "targets": [{"type": "IPAddress", "ip": source_ip}]})
    if "detach_admin_policies" in candidate_actions and iam_user:
        l2_actions.append(
            {
                "action_id": "detach_admin_policies",
                "targets": [{"type": "IAMUser", "id": iam_user, "user_name": iam_user}],
            }
        )

    l3_actions: List[Dict[str, Any]] = []
    if instance_id:
        for action_id in ["isolate_instance", "create_snapshot", "backup_instance", "stop_instance"]:
            if action_id in candidate_actions:
                l3_actions.append({"action_id": action_id, "targets": [{"type": "EC2Instance", "id": instance_id}]})
    if "disable_iam_entity" in candidate_actions and iam_user:
        l3_actions.append(
            {
                "action_id": "disable_iam_entity",
                "targets": [{"type": "IAMUser", "id": iam_user, "user_name": iam_user}],
            }
        )
    if "enable_vpc_flow_logs" in candidate_actions and vpc_id:
        l3_actions.append({"action_id": "enable_vpc_flow_logs", "targets": [{"type": "VPC", "id": vpc_id}]})
    if "block_s3_public_access" in candidate_actions and bucket:
        l3_actions.append({"action_id": "block_s3_public_access", "targets": [{"type": "S3Bucket", "id": bucket}]})
    if "enable_s3_bucket_logging" in candidate_actions and bucket:
        l3_actions.append(
            {
                "action_id": "enable_s3_bucket_logging",
                "targets": [{"type": "S3Bucket", "id": bucket, "target_bucket": log_bucket}],
            }
        )
    if "block_ip" in candidate_actions and source_ip and not any(a["action_id"] == "block_ip" for a in l3_actions):
        l3_actions.append({"action_id": "block_ip", "targets": [{"type": "IPAddress", "ip": source_ip}]})

    l2_title, l3_title = _playbook_names_for_incident(scenario, finding)

    playbooks: List[Dict[str, Any]] = []
    if l2_actions:
        playbooks.append(
            {
                "playbook_name": l2_title,
                "description": "Lower-impact containment aligned with retrieved regulation context.",
                "level": 2,
                "requires_approval": True,
                "expected_impact": "LOW",
                "actions": l2_actions,
            }
        )
    if l3_actions:
        playbooks.append(
            {
                "playbook_name": l3_title,
                "description": "Stronger isolation and evidence-preserving escalation.",
                "level": 3,
                "requires_approval": True,
                "expected_impact": "HIGH",
                "actions": l3_actions,
            }
        )

    return playbooks


def _rule_based_why_relevant_ko(
    clause_id: str,
    clause_title: str,
    incident_summary: Dict[str, Any],
    action_ids: List[str],
) -> str:
    resource = incident_summary.get("resource") or {}
    rid = resource.get("id") or resource.get("type") or "해당 리소스"
    actions = ", ".join(action_ids[:3]) if action_ids else "제안 조치"
    title = clause_title or clause_id
    return (
        f"탐지된 {rid} 이(가) `{clause_id}` {title} 통제와 연관되어 "
        f"{actions} 등의 후속 조치가 필요합니다."
    )


def _build_rule_based_output(
    incident_input: Dict[str, Any],
    severity_result: Dict[str, Any],
    retrieved: List[Dict[str, Any]],
    candidate_actions: List[str],
    response_targets: Dict[str, Any],
) -> RegulationAgentIntermediate:
    finding = incident_input.get("_finding_raw", {})
    scenario = incident_input["scenario"]
    incident_summary = incident_input["incident_summary"]
    resource = incident_summary.get("resource") or {}
    rid = resource.get("id") or "해당 리소스"
    action_ids = candidate_actions[:5]

    regulations = []
    for row in retrieved[:RERANK_OUTPUT_TOP_K]:
        meta = row.get("metadata") or {}
        cid = row.get("id", "N/A")
        title = meta.get("title", "")
        regulations.append(
            {
                "framework": meta.get("doc_type", "CSA_CCM"),
                "clause_id": cid,
                "clause_title": title,
                "relevance": 0.8,
                "excerpt": (row.get("document", "") or "")[:220],
                "why_relevant": _rule_based_why_relevant_ko(cid, title, incident_summary, action_ids),
            }
        )

    playbooks = _build_rule_based_playbooks(finding, candidate_actions, response_targets, scenario)
    rec_level = 3 if any(pb.get("level") == 3 for pb in playbooks) else 2

    raw = {
        "schema_version": "1.2",
        "generated_at": incident_input["generated_at"],
        "incident_id": incident_input["incident_id"],
        "scenario": scenario,
        "incident_summary": incident_input["incident_summary"],
        "executed_level1_actions": incident_input["executed_level1_actions"],
        "escalation_assessment": {
            "escalation_needed": True,
            "recommended_level": rec_level,
            "confidence": 0.9,
            "decision_questions": [
                "Do you approve escalation actions (Level 2/3) for this multi-surface incident?"
            ],
            "approval_notes": (
                f"Level 1 완료 후 {rid} 관련 추가 피해 확산 방지를 위해 "
                f"Level {rec_level} 플레이북 승인이 필요합니다."
            ),
        },
        "reasoning_bullets": [
            f"GuardDuty가 {rid}에 대한 {scenario} 유형 이벤트를 탐지했습니다.",
            f"규제 검색 결과와 후보 조치({', '.join(action_ids[:4])})를 반영해 Level 2/3 플레이북을 구성했습니다.",
        ],
        "regulations": regulations,
        "recommended_actions": playbooks,
        "insufficient_context": False,
        "missing_context_requests": [],
    }

    raw = _normalize_recommended_actions_shape(raw, scenario)
    return RegulationAgentIntermediate.model_validate(raw)


def _align_regulations_to_chunks(
    parsed: Dict[str, Any],
    context_chunks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    LLM이 regulations를 일부만 줄 때도 context_chunks와 동일 개수·순서로 맞춘다.
    insufficient_context 이면 손대지 않는다.
    """
    if not context_chunks or parsed.get("insufficient_context"):
        return parsed
    regs_in = parsed.get("regulations") or []
    if not isinstance(regs_in, list):
        regs_in = []
    by_clause_id: Dict[str, Dict[str, Any]] = {}
    for r in regs_in:
        if isinstance(r, dict) and r.get("clause_id") is not None:
            by_clause_id[str(r["clause_id"])] = r

    out: List[Dict[str, Any]] = []
    for ch in context_chunks[:RERANK_OUTPUT_TOP_K]:
        cid = str(ch.get("clause_id") or "")
        if cid and cid in by_clause_id:
            out.append(by_clause_id[cid])
        else:
            fw = ch.get("doc_type") or "CSA CCM"
            cid = str(ch.get("clause_id") or "")
            title = str(ch.get("title") or "")
            incident_summary = parsed.get("incident_summary") or {}
            action_ids = []
            for pb in parsed.get("recommended_actions") or []:
                if not isinstance(pb, dict):
                    continue
                for act in pb.get("actions") or []:
                    if isinstance(act, dict) and act.get("action_id"):
                        action_ids.append(str(act["action_id"]))
            out.append(
                {
                    "framework": str(fw),
                    "clause_id": cid,
                    "clause_title": title,
                    "relevance": 0.65,
                    "excerpt": (str(ch.get("content") or ""))[:220],
                    "why_relevant": _rule_based_why_relevant_ko(
                        cid, title, incident_summary, action_ids
                    ),
                }
            )
    parsed["regulations"] = out
    return parsed


def _call_regulation_agent_with_validation(
    incident_input: Dict[str, Any],
    context_chunks: List[Dict[str, Any]],
    model: str,
) -> RegulationAgentIntermediate:
    payload = dict(incident_input)
    payload["context_chunks"] = context_chunks

    scenario = incident_input.get("scenario", "SuspiciousActivity")
    raw = _call_llm_json(payload, model=model)
    try:
        parsed = json.loads(raw)
        parsed = _normalize_recommended_actions_shape(parsed, scenario)
        parsed = _align_regulations_to_chunks(parsed, context_chunks)
        return RegulationAgentIntermediate.model_validate(parsed)
    except (ValidationError, json.JSONDecodeError) as e:
        # ↓ 수정: 누락 필드를 명시적으로 힌트
        payload["_retry_note"] = (
            f"Previous response failed validation: {str(e)}. "
            "You MUST include ALL of these fields: "
            "escalation_assessment, reasoning_bullets, regulations, "
            "recommended_actions, insufficient_context, missing_context_requests. "
            "schema_version must be '1.2'. scenario is required. "
            "recommended_actions must be playbooks with actions[] (1+). "
            "Each playbook_name must be a specific English Title Case phrase "
            "(e.g. Credential Containment), not Containment Playbook or Isolation Playbook. "
            f"When insufficient_context is false, regulations must have exactly len(context_chunks) items."
        )
        raw_retry = _call_llm_json(payload, model=model)
        parsed_retry = json.loads(raw_retry)
        parsed_retry = _normalize_recommended_actions_shape(parsed_retry, scenario)
        parsed_retry = _align_regulations_to_chunks(parsed_retry, context_chunks)
        return RegulationAgentIntermediate.model_validate(parsed_retry)
    
    
    
def process_guardduty_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if os.environ.get("OPENAI_API_KEY") and not os.environ.get("CHROMA_OPENAI_API_KEY"):
        os.environ["CHROMA_OPENAI_API_KEY"] = os.environ["OPENAI_API_KEY"]

    # ── finding 추출 (MCP 포맷 / 직접 호출 포맷 둘 다 대응) ──────────────
    raw_event = event.get("raw_event") or {}

    if isinstance(event.get("detail"), dict):
        finding = event["detail"]                      # 직접 EventBridge 포맷
    elif isinstance(raw_event.get("detail"), dict):
        finding = raw_event["detail"]                  # MCP가 raw_event 안에 감싼 경우
    elif isinstance(event.get("finding"), dict):
        finding = event["finding"]                     # 테스트용 직접 호출
    else:
        finding = event                                # fallback

    # ── MCP가 보내준 컨텍스트 추출 ────────────────────────────────────────
    runtime_result = event.get("runtime_result") or raw_event.get("runtime_result") or {}
    response_targets = event.get("response_targets") or {}
    executed_level1_actions = event.get(
        "executed_level1_actions",
        ["record_finding", "notify_slack", "tag_finding_observe"],
    )
    candidate_actions = event.get("candidate_actions", DEFAULT_CANDIDATE_ACTIONS)
    # ─────────────────────────────────────────────────────────────────────

    force_rule_based = str(os.environ.get("FORCE_RULE_BASED_PLAYBOOKS", "false")).lower() in {
        "1", "true", "yes",
    } or bool(event.get("force_rule_based_playbooks"))


    router = decide_response_level(finding=finding, runtime_result=runtime_result)
    if router.selected_level == 1:
        return {
            "schema_version": "1.3",
            "status": "ok",
            "selected_level": 1,
            "route_reasons": router.reasons,
            "skipped": "RAG_AND_LLM",
            "incident_id": finding.get("id", "unknown-incident"),
            "selected_playbook": None,
            "alternative_playbooks": [],
            "recommended_actions": [],
        }

    retrieved: List[Dict[str, Any]] = []
    context_chunks: List[Dict[str, Any]] = []
    try:
        query_text, query_plan = build_guardduty_rag_query(
            finding=finding,
            runtime_result=runtime_result,
            candidate_actions=candidate_actions,
        )
        collection = _get_collection()
        pool = chroma_retrieve(
            collection, query_text, where_filter=query_plan, top_k=RETRIEVAL_TOP_K
        )
        retrieved = rerank_retrieved_documents(
            query_text,
            finding,
            pool,
            query_plan=query_plan,
        )[:RERANK_OUTPUT_TOP_K]
        context_chunks = build_context_chunks(retrieved)
    except Exception:
        if not force_rule_based:
            raise

    security_event = _build_security_event(finding)
    severity_result = decide_severity_level_with_xai(security_event, retrieved)
    scenario = _infer_scenario(finding, runtime_result)
    incident_input = _build_incident_input(
        finding=finding,
        executed_level1_actions=executed_level1_actions,
        candidate_actions=candidate_actions,
        severity_result=severity_result,
        scenario=scenario,
    )
    incident_input["_finding_raw"] = finding

    if force_rule_based:
        output = _build_rule_based_output(
            incident_input=incident_input,
            severity_result=severity_result,
            retrieved=retrieved,
            candidate_actions=candidate_actions,
            response_targets=response_targets,
        )
    else:
        model = os.environ.get("OPENAI_MODEL", "gpt-5.4")
        output = _call_regulation_agent_with_validation(
            incident_input=incident_input,
            context_chunks=context_chunks,
            model=model,
        )

    result = output.model_dump()

    regs = result.get("regulations") or []
    if isinstance(regs, list) and len(regs) > RERANK_OUTPUT_TOP_K:
        result["regulations"] = regs[:RERANK_OUTPUT_TOP_K]

    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    _apply_finding_targets_to_playbooks(result, finding)

    result = finalize_output_contract(
        result,
        router.selected_level,
        scenario,
        finding,
        candidate_actions,
        response_targets,
        list(router.reasons),
    )
    _apply_finding_targets_to_playbooks(result, finding)

    validate_output_contract(result, router.selected_level)
    result = RegulationAgentOutput.model_validate(result).model_dump()

    result["status"] = "ok"
    result["selected_level"] = router.selected_level
    result["route_reasons"] = router.reasons
    result["retrieved_count"] = len(retrieved)
    # RAG+risk가 넘긴 조항 id (rerank 후 상위 N); regulations는 LLM 인용 개수와 다를 수 있음
    result["retrieved_clause_ids"] = [
        row.get("id") or (row.get("metadata") or {}).get("clause_id") or ""
        for row in retrieved
    ]

    return result
