"""
Day 7: RAG(Chroma) → context_chunks → LLM(Regulation Agent) → Pydantic 검증
- MCP 서버 없이도 로컬에서 E2E로 흐름 검증하는 단일 파일 스크립트

실행:
    1) pip install chromadb pydantic openai
    2) 환경변수 OPENAI_API_KEY 설정
    - Windows PowerShell:  setx OPENAI_API_KEY "sk-..."
    - macOS/Linux:         export OPENAI_API_KEY="sk-..."
    3) python test_regulation_agent_flow.py

주의:
- 여기서는 Day 7 기준으로 context_chunks에 guidelines(원문)는 넣지 않습니다(document만 넣음).
- Day 11(XAI)에서 clause_id로 2단계 조회(A안)로 원문을 다시 가져오는 방식 권장.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Literal
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()

# -------- Pydantic schema (Day 6 fixed) --------
from pydantic import BaseModel, Field, ValidationError, conlist, confloat


class Resource(BaseModel):
    type: str
    id: str
    region: str
    account_id: str


class IncidentSummary(BaseModel):
    source: Literal["guardduty"]
    title: str
    severity: str
    resource: Resource


class EscalationAssessment(BaseModel):
    escalation_needed: bool
    recommended_level: Literal[2, 3]
    confidence: confloat(ge=0.0, le=1.0)
    decision_questions: conlist(str, min_length=1)  # Day 6: decision-support 성격 강제
    approval_notes: str


class RegulationRef(BaseModel):
    framework: str
    clause_id: str
    clause_title: str = ""
    relevance: confloat(ge=0.0, le=1.0) = 0.5
    excerpt: str = ""
    why_relevant: str = ""


class ActionTarget(BaseModel):
    type: str
    id: str


class RecommendedAction(BaseModel):
    action_id: str
    level: Literal[2, 3]
    description: str
    targets: List[ActionTarget]
    requires_approval: Literal[True] = True
    expected_impact: Literal["LOW", "MEDIUM", "HIGH"]


class RegulationAgentOutput(BaseModel):
    schema_version: Literal["1.1"]
    generated_at: str
    incident_id: str

    incident_summary: IncidentSummary
    executed_level1_actions: List[str]

    escalation_assessment: EscalationAssessment
    reasoning_bullets: List[str]

    regulations: List[RegulationRef]
    recommended_actions: List[RecommendedAction]

    insufficient_context: bool
    missing_context_requests: List[str]


# -------- Day 6 System Prompt (fixed) --------
REGULATION_AGENT_SYSTEM_PROMPT = r"""
You are the “Regulation Agent”, a compliance-first decision-support agent for AWS incident response.

Your role is NOT to execute actions and NOT to handle Level 1 responses.
Level 1 responses (recording, alerting, logging, tagging, basic inspection) are already executed automatically by the Runtime Agent.

Your sole responsibility is to:
- Evaluate whether additional response beyond Level 1 is necessary.
- Recommend escalation to Level 2 or Level 3 ONLY.
- Justify recommendations using provided regulatory context (ISMS-P, CSA CCM, ISO mappings).
- Support human decision-making for approval-based actions.

You MUST NOT:
- Decide or recommend Level 1.
- Execute any response actions.
- Calculate or rely on risk scores. Risk scoring is handled outside this agent.

---

## 1) Inputs You Will Receive
You will receive:
- An incident summary (after Level 1 actions have already been executed)
- A list of Level 1 actions already performed
- Candidate response actions under consideration (Level 2 / Level 3), which may be empty
- Retrieved regulatory context chunks (“context_chunks”) via RAG

Assume Level 1 actions are completed and immutable.

---

## 2) Your Decision Scope
- The field escalation_assessment.confidence MUST be a float between 0 and 1 and MUST NOT remain a default or placeholder value.
You must decide ONLY:
- Whether escalation is required beyond Level 1
- If so, whether Level 2 or Level 3 is more appropriate
- Which actions are REGULATORILY JUSTIFIABLE at that level

Both Level 2 and Level 3:
- ALWAYS require human approval
- Are proposals for decision-making, not execution commands

---

## 3) Level Interpretation (STRICT)
Levels are NOT incident severity tiers.
Levels represent the scope of response authority and organizational responsibility.

- Level 2 (Approval-Based Containment)
  - Actions are reversible or partially reversible
  - Moderate service or user impact
  - Regulatory intent favors controlled, approved response

- Level 3 (Approval-Based Critical Response)
  - Actions are irreversible or highly disruptive
  - Potential service outage, isolation, forensic evidence preservation
  - Active compromise, expansion risk, or ongoing malicious activity may be present
  - Organizational, legal, or contractual responsibility is involved

Do NOT select Level 3 solely based on severity.
Select Level 3 only when irreversible impact, evidence preservation, or organization-critical response is justified.

---

## 4) Regulatory Grounding Rules (NO HALLUCINATION)
- You MUST ONLY cite clauses present in context_chunks.
- You MUST NOT invent clause IDs, titles, or mappings.
- If regulatory context is insufficient:
  - Set insufficient_context = true
  - Populate missing_context_requests
  - Do NOT recommend escalation actions beyond Level 1 unless clearly justified
  - In this case, recommended_actions MUST be an empty array
  - decision_questions MUST include a request for additional context

---

## 5) Action Recommendation Rules
- Recommend ONLY Level 2 or Level 3 actions.
- If candidate response actions are provided:
    - You MUST select only from those actions.
- If candidate response actions are NOT provided or empty:
    - You MAY propose actions from the predefined action catalog
    - Action IDs MUST exactly match catalog identifiers.
- All recommended actions MUST:
    - If the affected object is an AccessKey, set targets[].type = "AccessKey" and targets[].id = the access_key_id.
    - If the affected object is an IAM identity, set targets[].type = "IAMUser" and targets[].id = the IAM user name or ARN.
    - Be implementable via AWS APIs
    - Include a regulatory justification
    - Require human approval (requires_approval = true)

Do NOT recommend execution order or automation logic.

---

## 6) Explainability (XAI)
For each recommendation:
- Clearly explain why escalation beyond Level 1 is necessary
- Link each action to specific regulatory clauses
- Explain why Level 2 or Level 3 is appropriate
- Clearly state assumptions or uncertainties if present
- The regulations field MUST include at least one directly relevant clause.
- If multiple relevant clauses are present in context_chunks, include up to two clauses to strengthen regulatory justification.
- shared or misused credentials reduce accountability


---

## 7) Output Contract (STRICT)
Return ONLY a single JSON object with exactly these top-level keys:

schema_version,
generated_at,
incident_id,
incident_summary,
executed_level1_actions,
escalation_assessment,
reasoning_bullets,
regulations,
recommended_actions,
insufficient_context,
missing_context_requests

Rules:
- Use the exact key names.
- Do NOT add extra keys.
- Do NOT include markdown.
- Do NOT include commentary or trailing text.
- Output MUST be valid JSON only.
""".strip()

OUTPUT_JSON_SKELETON = {
  "schema_version": "1.1",
  "generated_at": "ISO8601",
  "incident_id": "string",

  "incident_summary": {
    "source": "guardduty",
    "title": "string",
    "severity": "string",
    "resource": {
      "type": "string",
      "id": "string",
      "region": "string",
      "account_id": "string"
    }
  },

  "executed_level1_actions": [],

  "escalation_assessment": {
    "escalation_needed": True,
    "recommended_level": 2,
    "confidence": 0.0,
    "decision_questions": [
  "Do you approve escalation actions (Level 2/3) given the observed anomalous IAM access behavior?"
],
    "approval_notes": "string"
  },

  "reasoning_bullets": [],
  "regulations": [
  {
    "framework": "CSA_CCM",
    "clause_id": "IAM-05",
    "clause_title": "Least Privilege",
    "relevance": 0.0,
    "excerpt": "string",
    "why_relevant": "string"
  }
],

  "recommended_actions": [
  {
    "action_id": "disable_access_key",
    "level": 2,
    "description": "string",
    "targets": [{"type": "IAMUser", "id": "string"}],
    "requires_approval": True,
    "expected_impact": "LOW"
  }
],

  "insufficient_context": False,
  "missing_context_requests": []
}



# -------- Helpers (query builder + retrieval + context_chunks) --------
def _safe_get(d: Dict[str, Any], path: List[str], default: Any = "") -> Any:
    cur: Any = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _to_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x if v is not None]
    return [str(x)]


def build_guardduty_rag_query(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
    candidate_actions: Optional[List[str]] = None,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    GuardDuty '흔한' 구조를 가정한 query_text + where_filter 생성
    """
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
    remote_ip = _safe_get(finding, ["service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"], "")

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
        parts.append("iam user")
        parts.append(iam_user)
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
    lowered = " ".join(parts).lower()
    if any(k in lowered for k in ["access key", "credential", "iam", "excessive privilege", "privilege escalation"]):
        where_filter = {"category": "IAM"}

    return query_text, where_filter


def chroma_retrieve(
    collection,
    query_text: str,
    where_filter: Optional[Dict[str, Any]] = None,
    top_k: int = 6,
) -> List[Dict[str, Any]]:
    """
    return normalized list: [{"id":..,"metadata":..,"document":..}, ...]
    """
    if not query_text.strip():
        return []

    kwargs = {"query_texts": [query_text], "n_results": top_k}
    if where_filter:
        kwargs["where"] = where_filter

    res = collection.query(**kwargs)

    ids = (res.get("ids") or [[]])[0]
    metadatas = (res.get("metadatas") or [[]])[0]
    documents = (res.get("documents") or [[]])[0]

    out: List[Dict[str, Any]] = []
    for i in range(min(len(ids), len(metadatas), len(documents))):
        out.append({"id": ids[i], "metadata": metadatas[i] or {}, "document": documents[i] or ""})
    return out


def build_context_chunks(retrieved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Day 7 MVP: document만 content로 주입 (guidelines 원문 제외)
    """
    chunks: List[Dict[str, Any]] = []
    for r in retrieved:
        meta = r.get("metadata") or {}
        clause_id = r.get("id") or meta.get("clause_id") or meta.get("id")

        chunks.append(
            {
                "doc_type": meta.get("doc_type", meta.get("framework", "")),
                "doc_version": meta.get("doc_version", ""),
                "clause_id": clause_id,
                "title": meta.get("title", ""),
                "category": meta.get("category", ""),
                "mapping_iso27001": meta.get("mapping_iso27001", []) or [],
                "mapping_iso27017": meta.get("mapping_iso27017", []) or [],
                "content": r.get("document", ""),
            }
        )
    return chunks


# -------- LLM call (direct OpenAI SDK) + retry + Pydantic --------
def call_llm_json(system_prompt: str, payload: dict, model: str = "gpt-4o-mini") -> str:
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("CHROMA_OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing API key. Set OPENAI_API_KEY (recommended)")

    client = OpenAI(api_key=api_key)

    user_prompt = (
        "INPUT_JSON:\n"
        f"{json.dumps(payload, ensure_ascii=False)}\n\n"
        "OUTPUT_JSON_SKELETON (fill values ONLY, keep keys/structure EXACT):\n"
        f"{json.dumps(OUTPUT_JSON_SKELETON, ensure_ascii=False)}\n\n"
        "RULES:\n"
        "- Return ONLY the completed JSON object\n"
        "- Do NOT add/remove keys\n"
        "- Do NOT output any extra text\n"
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content


  

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"}
    )
    return resp.choices[0].message.content or ""


def call_regulation_agent_with_validation(
    incident_input: Dict[str, Any],
    context_chunks: List[Dict[str, Any]],
    model: str = "gpt-4o-mini",
) -> RegulationAgentOutput:
    """
    - LLM 호출 → Pydantic 검증
    - 실패 시 1회 retry(강한 JSON 강제 문구 추가)
    """
    payload = dict(incident_input)
    payload["context_chunks"] = context_chunks

    raw = call_llm_json(REGULATION_AGENT_SYSTEM_PROMPT, payload, model=model)

    try:
        return RegulationAgentOutput.model_validate_json(raw)
    except ValidationError:
        # 1회 retry: JSON/keys 강제
        payload_retry = dict(payload)
        payload_retry["_retry_note"] = (
        "STRICT JSON CONTRACT:\n"
        "- regulations MUST be a list of OBJECTS with keys: framework, clause_id, clause_title, relevance, excerpt, why_relevant\n"
        "- recommended_actions MUST be a list of OBJECTS with keys: action_id, level, description, targets, requires_approval, expected_impact\n"
        "- decision_questions MUST contain at least 1 question (non-empty)\n"
        "- Do NOT output string lists for regulations/recommended_actions\n"
        "- Return ONLY JSON, no extra text."
)

        raw2 = call_llm_json(REGULATION_AGENT_SYSTEM_PROMPT, payload_retry, model=model)
        return RegulationAgentOutput.model_validate_json(raw2)


# -------- Mock incident input (what MCP would pass into Regulation Agent) --------
def make_mock_incident_input() -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()

    # GuardDuty finding mock (일부 필드만)
    guardduty_finding = {
        "id": "gd-finding-123",
        "type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
        "severity": 5.3,
        "title": "IAM user anomalous behavior detected",
        "description": "Unusual API calls observed from an external IP using an access key.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"userName": "test-user", "accessKeyId": "AKIA..."},
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {"api": "ListBuckets"},
                "networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.10"}},
            }
        },
    }

    # Runtime Agent가 수행한 L1 결과(이미 실행됨)
    executed_level1_actions = [
        "record_finding",
        "notify_slack",
        "fetch_cloudtrail_related_events",
        "tag_finding_observe",
    ]

    # MCP가 Regulation Agent에 넘길 입력(JSON) = Day 6 스키마에 맞춘 incident_input "재료"
    incident_input = {
        "schema_version": "1.1",
        "generated_at": now,
        "incident_id": guardduty_finding["id"],
        "incident_summary": {
            "source": "guardduty",
            "title": "Access Key suspicious usage (post-L1)",
            "severity": str(guardduty_finding["severity"]),
            "resource": {
                "type": guardduty_finding["resource"]["resourceType"],
                "id": guardduty_finding["resource"]["accessKeyDetails"]["accessKeyId"],
                "region": guardduty_finding["region"],
                "account_id": guardduty_finding["accountId"],
            },
        },
        "executed_level1_actions": executed_level1_actions,
        # candidate_actions는 빈 배열일 수도 있음(프롬프트 규칙대로 허용)
        "candidate_actions": [
            "disable_access_key",
            "detach_admin_policies",
            "terminate_sessions",
            "isolate_instance",
            "create_snapshot",
        ],
        # (선택) runtime 결과 신호를 query builder에만 활용하고, Regulation Agent 입력에는 굳이 안 넣어도 됨
        "_guardduty_finding_raw": guardduty_finding,  # 테스트 편의를 위해 포함(실 운영에선 MCP 내부에만 둬도 됨)
    }
    return incident_input


# -------- Main: Chroma connect → retrieve → context_chunks → LLM → validate --------
def main():
    # 0) Chroma 설정 (팀원과 맞춰서 수정)
    CHROMA_PERSIST_DIR = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_db")
    COLLECTION_NAME = os.environ.get("CHROMA_COLLECTION", "csa_ccm_v4")



    # 1) incident input 준비
    incident_input = make_mock_incident_input()

    # 2) query builder 입력으로 GuardDuty raw를 사용(가정)
    finding = incident_input.get("_guardduty_finding_raw", {})
    candidate_actions = incident_input.get("candidate_actions", [])
    runtime_result = {"tags": ["credential_compromise"], "key_signals": ["unusual API calls", "external IP"]}

    query_text, where_filter = build_guardduty_rag_query(
        finding=finding, runtime_result=runtime_result, candidate_actions=candidate_actions
    )
    
        # =========================
    # Day 8 Router gate (L1 skip)
    # =========================
    decision = decide_response_level(finding=finding, runtime_result=runtime_result)

    print("\n=== [Day8] Router Decision ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    if decision.selected_level == 1:
        print("\n[Router] Level 1 → Runtime Agent only. Skip RAG/Regulation Agent.\n")
        return

    print("\n=== [Day7] Query Builder Output ===")
    print("query_text:", query_text)
    print("where_filter:", where_filter)

    # 3) Chroma에서 retrieve
    import chromadb

    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    print("collections:", [c.name for c in client.list_collections()])
    print("collection_name:", COLLECTION_NAME)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)
    print("collection_count:", collection.count())

    retrieved = chroma_retrieve(collection, query_text, where_filter=where_filter, top_k=6)

    print("\n=== [Day7] Retrieved Regulations (top-k) ===")
    for i, r in enumerate(retrieved, start=1):
        meta = r.get("metadata", {})
        print(f"- #{i} id={r.get('id')} title={meta.get('title','')} category={meta.get('category','')}")

    # 4) Severity Decision Engine + XAI (규제 문서 기반 정밀 결정)
    from severity_decision import decide_severity_level_with_xai
    
    # GuardDuty finding을 SecurityEvent로 변환
    def _safe_get(data, keys, default=None):
        """중첩된 딕셔너리에서 안전하게 값 가져오기"""
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                return default
            if data is None:
                return default
        return data if data is not None else default
    
    # SecurityEvent 생성
    finding_type = finding.get("type", "").lower()
    resource_type = _safe_get(finding, ["resource", "resourceType"], "")
    access_key_details = _safe_get(finding, ["resource", "accessKeyDetails"], {})
    
    # exposure 판단
    exposure = "public"
    if access_key_details:
        exposure = "public"
    elif "internal" in finding_type or "private" in finding_type:
        exposure = "internal"
    else:
        exposure = "internal"
    
    # privilege_impact 판단
    privilege_impact = any(keyword in finding_type for keyword in ["privilege", "escalation", "admin", "root"])
    
    # data_sensitivity 판단
    severity_score = finding.get("severity", 0.0)
    if severity_score >= 7.0:
        data_sensitivity = "high"
    elif severity_score >= 4.0:
        data_sensitivity = "medium"
    else:
        data_sensitivity = "low"
    
    security_event = {
        "event_type": finding.get("type", "Unknown"),
        "resource_type": resource_type or "Unknown",
        "exposure": exposure,
        "privilege_impact": privilege_impact,
        "data_sensitivity": data_sensitivity
    }
    
    # Severity Decision + XAI 실행
    print("\n=== [Severity Decision] 규제 문서 기반 정밀 결정 ===")
    severity_result = decide_severity_level_with_xai(security_event, retrieved)
    
    print(f"Assigned Level: {severity_result['assigned_level']}")
    print(f"Justification: {severity_result['justification']}")
    print(f"Event Factors: {', '.join(severity_result['triggers']['event_factors'])}")
    if severity_result['triggers']['regulatory_signals']:
        signals = severity_result['triggers']['regulatory_signals']
        print(f"Regulatory Signals: {len(signals)}개")
        for sig in signals[:3]:
            print(f"  - {sig.get('clause_id', 'N/A')}: {sig.get('intent', 'N/A')}")
    if severity_result['triggers']['fallback']:
        print("⚠️ Fallback 조건: 규제 문서 부족으로 기본값 사용")

    # 5) context_chunks 생성 (document만)
    context_chunks = build_context_chunks(retrieved)

    print("\n=== [Day7] context_chunks (preview) ===")
    print(json.dumps(context_chunks[:2], ensure_ascii=False, indent=2))

    # 6) Regulation Agent 호출 + Pydantic 검증
    # (테스트 편의: _guardduty_finding_raw 제거)
    incident_input.pop("_guardduty_finding_raw", None)

    print("\n=== [Day7] Calling Regulation Agent (LLM) ===")
    output = call_regulation_agent_with_validation(
        incident_input=incident_input,
        context_chunks=context_chunks,
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    )

    print("\n=== [Day7] ✅ Pydantic Validated Output ===")
    print(json.dumps(output.model_dump(), ensure_ascii=False, indent=2))


# =========================
# Day 8: Level Router + TC
# =========================

# Level Router는 별도 모듈로 분리
from level_router import decide_response_level, LevelDecision


def make_mock_finding_tc1_accesskey_anomalous() -> Dict[str, Any]:
    """TC-1: Access Key 이상행위(유출 의심)"""
    return {
        "id": "tc1-finding-001",
        "type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
        "severity": 5.3,
        "title": "IAM user anomalous behavior detected",
        "description": "Unusual API calls observed from an external IP using an access key.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"userName": "test-user", "accessKeyId": "AKIA..."},
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {"api": "ListBuckets"},
                "networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.10"}},
            }
        },
    }

def run_tc1():
    # ---- TC-1 ----
    finding = make_mock_finding_tc1_accesskey_anomalous()
    runtime_result = {
        "tags": ["credential_compromise"],
        "key_signals": ["unusual API calls", "external IP"]
    }

    decision = decide_response_level(finding, runtime_result)
    expected = 2

    print("\n=== [Day8][TC-1] AccessKey anomalous → expect Level 2 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == expected, f"TC-1 failed: expected {expected}, got {decision.selected_level}"
    print("✅ TC-1 PASSED")


def make_mock_finding_tc2_low_single_recon() -> Dict[str, Any]:
    return {
        "id": "gd-finding-tc2",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "severity": 2.2,
        "title": "EC2 port probe detected (single occurrence)",
        "description": "A remote host performed a port probe against an EC2 instance. No evidence of successful compromise.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0123456789abcdef0"},
        },
        "service": {
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.55"}
                },
            }
        },
    }
    
def run_tc2():
    finding = make_mock_finding_tc2_low_single_recon()

    # 단발성/낮은 신호 가정
    runtime_result = {
        "tags": [],            # 중요한 태그 없음
        "key_signals": [],     # 추가 이상 징후 없음
        "repeat_count": 1      # (있으면 좋음) 반복 없음
    }

    decision = decide_response_level(finding, runtime_result)

    print("\n=== [Day8][TC-2] Low severity recon single → expect Level 1 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 1, f"TC-2 FAILED: expected 1, got {decision.selected_level}"
    print("✅ TC-2 PASSED")

# ----------------------------
# Day8 TestCase-3
# ----------------------------
def make_tc3_finding_exfiltration() -> Dict[str, Any]:
    """
    TC-3: Data exfiltration / ongoing attack signals → expect Level 3
    - Level 3 trigger는 signals에 'data exfiltration' 같은 키워드가 있으면 바로 발동
    """
    return {
        "id": "gd-finding-tc3",
        "type": "UnauthorizedAccess:EC2/PortProbeUnprotectedPort",  # type은 L3 트리거와 무관하게 둬도 됨
        "severity": 8.1,
        "title": "Potential data exfiltration detected",
        "description": "Suspicious large outbound transfer observed.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0abc123def456"},
        },
        "service": {
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.77"}
                },
            }
        },
    }


def run_tc3():
    finding = make_tc3_finding_exfiltration()

    # runtime_result에서 L3 트리거 신호 제공
    runtime_result = {
        "tags": ["possible_compromise"],
        "key_signals": [
            "data exfiltration",     # ✅ 네 로직에 박힌 L3 트리거
            "ongoing attack",
        ],
    }

    decision = decide_response_level(finding=finding, runtime_result=runtime_result)

    print("\n=== [Day8][TC-3] Exfiltration signals → expect Level 3 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 3, "TC-3 FAILED: expected Level 3"
    assert any("Signals indicate" in r or "ongoing" in r.lower() or "exfil" in r.lower() for r in decision.reasons), \
        "TC-3 FAILED: reasons should mention L3 trigger signals"
    print("✅ TC-3 PASSED")
    
    
# ----------------------------
# Day8 TestCase-4
# ----------------------------
def make_tc4_finding_privilege_escalation() -> Dict[str, Any]:
    """
    TC-4: Privilege escalation / unauthorized admin access → expect Level 2
    - decide_response_level()에서 gd_type에 'privilegeescalation' / 'unauthorizedadminaccess' 포함 시 L2
    """
    return {
        "id": "gd-finding-tc4",
        "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",  # ✅ L2 트리거 키워드 포함
        "severity": 6.5,
        "title": "IAM user gained administrative permissions",
        "description": "An IAM user appears to have gained elevated permissions.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "userName": "tc4-user",
                "accessKeyId": "AKIA-TC4-KEY"
            },
        },
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {"api": "AttachUserPolicy"},
            }
        },
    }


def run_tc4():
    finding = make_tc4_finding_privilege_escalation()

    runtime_result = {
        "tags": ["privilege_escalation"],  # 있어도 되고 없어도 됨
        "key_signals": ["policy attached", "admin policy"],
    }

    decision = decide_response_level(finding=finding, runtime_result=runtime_result)

    print("\n=== [Day8][TC-4] Privilege escalation → expect Level 2 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 2, "TC-4 FAILED: expected Level 2"
    assert any("Privilege-impacting" in r or "privilege" in r.lower() for r in decision.reasons), \
        "TC-4 FAILED: reasons should mention privilege impact"
    print("✅ TC-4 PASSED")

# ----------------------------
# Day8 TestCase-5
# ----------------------------
def make_tc5_finding_high_severity_no_l3() -> Dict[str, Any]:
    """
    TC-5: High severity (>=7) but no L3 triggers → expect Level 2
    - decide_response_level()의 'sev >= 7.0 -> L2' 분기 검증
    """
    return {
        "id": "gd-finding-tc5",
        "type": "Recon:EC2/PortProbeUnprotectedPort",  # L3 키워드(crypto/malware 등) 없음
        "severity": 7.8,  # ✅ high severity
        "title": "EC2 port probe detected",
        "description": "Multiple ports were probed on an EC2 instance from an external IP.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0tc5instance"},
        },
        "service": {
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.23"}
                },
            }
        },
    }


def run_tc5():
    finding = make_tc5_finding_high_severity_no_l3()

    # ✅ 일부러 L3 신호는 안 넣음
    runtime_result = {
        "tags": ["recon"],  # 있어도 무방
        "key_signals": ["port probe", "external ip"],  # L3 트리거( data exfiltration, lateral movement 등) 없음
    }

    decision = decide_response_level(finding=finding, runtime_result=runtime_result)

    print("\n=== [Day8][TC-5] High severity but no L3 triggers → expect Level 2 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 2, "TC-5 FAILED: expected Level 2"
    assert any("High severity" in r for r in decision.reasons), \
        "TC-5 FAILED: reasons should mention high severity fallback"
    print("✅ TC-5 PASSED")



# ----------------------------
# Day8 TestCase-6
# ----------------------------
def make_tc6_finding_exfiltration_signal() -> Dict[str, Any]:
    """
    TC-6: L3 trigger signal present (data exfiltration / lateral movement / persistence / ongoing attack)
    → expect Level 3
    """
    return {
        "id": "gd-finding-tc6",
        "type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",  # 타입은 뭐든 상관 없음
        "severity": 4.0,  # severity 낮아도 L3 신호면 L3로 가야 함
        "title": "Possible data exfiltration activity detected",
        "description": "Suspicious large data transfer patterns detected.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0tc6instance"},
        },
    }


def run_tc6():
    finding = make_tc6_finding_exfiltration_signal()

    # ✅ L3 트리거 신호를 정확히 포함 (소문자 비교라서 lower()될 예정)
    runtime_result = {
        "tags": ["suspicious-transfer"],
        "key_signals": ["data exfiltration", "external ip", "large outbound traffic"],
    }

    decision = decide_response_level(finding=finding, runtime_result=runtime_result)

    print("\n=== [Day8][TC-6] L3 signal present → expect Level 3 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 3, "TC-6 FAILED: expected Level 3"
    assert any("Signals indicate expansion/persistence/ongoing malicious activity" in r for r in decision.reasons), \
        "TC-6 FAILED: reasons should mention L3 signals trigger"
    print("✅ TC-6 PASSED")

if __name__ == "__main__":
    main()
    run_tc1()
    run_tc2()
    run_tc3()
    run_tc4()
    run_tc5()
    run_tc6()
    