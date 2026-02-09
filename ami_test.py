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
    
# =========================
# Day10: Semantic validator + normalizer
# =========================

ALLOWED_IMPACTS = {"LOW", "MEDIUM", "HIGH"}

_IMPACT_SYNONYM_MAP = {
    "MODERATE": "MEDIUM",
    "MID": "MEDIUM",
    "MIDDLE": "MEDIUM",
    "LOWER": "LOW",
    "HIGHER": "HIGH",
}

_PLACEHOLDER_STRINGS = {"string", "iso8601", "n/a", "na", "tbd", "todo", "none", ""}


def _is_placeholder_text(s: str) -> bool:
    if s is None:
        return True
    t = str(s).strip().lower()
    return t in _PLACEHOLDER_STRINGS or len(t) < 2


def normalize_output_dict(raw_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    스키마 검증 전에 '흔한 LLM 실수'를 룰로 보정해서 통과율 올림
    - expected_impact: MODERATE -> MEDIUM 등
    - requires_approval: 항상 True 강제(스키마도 True로 고정이지만, 혹시 문자열/false 오면 보정)
    """
    out = dict(raw_obj)

    # recommended_actions.expected_impact normalize
    ra = out.get("recommended_actions", [])
    if isinstance(ra, list):
        for a in ra:
            if not isinstance(a, dict):
                continue
            imp = a.get("expected_impact")
            if isinstance(imp, str):
                up = imp.strip().upper()
                if up in _IMPACT_SYNONYM_MAP:
                    a["expected_impact"] = _IMPACT_SYNONYM_MAP[up]
                else:
                    a["expected_impact"] = up  # 일단 대문자화

            # requires_approval normalize
            if "requires_approval" in a:
                a["requires_approval"] = True

    out["recommended_actions"] = ra
    return out


def semantic_checks(output: RegulationAgentOutput) -> List[str]:
    """
    Pydantic은 통과했는데 '내용적으로 말이 안 되는' 케이스를 잡아내기 위한 체크
    -> 에러 메시지 리스트 반환 (비어있으면 OK)
    """
    errs: List[str] = []

    # 0) 기본 placeholder 방지
    if _is_placeholder_text(output.incident_summary.title):
        errs.append("incident_summary.title looks like a placeholder.")
    if _is_placeholder_text(output.escalation_assessment.approval_notes):
        errs.append("escalation_assessment.approval_notes looks like a placeholder.")

    # 1) confidence가 0에 가깝거나 기본값 느낌이면 경고(너 프롬프트 규칙과 맞춤)
    if output.escalation_assessment.confidence <= 0.05:
        errs.append("escalation_assessment.confidence is too low (looks like default/placeholder).")

    # 2) insufficient_context 논리 규칙 (네 system prompt 규칙 그대로)
    if output.insufficient_context:
        if len(output.missing_context_requests) < 1:
            errs.append("insufficient_context=true but missing_context_requests is empty.")
        if len(output.recommended_actions) != 0:
            errs.append("insufficient_context=true but recommended_actions is not empty.")
        # decision_questions는 conlist로 최소 1개 보장되긴 함

    else:
        # 충분한 컨텍스트면 규정 1개 이상이 자연스러움(너 prompt에 MUST)
        if len(output.regulations) < 1:
            errs.append("insufficient_context=false but regulations is empty.")

    # 3) escalation vs actions 모순
    if output.escalation_assessment.escalation_needed is False:
        if len(output.recommended_actions) > 0:
            errs.append("escalation_needed=false but recommended_actions is not empty.")

    # 4) actions 내부 값 sanity
    for i, act in enumerate(output.recommended_actions):
        if act.expected_impact not in ALLOWED_IMPACTS:
            errs.append(f"recommended_actions[{i}].expected_impact invalid: {act.expected_impact}")

        if act.requires_approval is not True:
            errs.append(f"recommended_actions[{i}].requires_approval must be True")

    # 5) recommended_level과 action.level 일치성(강제는 아니지만 보통 맞추는 게 좋음)
    rec_level = output.escalation_assessment.recommended_level
    for i, act in enumerate(output.recommended_actions):
        if act.level != rec_level:
            errs.append(
                f"recommended_actions[{i}].level({act.level}) != escalation_assessment.recommended_level({rec_level})"
            )

    return errs


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
  "Do you approve the proposed Level 2/3 actions given the incident context?"
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
    ami_id = _safe_get(finding, ["resource", "instanceDetails", "imageId"], "")
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
    if ami_id:
        parts.append("ami")
        parts.append(ami_id)
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

def normalize_expected_impact(raw_json: str) -> str:
    """
    LLM이 expected_impact를 LOW/MEDIUM/HIGH 대신
    MODERATE 같은 값으로 주는 경우를 교정
    """
    import json

    try:
        obj = json.loads(raw_json)
    except Exception:
        # JSON 파싱 안 되면 그대로 반환
        return raw_json

    actions = obj.get("recommended_actions", [])
    for action in actions:
        val = str(action.get("expected_impact", "")).upper().strip()

        if val in ["MODERATE", "MID", "MIDDLE"]:
            action["expected_impact"] = "MEDIUM"
        elif val in ["LOW", "MEDIUM", "HIGH"]:
            action["expected_impact"] = val
        else:
            # 이상하거나 비어 있으면 보수적으로 MEDIUM
            action["expected_impact"] = "MEDIUM"

    return json.dumps(obj, ensure_ascii=False)

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
    Day10(영서):
    - 1) LLM 호출
    - 2) JSON parse -> normalize_output_dict (MODERATE->MEDIUM 등)
    - 3) Pydantic validate
    - 4) semantic_checks (필수 필드/논리 모순 체크)
    - 5) 실패 시 1회 repair 재요청
    """
    payload = dict(incident_input)
    payload["context_chunks"] = context_chunks

    raw = call_llm_json(REGULATION_AGENT_SYSTEM_PROMPT, payload, model=model)

    def _parse_normalize_validate(raw_json_str: str) -> RegulationAgentOutput:
        # 1) JSON parse
        obj = json.loads(raw_json_str)

        # 2) normalize (expected_impact 등 룰 보정)
        obj = normalize_output_dict(obj)

        # 3) validate
        out = RegulationAgentOutput.model_validate(obj)
        return out

    # ---- 1차 시도 ----
    try:
        out1 = _parse_normalize_validate(raw)
        errs = semantic_checks(out1)
        if not errs:
            return out1
        # semantic 실패면 repair로 넘어감
        semantic_error_text = "\n".join([f"- {e}" for e in errs])
    except (ValidationError, json.JSONDecodeError) as e:
        semantic_error_text = f"- validation/parsing error: {str(e)}"

    # ---- 1회 repair 재요청 ----
    payload_retry = dict(payload)
    payload_retry["_retry_note"] = (
        "FIX THE OUTPUT TO SATISFY BOTH SCHEMA + SEMANTIC RULES.\n"
        "Must satisfy:\n"
        "- expected_impact must be one of: LOW, MEDIUM, HIGH (NOT MODERATE)\n"
        "- If insufficient_context=true -> recommended_actions must be [] and missing_context_requests must be non-empty\n"
        "- If insufficient_context=false -> regulations must be non-empty\n"
        "- escalation_needed=false -> recommended_actions must be []\n"
        "- decision_questions must be non-empty\n"
        "- Do NOT output placeholders like 'string'\n"
        "Errors to fix:\n"
        f"{semantic_error_text}\n"
        "Return ONLY valid JSON."
    )

    raw2 = call_llm_json(REGULATION_AGENT_SYSTEM_PROMPT, payload_retry, model=model)

    # repair 결과도 normalize+validate+semantic
    out2 = _parse_normalize_validate(raw2)
    errs2 = semantic_checks(out2)
    if errs2:
        # 여기까지 왔는데도 semantic이 깨지면, 디버깅 용도로 에러를 터뜨리는 게 맞음
        raise ValueError("Semantic validation failed after repair:\n" + "\n".join(errs2))
    return out2



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

def make_mock_incident_input_ami() -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()

    guardduty_finding = {
        "id": "gd-finding-ami-001",
        "type": "UnauthorizedAccess:EC2/UntrustedAMI",
        "severity": 6.0,
        "title": "Untrusted AMI used to launch instance",
        "description": "Instance launched from untrusted AMI.",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-ami-test-001",
                "imageId": "ami-0external123",
            },
        },
    }

    executed_level1_actions = ["record_finding", "notify_slack"]

    incident_input = {
        "schema_version": "1.1",
        "generated_at": now,
        "incident_id": guardduty_finding["id"],
        "incident_summary": {
            "source": "guardduty",
            "title": "Untrusted AMI detected (post-L1)",
            "severity": str(guardduty_finding["severity"]),
            "resource": {
                "type": "Instance",
                "id": guardduty_finding["resource"]["instanceDetails"]["instanceId"],
                "region": guardduty_finding["region"],
                "account_id": guardduty_finding["accountId"],
            },
        },
        "executed_level1_actions": executed_level1_actions,
        "candidate_actions": [
            "isolate_instance",
            "create_snapshot",
        ],
        "_guardduty_finding_raw": guardduty_finding,
    }
    return incident_input

# -------- Main: Chroma connect → retrieve → context_chunks → LLM → validate --------
def main():
    # 0) Chroma 설정 (팀원과 맞춰서 수정)
    CHROMA_PERSIST_DIR = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_db")
    COLLECTION_NAME = os.environ.get("CHROMA_COLLECTION", "csa_ccm_v4")



    # 1) incident input 준비
    #incident_input = make_mock_incident_input()
    incident_input = make_mock_incident_input_ami()

    # 2) query builder 입력으로 GuardDuty raw를 사용(가정)
    finding = incident_input.get("_guardduty_finding_raw", {})
    candidate_actions = incident_input.get("candidate_actions", [])
    #runtime_result = {"tags": ["credential_compromise"], "key_signals": ["unusual API calls", "external IP"]}

    runtime_result = {
        "ami_source": "external",
        "is_production": True,
        "tags": ["untrusted_ami"],
        "key_signals": ["untrusted ami"]
    }
    
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

    # 4) context_chunks 생성 (document만)
    context_chunks = build_context_chunks(retrieved)

    print("\n=== [Day7] context_chunks (preview) ===")
    print(json.dumps(context_chunks[:2], ensure_ascii=False, indent=2))

    # 5) Regulation Agent 호출 + Pydantic 검증
    # (테스트 편의: _guardduty_finding_raw 제거)
    incident_input.pop("_guardduty_finding_raw", None)

    print("\n=== [Day7] Calling Regulation Agent (LLM) ===")
    output = call_regulation_agent_with_validation(
        incident_input=incident_input,
        context_chunks=context_chunks,
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    )
    



# =========================
# Day 8: Level Router + TC
# =========================

from typing import NamedTuple

class LevelDecision(NamedTuple):
    selected_level: int               # 1|2|3
    reasons: List[str]                # explainability for tests

def decide_response_level(
    finding: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
) -> LevelDecision:
    """
    Day8 MVP rule-based level router (MCP 역할을 로컬 함수로 대체)
    - severity는 참고만
    - 키워드/리소스/권한영향/반복성/확산위험 신호로 1/2/3 분기
    """
    runtime_result = runtime_result or {}
    reasons: List[str] = []

    gd_type = str(finding.get("type", "")).lower()
    sev = float(finding.get("severity", 0) or 0)
    resource_type = _safe_get(finding, ["resource", "resourceType"], "")
    access_key_id = _safe_get(finding, ["resource", "accessKeyDetails", "accessKeyId"], "")
    iam_user = _safe_get(finding, ["resource", "accessKeyDetails", "userName"], "")

    signals = [s.lower() for s in _to_list(runtime_result.get("key_signals"))]
    tags = [t.lower() for t in _to_list(runtime_result.get("tags"))]
    
    # --- Level 1 fast-path (낮은 위험 + 단발성/약한 신호) ---
    if sev < 4.0 and not signals and not tags and not access_key_id and "accesskey" not in str(resource_type).lower():
        reasons.append(f"Low severity ({sev}) and no signals/tags → observe only.")
        return LevelDecision(1, reasons)
      
        # --- AMI / Image 기반 분기 ---
    # GuardDuty finding에서 imageId(AMI)가 잡히는 케이스: InstanceDetails.imageId
    image_id = _safe_get(finding, ["resource", "instanceDetails", "imageId"], "")
    ami_source = str(runtime_result.get("ami_source", "")).lower()  # "external" | "marketplace" | "approved" | "unknown"
    is_production = bool(runtime_result.get("is_production", False))

    # --- Level 3 trigger (확정 침해/확산/증거보존 필요) ---
    if any(k in gd_type for k in ["backdoor", "malware", "crypto", "ransom", "trojan"]):
        reasons.append("Finding type suggests active compromise/malware.")
        return LevelDecision(3, reasons)

    if any(k in signals for k in ["data exfiltration", "lateral movement", "persistence", "ongoing attack"]):
        reasons.append("Signals indicate expansion/persistence/ongoing malicious activity.")
        return LevelDecision(3, reasons)

    # Level 3: 악성 AMI / 확산 정황
    if any(k in signals for k in ["malicious ami", "backdoored ami", "ami persistence", "worm-like spread"]):
        reasons.append("Signals indicate malicious AMI / persistence via image.")
        return LevelDecision(3, reasons)

    # Level 2: 비신뢰 AMI가 prod에서 사용됨 (승인 기반 대응)
    if image_id and (ami_source in ["external", "unknown", "untrusted"]):
        reasons.append(f"Untrusted AMI used (imageId={image_id}, source={ami_source}).")
        if is_production:
            reasons.append("Production environment → approve containment before impact.")
        return LevelDecision(2, reasons)

    # --- Level 2 trigger (승인 기반 containment 필요) ---
    if "accesskey" in str(resource_type).lower() or access_key_id:
        reasons.append("AccessKey related event → credential misuse risk.")
        # 유출/오남용 관련 태그/시그널이 있으면 L2 강제
        if any(k in tags for k in ["credential_compromise", "key_leak", "stolen_credential"]) or \
            any(k in signals for k in ["unusual api calls", "external ip", "anomalous behavior"]):
            reasons.append("Signals/tags suggest anomalous credential usage → containment needed.")
            return LevelDecision(2, reasons)

    if any(k in gd_type for k in ["privilegeescalation", "excessive", "unauthorizedadminaccess"]):
        reasons.append("Privilege-impacting finding type → containment/mitigation needed.")
        return LevelDecision(2, reasons)

    # severity가 높아도 '확정 침해'가 아니면 L2로 두는 게 안전
    if sev >= 7.0:
        reasons.append(f"High severity ({sev}) but no L3 triggers → prefer L2.")
        return LevelDecision(2, reasons)

    # --- Default Level 1 (inform/observe) ---
    reasons.append("No strong indicators for containment or critical response → observe.")
    return LevelDecision(1, reasons)


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
    
    
    
def make_tc_ami_1_untrusted_ami_used() -> Dict[str, Any]:
    return {
        "id": "gd-finding-ami-001",
        "type": "UnauthorizedAccess:EC2/UntrustedAMI",
        "severity": 6.0,
        "title": "Untrusted AMI used to launch instance",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-ami-test-001",
                "imageId": "ami-0external123"
            },
        },
    }

def run_tc_ami_1():
    finding = make_tc_ami_1_untrusted_ami_used()
    runtime_result = {
        "ami_source": "external",
        "is_production": True,
        "tags": ["untrusted_ami"],
        "key_signals": ["untrusted ami"]
    }

    decision = decide_response_level(finding, runtime_result)

    print("\n=== [Day8][TC-AMI-1] Untrusted AMI in prod → expect Level 2 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 2, "TC-AMI-1 FAILED: expected Level 2"
    print("✅ TC-AMI-1 PASSED")
    
    
def make_tc_ami_2_malicious_ami_signal() -> Dict[str, Any]:
    return {
        "id": "gd-finding-ami-002",
        "type": "UnauthorizedAccess:EC2/UntrustedAMI",
        "severity": 5.0,
        "title": "Possible malicious AMI behavior detected",
        "region": "ap-northeast-2",
        "accountId": "123456789012",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-ami-test-002",
                "imageId": "ami-0bad999"
            },
        },
    }

def run_tc_ami_2():
    finding = make_tc_ami_2_malicious_ami_signal()
    runtime_result = {
        "ami_source": "unknown",
        "is_production": False,
        "tags": ["suspicious-ami"],
        "key_signals": ["malicious ami", "persistence"]
    }

    decision = decide_response_level(finding, runtime_result)

    print("\n=== [Day8][TC-AMI-2] Malicious AMI signals → expect Level 3 ===")
    print("selected_level:", decision.selected_level)
    print("reasons:", decision.reasons)

    assert decision.selected_level == 3, "TC-AMI-2 FAILED: expected Level 3"
    print("✅ TC-AMI-2 PASSED")   

if __name__ == "__main__":
    main()
    run_tc1()
    run_tc2()
    run_tc3()
    run_tc4()
    run_tc5()
    run_tc6()
    
    run_tc_ami_1()
    run_tc_ami_2()