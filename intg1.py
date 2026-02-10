from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Literal, NamedTuple

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, ValidationError, conlist, confloat
import chromadb

load_dotenv()


# =========================================================
# 0) Env / Clients
# =========================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not set. Put it in .env or export it.")

client = OpenAI(api_key=OPENAI_API_KEY)

CHROMA_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_store")
COLLECTION_NAME = os.getenv("CHROMA_COLLECTION", "isms_p_test")  # 팀 합의로 변경 가능
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

OUT_DIR = os.getenv("OUT_DIR", "./out")
os.makedirs(OUT_DIR, exist_ok=True)


# =========================================================
# 1) (수민) Embedding + Chroma Setup
# =========================================================
def get_embeddings(texts: List[str], model: str = "text-embedding-3-large") -> List[List[float]]:
    resp = client.embeddings.create(model=model, input=texts)
    return [item.embedding for item in resp.data]


# 샘플 규제 데이터(실전에서는 파일 로드/CSV/JSON로 대체 권장)
REGULATION_DOCUMENTS = [
    {
        "text": "접근권한은 업무상 필요한 최소한으로 부여하고, 변경 및 회수 이력을 관리해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "2.4.1",
        "category": "AccessControl",
        "title": "접근권한 최소 부여 및 이력관리",
        "doc_version": "test",
    },
    {
        "text": "침해사고 발생 시 신속한 대응을 통해 확산을 방지하고 피해를 최소화해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "3.1.2",
        "category": "IncidentResponse",
        "title": "침해사고 대응",
        "doc_version": "test",
    },
    {
        "text": "시스템 접근 및 보안 이벤트에 대한 로그를 생성하고 일정 기간 안전하게 보관해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "4.2.3",
        "category": "Logging",
        "title": "로그 생성 및 보관",
        "doc_version": "test",
    },
]


def setup_chromadb(documents: List[Dict[str, Any]]) -> chromadb.Collection:
    chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)

    # 있으면 로드
    try:
        col = chroma_client.get_collection(COLLECTION_NAME)
        # 비어있지 않으면 그대로 사용
        if col.count() > 0:
            print(f"📦 Loaded existing collection: {COLLECTION_NAME} (count={col.count()}) @ {CHROMA_DIR}")
            return col
    except Exception:
        pass

    # 없으면 생성
    col = chroma_client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "Regulation clauses (ISMS-P test)"},
    )

    texts = [d["text"] for d in documents]
    embeddings = get_embeddings(texts)

    metadatas = []
    ids = []
    for i, d in enumerate(documents):
        ids.append(d.get("clause_id", f"doc_{i}"))
        metadatas.append(
            {
                "doc_type": d.get("doc_type", ""),
                "doc_version": d.get("doc_version", ""),
                "clause_id": d.get("clause_id", ""),
                "title": d.get("title", ""),
                "category": d.get("category", ""),
                # 확장 가능: mapping_iso27001 등
            }
        )

    col.add(
        ids=ids,
        documents=texts,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    print(f"✅ Created collection: {COLLECTION_NAME} (count={col.count()}) @ {CHROMA_DIR}")
    return col


def retrieve_regulations(
    collection: chromadb.Collection,
    query_text: str,
    top_k: int = 6,
    where_filter: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    q_emb = get_embeddings([query_text])[0]

    kwargs: Dict[str, Any] = {
        "query_embeddings": [q_emb],
        "n_results": top_k,
        "include": ["metadatas", "documents", "distances"],
    }
    if where_filter:
        kwargs["where"] = where_filter

    res = collection.query(**kwargs)

    out: List[Dict[str, Any]] = []
    ids = (res.get("ids") or [[]])[0]
    mets = (res.get("metadatas") or [[]])[0]
    docs = (res.get("documents") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]

    for i in range(min(len(ids), len(mets), len(docs), len(dists))):
        out.append(
            {
                "id": ids[i],
                "metadata": mets[i] or {},
                "document": docs[i] or "",
                "distance": dists[i],
            }
        )
    return out


def build_context_chunks(retrieved: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chunks: List[Dict[str, Any]] = []
    for r in retrieved:
        meta = r.get("metadata") or {}
        clause_id = meta.get("clause_id") or r.get("id")

        chunks.append(
            {
                "doc_type": meta.get("doc_type", ""),
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


# =========================================================
# 2) (영서) Output Schema + Normalizer + Semantic Checks
# =========================================================
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
    decision_questions: conlist(str, min_length=1)
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


_IMPACT_SYNONYM_MAP = {"MODERATE": "MEDIUM", "MID": "MEDIUM", "MIDDLE": "MEDIUM"}
_PLACEHOLDERS = {"string", "iso8601", "n/a", "na", "tbd", "todo", "none", ""}


def _is_placeholder(x: Any) -> bool:
    if x is None:
        return True
    t = str(x).strip().lower()
    return t in _PLACEHOLDERS or len(t) < 2


def normalize_output_dict(raw_obj: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(raw_obj)

    if _is_placeholder(out.get("generated_at")):
        out["generated_at"] = datetime.now(timezone.utc).isoformat()

    ra = out.get("recommended_actions", [])
    if isinstance(ra, list):
        for a in ra:
            if not isinstance(a, dict):
                continue
            # impact normalize
            imp = a.get("expected_impact")
            if isinstance(imp, str):
                up = imp.strip().upper()
                a["expected_impact"] = _IMPACT_SYNONYM_MAP.get(up, up if up else "MEDIUM")
            else:
                a["expected_impact"] = "MEDIUM"
            # approval force
            a["requires_approval"] = True
    out["recommended_actions"] = ra
    return out


def semantic_checks(output: RegulationAgentOutput) -> List[str]:
    errs: List[str] = []

    if _is_placeholder(output.incident_summary.title):
        errs.append("incident_summary.title looks placeholder")
    if _is_placeholder(output.escalation_assessment.approval_notes):
        errs.append("approval_notes looks placeholder")
    if output.escalation_assessment.confidence <= 0.05:
        errs.append("confidence too low / placeholder-like")

    if output.insufficient_context:
        if not output.missing_context_requests:
            errs.append("insufficient_context=true but missing_context_requests empty")
        if output.recommended_actions:
            errs.append("insufficient_context=true but recommended_actions not empty")
    else:
        if not output.regulations:
            errs.append("insufficient_context=false but regulations empty")

    if output.escalation_assessment.escalation_needed is False and output.recommended_actions:
        errs.append("escalation_needed=false but recommended_actions not empty")

    rec_level = output.escalation_assessment.recommended_level
    for i, act in enumerate(output.recommended_actions):
        if act.level != rec_level:
            errs.append(f"recommended_actions[{i}].level != recommended_level")

    return errs


# =========================================================
# 3) Regulation Agent Prompt + LLM Call (JSON Output)
# =========================================================
REGULATION_AGENT_SYSTEM_PROMPT = r"""
You are the “Regulation Agent”, a compliance-first decision-support agent for AWS incident response.

- Level 1 actions are already executed by Runtime Agent.
- You must recommend ONLY Level 2 or Level 3 (approval-based).
- You MUST ONLY cite clauses present in context_chunks (NO hallucination).
- If regulatory context is insufficient:
  - insufficient_context=true
  - missing_context_requests non-empty
  - recommended_actions must be []

Return ONLY a single JSON object with exactly these top-level keys:
schema_version, generated_at, incident_id, incident_summary, executed_level1_actions,
escalation_assessment, reasoning_bullets, regulations, recommended_actions,
insufficient_context, missing_context_requests
""".strip()

OUTPUT_JSON_SKELETON = {
    "schema_version": "1.1",
    "generated_at": "ISO8601",
    "incident_id": "string",
    "incident_summary": {
        "source": "guardduty",
        "title": "string",
        "severity": "string",
        "resource": {"type": "string", "id": "string", "region": "string", "account_id": "string"},
    },
    "executed_level1_actions": [],
    "escalation_assessment": {
        "escalation_needed": True,
        "recommended_level": 2,
        "confidence": 0.42,
        "decision_questions": ["Do you approve the proposed Level 2/3 actions given the incident context?"],
        "approval_notes": "Explain assumptions and approval considerations.",
    },
    "reasoning_bullets": [],
    "regulations": [
        {"framework": "ISMS-P", "clause_id": "2.4.1", "clause_title": "", "relevance": 0.7, "excerpt": "", "why_relevant": ""}
    ],
    "recommended_actions": [
        {
            "action_id": "disable_access_key",
            "level": 2,
            "description": "Disable compromised access key after approval.",
            "targets": [{"type": "AccessKey", "id": "AKIA..."}],
            "requires_approval": True,
            "expected_impact": "LOW",
        }
    ],
    "insufficient_context": False,
    "missing_context_requests": [],
}


def call_llm_json(payload: dict, model: str = OPENAI_MODEL) -> str:
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
            {"role": "system", "content": REGULATION_AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content or ""


def call_regulation_agent_with_validation(
    incident_input: Dict[str, Any],
    context_chunks: List[Dict[str, Any]],
    model: str = OPENAI_MODEL,
) -> RegulationAgentOutput:
    payload = dict(incident_input)
    payload["context_chunks"] = context_chunks

    def parse_norm_validate(raw: str) -> RegulationAgentOutput:
        obj = json.loads(raw)
        obj = normalize_output_dict(obj)
        return RegulationAgentOutput.model_validate(obj)

    raw1 = call_llm_json(payload, model=model)
    try:
        out1 = parse_norm_validate(raw1)
        errs = semantic_checks(out1)
        if not errs:
            return out1
        err_text = "\n".join(f"- {e}" for e in errs)
    except (ValidationError, json.JSONDecodeError) as e:
        err_text = f"- parsing/validation error: {str(e)}"

    # 1회 repair
    payload_retry = dict(payload)
    payload_retry["_retry_note"] = (
        "FIX OUTPUT to satisfy schema + semantic rules.\n"
        "- If insufficient_context=true -> recommended_actions=[] and missing_context_requests non-empty\n"
        "- If insufficient_context=false -> regulations non-empty\n"
        "- escalation_needed=false -> recommended_actions=[]\n"
        "- decision_questions non-empty\n"
        "- avoid placeholders like 'string'\n"
        f"Errors:\n{err_text}\n"
        "Return ONLY valid JSON."
    )

    raw2 = call_llm_json(payload_retry, model=model)
    out2 = parse_norm_validate(raw2)
    errs2 = semantic_checks(out2)
    if errs2:
        raise ValueError("Semantic validation failed after repair:\n" + "\n".join(errs2))
    return out2


# =========================================================
# 4) Mock Incident Input (MCP -> Regulation)
# =========================================================
def make_mock_incident_input_accesskey() -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": "1.1",
        "generated_at": now,
        "incident_id": "gd-finding-123",
        "incident_summary": {
            "source": "guardduty",
            "title": "Access Key suspicious usage (post-L1)",
            "severity": "5.3",
            "resource": {"type": "AccessKey", "id": "AKIA-TESTKEY", "region": "ap-northeast-2", "account_id": "123456789012"},
        },
        "executed_level1_actions": ["record_finding", "notify_slack", "fetch_cloudtrail_related_events"],
        "candidate_actions": ["disable_access_key", "terminate_sessions", "detach_admin_policies"],
    }




# =========================================================
# 5) Query Builder (간단 버전)
# =========================================================
def build_rag_query(incident_input: Dict[str, Any]) -> str:
    s = incident_input["incident_summary"]
    parts = [
        s.get("title", ""),
        f"resource:{s['resource'].get('type','')}",
        f"severity:{s.get('severity','')}",
    ]
    cand = incident_input.get("candidate_actions", [])
    if cand:
        parts.append("candidate_actions:" + ",".join(cand[:8]))
    return " | ".join(p for p in parts if p)


# =========================================================
# 6) Export (Runtime 팀에 넘길 JSON)
# =========================================================
def export_json(output: RegulationAgentOutput) -> str:
    fname = f"regulation_output_{output.incident_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path = os.path.join(OUT_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(), f, ensure_ascii=False, indent=2)
    return path


# =========================================================
# 7) Main E2E
# =========================================================
def main():
    print(f"== Chroma setup @ {CHROMA_DIR} / collection={COLLECTION_NAME} ==")
    collection = setup_chromadb(REGULATION_DOCUMENTS)

    incident_input = make_mock_incident_input_accesskey()
    query_text = build_rag_query(incident_input)

    print("\n== RAG query ==")
    print(query_text)

    retrieved = retrieve_regulations(collection, query_text, top_k=3)
    print("\n== Retrieved ==")
    for r in retrieved:
        m = r["metadata"]
        print(f"- clause_id={m.get('clause_id')} category={m.get('category')} dist={r['distance']:.4f}")

    context_chunks = build_context_chunks(retrieved)

    print("\n== Call Regulation Agent ==")
    output = call_regulation_agent_with_validation(
        incident_input=incident_input,
        context_chunks=context_chunks,
        model=OPENAI_MODEL,
    )

    print("\n== Validated Output ==")
    print(json.dumps(output.model_dump(), ensure_ascii=False, indent=2))

    saved = export_json(output)
    print(f"\n✅ Exported for Runtime team: {saved}")


if __name__ == "__main__":
    main()