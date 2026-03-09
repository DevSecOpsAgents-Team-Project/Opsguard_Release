"""
Security Incident Simulation Questions.
Finance Agent가 MCP에 전달할 질문 JSON 생성, 사용자 응답 검증, 사용자 선택 기반 L2 vs L3 추천.
OpenAI 직접 호출로 추천 결과 + XAI를 JSON으로 반환 (MCP 전달용).
"""
import json
import logging
import os

import jsonschema

from .schema_io import get_simulation_user_response_schema

logger = logging.getLogger(__name__)


def _load_dotenv_if_present() -> None:
    try:
        from pathlib import Path
        import dotenv
        root = Path(__file__).resolve().parent.parent
        env_path = root / ".env"
        if env_path.exists():
            dotenv.load_dotenv(env_path)
    except ImportError:
        pass

# 시뮬레이션 질문 4개. (비용 기간은 질문하지 않음: 액션이 격리/설정 변경 위주면 1회 비용 비중이 커서 기간 영향 적음 → 기본 30일 통일)
SIMULATION_QUESTIONS_PAYLOAD = {
    "simulation_questions": [
        {
            "id": "environment",
            "question": "이 시스템의 운영 환경은 무엇입니까?",
            "type": "choice",
            "options": ["production", "internal", "dev_test"],
        },
        {
            "id": "data_sensitivity",
            "question": "이 시스템에 저장된 데이터의 민감도는 어느 정도입니까?",
            "type": "choice",
            "options": ["pii", "internal", "public"],
        },
        {
            "id": "downtime_tolerance",
            "question": "보안 대응 과정에서 서비스가 일시적으로 중단될 수 있습니다. 허용 가능합니까?",
            "type": "choice",
            "options": ["allowed", "approval_required", "not_allowed"],
        },
        {
            "id": "priority",
            "question": "이번 대응에서 보안과 비용 중 무엇을 더 우선하시겠습니까?",
            "type": "choice",
            "options": ["security", "balanced", "cost"],
        },
    ]
}


# 사용자 기간 선택 → finance_run assumptions.duration_hours 매핑
PERIOD_TO_DURATION_HOURS = {"24h": 24, "7d": 168, "30d": 720}
DEFAULT_DURATION_HOURS = 720


def period_to_duration_hours(period: str | None) -> int:
    """시뮬레이션 period 값(24h|7d|30d)을 assumptions.duration_hours로 변환. 모르면 720."""
    if not period:
        return DEFAULT_DURATION_HOURS
    return PERIOD_TO_DURATION_HOURS.get(period, DEFAULT_DURATION_HOURS)


def get_simulation_questions() -> dict:
    """MCP에 전달할 시뮬레이션 질문 JSON. Slack Block Kit 변환용."""
    return dict(SIMULATION_QUESTIONS_PAYLOAD)


def validate_user_response(obj: dict) -> None:
    """사용자 응답이 simulation_user_response 스키마에 맞는지 검사. 불일치 시 jsonschema.ValidationError."""
    jsonschema.validate(obj, get_simulation_user_response_schema())


def recommend_level_from_user_response(
    user_response: dict, comparison: dict
) -> dict:
    """
    사용자 응답 + 비용 시뮬레이션 비교 결과로 L2 vs L3 추천 (결정론적).
    반환: { "recommended_level", "playbook_name", "reason" }.
    """
    validate_user_response(user_response)
    playbooks = comparison.get("playbooks") or []
    if len(playbooks) < 2:
        p = playbooks[0] if playbooks else {}
        return {
            "recommended_level": p.get("level"),
            "playbook_name": p.get("playbook_name", ""),
            "reason": "플레이북 후보가 부족하여 비교 추천을 할 수 없습니다.",
        }

    env = user_response.get("environment", "internal")
    data_sens = user_response.get("data_sensitivity", "internal")
    downtime = user_response.get("downtime_tolerance", "approval_required")
    priority = user_response.get("priority", "balanced")

    # L3 쪽으로 기울이는 점수 (높을수록 L3 추천)
    score_l3_bias = 0
    if env == "production":
        score_l3_bias += 2
    elif env == "internal":
        score_l3_bias += 1
    if data_sens == "pii":
        score_l3_bias += 2
    elif data_sens == "internal":
        score_l3_bias += 1
    if downtime == "allowed":
        score_l3_bias += 2
    elif downtime == "approval_required":
        score_l3_bias += 1
    if priority == "security":
        score_l3_bias += 2
    elif priority == "balanced":
        score_l3_bias += 1
    # priority == "cost" -> 0

    p_l2 = next((p for p in playbooks if p.get("level") == 2), None)
    p_l3 = next((p for p in playbooks if p.get("level") == 3), None)
    if not p_l2:
        p_l2 = playbooks[0]
    if not p_l3:
        p_l3 = playbooks[1]
    cost_l2 = (p_l2.get("cost_summary") or {}).get("estimated_monthly_cost") or 0
    cost_l3 = (p_l3.get("cost_summary") or {}).get("estimated_monthly_cost") or 0

    # L3 추천: 보안/프로덕션/PII/중단허용 등으로 점수 높을 때. 비용 우선이면 L2 유리.
    if priority == "cost":
        chosen = p_l2 if cost_l2 <= cost_l3 else p_l3
    elif score_l3_bias >= 5:
        chosen = p_l3
    elif score_l3_bias <= 2:
        chosen = p_l2
    else:
        chosen = p_l3 if cost_l2 >= cost_l3 else p_l2

    level = chosen.get("level")
    name = chosen.get("playbook_name", "")
    cost = (chosen.get("cost_summary") or {}).get("estimated_monthly_cost")
    reason = (
        f"사용자 선택(환경={env}, 데이터민감도={data_sens}, 중단허용={downtime}, 우선순위={priority})과 "
        f"예상 비용({cost} USD)을 반영하여 L{level} ({name})를 추천합니다."
    )
    return {
        "recommended_level": level,
        "playbook_name": name,
        "reason": reason,
    }


def _template_reason_for_playbook(
    user_response: dict, level: int, playbook_name: str, cost: int | float | None
) -> str:
    """고정된 level/playbook_name에 대한 템플릿 reason (LLM 실패 시 폴백용)."""
    env = user_response.get("environment", "")
    data_sens = user_response.get("data_sensitivity", "")
    downtime = user_response.get("downtime_tolerance", "")
    priority = user_response.get("priority", "")
    cost_str = f"{cost} USD" if cost is not None else "알 수 없음"
    return (
        f"사용자 선택(환경={env}, 데이터민감도={data_sens}, 중단허용={downtime}, 우선순위={priority})과 "
        f"예상 비용({cost_str})을 반영하여 L{level} ({playbook_name})를 추천합니다."
    )


def _get_playbook_cost(comparison: dict, level: int, playbook_name: str) -> int | float | None:
    """comparison.playbooks에서 level+playbook_name에 해당하는 예상 월 비용 반환."""
    for p in comparison.get("playbooks") or []:
        if p.get("level") == level and (p.get("playbook_name") or "") == playbook_name:
            return (p.get("cost_summary") or {}).get("estimated_monthly_cost")
    return None


def run_simulation_recommendation(
    comparison: dict, user_response: dict
) -> dict:
    """
    시뮬레이션 비교 결과 + 사용자 응답으로 추천 레벨과 이유 반환 (결정론적만).
    MCP에서 사용자 선택 수신 후 Finance Agent에 넘길 때 사용.
    반환: { "recommended_playbook": { recommended_level, playbook_name, reason }, "user_response": user_response }
    """
    rec = recommend_level_from_user_response(user_response, comparison)
    return {
        "recommended_playbook": rec,
        "user_response": user_response,
    }


def _build_llm_prompt(
    user_response: dict,
    comparison: dict,
    recommended_level: int,
    playbook_name: str,
) -> str:
    """
    LLM용 프롬프트. 추천(level, playbook_name)은 이미 결정론적으로 확정된 상태로 전달되며,
    LLM의 역할은 이 추천을 사용자가 L2/L3 결정을 내리는 데 도움이 되도록 자연어(reason)로 설명하는 것만 수행.
    """
    playbooks = comparison.get("playbooks") or []
    lines = []
    chosen_cost = None
    chosen_impact = None
    for p in playbooks:
        cost = (p.get("cost_summary") or {}).get("estimated_monthly_cost")
        name = p.get("playbook_name", "")
        impact = p.get("expected_impact", "")
        lines.append(
            f"- L{p.get('level')} {name}: 예상 월 비용 {cost} USD, expected_impact {impact}"
        )
        if p.get("level") == recommended_level and name == playbook_name:
            chosen_cost = cost
            chosen_impact = impact
    summary = "\n".join(lines) if lines else "없음"

    event_context_parts = []
    if comparison.get("incident_id"):
        event_context_parts.append(f"- incident_id: {comparison.get('incident_id')}")
    if comparison.get("event_summary"):
        event_context_parts.append(f"- 이벤트 요약: {comparison.get('event_summary')}")
    if comparison.get("finding_type"):
        event_context_parts.append(f"- finding_type: {comparison.get('finding_type')}")
    event_context_block = ""
    if event_context_parts:
        event_context_block = "\n[감지된 보안 이벤트 컨텍스트]\n" + "\n".join(event_context_parts) + "\n\n"

    env = user_response.get("environment", "")
    data_sens = user_response.get("data_sensitivity", "")
    downtime = user_response.get("downtime_tolerance", "")
    priority = user_response.get("priority", "")

    return f"""당신은 보안 사고 대응 시뮬레이션에서 **사용자에게 전달할 설명문(reason)**을 작성하는 역할만 수행합니다.
추천 결과(Level, 플레이북)는 이미 시스템에 의해 확정되었으며, 사용자는 이 설명을 읽고 Level2 vs Level3 플레이북 선택을 최종 결정합니다.
따라서 **추천을 바꾸거나 다른 플레이북을 권유하지 말고**, 아래 확정된 추천에 대한 자연어 설명만 작성하세요.

---
[확정된 추천 결과]
- 추천 레벨: L{recommended_level}
- 추천 플레이북: {playbook_name}
- 해당 플레이북 예상 월 비용: {chosen_cost} USD
- 해당 플레이북 예상 영향도: {chosen_impact or "N/A"}
---

{event_context_block}[사용자가 입력한 선택]
- 운영 환경: {env}
- 데이터 민감도: {data_sens}
- 서비스 중단 허용: {downtime}
- 보안 vs 비용 우선순위: {priority}

[전체 후보 플레이북 요약]
{summary}

---
**작성할 내용: reason (자연어 설명)**

사용자가 "왜 L{recommended_level} {playbook_name}가 추천되었는지" 이해하고, 최종 결정에 활용할 수 있도록 아래 두 부분을 한글로 작성하세요.

① **이벤트·시나리오 맥락 (1~2문장)**
- 이번 시나리오가 "[운영 환경] + [데이터 민감도]"에서 발생한 보안 사건임을 명시.
- 추천 플레이북 "{playbook_name}"의 예상 영향도가 {chosen_impact or "N/A"}인 점에서 시나리오의 심각성·특성을 한 문장으로 요약.

② **플레이북 설명 및 추천 근거 (2~3문장)**
- "L{recommended_level} {playbook_name}"가 실제로 어떤 조치(격리·증거 확보·접근 제한 등)를 취하는지 구체적으로 서술.
- 사용자 선택(우선순위={priority}, 중단 허용={downtime})과 예상 비용({chosen_cost} USD)을 언급하며, **왜 이 플레이북이 이번 선택에 적합한지** 한 문장으로 판단 근거 제시.
- 필요 시 "비용을 더 들이더라도" 또는 "비용을 절감하면서" 등 트레이드오프를 한 줄로 언급해도 됨.

**금지:** 다른 플레이북을 추천하거나, recommended_level/playbook_name을 위 확정 결과와 다르게 작성하는 것.
**필수:** 플레이북 이름은 반드시 "{playbook_name}"(위 확정 결과와 동일)을 사용할 것.

---
아래 JSON만 한 줄로 출력하세요 (다른 텍스트 없이). recommended_level과 playbook_name은 반드시 위 [확정된 추천 결과]와 동일하게 넣으세요.
사용자에게 반환하는 reason에는 반드시 L2, L3 말고 Level2, Level3로 표기해주세요.
{{"recommended_level": {recommended_level}, "playbook_name": "{playbook_name}", "reason": "① 이벤트·시나리오 맥락 ② L{recommended_level} {playbook_name} 구체적 조치 + 사용자 선택 반영 추천 근거 (한글)"}}
"""


def _call_openai_recommendation(
    api_key: str,
    user_response: dict,
    comparison: dict,
    model: str = "gpt-4o-mini",
    fixed_level: int | None = None,
    fixed_playbook_name: str | None = None,
) -> dict | None:
    """
    OpenAI API 호출. level/playbook_name은 결정론적 결과로 유지, LLM은 reason(XAI) 생성에만 사용.
    fixed_level, fixed_playbook_name이 주어지면 그대로 사용(rule-based 결정); 없으면 recommend_level_from_user_response 사용.
    반환: { recommended_level, playbook_name, reason } 또는 실패 시 None.
    """
    try:
        if fixed_level is not None and fixed_playbook_name is not None:
            level = fixed_level
            playbook_name = fixed_playbook_name
            cost = _get_playbook_cost(comparison, level, playbook_name)
            default_reason = _template_reason_for_playbook(user_response, level, playbook_name, cost)
        else:
            deterministic = recommend_level_from_user_response(user_response, comparison)
            level = deterministic["recommended_level"]
            playbook_name = deterministic["playbook_name"]
            default_reason = deterministic["reason"]

        import openai
        client = openai.OpenAI(api_key=api_key)
        prompt = _build_llm_prompt(user_response, comparison, level, playbook_name)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,  # 결정론에 가깝게 (reason만 생성)
        )
        text = (resp.choices[0].message.content or "").strip()
        reason = default_reason
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    r = (data.get("reason") or "").strip()
                    if r and len(r) <= 1000:  # 이벤트 분석+플레이북 설명 포함 시 3~5문장 허용
                        reason = r
                except (json.JSONDecodeError, TypeError):
                    pass
                break
        return {
            "recommended_level": level,
            "playbook_name": playbook_name,
            "reason": reason,
        }
    except Exception as e:
        logger.warning("OpenAI recommendation failed: %s", e)
        return None


def get_simulation_recommendation_for_mcp(
    comparison: dict,
    user_response: dict,
    recommended_level: int | None = None,
    playbook_name: str | None = None,
) -> dict:
    """
    사용자 시뮬레이션 기반 추천을 OpenAI로 생성하고, MCP에 넘길 JSON 반환.
    recommended_level, playbook_name이 주어지면 그대로 결정으로 사용(rule-based)하고 reason만 LLM 생성.
    없으면 recommend_level_from_user_response로 결정 후 reason만 LLM 생성.
    OPENAI_API_KEY가 있으면 LLM 호출, 없거나 실패 시 결정론적 추천 + 템플릿 reason 사용.
    반환 (MCP 전달용):
    {
      "recommended_playbook": { "recommended_level", "playbook_name", "reason" },
      "user_response": { ... },
      "source": "llm" | "fallback"
    }
    """
    _load_dotenv_if_present()
    validate_user_response(user_response)

    api_key = (os.environ.get("OPENAI_API_KEY") or os.environ.get("api_key") or "").strip()
    if api_key:
        rec = _call_openai_recommendation(
            api_key,
            user_response,
            comparison,
            fixed_level=recommended_level,
            fixed_playbook_name=playbook_name,
        )
        if rec is not None:
            return {
                "recommended_playbook": rec,
                "user_response": user_response,
                "source": "llm",
            }

    # Fallback: 결정은 넘겨받은 값 또는 recommend_level_from_user_response
    if recommended_level is not None and playbook_name is not None:
        cost = _get_playbook_cost(comparison, recommended_level, playbook_name)
        rec = {
            "recommended_level": recommended_level,
            "playbook_name": playbook_name,
            "reason": _template_reason_for_playbook(user_response, recommended_level, playbook_name, cost),
        }
    else:
        rec = recommend_level_from_user_response(user_response, comparison)
    return {
        "recommended_playbook": rec,
        "user_response": user_response,
        "source": "fallback",
    }
