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


def _build_llm_prompt(user_response: dict, comparison: dict) -> str:
    """LLM/XAI 프롬프트 (수정 시 이 함수만 편집). 사용자 응답 + 플레이북 비용 요약 → 추천+이유 JSON 요청."""
    playbooks = comparison.get("playbooks") or []
    lines = []
    for p in playbooks:
        cost = (p.get("cost_summary") or {}).get("estimated_monthly_cost")
        lines.append(
            f"- L{p.get('level')} {p.get('playbook_name', '')}: 예상 월 비용 {cost} USD, "
            f"expected_impact {p.get('expected_impact', '')}"
        )
    summary = "\n".join(lines) if lines else "없음"
    return f"""다음은 보안 사고 대응 시뮬레이션 결과입니다.

[사용자 선택]
- 운영 환경: {user_response.get('environment', '')}
- 데이터 민감도: {user_response.get('data_sensitivity', '')}
- 서비스 중단 허용: {user_response.get('downtime_tolerance', '')}
- 보안 vs 비용 우선순위: {user_response.get('priority', '')}

[플레이북별 예상 비용]
{summary}

위 사용자 선택과 비용 정보를 바탕으로, Level 2 vs Level 3 중 어떤 플레이북을 추천할지 결정하고, 사용자가 이해하기 쉬운 추천 이유(XAI)를 2~3문장으로 한글로 작성해주세요.

반드시 아래 JSON만 한 줄로 출력하세요 (다른 설명 없이):
{{"recommended_level": 2 또는 3, "playbook_name": "추천 플레이북 한글 이름", "reason": "추천 이유 한글로 2~3문장"}}
"""


def _call_openai_recommendation(
    api_key: str, user_response: dict, comparison: dict, model: str = "gpt-4o-mini"
) -> dict | None:
    """
    OpenAI API 호출. level/playbook_name은 결정론적 결과로 덮어써서 환각 방지, LLM은 reason(XAI) 생성에만 사용.
    반환: { recommended_level, playbook_name, reason } 또는 실패 시 None.
    """
    try:
        # 1) 결정론적로 level·playbook_name 확정 (LLM이 잘못 내놓아도 덮어씀)
        deterministic = recommend_level_from_user_response(user_response, comparison)
        level = deterministic["recommended_level"]
        playbook_name = deterministic["playbook_name"]

        import openai
        client = openai.OpenAI(api_key=api_key)
        prompt = _build_llm_prompt(user_response, comparison)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,  # 결정론에 가깝게 (reason만 생성)
        )
        text = (resp.choices[0].message.content or "").strip()
        reason = deterministic["reason"]  # 기본값: 결정론적 이유
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    r = (data.get("reason") or "").strip()
                    if r and len(r) <= 500:  # 비정상 길이 방지
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
    comparison: dict, user_response: dict
) -> dict:
    """
    사용자 시뮬레이션 기반 추천을 OpenAI로 생성하고, MCP에 넘길 JSON 반환.
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
        rec = _call_openai_recommendation(api_key, user_response, comparison)
        if rec is not None:
            return {
                "recommended_playbook": rec,
                "user_response": user_response,
                "source": "llm",
            }

    rec = recommend_level_from_user_response(user_response, comparison)
    return {
        "recommended_playbook": rec,
        "user_response": user_response,
        "source": "fallback",
    }
