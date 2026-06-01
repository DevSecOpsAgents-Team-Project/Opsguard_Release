# engine_handler.py // Agent B의 메인 엔진 핸들러 (팀 A 담당)
import json
import logging
from typing import Any, Dict
from .dispatcher_module import ActionDispatcher

# playbook 함수 직접 import (필수)
from .playbooks_module import (
    playbook_ec2_isolate,
    playbook_s3_public_access,
    playbook_iam_abuse_response, # 시나리오 3 추가
    playbook_ec2_investigation_logging,
    playbook_integrated_base_mitigation
)

# Actions 클래스 import (모든 액션과 LLM 호출 담당)
from .actions_module import Actions 

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# GuardDuty 시나리오 키 → 플레이북 매핑
PLAYBOOK_MAP = {
    "BASE_MITIGATION": playbook_integrated_base_mitigation,
    "EC2_ISOLATION": playbook_ec2_isolate,
    "S3_POLICY_BLOCK": playbook_s3_public_access,
    "IAM_PERMISSION_ABUSE": playbook_iam_abuse_response, # 새로운 IAM 플레이북 매핑
    "EC2_INVESTIGATION_LOGGING": playbook_ec2_investigation_logging,
}

def _format_action_result_line(result: Dict[str, Any]) -> str:
    action_id = result.get("action_id", "?")
    target_id = result.get("target_id", "N/A")
    status = result.get("status", "UNKNOWN")
    line = f"• `{action_id}` ({target_id}): {status}"
    if status == "SKIPPED":
        reason = result.get("skip_reason")
        if reason:
            line += f" — {reason}"
    elif result.get("error"):
        line += f" — {result['error']}"
    return line


def _build_execution_slack_detail(execution_results: list) -> tuple:
    """조치 실행 결과 목록으로 Slack 상세 문구와 성공 여부를 만듭니다."""
    if not execution_results:
        return False, "실행할 조치가 없거나 recommended_actions가 비어 있습니다."

    ok_statuses = {"SUCCESS", "SKIPPED"}
    failed = [r for r in execution_results if r.get("status") not in ok_statuses]
    succeeded = [r for r in execution_results if r.get("status") == "SUCCESS"]
    skipped = [r for r in execution_results if r.get("status") == "SKIPPED"]

    if failed:
        lines = [_format_action_result_line(r) for r in failed]
        if skipped:
            lines.append("")
            lines.append("*건너뛴 조치:*")
            lines.extend(_format_action_result_line(r) for r in skipped)
        if succeeded:
            lines.append("")
            lines.append("*완료된 조치:*")
            lines.extend(_format_action_result_line(r) for r in succeeded)
        return False, "다음 조치가 실패했습니다:\n" + "\n".join(lines)

    if skipped and not succeeded:
        lines = [_format_action_result_line(r) for r in skipped]
        return True, (
            "실행 가능한 IAM User 장기 키 조치가 없어 다음 항목을 건너뛰었습니다:\n"
            + "\n".join(lines)
        )

    if skipped and succeeded:
        lines = [_format_action_result_line(r) for r in succeeded + skipped]
        return True, "조치 결과:\n" + "\n".join(lines)

    return True, f"승인된 플레이북 조치 {len(execution_results)}건이 정상 처리되었습니다."


def _execute_approved_actions(event: Dict[str, Any]) -> Dict[str, Any]:
    """슬랙에서 승인된 L2/L3 액션들을 Dispatcher를 통해 동적으로 실행합니다."""
    incident_id = event.get("incident_id", "UNKNOWN")
    logger.info(f"🚀 [조치 실행] 슬랙 승인에 의한 L2/L3 조치 시작 (ID: {incident_id})")

    dispatcher = ActionDispatcher(dry_run=False)
    execution_results = dispatcher.dispatch(event)

    success, detail = _build_execution_slack_detail(execution_results)

    actions = Actions()
    actions.notify_execution_result_to_slack(incident_id, success, detail)

    return {
        "status": "ACTION_EXECUTED" if success else "ACTION_PARTIAL_OR_FAILED",
        "incident_id": incident_id,
        "execution_success": success,
        "detail": detail,
        "results": execution_results,
    }


def _detect_scenario(event: Dict[str, Any]) -> str:
    detail = event.get("detail", {})
    finding_type = detail.get("type", "")
    severity = detail.get("severity") 

    if not finding_type:
        return "UNKNOWN"

    # === EC2 관련 시나리오 ===
    if finding_type.startswith("UnauthorizedAccess:EC2") or \
        finding_type.startswith("Backdoor:EC2") or \
        finding_type.startswith("CryptoCurrency:EC2") or \
        finding_type.startswith("Impact:EC2") or \
        ("Runtime" in finding_type and "Suspicious" in finding_type):

        # severity가 명시되어 있고, 4 미만이면 "조사용"으로만 처리
        if severity is not None and severity < 4:
            return "EC2_INVESTIGATION_LOGGING"
        return "EC2_ISOLATION"

    # === S3 공개 정책 변경 ===
    if "S3" in finding_type and "Policy" in finding_type:
        return "S3_POLICY_BLOCK"

    # === IAM 권한 악용 시나리오 ===
    if finding_type.startswith("CredentialAccess") or \
        finding_type.startswith("UnauthorizedAccess:IAMUser") or \
        finding_type.startswith("Policy:IAMUser"):
        return "IAM_PERMISSION_ABUSE"

    return "UNKNOWN"


def lambda_handler(event: Any, context: Any = None) -> Dict[str, Any]:

    try:
        if isinstance(event, str):
            event = json.loads(event)

        incident_id = event.get("id", "UNKNOWN")
        actions = Actions()

        # ==================================================================
        # 🟢 [분기 1] 슬랙 버튼 승인을 통해 들어온 '조치 실행' 요청인지 확인
        # ==================================================================
        if "recommended_actions" in event:
            try:
                return _execute_approved_actions(event)
            except Exception as e:
                incident_id = event.get("incident_id", "UNKNOWN")
                logger.exception("슬랙 승인 조치 실행 중 오류: %s", e)
                actions = Actions()
                actions.notify_execution_result_to_slack(
                    incident_id, False, f"조치 실행 중 예외 발생: {e}"
                )
                return {
                    "status": "error",
                    "incident_id": incident_id,
                    "execution_success": False,
                    "detail": f"조치 실행 중 예외 발생: {e}",
                    "reason": str(e),
                }

        # ==================================================================
        # 🔵 [분기 2] GuardDuty에서 처음 들어온 이벤트 처리 (Level 1)
        # ==================================================================
        incident_id = event.get("id", "UNKNOWN")
        base_result = None
        key_signals = [] # 분리할 변수 미리 선언
        tags = []        # 분리할 변수 미리 선언

        try:
            logger.info(f"🛡️ [Base Mitigation] 공통 대응 시작 (ID: {incident_id})")
            base_result = playbook_integrated_base_mitigation(event, actions=actions)

            # --- 💡 핵심 수정 부분: base_result에서 데이터 분리하기 ---
            if isinstance(base_result, dict):
                # .pop()을 사용하면 base_result 안에서는 해당 키가 삭제되고 값만 빠져나옵니다.
                key_signals = base_result.pop("key_signals", [])
                tags = base_result.pop("tags", [])
            # ----------------------------------------------------

            logger.info("✅ [Base Mitigation] 공통 대응 완료")
        except Exception as e:
            logger.error(f"❌ [Base Mitigation] 실패 (계속 진행함): {e}")
            base_result = {"status": "error", "error": str(e)}
            
        # 🎯 현재 모드: 처음 들어온 GuardDuty 로그는 여기서 Level 1만 실행하고 MCP로 넘김
        return {
            "status": "LEVEL1_ONLY",
            "base_result": base_result,
            "key_signals": key_signals,   # 팀원이 요청한 대로 1 Depth에 배치!
            "tags": tags,                 # 팀원이 요청한 대로 1 Depth에 배치!
            "incident_id": incident_id
        }
        
        scenario_key = _detect_scenario(event)

        if scenario_key == "UNKNOWN":
            logger.warning("GuardDuty detail.type을 찾지 못했거나 매칭 불가. 시나리오 UNKNOWN.")
            return {
                "status": "ignored",
                "reason": "no matching scenario (UNKNOWN)",
                "incident_id": incident_id,
                "base_result": base_result  
            }

        playbook_func = PLAYBOOK_MAP.get(scenario_key)
        if not playbook_func:
            logger.warning(f"scenario_key={scenario_key} 에 매핑된 플레이북이 없음.")
            return {
                "status": "error",
                "reason": f"PLAYBOOK_MAP에 {scenario_key} 매핑이 없음",
                "incident_id": incident_id,
                "base_result": base_result
            }



        logger.info(
            f"시나리오 감지: {scenario_key}, "
            f"플레이북 실행: {playbook_func.__name__}"
        )
        
        # ------------------------------------------------------------------
        # 🧠 [고도화 핵심] 지능형 판단 및 전략 결정 (모든 Agent B 시나리오에 적용됨)
        # ------------------------------------------------------------------
        if scenario_key == "EC2_ISOLATION":
            # EC2 격리 시나리오는 고도화 로직을 따름
            # 플레이북 내부에서 LLM 호출 및 Go/No-Go 판단을 수행합니다.
            playbook_result = playbook_func(event=event, actions=actions)
        
        elif scenario_key == "IAM_PERMISSION_ABUSE":
            # IAM 시나리오 (IAM은 격리 대신 차단/권한 회수가 목적이므로 별도 로직 적용 가능)
            # 여기서는 플레이북을 바로 호출 (향후 LLM 판단 추가 가능)
            playbook_result = playbook_func(event=event, actions=actions)

        elif scenario_key == "S3_POLICY_BLOCK":
            # S3 시나리오 (현재는 바로 플레이북 호출)
            playbook_result = playbook_func(event=event, actions=actions)
        
        else:
            playbook_result = playbook_func(event=event, actions=actions)

        # ------------------------------------------------------------------

        return {
            "status": "ok",
            "scenario": scenario_key,
            "base_result": base_result,
            "playbook_result": playbook_result,
            "incident_id": incident_id,
        }

    except Exception as e:
        logger.exception(f"엔진 실행 중 오류 발생: {e}")
        return {
            "status": "error",
            "reason": str(e),
            "incident_id": event.get("id", "UNKNOWN") if isinstance(event, dict) else "UNKNOWN",
        }