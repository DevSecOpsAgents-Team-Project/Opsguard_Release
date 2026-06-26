import json
import logging
import os
import traceback
from typing import Any, Dict, List, Optional, Tuple

import boto3

lambda_client = boto3.client("lambda")

RUNTIME_ARN = os.environ.get("RUNTIME_ARN")
REGULATION_ARN = os.environ.get("REGULATION_ARN")  # 아직 없으면 비워둬도 됨

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


def _log_json(level: int, prefix: str, payload: Any) -> None:
    """CloudWatch에서 필터하기 쉬운 JSON 한 줄 로그."""
    try:
        text = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = repr(payload)
    logger.log(level, "%s %s", prefix, text)


def _safe_get(d, path, default=None):
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def unwrap_incoming_event(event: Any) -> Any:
    """
    SNS → Lambda 등으로 한 번 더 감싸진 이벤트를 EventBridge/GuardDuty 본문으로 풀기.
  """
    if isinstance(event, list):
        if not event:
            logger.warning("[MCP][EVENT] empty list event")
            return {}
        logger.info("[MCP][EVENT] unwrapped list event (first item)")
        event = event[0]

    if not isinstance(event, dict):
        logger.warning("[MCP][EVENT] event is not a dict: %s", type(event).__name__)
        return event

    records = event.get("Records")
    if isinstance(records, list) and records:
        first = records[0] if isinstance(records[0], dict) else {}
        sns = first.get("Sns") or first.get("sns") or {}
        message = sns.get("Message") or sns.get("message")
        if isinstance(message, str) and message.strip():
            try:
                inner = json.loads(message)
                logger.info("[MCP][EVENT] unwrapped SNS Records[0].Sns.Message")
                return inner
            except json.JSONDecodeError as exc:
                logger.error(
                    "[MCP][EVENT] SNS Message JSON parse failed: %s body_preview=%s",
                    exc,
                    message[:500],
                )
    return event


def _invoke_lambda_logged(
    *,
    label: str,
    function_arn: str,
    payload: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Lambda invoke + FunctionError / StatusCode / raw payload 로깅."""
    _log_json(logging.INFO, f"[MCP][{label}] invoke request", {"function": function_arn, "payload_keys": list(payload.keys())})

    resp = lambda_client.invoke(
        FunctionName=function_arn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )

    meta = {
        "StatusCode": resp.get("StatusCode"),
        "FunctionError": resp.get("FunctionError"),
        "ExecutedVersion": resp.get("ExecutedVersion"),
    }
    _log_json(logging.INFO, f"[MCP][{label}] invoke meta", meta)

    raw = resp["Payload"].read().decode("utf-8")
    if resp.get("FunctionError"):
        logger.error(
            "[MCP][%s] Lambda FunctionError=%s raw_payload=%s",
            label,
            resp.get("FunctionError"),
            raw[:4000],
        )

    try:
        parsed = _parse_lambda_payload_raw(raw)
    except json.JSONDecodeError as exc:
        logger.error(
            "[MCP][%s] response JSON decode failed: %s raw=%s",
            label,
            exc,
            raw[:4000],
        )
        raise

    if isinstance(parsed, dict) and (parsed.get("error") or parsed.get("status") == "error"):
        logger.error("[MCP][%s] downstream returned error payload", label)
        _log_json(logging.ERROR, f"[MCP][{label}] error body", parsed)

    return parsed, meta


def _parse_lambda_payload_raw(raw: str):
    """
    Lambda invoke Payload 문자열 파싱.
    - dict 직접 반환 또는 {statusCode, body} 래퍼 모두 지원.
    """
    obj = json.loads(raw)

    if isinstance(obj, dict) and "body" in obj:
        status_code = obj.get("statusCode")
        body = obj["body"]
        if isinstance(body, str):
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                logger.warning(
                    "[MCP][PARSE] API Gateway body is not JSON statusCode=%s preview=%s",
                    status_code,
                    body[:500],
                )
                return {"raw_body": body, "statusCode": status_code}
            if status_code and int(status_code) >= 400:
                logger.error("[MCP][PARSE] downstream statusCode=%s", status_code)
                _log_json(logging.ERROR, "[MCP][PARSE] error body", parsed_body)
            return parsed_body
        return body

    return obj


def _parse_lambda_payload(resp):
    raw = resp["Payload"].read().decode("utf-8")
    return _parse_lambda_payload_raw(raw)


def _playbook_levels(playbooks: Any) -> List[Any]:
    if not isinstance(playbooks, list):
        return []
    levels = []
    for pb in playbooks:
        if isinstance(pb, dict) and "level" in pb:
            levels.append(pb.get("level"))
    return levels


def summarize_regulation_result(reg: Any) -> Dict[str, Any]:
    if not isinstance(reg, dict):
        return {"type": type(reg).__name__, "valid": False}
    ra = reg.get("recommended_actions")
    alt = reg.get("alternative_playbooks")
    return {
        "valid": True,
        "schema_version": reg.get("schema_version"),
        "status": reg.get("status"),
        "selected_level": reg.get("selected_level"),
        "incident_id_in_body": reg.get("incident_id"),
        "recommended_actions_count": len(ra) if isinstance(ra, list) else None,
        "recommended_action_levels": _playbook_levels(ra),
        "alternative_playbooks_count": len(alt) if isinstance(alt, list) else None,
        "alternative_levels": _playbook_levels(alt),
        "has_selected_playbook": reg.get("selected_playbook") is not None,
        "insufficient_context": reg.get("insufficient_context"),
        "error": reg.get("error"),
        "message": reg.get("message"),
    }


def should_slack_finance_form(regulation_result: Any) -> Tuple[bool, str]:
    """DynamoDB 저장 + Slack 폼 전송 가능 여부와 사유."""
    if not regulation_result:
        return False, "regulation_result is empty"
    if not isinstance(regulation_result, dict):
        return False, f"regulation_result is not dict ({type(regulation_result).__name__})"

    if regulation_result.get("status") == "DRY_RUN_STOP":
        return False, "dry_run: Regulation was not executed"

    if regulation_result.get("status") == "error":
        return False, f"regulation error: {regulation_result.get('message') or regulation_result.get('error')}"

    ra = regulation_result.get("recommended_actions")
    if isinstance(ra, list) and len(ra) > 0:
        return True, f"recommended_actions has {len(ra)} playbook(s)"

    alt = regulation_result.get("alternative_playbooks")
    sp = regulation_result.get("selected_playbook")
    if isinstance(alt, list) and len(alt) > 0 and sp is not None:
        return True, "recommended_actions empty but selected_playbook + alternative_playbooks present (schema 1.3)"

    if isinstance(alt, list) and len(alt) > 0:
        return False, (
            "recommended_actions empty; alternative_playbooks only — "
            "MCP currently requires recommended_actions non-empty to send Slack"
        )

    return False, "no recommended_actions (and no usable alternative_playbooks / selected_playbook)"


def should_call_regulation(event, runtime_result):
    """
    Regulation Agent 호출 여부 판단 규칙(v1)
    """
    detail = event.get("detail", {})

    finding_type = str(detail.get("type", ""))
    severity = detail.get("severity", 0)

    resource_type = str(_safe_get(detail, ["resource", "resourceType"], ""))
    access_key_id = _safe_get(detail, ["resource", "accessKeyDetails", "accessKeyId"], "")
    access_key_user = _safe_get(detail, ["resource", "accessKeyDetails", "userName"], "")

    base_result = runtime_result.get("base_result", {}) if isinstance(runtime_result, dict) else {}
    extracted_user = str(base_result.get("extracted_user", "Unknown-User"))
    extracted_resource = str(base_result.get("extracted_resource", "UNKNOWN-RES"))

    reasons = []

    if (
        "IAMUser" in finding_type
        or finding_type.startswith("CredentialAccess")
        or finding_type.startswith("Policy:IAMUser")
        or "AccessKey" in resource_type
        or bool(access_key_id)
        or bool(access_key_user)
    ):
        reasons.append("IAM/AccessKey/권한 관련 이벤트")

    try:
        severity_value = float(severity)
    except (TypeError, ValueError):
        severity_value = 0.0

    if severity_value >= 5.0:
        reasons.append(f"severity {severity_value} >= 5.0")

    if extracted_user != "Unknown-User" or extracted_resource != "UNKNOWN-RES":
        reasons.append("Level1에서 대상(user/resource) 식별됨")

    should_call = len(reasons) > 0

    if not should_call:
        logger.warning(
            "[MCP][REGULATION_GATE] skip Regulation call — no rule matched "
            "finding_type=%r severity=%r resource_type=%r access_key=%r user=%r "
            "extracted_user=%r extracted_resource=%r has_detail=%s",
            finding_type,
            severity,
            resource_type,
            bool(access_key_id),
            bool(access_key_user),
            extracted_user,
            extracted_resource,
            isinstance(detail, dict) and bool(detail),
        )
    else:
        logger.info("[MCP][REGULATION_GATE] call Regulation — reasons=%s", reasons)

    return should_call, reasons


def build_regulation_input(event, runtime_result):
    detail = event.get("detail", {})
    base_result = runtime_result.get("base_result", {}) if isinstance(runtime_result, dict) else {}

    severity = detail.get("severity", "")
    resource_type = _safe_get(detail, ["resource", "resourceType"], "")
    access_key_id = _safe_get(detail, ["resource", "accessKeyDetails", "accessKeyId"], "")
    access_key_user = _safe_get(detail, ["resource", "accessKeyDetails", "userName"], "")
    remote_ip = _safe_get(detail, ["service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4"], "")
    if not remote_ip:
        remote_ip = _safe_get(detail, ["service", "action", "awsApiCallAction", "remoteIpDetails", "ipAddressV4"], "")
    if not remote_ip:
        remote_ip = _safe_get(detail, ["service", "action", "dnsRequestAction", "remoteIpDetails", "ipAddressV4"], "")
    instance_id = _safe_get(detail, ["resource", "instanceDetails", "instanceId"], "")
    incident_id = event.get("id", "UNKNOWN")

    regulation_input = {
        "incident_id": incident_id,
        "incident_summary": {
            "source": "guardduty",
            "title": detail.get("type", "Unknown"),
            "severity": str(severity),
            "resource": {
                "type": resource_type or "Unknown",
                "id": access_key_id or instance_id or extracted_or_default(base_result.get("extracted_resource"), "UNKNOWN-RES"),
                "region": event.get("region", detail.get("region", "")),
                "account_id": event.get("account", detail.get("accountId", "")),
            },
        },
        "executed_level1_actions": ["base_mitigation"],
        "entity_context": {
            "iam_user_name": access_key_user or extracted_or_default(base_result.get("extracted_user"), ""),
            "access_key_id": access_key_id,
            "remote_ip": remote_ip,
        },
        "runtime_result": runtime_result,
        "raw_event": event,
        "response_targets": {
            "source_ip": remote_ip,
            "instance_id": instance_id,
        },
    }

    return regulation_input


def extracted_or_default(value, default):
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


def normalize_test_event(event):
    if isinstance(event, list):
        if len(event) == 0:
            return {}
        event = event[0]

    is_dry_run = event.get("dry_run", False)

    if "sample_id" in event or "finding_type" in event:
        logger.info("[MCP][EVENT] normalize: RAG custom test → EventBridge shape")
        return {
            "id": event.get("sample_id", "mock-test-id"),
            "region": "ap-northeast-2",
            "account": "123456789012",
            "detail": {
                "type": event.get("finding_type", "Unknown:Test/Finding"),
                "severity": 9,
                "id": event.get("Id", "UNKNOWN_ID"),
                "accountId": event.get("AccountId", ""),
                "region": event.get("Region", "Unknown"),
                "resource": {
                    "resourceType": "IAMUser",
                    "accessKeyDetails": {
                        "accessKeyId": "AKIA-MOCK-TEST-KEY",
                        "userName": "mock-stealth-user",
                    },
                },
                "service": {
                    "action": {
                        "awsApiCallAction": {
                            "api": "DeleteAccountPasswordPolicy",
                            "remoteIpDetails": {"ipAddressV4": "198.51.100.55"},
                        }
                    }
                },
            },
        }

    if "AccountId" in event and "Type" in event:
        logger.info("[MCP][EVENT] normalize: GuardDuty raw JSON → EventBridge shape")

        def pascal_to_camel(data):
            if isinstance(data, dict):
                return {
                    (k[0].lower() + k[1:] if isinstance(k, str) and len(k) > 0 else k): pascal_to_camel(v)
                    for k, v in data.items()
                }
            elif isinstance(data, list):
                return [pascal_to_camel(item) for item in data]
            return data

        camel_detail = pascal_to_camel(event)

        return {
            "version": "0",
            "id": "mock-eb-" + event.get("Id", "UNKNOWN_ID"),
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": event.get("AccountId", "UNKNOWN_ACCOUNT"),
            "time": event.get("CreatedAt", "1970-01-01T00:00:00Z"),
            "region": event.get("Region", "Unknown"),
            "resources": [],
            "detail": camel_detail,
            "dry_run": is_dry_run,
        }

    return event


def _log_event_shape(event: Dict[str, Any], incident_id: str) -> None:
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    logger.info(
        "[MCP][EVENT] shape incident_id=%s source=%s detail-type=%s has_detail=%s detail.type=%r detail.severity=%r",
        incident_id,
        event.get("source"),
        event.get("detail-type"),
        bool(detail),
        detail.get("type"),
        detail.get("severity"),
    )


def lambda_handler(event, context):
    request_id = getattr(context, "aws_request_id", None) if context else None
    logger.info("[MCP] ========== handler start request_id=%s ==========", request_id)

    try:
        raw_event_keys = list(event.keys()) if isinstance(event, dict) else type(event).__name__
        logger.info("[MCP][EVENT] incoming top-level keys=%s", raw_event_keys)

        event = unwrap_incoming_event(event)
        event = normalize_test_event(event)

        if not RUNTIME_ARN:
            logger.error("[MCP][CONFIG] RUNTIME_ARN env var not set")
            return {
                "status": "error",
                "error": "RUNTIME_ARN env var not set",
                "request_id": request_id,
            }

        incident_id = event.get("id", "UNKNOWN")
        _log_event_shape(event, incident_id)

        # 1) Runtime Level1
        try:
            runtime_result, runtime_meta = _invoke_lambda_logged(
                label="RUNTIME",
                function_arn=RUNTIME_ARN,
                payload=event,
            )
        except Exception as exc:
            logger.error("[MCP][RUNTIME] invoke failed: %s", exc)
            logger.error("[MCP][RUNTIME] traceback:\n%s", traceback.format_exc())
            return {
                "status": "error",
                "stage": "runtime_invoke",
                "incident_id": incident_id,
                "error": str(exc),
                "request_id": request_id,
            }

        _log_json(logging.INFO, "[MCP][RUNTIME] result summary", {
            "keys": list(runtime_result.keys()) if isinstance(runtime_result, dict) else None,
            "status": runtime_result.get("status") if isinstance(runtime_result, dict) else None,
            "meta": runtime_meta,
        })

        regulation_needed, regulation_reasons = should_call_regulation(event, runtime_result)

        regulation_result = None
        regulation_invoked = False
        slack_sent = False
        db_saved = False
        skip_slack_reason = None

        if regulation_needed:
            regulation_input = build_regulation_input(event, runtime_result)
            regulation_invoked = True

            if "mock_regulation_result" in event:
                logger.info("[MCP][REGULATION] using mock_regulation_result from event")
                regulation_result = event["mock_regulation_result"]

            elif REGULATION_ARN:
                logger.info("[MCP][REGULATION] live invoke REGULATION_ARN=%s", REGULATION_ARN)
                _log_json(logging.INFO, "[MCP][REGULATION] input", regulation_input)

                if event.get("dry_run") is True:
                    logger.warning("[MCP][REGULATION] dry_run=true — skipping Regulation invoke")
                    regulation_result = {
                        "status": "DRY_RUN_STOP",
                        "message": "수동 테스트를 위해 생성된 JSON입니다. 복사해서 사용하세요.",
                        "regulation_input_payload": regulation_input,
                    }
                else:
                    try:
                        regulation_result, reg_meta = _invoke_lambda_logged(
                            label="REGULATION",
                            function_arn=REGULATION_ARN,
                            payload=regulation_input,
                        )
                        _log_json(logging.INFO, "[MCP][REGULATION] meta", reg_meta)
                    except Exception as exc:
                        logger.error("[MCP][REGULATION] invoke failed: %s", exc)
                        logger.error("[MCP][REGULATION] traceback:\n%s", traceback.format_exc())
                        regulation_result = {"status": "error", "message": str(exc)}
            else:
                logger.error("[MCP][CONFIG] REGULATION_ARN not set — cannot call Regulation Agent")
                regulation_result = {}

            _log_json(logging.INFO, "[MCP][REGULATION] result summary", summarize_regulation_result(regulation_result))

            can_slack, skip_slack_reason = should_slack_finance_form(regulation_result)
            if can_slack:
                try:
                    dynamodb = boto3.resource("dynamodb")
                    table = dynamodb.Table("Regulation_JSON")
                    table.put_item(
                        Item={
                            "incident_id": incident_id,
                            "regulation_data": json.dumps(regulation_result),
                        }
                    )
                    db_saved = True
                    logger.info("[MCP][DB] put_item OK table=Regulation_JSON incident_id=%s", incident_id)

                    from send_to_slack import send_finance_context_request

                    summary = regulation_input.get("incident_summary", {})
                    send_finance_context_request(
                        incident_id=incident_id,
                        summary_title=summary.get("title", "Unknown"),
                        severity=summary.get("severity", "0"),
                    )
                    slack_sent = True
                    logger.info("[MCP][SLACK] Finance context form sent incident_id=%s", incident_id)
                except Exception as exc:
                    logger.error(
                        "[MCP][SLACK_OR_DB] failed incident_id=%s error=%s",
                        incident_id,
                        exc,
                    )
                    logger.error("[MCP][SLACK_OR_DB] traceback:\n%s", traceback.format_exc())
                    skip_slack_reason = f"exception during save/slack: {exc}"
            else:
                logger.warning(
                    "[MCP][SLACK] skipped Finance form incident_id=%s reason=%s",
                    incident_id,
                    skip_slack_reason,
                )
        else:
            regulation_result = {
                "status": "NOT_CALLED",
                "reason": "regulation_needed=false",
                "regulation_reasons": regulation_reasons,
            }
            skip_slack_reason = "regulation_needed=false"
            logger.warning(
                "[MCP][REGULATION] not called incident_id=%s reasons=%s",
                incident_id,
                regulation_reasons,
            )

        final_result = {
            "status": "ok" if not (isinstance(regulation_result, dict) and regulation_result.get("status") == "error") else "error",
            "incident_id": incident_id,
            "request_id": request_id,
            "runtime_result": runtime_result,
            "regulation_needed": regulation_needed,
            "regulation_reasons": regulation_reasons,
            "regulation_invoked": regulation_invoked,
            "regulation_result": regulation_result,
            "db_saved": db_saved,
            "slack_finance_form_sent": slack_sent,
            "skip_slack_reason": skip_slack_reason,
        }

        _log_json(
            logging.INFO,
            "[MCP] ========== handler end ==========",
            {
                "incident_id": incident_id,
                "request_id": request_id,
                "regulation_needed": regulation_needed,
                "regulation_invoked": regulation_invoked,
                "db_saved": db_saved,
                "slack_finance_form_sent": slack_sent,
                "skip_slack_reason": skip_slack_reason,
                "regulation_summary": summarize_regulation_result(regulation_result),
            },
        )

        return final_result

    except Exception as exc:
        logger.error("[MCP] FATAL unhandled exception request_id=%s: %s", request_id, exc)
        logger.error("[MCP] FATAL traceback:\n%s", traceback.format_exc())
        return {
            "status": "error",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "request_id": request_id,
        }
