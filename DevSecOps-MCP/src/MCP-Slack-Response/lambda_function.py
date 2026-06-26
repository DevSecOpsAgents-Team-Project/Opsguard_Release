# MCP-Slack-Response의 lambda_function.py

import json
import os
import urllib.parse
import base64
import requests
import boto3

from finance_bridge import (
    build_comparison_with_costs,
    extract_recommended_from_finance_response,
    format_execution_result_slack_message,
    format_regulation_xai_explanation,
    invoke_simulation_recommendation,
    norm_level,
    parse_runtime_lambda_response,
    playbooks_for_slack_ui,
)

lambda_client = boto3.client("lambda")
dynamodb = boto3.resource('dynamodb')
RUNTIME_ARN = os.environ.get("RUNTIME_ARN")
FINANCE_ARN = os.environ.get("FINANCE_ARN")

# 헬퍼 함수: Slack Dropdown에서 선택된 값을 안전하게 추출
def _get_selected_value(state_values, block_id, action_id):
    try:
        return state_values[block_id][action_id]['selected_option']['value']
    except (KeyError, TypeError):
        return None

def lambda_handler(event, context):
    try:
        body = event.get('body', '')
        if event.get('isBase64Encoded', False):
            body = base64.b64decode(body).decode('utf-8')

        # Slack URL 등록 시 challenge 응답 (Event Subscriptions / Interactivity 공통)
        if body:
            try:
                json_body = json.loads(body)
                if isinstance(json_body, dict):
                    if json_body.get('type') == 'url_verification':
                        return {
                            "statusCode": 200,
                            "headers": {"Content-Type": "application/json"},
                            "body": json.dumps({"challenge": json_body.get("challenge", "")}),
                        }
                    if json_body.get('type') == 'event_callback':
                        return {"statusCode": 200, "body": "ok"}
            except json.JSONDecodeError:
                pass

        parsed_body = urllib.parse.parse_qs(body)
        if 'payload' not in parsed_body:
            return {"statusCode": 400, "body": "Invalid payload"}
            
        slack_payload = json.loads(parsed_body['payload'][0])
        action = slack_payload['actions'][0]
        action_id = action['action_id']

        # 만약 그냥 선택만 한 경우, 실행X
        if action_id.startswith("select_"):
            return {"statusCode": 200, "body": "OK"}

        user_name = slack_payload.get('user', {}).get('username', 'Unknown')
        response_url = slack_payload['response_url']
        
        # ==========================================
        # 1. 사용자가 Finance 컨텍스트 폼을 제출했을 때
        # ==========================================
        if action_id == "submit_finance_context":
            incident_id = action['value'] # 버튼 value에 심어둔 incident_id
            
            # Slack 상태(State)에서 유저가 선택한 4개 값 추출
            state_values = slack_payload.get('state', {}).get('values', {})
            env_val = _get_selected_value(state_values, 'block_env', 'select_env')
            data_val = _get_selected_value(state_values, 'block_data', 'select_data')
            downtime_val = _get_selected_value(state_values, 'block_downtime', 'select_downtime')
            priority_val = _get_selected_value(state_values, 'block_priority', 'select_priority')

            # 유효성 검사 (입력 안 한 항목이 있는지)
            if not all([env_val, data_val, downtime_val, priority_val]):
                requests.post(response_url, json={"replace_original": False, "text": "⚠️ 모든 항목을 선택한 후 제출해 주세요!"})
                return {"statusCode": 200, "body": "Missing inputs"}

            # DynamoDB에서 Regulation JSON 꺼내오기
            table = dynamodb.Table('Regulation_JSON')
            db_response = table.get_item(Key={'incident_id': incident_id})
            
            if 'Item' not in db_response:
                requests.post(response_url, json={"text": f"⚠️ 에러: DB에서 {incident_id}의 Regulation 데이터를 찾을 수 없습니다."})
                return {"statusCode": 200, "body": "Not found"}
                
            regulation_data = json.loads(db_response['Item']['regulation_data'])

            user_response = {
                "environment": env_val,
                "data_sensitivity": data_val,
                "downtime_tolerance": downtime_val,
                "priority": priority_val,
            }

            # ==========================================
            # 1. Slack에 "계산 중..." 메시지 먼저 보내기 (3초 타임아웃 방지 & UX)
            # ==========================================
            update_message = {
                "replace_original": True,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"✅ *{user_name}* 님이 컨텍스트 입력을 완료했습니다.\n\n"
                                    f"• 환경: `{env_val}`\n"
                                    f"• 민감도: `{data_val}`\n"
                                    f"• 중단허용: `{downtime_val}`\n"
                                    f"• 우선순위: `{priority_val}`\n\n"
                                    f"⏳ *Finance Agent가 비용과 컨텍스트를 분석하여 최적의 대응 방안을 계산 중입니다...*"
                        }
                    }
                ]
            }
            requests.post(response_url, json=update_message)

            # ==========================================
            # 2. 신 Finance Agent: finance_run(L2/L3) → get_simulation_recommendation
            # ==========================================
            FINANCE_ARN = os.environ.get("FINANCE_ARN")
            if not FINANCE_ARN:
                requests.post(response_url, json={"text": "⚠️ FINANCE_ARN 환경변수가 설정되지 않아 조치를 계산할 수 없습니다."})
                return {"statusCode": 500, "body": "Missing FINANCE_ARN"}

            policy_version = os.environ.get("FINANCE_POLICY_VERSION", "v1.0.0")

            try:
                print("🚀 [Finance] Regulation → comparison (L2/L3 비용 산정)...")
                comparison = build_comparison_with_costs(
                    lambda_client,
                    FINANCE_ARN,
                    regulation_data,
                    incident_id,
                    policy_version=policy_version,
                )
                print(f"📦 [Finance] comparison playbooks: {json.dumps(comparison.get('playbooks'), ensure_ascii=False, default=str)}")

                print("🚀 [Finance] get_simulation_recommendation 호출...")
                fin_data = invoke_simulation_recommendation(
                    lambda_client,
                    FINANCE_ARN,
                    comparison,
                    user_response,
                )
                print(f"📊 [Finance] recommendation: {json.dumps(fin_data, ensure_ascii=False, indent=2)}")

            except Exception as e:
                print(f"Finance Lambda 호출 실패: {e}")
                requests.post(response_url, json={"text": f"⚠️ Finance 계산 중 오류가 발생했습니다: {e}"})
                return {"statusCode": 500, "body": "Finance Invoke Failed"}

            # ==========================================
            # 3. Finance 결과 해석 및 최종 슬랙 메시지 조립
            # ==========================================
            summary = regulation_data.get("incident_summary", {})
            playbooks = playbooks_for_slack_ui(comparison)
            regs = regulation_data.get("regulations", [])

            rec = extract_recommended_from_finance_response(fin_data)
            fin_result = {
                "recommended_level": rec.get("recommended_level"),
                "playbook_name": rec.get("playbook_name"),
                "reason": rec.get("reason") or "비용 분석 및 우선순위 검토 완료",
            }
            fin_reason = fin_result.get("reason", "비용 분석 및 우선순위 검토 완료")
            recommended_level = norm_level(fin_result.get("recommended_level"))
            recommended_name = fin_result.get("playbook_name") or ""

            # 규제 근거 텍스트
            reg_text = ""
            for reg in regs:
                reg_text += f"• *{reg.get('framework', 'N/A')} ({reg.get('clause_id', '')})*: {reg.get('clause_title', '')}\n"
            if not reg_text:
                reg_text = "매핑된 규제 근거 없음"

            xai_text = format_regulation_xai_explanation(regulation_data)

            # Slack Block 조립
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 최종 조치 결정: {summary.get('title', 'Unknown')}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*이벤트 ID:*\n`{incident_id}`"},
                        {"type": "mrkdwn", "text": f"*우선순위:*\n`{priority_val}`"}
                    ]
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*💡 Finance Agent의 분석 및 추천:*\n{fin_reason}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⚖️ 관련 규제 (Regulation):*\n{reg_text}"
                    }
                },
                {"type": "divider"},
            ]

            if xai_text:
                blocks.extend([
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*🧠 Regulation Agent (XAI) — 왜 L2/L3 플레이북을 제안했는가?*\n{xai_text}",
                        },
                    },
                    {"type": "divider"},
                ])

            blocks.extend([
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*🛠️ 추천 대응 방안 (실행할 조치를 선택하세요):*"}
                }
            ])

            # Playbook 버튼 렌더링 (L2 + L3 후보)
            for pb in playbooks:
                level = norm_level(pb.get("level", 2))
                pb_name = pb.get("playbook_name", f"Level {level} 대응")
                actions_list = pb.get("actions", [])
                estimated_cost = pb.get("_estimated_monthly_cost", "N/A")

                is_recommended = (
                    level == recommended_level
                    and (not recommended_name or pb_name == recommended_name)
                )
                recommend_badge = "🌟 *[AI 추천]* " if is_recommended else ""
                
                button_payload = {
                    "incident_id": incident_id,
                    "scenario": regulation_data.get("scenario", "UNKNOWN"),
                    "recommended_actions": actions_list
                }
                
                action_ids_str = ", ".join([f"`{a.get('action_id', '')}`" for a in actions_list])

                # 1. 먼저 style을 제외한 기본 버튼 요소를 만듭니다.
                button_element = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": f"L{level} 승인 및 실행"},
                    "value": json.dumps(button_payload),
                    "action_id": f"approve_l{level}"
                }

                # 2. 추천 레벨인 경우에만 style 키를 추가합니다.
                if is_recommended:
                    button_element["style"] = "primary"

                # 3. block에 append 합니다.
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"> {recommend_badge}*[Level {level}] {pb_name}*\n> *포함된 조치:* {action_ids_str}\n> *예상 발생 비용:* `약 ${estimated_cost} / 월`"
                    },
                    "accessory": button_element
                })

            blocks.append({"type": "divider"})
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ 전체 거절 (조치 안 함)"},
                        "style": "danger",
                        "value": incident_id,
                        "action_id": "reject_all_action"
                    }
                ]
            })

            # 최종 완성된 메시지로 업데이트 (계산 중 -> 플레이북 선택창)
            slack_resp = requests.post(response_url, json={"replace_original": True, "blocks": blocks})

            # Slack API가 거절했을 경우 CloudWatch에 에러를 남기도록 추가
            if slack_resp.status_code != 200:
                print(f"🚨 Slack API 에러 ({slack_resp.status_code}): {slack_resp.text}")
            
            # Lambda 종료
            return {"statusCode": 200, "body": "Finance processing complete"}
        
        # ==========================================
        # 2. 사용자가 조치 승인(Approve) 버튼을 눌렀을 때
        # ==========================================
        elif action_id.startswith("approve_l"):
            # 1. 버튼 value에 심어둔 JSON 페이로드 파싱 (incident_id, scenario, recommended_actions)
            action_value = json.loads(action['value'])
            incident_id = action_value.get('incident_id', 'UNKNOWN')

            # 2. Slack에 즉각적인 피드백 (로딩 중 메시지 업데이트)
            # 💡 Slack은 3초 내에 응답을 받아야 하므로 메시지부터 업데이트합니다.
            requests.post(response_url, json={
                "replace_original": True,
                "text": f"🚀 *조치 실행 중...* (이벤트 ID: `{incident_id}`)\n선택하신 플레이북에 따라 자동 보안 조치를 진행하고 있습니다. 잠시만 기다려주세요."
            })

            # 3. Runtime Lambda 호출 (엔진 핸들러)
            if not RUNTIME_ARN:
                requests.post(response_url, json={
                    "replace_original": True,
                    "text": f"❌ *조치 실행 실패* (이벤트 ID: `{incident_id}`)\nRUNTIME_ARN 환경변수가 설정되지 않아 조치를 실행할 수 없습니다.",
                })
                return {"statusCode": 500, "body": "Missing RUNTIME_ARN"}

            try:
                print("🚀 [Runtime Call] 조치 실행을 위해 Runtime 람다 동기 호출 시작...")
                runtime_resp = lambda_client.invoke(
                    FunctionName=RUNTIME_ARN,
                    InvocationType="RequestResponse",
                    Payload=json.dumps(action_value).encode("utf-8"),
                )
                if runtime_resp.get("FunctionError"):
                    err_raw = runtime_resp["Payload"].read().decode("utf-8")
                    print(f"Runtime Lambda FunctionError: {err_raw}")
                    fail_msg = (
                        f"❌ *조치 실행 실패* (이벤트 ID: `{incident_id}`)\n"
                        f"Runtime Lambda 실행 중 오류가 발생했습니다.\n```{err_raw[:500]}```"
                    )
                    requests.post(response_url, json={"replace_original": True, "text": fail_msg})
                    return {"statusCode": 500, "body": "Runtime FunctionError"}

                runtime_result = parse_runtime_lambda_response(
                    runtime_resp["Payload"].read().decode("utf-8")
                )
                print(f"📦 [Runtime] result: {json.dumps(runtime_result, ensure_ascii=False, default=str)}")
                result_text = format_execution_result_slack_message(incident_id, runtime_result)
                requests.post(response_url, json={"replace_original": True, "text": result_text})
            except Exception as e:
                print(f"Runtime Lambda 호출 실패: {e}")
                fail_msg = (
                    f"❌ *조치 실행 실패* (이벤트 ID: `{incident_id}`)\n"
                    f"Runtime 람다 호출 중 오류가 발생했습니다: {e}"
                )
                requests.post(response_url, json={"replace_original": True, "text": fail_msg})
                return {"statusCode": 500, "body": "Runtime Invoke Failed"}

            return {"statusCode": 200, "body": "Action execution complete"}

        # ==========================================
        # 3. 사용자가 전체 거절 버튼을 눌렀을 때
        # ==========================================
        elif action_id == "reject_all_action":
            incident_id = action['value']
            requests.post(response_url, json={
                "replace_original": True,
                "text": f"❌ *조치 거절됨* (이벤트 ID: `{incident_id}`)\n해당 이벤트에 대해 아무런 조치도 실행하지 않고 종료합니다."
            })
            return {"statusCode": 200, "body": "Action rejected"}

            
    except Exception as e:
        print(f"Lambda Handler 크래시 발생: {str(e)}")
        return {"statusCode": 500, "body": "Internal Server Error"}