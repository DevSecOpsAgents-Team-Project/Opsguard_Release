# server.py
import os
import sys
import json
import urllib.parse
import requests
from fastapi import FastAPI, Request

# 1. Runtime Agent 경로 추가 (상대 경로 주의!)
# 현재 위치: DevSecOps-MCP/src
# 목표 위치: DevSecOps-Runtime_Agent/src
current_dir = os.path.dirname(os.path.abspath(__file__))
runtime_agent_path = os.path.join(current_dir, "../../DevSecOps-Runtime_Agent/src")
sys.path.append(runtime_agent_path)

# 2. Runtime Agent의 핸들러 임포트
try:
    from dispatcher_module import lambda_handler
except ImportError as e:
    print(f"❌ Runtime Agent를 찾을 수 없습니다: {e}")

# 3. 환경 변수 설정 (simulate_lambda.py에 있던 것들)
os.environ["AWS_REGION"] = "ap-northeast-2"
os.environ["DB_TABLE_NAME"] = "AgentB_Response_History"
# ... 필요한 다른 환경변수들도 여기에 추가 ...

app = FastAPI()

@app.post("/slack/events")
async def handle_slack_interaction(request: Request):
    body = await request.body()
    decoded_body = body.decode("utf-8")
    parsed_body = urllib.parse.parse_qs(decoded_body)
    payload = json.loads(parsed_body["payload"][0])
    
    action = payload["actions"][0]
    
    if action["action_id"] != "reject_all_action":
        # 슬랙 버튼에서 뭉쳐놓은 JSON 데이터를 꺼냅니다.
        # 이 데이터는 이미 dispatcher가 좋아하는 형식을 갖추고 있습니다!
        runtime_event = json.loads(action["value"])
        
        print(f"🚀 Runtime Agent 호출 중: {runtime_event['recommended_actions'][0]['action_id']}")
        
        # 4. 실제 Dispatcher 실행 (simulate_lambda.py의 로직과 동일)
        # Mock Context는 비워두거나 간단히 만듭니다.
        response = lambda_handler(runtime_event, None) 
        
        print(f"✅ 실행 결과: {response['body']}")
        msg_text = f"✅ 조치 완료: {runtime_event['recommended_actions'][0]['action_id']} 가 실행되었습니다."
    else:
        msg_text = "❌ 조치가 거절되었습니다."

    # 슬랙 메시지 업데이트
    requests.post(payload["response_url"], json={"replace_original": "true", "text": msg_text})

    return {"status": "ok"}


# ⭐️⭐️⭐️ 이 부분이 있어야 서버가 실행됩니다! ⭐️⭐️⭐️
if __name__ == "__main__":
    import uvicorn
    print("🛰️ MCP Server가 8000번 포트에서 가동 중입니다...")
    uvicorn.run(app, host="0.0.0.0", port=8000)