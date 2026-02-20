# server.py
from fastapi import FastAPI, Request
import json
import urllib.parse
import requests

app = FastAPI()

@app.post("/slack/events")  # 슬랙이 이 주소로 데이터를 쏠 겁니다.
async def handle_slack_interaction(request: Request):
    # 1. 슬랙이 보낸 데이터 받기
    body = await request.body()
    decoded_body = body.decode("utf-8")
    
    # 2. 슬랙 데이터는 payload=... 형태라 파싱이 필요함
    parsed_body = urllib.parse.parse_qs(decoded_body)
    payload = json.loads(parsed_body["payload"][0])
    
    # 3. 데이터 확인 (터미널에 출력됨)
    user_name = payload["user"]["username"]
    action = payload["actions"][0]
    incident_id = action["value"]
    
    print(f"[{incident_id}] 사용자 {user_name}가 {action['action_id']}를 눌렀습니다!")

    # 4. 슬랙 메시지 업데이트 (버튼 없애기)
    response_url = payload["response_url"]
    update_data = {
        "replace_original": "true",
        "text": f"✅ 조치 완료: {user_name}님이 {incident_id} 이벤트를 승인했습니다."
    }
    requests.post(response_url, json=update_data)

    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)