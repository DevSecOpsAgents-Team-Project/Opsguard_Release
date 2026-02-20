import os
import json
import sys 
from dotenv import load_dotenv

# --- [여기부터 추가] ---
# 현재 파일(tests 폴더)의 부모 디렉토리(프로젝트 루트)를 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
# --- [여기까지 추가] ---

load_dotenv()

from src.playbooks_module import playbook_integrated_base_mitigation
from src.actions_module import Actions

def run_integrated_test():
    real_actions = Actions()
    real_actions.dry_run = False 

    # 1. EC2 테스트 (기존 파일)
    print("\n" + "="*50)
    print("🚀 [STEP 1] EC2 Base Mitigation 가동")
    print("="*50)
    EC2_FILE = "tests/sample_events/Backdoor_Runtime_C&CActivity.B!DNS_0621c920f4d14a1ab88f7bd515bc9acc.json"
    if os.path.exists(EC2_FILE):
        with open(EC2_FILE, 'r') as f:
            ec2_data = json.load(f)
        playbook_integrated_base_mitigation({"id": ec2_data.get("Id"), "detail": ec2_data}, actions=real_actions)

    # 2. S3 테스트 (방금 주신 원문 파일)
    print("\n" + "="*50)
    print("🚀 [STEP 2] S3 Base Mitigation 가동")
    print("="*50)
    S3_FILE = "tests/sample_events/Policy_S3_AccountBlockPublicAccessDisabled_13a0c70156b843e79d0ecd3e16fa0a15.json"
    
    if os.path.exists(S3_FILE):
        with open(S3_FILE, 'r') as f:
            s3_data = json.load(f)
        # 원문 구조 그대로 투입
        playbook_integrated_base_mitigation({"id": s3_data.get("Id"), "detail": s3_data}, actions=real_actions)
    else:
        print(f"❌ {S3_FILE} 파일을 찾을 수 없습니다.")

if __name__ == "__main__":
    run_integrated_test()