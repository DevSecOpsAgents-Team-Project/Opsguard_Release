import os
import json
import glob

def get_latest_playbooks(directory, count=2):
    # 폴더 내 모든 json 파일 가져오기
    path = os.path.join(directory, "*.json")
    files = glob.glob(path)
    
    # 생성 시간 순으로 정렬 (최신순)
    files.sort(key=os.path.getmtime, reverse=True)
    return files[:count]

def display_playbook_info(file_path, index):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    summary = data.get("incident_summary", {})
    assessment = data.get("escalation_assessment", {})
    regulations = data.get("regulations", [{}])[0]
    actions = data.get("recommended_actions", [])

    print(f"\n{'='*60}")
    print(f"Playbook #{index} | 파일명: {os.path.basename(file_path)}")
    print(f"{'='*60}")
    print(f"• 인시던트 제목: {summary.get('title', 'N/A')}")
    print(f"• 심각도: {summary.get('severity', 'N/A')}")
    print(f"• 권장 레벨: Level {assessment.get('recommended_level', 'N/A')}")
    print(f"• 관련 규정: {regulations.get('framework', '')} {regulations.get('clause_id', '')} - {regulations.get('clause_title', '정보 없음')}")
    print(f"• 권장 조치:")
    for action in actions:
        print(f"  - [{action.get('action_id')}] {action.get('description')}")
    print(f"{'='*60}")

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, "..", "data")
    
    # 1. 최신 파일 2개 가져오기
    latest_files = get_latest_playbooks(data_dir)
    
    if not latest_files:
        print(f"'{data_dir}' 폴더에 JSON 파일이 없습니다.")
        return

    # 2. 정보 출력
    print("\n[Regulation Agent] 최신 동적 플레이북 분석 결과")
    for i, file in enumerate(latest_files, 1):
        display_playbook_info(file, i)

    # 3. 사용자 선택 (Recommended Level 기반)
    while True:
        try:
            choice = input("\n실행할 권장 레벨(Recommended Level)을 선택하세요 (2 또는 3, 종료: q): ")
            
            if choice.lower() == 'q':
                print("프로그램을 종료합니다.")
                break
                
            if choice in ['2', '3']:
                print(f"\n[알림] Level {choice} 대응 시나리오를 시작합니다...")
                # 여기에 실제 동작 로직(Action 실행 등)을 추가하세요.
                break
            else:
                print("잘못된 입력입니다. 2 또는 3을 입력해주세요.")
        except ValueError:
            print("숫자를 입력해주세요.")

if __name__ == "__main__":
    main()