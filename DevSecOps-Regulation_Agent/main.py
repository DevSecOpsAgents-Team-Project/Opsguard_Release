"""
메인 실행 스크립트

Step 1: 체크리스트 검증
Step 2: RAG 규정 검색
Step 4: LLM 기반 보안 분석

사용법:
    python main.py <문서파일>
    예: python main.py test_doc.txt
"""

import sys
import json
from typing import List, Dict, Any
from pathlib import Path

# Step 4 모듈 import
from step4_llm_analysis import Step4LLMAnalyzer

# Step 2 RAG 모듈 import
from test_isms_rag import load_chromadb, search_similar_documents


def step1_checklist_validation(doc_path: str) -> List[Dict[str, Any]]:
    """
    Step 1: 문서를 읽어서 체크리스트 검증을 수행합니다.
    
    현재는 예시 구현입니다. 실제 체크리스트 로직에 맞게 수정이 필요합니다.
    
    Args:
        doc_path: 검증할 문서 파일 경로
    
    Returns:
        True로 판정된 체크리스트 항목 리스트
        [
            {
                "check_id": "CHK-06",
                "reason": "사유 설명"
            }
        ]
    """
    # 문서 읽기
    try:
        with open(doc_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[오류] 파일을 찾을 수 없습니다: {doc_path}")
        raise
    except Exception as e:
        print(f"[오류] 파일 읽기 실패: {e}")
        raise RuntimeError(f"파일 읽기 실패: {e}") from e
    
    # TODO: 실제 체크리스트 검증 로직 구현
    # 현재는 예시로 문서 내용을 기반으로 간단한 검증 수행
    true_items = []
    
    # 예시: 문서에 특정 키워드가 있으면 True로 판정
    if "public" in content.lower() or "공개" in content:
        true_items.append({
            "check_id": "CHK-06",
            "reason": "문서에서 공개 노출 관련 내용이 발견되었습니다."
        })
    
    if "admin" in content.lower() or "관리자" in content:
        true_items.append({
            "check_id": "CHK-12",
            "reason": "문서에서 관리자 권한 관련 내용이 발견되었습니다."
        })
    
    if "password" in content.lower() or "비밀번호" in content or "key" in content.lower():
        true_items.append({
            "check_id": "CHK-15",
            "reason": "문서에서 인증 정보 관련 내용이 발견되었습니다."
        })
    
    return true_items


def step2_rag_search(
    collection,
    step1_items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Step 2: Step 1 True 항목을 기반으로 RAG 규정 검색을 수행합니다.
    
    Args:
        collection: ChromaDB Collection 객체
        step1_items: Step 1 True 항목 리스트
    
    Returns:
        RAG 검색 결과 리스트
        [
            {
                "section": "섹션명",
                "no": 4,
                "citation_key": "인용키",
                "excerpt": "규정 발췌문"
            }
        ]
    """
    rag_results = []
    
    # 각 Step 1 항목에 대해 RAG 검색 수행
    for item in step1_items:
        check_id = item.get("check_id", "")
        reason = item.get("reason", "")
        
        # 검색 쿼리 생성
        query = f"{check_id} {reason}"
        
        # RAG 검색
        search_results = search_similar_documents(collection, query, top_k=3)
        
        # 결과 변환
        for result in search_results:
            rag_result = {
                "section": result.get("category", "N/A"),
                "no": result.get("rank", 0),
                "citation_key": result.get("id", "N/A"),
                "excerpt": result.get("document", "")[:500]  # 처음 500자만
            }
            rag_results.append(rag_result)
    
    return rag_results


def main():
    """메인 실행 함수"""
    # 명령행 인자 확인
    if len(sys.argv) < 2:
        print("사용법: python main.py <문서파일>")
        print("예: python main.py test_doc.txt")
        sys.exit(1)
    
    doc_path = sys.argv[1]
    
    # 파일 존재 확인
    if not Path(doc_path).exists():
        print(f"[오류] 파일을 찾을 수 없습니다: {doc_path}")
        sys.exit(1)
    
    print("=" * 70)
    print("보안 규제 준수 분석 시스템")
    print("=" * 70)
    print(f"\n[입력] 문서 파일: {doc_path}\n")
    
    # Step 1: 체크리스트 검증
    print("[Step 1] 체크리스트 검증 수행 중...")
    step1_items = step1_checklist_validation(doc_path)
    print(f"  True로 판정된 항목: {len(step1_items)}개")
    for item in step1_items:
        print(f"    - {item['check_id']}: {item['reason']}")
    print()
    
    if not step1_items:
        print("[경고] True로 판정된 체크리스트 항목이 없습니다.")
        print("Step 4 분석을 건너뜁니다.")
        sys.exit(0)
    
    # Step 2: RAG 규정 검색
    print("[Step 2] RAG 규정 검색 수행 중...")
    try:
        collection = load_chromadb()
        step2_results = step2_rag_search(collection, step1_items)
        print(f"  검색된 규정: {len(step2_results)}개")
        for result in step2_results[:5]:  # 처음 5개만 출력
            print(f"    - {result['citation_key']} (Section: {result['section']})")
        print()
    except Exception as e:
        print(f"[오류] RAG 검색 실패: {e}")
        sys.exit(1)
    
    if not step2_results:
        print("[경고] 검색된 규정 결과가 없습니다.")
        print("Step 4 분석을 건너뜁니다.")
        sys.exit(0)
    
    # Step 4: LLM 기반 보안 분석
    print("[Step 4] LLM 기반 보안 분석 수행 중...")
    try:
        analyzer = Step4LLMAnalyzer()
        result = analyzer.analyze(step1_items, step2_results)
        
        # 결과 출력
        print("\n" + "=" * 70)
        print("분석 결과")
        print("=" * 70)
        print(f"\n[요약]")
        print(result.get("summary", "N/A"))
        print(f"\n[발견 사항] {len(result.get('findings', []))}개")
        
        for finding in result.get("findings", []):
            print(f"\n  - {finding.get('check_id', 'N/A')}")
            print(f"    이슈: {finding.get('issue', 'N/A')}")
            print(f"    근거: {len(finding.get('evidence', []))}개")
            for evidence in finding.get("evidence", []):
                print(f"      * {evidence.get('citation_key', 'N/A')} (Section: {evidence.get('section', 'N/A')})")
            print(f"    권고사항: {finding.get('recommendation', 'N/A')}")
        
        # JSON 파일로 저장
        output_file = Path(doc_path).stem + "_analysis_result.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n[저장] 결과가 '{output_file}'에 저장되었습니다.")
        
    except Exception as e:
        print(f"[오류] LLM 분석 실패: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("[완료] 모든 단계 완료")
    print("=" * 70)


if __name__ == "__main__":
    main()

