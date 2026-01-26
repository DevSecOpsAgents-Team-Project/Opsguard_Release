"""
XAI 설명 레이어 테스트 스크립트

기존 심각도 결정 로직에 XAI 설명이 제대로 추가되는지 테스트합니다.
"""

from severity_decision import (
    SeverityDecisionEngine,
    SecurityEvent,
    SeverityLevel,
    decide_severity_level_with_xai
)
from xai_explainer import build_xai, XAIExplainer
from test_isms_rag import load_chromadb, search_similar_documents
import json


def test_xai_standalone():
    """
    XAI 레이어만 독립적으로 테스트합니다.
    """
    print("=" * 70)
    print("XAI 설명 레이어 테스트 (독립 실행)")
    print("=" * 70)
    print()
    
    # 모의 규제 문서
    mock_regulations = [
        {
            "id": "SEF-07",
            "title": "Security Breach Notification",
            "document": "보안 침해 또는 침해 추정 사고 발생 시, 즉시 신고하고 알리는 절차를 수립해야 한다. 개인정보 유출 등 보안 침해 사고가 확인되었거나 의심될 때, 법적 규제에 따라 규제 기관 및 피해 고객에게 의무적으로 신고해야 한다.",
            "category": "SEF",
            "metadata": {
                "doc_type": "CSA_CCM",
                "doc_version": "v4.0"
            }
        },
        {
            "id": "LOG-03",
            "title": "Security Monitoring and Alerting",
            "document": "애플리케이션 및 인프라의 보안 관련 이벤트를 식별·모니터링하고, 책임자에게 알림을 생성하는 체계를 구축해야 한다. 보안 이벤트를 모니터링하여 경보 조건을 정의하고, 이벤트 발생 시 책임자에게 즉시 통지합니다.",
            "category": "LOG",
            "metadata": {
                "doc_type": "CSA_CCM",
                "doc_version": "v4.0"
            }
        }
    ]
    
    # 테스트 케이스
    test_cases = [
        {
            "name": "Level 1: 공개 노출 + 권한 영향 + 침해 규제",
            "event": SecurityEvent(
                event_type="DataBreach",
                resource_type="Database",
                exposure="public",
                privilege_impact=True,
                data_sensitivity="high"
            ),
            "docs": mock_regulations,
            "expected_level": SeverityLevel.LEVEL_1
        },
        {
            "name": "Level 2: 일반 위협",
            "event": SecurityEvent(
                event_type="SuspiciousActivity",
                resource_type="EC2Instance",
                exposure="internal",
                privilege_impact=False,
                data_sensitivity="medium"
            ),
            "docs": mock_regulations,
            "expected_level": SeverityLevel.LEVEL_2
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'=' * 70}")
        print(f"테스트 케이스 {i}: {test_case['name']}")
        print(f"{'=' * 70}")
        
        # 기존 결정 로직 실행
        engine = SeverityDecisionEngine()
        decision_result = engine.decide_severity(test_case["event"], test_case["docs"])
        
        print(f"\n[결정] 할당된 레벨: Level {decision_result.level.value}")
        print(f"       예상 레벨: Level {test_case['expected_level'].value}")
        
        # XAI 설명 생성
        xai_result = build_xai(test_case["event"], test_case["docs"], decision_result.level)
        
        # XAI 결과 출력
        print(f"\n[XAI 결과]")
        print(f"  Assigned Level: {xai_result['assigned_level']}")
        print(f"  Justification: {xai_result['justification']}")
        print(f"\n  Event Factors:")
        for factor in xai_result['triggers']['event_factors']:
            print(f"    - {factor}")
        print(f"\n  Regulatory Signals:")
        for signal in xai_result['triggers']['regulatory_signals']:
            print(f"    - {signal['clause_id']} ({signal['doc_type']}): {signal['intent']}")
        print(f"\n  Fallback: {xai_result['triggers']['fallback']}")
        
        # JSON 출력 (요구사항 형식 확인)
        print(f"\n[JSON 형식]")
        print(json.dumps(xai_result, ensure_ascii=False, indent=2))
        print()
    
    print("=" * 70)
    print("[완료] 독립 테스트 완료")
    print("=" * 70)


def test_xai_with_rag():
    """
    RAG 시스템과 통합하여 XAI를 테스트합니다.
    """
    print("=" * 70)
    print("XAI 설명 레이어 테스트 (RAG 통합)")
    print("=" * 70)
    print()
    
    # ChromaDB 로드
    collection = load_chromadb()
    
    # 테스트 케이스
    test_cases = [
        {
            "name": "공개 노출 + 권한 영향 + 고민감도 데이터",
            "event": {
                "event_type": "UnauthorizedAccess",
                "resource_type": "S3Bucket",
                "exposure": "public",
                "privilege_impact": True,
                "data_sensitivity": "high"
            },
            "query": "Access Key 유출 시 대응"
        },
        {
            "name": "내부 노출 + 낮은 민감도",
            "event": {
                "event_type": "SuspiciousActivity",
                "resource_type": "EC2Instance",
                "exposure": "internal",
                "privilege_impact": False,
                "data_sensitivity": "low"
            },
            "query": "로그 보관 및 증적"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'=' * 70}")
        print(f"테스트 케이스 {i}: {test_case['name']}")
        print(f"{'=' * 70}")
        
        # RAG로 규제 문서 검색
        print(f"\n[검색] 규제 문서 검색: {test_case['query']}")
        retrieved_docs = search_similar_documents(collection, test_case["query"], top_k=5)
        
        if not retrieved_docs:
            print("[경고] 검색된 규제 문서가 없습니다.")
            continue
        
        print(f"[성공] {len(retrieved_docs)}개의 관련 규제 문서 검색됨")
        for doc in retrieved_docs[:3]:
            print(f"   - {doc['id']}: {doc['title']}")
        
        # XAI 포함 결정 실행
        print(f"\n[XAI 결정] 심각도 레벨 결정 및 설명 생성 중...")
        xai_result = decide_severity_level_with_xai(test_case["event"], retrieved_docs)
        
        # 결과 출력
        print(f"\n[결과]")
        print(f"  Assigned Level: {xai_result['assigned_level']}")
        print(f"  Justification: {xai_result['justification']}")
        print(f"\n  Event Factors:")
        for factor in xai_result['triggers']['event_factors']:
            print(f"    - {factor}")
        print(f"\n  Regulatory Signals:")
        for signal in xai_result['triggers']['regulatory_signals']:
            print(f"    - {signal['clause_id']} ({signal['doc_type']}): {signal['intent']}")
        print(f"\n  Fallback: {xai_result['triggers']['fallback']}")
        
        # JSON 출력
        print(f"\n[JSON 출력]")
        print(json.dumps(xai_result, ensure_ascii=False, indent=2))
        print()
    
    print("=" * 70)
    print("[완료] RAG 통합 테스트 완료")
    print("=" * 70)


def test_xai_explainer_components():
    """
    XAI 설명기의 개별 컴포넌트를 테스트합니다.
    """
    print("=" * 70)
    print("XAI 설명기 컴포넌트 테스트")
    print("=" * 70)
    print()
    
    explainer = XAIExplainer()
    
    # 테스트 이벤트
    event = SecurityEvent(
        event_type="DataBreach",
        resource_type="Database",
        exposure="public",
        privilege_impact=True,
        data_sensitivity="high"
    )
    
    # 이벤트 요인 추출 테스트
    print("[테스트 1] 이벤트 요인 추출")
    event_factors = explainer.extract_event_factors(event)
    print(f"  결과: {event_factors}")
    print()
    
    # 규제 문서
    mock_doc = {
        "id": "SEF-07",
        "document": "보안 침해 또는 침해 추정 사고 발생 시, 즉시 신고하고 알리는 절차를 수립해야 한다.",
        "metadata": {
            "doc_type": "CSA_CCM",
            "doc_version": "v4.0"
        }
    }
    
    # 규제 의도 추출 테스트
    print("[테스트 2] 규제 의도 추출")
    intent = explainer.extract_regulatory_intent(mock_doc)
    print(f"  문서 ID: {mock_doc['id']}")
    print(f"  추출된 의도: {intent}")
    print()
    
    # 규제 신호 추출 테스트
    print("[테스트 3] 규제 신호 추출")
    signals = explainer.extract_regulatory_signals([mock_doc])
    print(f"  결과: {signals}")
    print()
    
    # Fallback 조건 테스트
    print("[테스트 4] Fallback 조건 확인")
    is_fallback_empty = explainer.check_fallback_condition([], SeverityLevel.LEVEL_2)
    is_fallback_with_docs = explainer.check_fallback_condition([mock_doc], SeverityLevel.LEVEL_1)
    print(f"  빈 문서 + Level 2: {is_fallback_empty}")
    print(f"  문서 있음 + Level 1: {is_fallback_with_docs}")
    print()
    
    print("=" * 70)
    print("[완료] 컴포넌트 테스트 완료")
    print("=" * 70)


def main():
    """메인 실행 함수"""
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--standalone":
            test_xai_standalone()
        elif sys.argv[1] == "--components":
            test_xai_explainer_components()
        else:
            print("사용법:")
            print("  python test_xai_explainer.py              # RAG 통합 테스트")
            print("  python test_xai_explainer.py --standalone  # 독립 테스트")
            print("  python test_xai_explainer.py --components  # 컴포넌트 테스트")
    else:
        test_xai_with_rag()


if __name__ == "__main__":
    main()

