"""
심각도 레벨 결정 로직 테스트 스크립트

보안 이벤트와 규제 문서를 기반으로 심각도 레벨을 결정하는 로직을 테스트합니다.
"""

from severity_decision import (
    SeverityDecisionEngine,
    SecurityEvent,
    SeverityLevel,
    decide_severity_level
)
from test_isms_rag import load_chromadb, search_similar_documents


def test_severity_decision_with_rag():
    """
    RAG 시스템과 통합하여 심각도 결정을 테스트합니다.
    """
    print("=" * 70)
    print("심각도 레벨 결정 로직 테스트 (RAG 통합)")
    print("=" * 70)
    print()
    
    # ChromaDB 로드
    collection = load_chromadb()
    
    # 테스트 케이스 정의
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
        },
        {
            "name": "관리자 권한 오남용",
            "event": {
                "event_type": "PrivilegeEscalation",
                "resource_type": "IAMAdminRole",
                "exposure": "internal",
                "privilege_impact": True,
                "data_sensitivity": "medium"
            },
            "query": "관리자 권한 오남용 사고"
        },
        {
            "name": "침해사고 대응",
            "event": {
                "event_type": "DataBreach",
                "resource_type": "Database",
                "exposure": "public",
                "privilege_impact": True,
                "data_sensitivity": "high"
            },
            "query": "침해사고 대응 절차"
        },
        {
            "name": "모니터링 강화 필요",
            "event": {
                "event_type": "AnomalyDetection",
                "resource_type": "CloudTrail",
                "exposure": "internal",
                "privilege_impact": False,
                "data_sensitivity": "low"
            },
            "query": "최소 권한 원칙 적용"
        }
    ]
    
    engine = SeverityDecisionEngine()
    
    # 각 테스트 케이스 실행
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'=' * 70}")
        print(f"테스트 케이스 {i}: {test_case['name']}")
        print(f"{'=' * 70}")
        
        # 보안 이벤트 생성
        event = SecurityEvent(**test_case["event"])
        
        # RAG로 관련 규제 문서 검색
        print(f"\n[검색] 규제 문서 검색: {test_case['query']}")
        retrieved_docs = search_similar_documents(collection, test_case["query"], top_k=5)
        
        if not retrieved_docs:
            print("[경고] 검색된 규제 문서가 없습니다.")
            continue
        
        print(f"[성공] {len(retrieved_docs)}개의 관련 규제 문서 검색됨")
        for doc in retrieved_docs[:3]:
            print(f"   - {doc['id']}: {doc['title']}")
        
        # 심각도 결정
        print(f"\n[결정] 심각도 레벨 결정 중...")
        result = engine.decide_severity(event, retrieved_docs)
        
        # 결과 출력
        print(f"\n[결과] 결정 결과:")
        print(f"   레벨: Level {result.level.value} ({result.level.name})")
        print(f"   설명: {result.justification}")
        print(f"   트리거된 요인: {', '.join(result.triggered_factors)}")
        print(f"   참조 규제: {', '.join(result.regulation_references[:5])}")
        
        print()
    
    print("=" * 70)
    print("[완료] 모든 테스트 완료")
    print("=" * 70)


def test_severity_decision_standalone():
    """
    RAG 없이 심각도 결정 로직만 테스트합니다.
    """
    print("=" * 70)
    print("심각도 레벨 결정 로직 테스트 (독립 실행)")
    print("=" * 70)
    print()
    
    # 모의 규제 문서 데이터
    mock_regulations_level1 = [
        {
            "id": "SEF-07",
            "title": "Security Breach Notification",
            "document": "보안 침해 또는 침해 추정 사고 발생 시, 즉시 신고하고 알리는 절차를 수립해야 한다. 개인정보 유출 등 보안 침해 사고가 확인되었거나 의심될 때, 법적 규제에 따라 규제 기관 및 피해 고객에게 의무적으로 신고해야 한다.",
            "category": "SEF",
            "metadata": {}
        }
    ]
    
    mock_regulations_level2 = [
        {
            "id": "SEF-06",
            "title": "Event Triage Processes",
            "document": "보안 관련 이벤트 발생 시 그 중요도와 긴급성을 분류하고 우선순위를 정하는 프로세스와 기술적 조치를 구현해야 한다. 이벤트를 사전에 정의된 기준에 따라 분류하고, 관련 정보를 신속하게 공유해야 한다.",
            "category": "SEF",
            "metadata": {}
        }
    ]
    
    mock_regulations_level3 = [
        {
            "id": "LOG-03",
            "title": "Security Monitoring and Alerting",
            "document": "애플리케이션 및 인프라의 보안 관련 이벤트를 식별·모니터링하고, 책임자에게 알림을 생성하는 체계를 구축해야 한다. 보안 이벤트를 모니터링하여 경보 조건을 정의하고, 이벤트 발생 시 책임자에게 즉시 통지합니다.",
            "category": "LOG",
            "metadata": {}
        }
    ]
    
    test_cases = [
        {
            "name": "Level 1: 공개 노출 + 권한 영향 + 침해 규제",
            "event": {
                "event_type": "DataBreach",
                "resource_type": "Database",
                "exposure": "public",
                "privilege_impact": True,
                "data_sensitivity": "high"
            },
            "docs": mock_regulations_level1
        },
        {
            "name": "Level 2: 일반 위협 + 완화 규제",
            "event": {
                "event_type": "SuspiciousActivity",
                "resource_type": "EC2Instance",
                "exposure": "internal",
                "privilege_impact": False,
                "data_sensitivity": "medium"
            },
            "docs": mock_regulations_level2
        },
        {
            "name": "Level 3: 내부 노출 + 낮은 민감도 + 모니터링 규제",
            "event": {
                "event_type": "AnomalyDetection",
                "resource_type": "CloudTrail",
                "exposure": "internal",
                "privilege_impact": False,
                "data_sensitivity": "low"
            },
            "docs": mock_regulations_level3
        }
    ]
    
    engine = SeverityDecisionEngine()
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'=' * 70}")
        print(f"테스트 케이스 {i}: {test_case['name']}")
        print(f"{'=' * 70}")
        
        event = SecurityEvent(**test_case["event"])
        result = engine.decide_severity(event, test_case["docs"])
        
        print(f"\n[결과] 결정 결과:")
        print(f"   레벨: Level {result.level.value}")
        print(f"   설명: {result.justification}")
        print(f"   트리거된 요인: {', '.join(result.triggered_factors)}")
        print()
    
    print("=" * 70)
    print("[완료] 독립 테스트 완료")
    print("=" * 70)


def main():
    """메인 실행 함수"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--standalone":
        test_severity_decision_standalone()
    else:
        test_severity_decision_with_rag()


if __name__ == "__main__":
    main()

