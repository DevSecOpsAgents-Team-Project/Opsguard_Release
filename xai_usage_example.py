"""
XAI 설명 레이어 사용 예제

기존 심각도 결정 로직에 XAI 설명을 추가하는 방법을 보여줍니다.
"""

from severity_decision import (
    SecurityEvent,
    SeverityDecisionEngine,
    decide_severity_level_with_xai
)
from xai_explainer import build_xai
from test_isms_rag import load_chromadb, search_similar_documents
import json


def example_basic_xai():
    """
    기본 XAI 사용 예제
    """
    print("=" * 70)
    print("예제 1: 기본 XAI 사용")
    print("=" * 70)
    print()
    
    # 보안 이벤트 정의
    security_event = {
        "event_type": "DataBreach",
        "resource_type": "Database",
        "exposure": "public",
        "privilege_impact": True,
        "data_sensitivity": "high"
    }
    
    # 모의 규제 문서
    retrieved_docs = [
        {
            "id": "SEF-07",
            "title": "Security Breach Notification",
            "document": "보안 침해 또는 침해 추정 사고 발생 시, 즉시 신고하고 알리는 절차를 수립해야 한다.",
            "doc_type": "CSA_CCM",
            "metadata": {
                "doc_type": "CSA_CCM",
                "doc_version": "v4.0"
            }
        }
    ]
    
    # XAI 포함 결정 실행
    xai_result = decide_severity_level_with_xai(security_event, retrieved_docs)
    
    print("보안 이벤트:")
    print(f"  - Event Type: {security_event['event_type']}")
    print(f"  - Resource: {security_event['resource_type']}")
    print(f"  - Exposure: {security_event['exposure']}")
    print()
    
    print("XAI 결과:")
    print(json.dumps(xai_result, ensure_ascii=False, indent=2))
    print()


def example_rag_integration():
    """
    RAG 시스템과 통합한 XAI 사용 예제
    """
    print("=" * 70)
    print("예제 2: RAG 통합 XAI 사용")
    print("=" * 70)
    print()
    
    # ChromaDB 로드
    collection = load_chromadb()
    
    # 보안 이벤트
    security_event = {
        "event_type": "UnauthorizedAPICall",
        "resource_type": "S3Bucket",
        "exposure": "public",
        "privilege_impact": True,
        "data_sensitivity": "high"
    }
    
    # RAG로 규제 문서 검색
    query = "Access Key 유출 시 대응"
    print(f"규제 문서 검색: {query}")
    retrieved_docs = search_similar_documents(collection, query, top_k=5)
    
    print(f"검색된 문서: {len(retrieved_docs)}개")
    for doc in retrieved_docs[:3]:
        print(f"  - {doc['id']}: {doc['title']}")
    print()
    
    # XAI 포함 결정 실행
    xai_result = decide_severity_level_with_xai(security_event, retrieved_docs)
    
    print("XAI 결과:")
    print(f"  Assigned Level: {xai_result['assigned_level']}")
    print(f"  Justification: {xai_result['justification']}")
    print()
    print("  Event Factors:")
    for factor in xai_result['triggers']['event_factors']:
        print(f"    - {factor}")
    print()
    print("  Regulatory Signals:")
    for signal in xai_result['triggers']['regulatory_signals']:
        print(f"    - {signal['clause_id']} ({signal['doc_type']}): {signal['intent']}")
    print()
    print("  Fallback: {xai_result['triggers']['fallback']}")
    print()


def example_manual_xai():
    """
    수동으로 XAI를 추가하는 예제
    """
    print("=" * 70)
    print("예제 3: 수동 XAI 추가")
    print("=" * 70)
    print()
    
    # 보안 이벤트 객체 생성
    event = SecurityEvent(
        event_type="PrivilegeEscalation",
        resource_type="IAMAdminRole",
        exposure="internal",
        privilege_impact=True,
        data_sensitivity="medium"
    )
    
    # 모의 규제 문서
    retrieved_docs = [
        {
            "id": "IAM-05",
            "title": "Least Privilege",
            "document": "최소 권한 원칙 - 정보 시스템 접근 권한 부여 시 업무 수행에 필요한 최소한의 권한만 부여해야 한다.",
            "doc_type": "CSA_CCM",
            "metadata": {
                "doc_type": "CSA_CCM"
            }
        }
    ]
    
    # 1. 기존 결정 로직 실행
    engine = SeverityDecisionEngine()
    decision_result = engine.decide_severity(event, retrieved_docs)
    
    print(f"기존 결정 결과: Level {decision_result.level.value}")
    print()
    
    # 2. XAI 설명 추가 (결정 로직 변경 없이)
    xai_result = build_xai(event, retrieved_docs, decision_result.level)
    
    print("XAI 설명:")
    print(json.dumps(xai_result, ensure_ascii=False, indent=2))
    print()


def example_fallback_case():
    """
    Fallback 케이스 예제 (규제 문서 부족)
    """
    print("=" * 70)
    print("예제 4: Fallback 케이스 (규제 문서 부족)")
    print("=" * 70)
    print()
    
    security_event = {
        "event_type": "UnknownThreat",
        "resource_type": "EC2Instance",
        "exposure": "internal",
        "privilege_impact": False,
        "data_sensitivity": "low"
    }
    
    # 규제 문서 없음
    retrieved_docs = []
    
    # XAI 포함 결정 실행
    xai_result = decide_severity_level_with_xai(security_event, retrieved_docs)
    
    print("상황: 규제 문서가 검색되지 않음")
    print()
    print("XAI 결과:")
    print(f"  Assigned Level: {xai_result['assigned_level']}")
    print(f"  Justification: {xai_result['justification']}")
    print(f"  Fallback: {xai_result['triggers']['fallback']}")
    print()
    print("설명: 규제 증거가 부족하여 보수적으로 Level 2로 설정되었습니다.")
    print()


def main():
    """모든 예제 실행"""
    example_basic_xai()
    print("\n" + "=" * 70 + "\n")
    
    example_rag_integration()
    print("\n" + "=" * 70 + "\n")
    
    example_manual_xai()
    print("\n" + "=" * 70 + "\n")
    
    example_fallback_case()
    
    print("=" * 70)
    print("[완료] 모든 예제 실행 완료")
    print("=" * 70)


if __name__ == "__main__":
    main()

