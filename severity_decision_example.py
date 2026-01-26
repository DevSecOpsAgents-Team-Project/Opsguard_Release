"""
심각도 레벨 결정 로직 사용 예제

실제 GuardDuty 이벤트나 보안 이벤트를 처리하는 예제를 보여줍니다.
"""

from severity_decision import decide_severity_level, SeverityDecisionEngine, SecurityEvent
from test_isms_rag import load_chromadb, search_similar_documents


def process_guardduty_finding(finding: dict, collection) -> dict:
    """
    AWS GuardDuty Finding을 처리하여 심각도 레벨을 결정합니다.
    
    Args:
        finding: GuardDuty Finding 딕셔너리
            {
                "Type": "UnauthorizedAPICall",
                "Resource": {"ResourceType": "S3Bucket", ...},
                "Service": {...},
                ...
            }
        collection: ChromaDB Collection 객체
    
    Returns:
        {
            "assigned_level": int,
            "justification": str,
            "triggered_factors": List[str],
            "regulation_references": List[str],
            "finding_type": str
        }
    """
    # GuardDuty Finding에서 보안 이벤트 속성 추출
    finding_type = finding.get("Type", "")
    resource_type = finding.get("Resource", {}).get("ResourceType", "")
    
    # 노출 여부 판단 (예: S3 버킷이 public인지)
    exposure = "internal"  # 기본값
    if "S3Bucket" in resource_type:
        # 실제로는 버킷 정책을 확인해야 함
        exposure = "public"  # 예시
    
    # 권한 영향 여부 판단
    privilege_impact = False
    if any(keyword in finding_type.lower() for keyword in ["privilege", "iam", "unauthorized"]):
        privilege_impact = True
    
    # 데이터 민감도 판단 (예시 로직)
    data_sensitivity = "low"
    if "PII" in str(finding) or "personal" in str(finding).lower():
        data_sensitivity = "high"
    elif "database" in resource_type.lower():
        data_sensitivity = "medium"
    
    # 보안 이벤트 객체 생성
    security_event = {
        "event_type": finding_type,
        "resource_type": resource_type,
        "exposure": exposure,
        "privilege_impact": privilege_impact,
        "data_sensitivity": data_sensitivity
    }
    
    # RAG로 관련 규제 문서 검색
    query = f"{finding_type} {resource_type} 보안 대응"
    retrieved_docs = search_similar_documents(collection, query, top_k=5)
    
    # 심각도 결정
    result = decide_severity_level(security_event, retrieved_docs)
    result["finding_type"] = finding_type
    
    return result


def example_usage():
    """사용 예제"""
    print("=" * 70)
    print("심각도 레벨 결정 로직 사용 예제")
    print("=" * 70)
    print()
    
    # ChromaDB 로드
    collection = load_chromadb()
    
    # 예제 1: GuardDuty Finding 처리
    print("\n예제 1: GuardDuty Finding 처리")
    print("-" * 70)
    
    guardduty_finding = {
        "Type": "UnauthorizedAPICall",
        "Resource": {
            "ResourceType": "S3Bucket",
            "InstanceDetails": {}
        },
        "Service": {
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "PutObject",
                    "ServiceName": "s3"
                }
            }
        }
    }
    
    result = process_guardduty_finding(guardduty_finding, collection)
    print(f"Finding Type: {result['finding_type']}")
    print(f"Assigned Level: {result['assigned_level']}")
    print(f"Justification: {result['justification']}")
    print(f"Triggered Factors: {', '.join(result['triggered_factors'])}")
    print()
    
    # 예제 2: 직접 보안 이벤트 처리
    print("예제 2: 직접 보안 이벤트 처리")
    print("-" * 70)
    
    security_event = {
        "event_type": "DataExfiltration",
        "resource_type": "RDSDatabase",
        "exposure": "public",
        "privilege_impact": True,
        "data_sensitivity": "high"
    }
    
    # 규제 문서 검색
    query = "데이터 유출 침해사고 대응"
    retrieved_docs = search_similar_documents(collection, query, top_k=5)
    
    # 심각도 결정
    result = decide_severity_level(security_event, retrieved_docs)
    
    print(f"Event Type: {security_event['event_type']}")
    print(f"Assigned Level: {result['assigned_level']}")
    print(f"Justification: {result['justification']}")
    print(f"Triggered Factors: {', '.join(result['triggered_factors'])}")
    print(f"Regulation References: {', '.join(result['regulation_references'])}")
    print()
    
    # 예제 3: 여러 이벤트 일괄 처리
    print("예제 3: 여러 이벤트 일괄 처리")
    print("-" * 70)
    
    events = [
        {
            "event_type": "PrivilegeEscalation",
            "resource_type": "IAMRole",
            "exposure": "internal",
            "privilege_impact": True,
            "data_sensitivity": "medium"
        },
        {
            "event_type": "SuspiciousActivity",
            "resource_type": "EC2Instance",
            "exposure": "internal",
            "privilege_impact": False,
            "data_sensitivity": "low"
        }
    ]
    
    for i, event in enumerate(events, 1):
        query = f"{event['event_type']} 보안 대응"
        docs = search_similar_documents(collection, query, top_k=3)
        result = decide_severity_level(event, docs)
        
        print(f"\n이벤트 {i}: {event['event_type']}")
        print(f"  Level: {result['assigned_level']}")
        print(f"  요인: {', '.join(result['triggered_factors'][:3])}")
    
    print("\n" + "=" * 70)
    print("[완료] 예제 실행 완료")
    print("=" * 70)


if __name__ == "__main__":
    example_usage()

