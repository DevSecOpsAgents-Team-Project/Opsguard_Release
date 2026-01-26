"""
XAI (Explainable AI) 레이어 모듈

기존 심각도 결정 로직의 결과를 설명하는 결정론적 설명 생성기입니다.
결정 로직을 변경하지 않고, 결정의 근거와 이유를 구조화된 형태로 제공합니다.
"""

from typing import List, Dict, Any, Optional
from severity_decision import SecurityEvent, SeverityLevel, SeverityDecisionResult


class XAIExplainer:
    """
    XAI 설명 생성기
    
    보안 이벤트, 규제 문서, 할당된 레벨을 기반으로 결정론적 설명을 생성합니다.
    결정 로직을 변경하지 않고 설명만 제공합니다.
    """
    
    # 규제 의도 분류 키워드 (기존 RegulationAnalyzer와 일치)
    IMMEDIATE_ACTION_KEYWORDS = [
        "즉시", "immediate", "urgent", "긴급", "emergency",
        "침해", "breach", "유출", "exposed", "leak", "leakage",
        "격리", "isolation", "차단", "block", "blocking",
        "신고", "report", "notification", "통지",
        "강제", "forced", "mandatory", "의무"
    ]
    
    MITIGATION_KEYWORDS = [
        "완화", "mitigation", "대응", "response", "조치", "action",
        "위협", "threat", "취약점", "vulnerability",
        "분류", "triage", "우선순위", "priority",
        "평가", "assessment", "evaluation"
    ]
    
    MONITORING_KEYWORDS = [
        "로깅", "logging", "기록", "record",
        "감사", "audit", "auditing",
        "모니터링", "monitoring", "감시", "surveillance",
        "보관", "retention", "저장", "storage"
    ]
    
    @staticmethod
    def extract_regulatory_intent(doc: Dict[str, Any]) -> str:
        """
        단일 규제 문서에서 의도를 추출합니다.
        
        Args:
            doc: 규제 문서 딕셔너리 (document, metadata 포함)
        
        Returns:
            "immediate action" | "mitigation" | "monitoring" | "unknown"
        """
        doc_text = doc.get("document", "").lower()
        
        # 즉시 대응 키워드 검사
        immediate_count = sum(1 for keyword in XAIExplainer.IMMEDIATE_ACTION_KEYWORDS 
                             if keyword.lower() in doc_text)
        mitigation_count = sum(1 for keyword in XAIExplainer.MITIGATION_KEYWORDS 
                              if keyword.lower() in doc_text)
        monitoring_count = sum(1 for keyword in XAIExplainer.MONITORING_KEYWORDS 
                              if keyword.lower() in doc_text)
        
        # 가장 많은 키워드가 있는 의도 반환
        if immediate_count > 0 and immediate_count >= mitigation_count and immediate_count >= monitoring_count:
            return "immediate action"
        elif mitigation_count > 0 and mitigation_count >= monitoring_count:
            return "mitigation"
        elif monitoring_count > 0:
            return "monitoring"
        else:
            return "unknown"
    
    @staticmethod
    def extract_event_factors(security_event: SecurityEvent) -> List[str]:
        """
        보안 이벤트에서 레벨 결정에 기여한 요인을 추출합니다.
        
        Args:
            security_event: 보안 이벤트 객체
        
        Returns:
            이벤트 요인 리스트 (예: ["exposure=public", "privilege_impact=true"])
        """
        factors = []
        
        # 노출 수준
        if security_event.exposure == "public":
            factors.append("exposure=public")
        elif security_event.exposure == "internal":
            factors.append("exposure=internal")
        
        # 권한 영향
        if security_event.privilege_impact:
            factors.append("privilege_impact=true")
        else:
            factors.append("privilege_impact=false")
        
        # 데이터 민감도
        if security_event.data_sensitivity in ["medium", "high"]:
            factors.append(f"data_sensitivity={security_event.data_sensitivity}")
        else:
            factors.append("data_sensitivity=low")
        
        # 리소스 타입 (관리자 리소스인 경우)
        if "admin" in security_event.resource_type.lower() or "root" in security_event.resource_type.lower():
            factors.append("resource_type=admin")
        
        return factors
    
    @staticmethod
    def extract_regulatory_signals(retrieved_docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        검색된 규제 문서에서 규제 신호를 추출합니다.
        
        Args:
            retrieved_docs: ChromaDB에서 검색된 규제 문서 리스트
        
        Returns:
            규제 신호 리스트, 각각은 {
                "doc_type": str,
                "clause_id": str,
                "intent": str
            } 형태
        """
        signals = []
        
        for doc in retrieved_docs:
            # 메타데이터에서 문서 타입 추출
            # search_similar_documents는 doc_type을 직접 키로 반환하거나 metadata 딕셔너리에 포함
            if "doc_type" in doc:
                doc_type = doc.get("doc_type", "UNKNOWN")
            elif "metadata" in doc:
                metadata = doc.get("metadata", {})
                if isinstance(metadata, dict):
                    doc_type = metadata.get("doc_type", "UNKNOWN")
                else:
                    doc_type = "UNKNOWN"
            else:
                doc_type = "UNKNOWN"
            
            # 규제 ID 추출 (clause_id)
            clause_id = doc.get("id", "")
            
            # 규제 의도 추출
            intent = XAIExplainer.extract_regulatory_intent(doc)
            
            signals.append({
                "doc_type": doc_type,
                "clause_id": clause_id,
                "intent": intent
            })
        
        return signals
    
    @staticmethod
    def check_fallback_condition(
        retrieved_docs: List[Dict[str, Any]],
        assigned_level: SeverityLevel
    ) -> bool:
        """
        보수적 기본값(fallback) 조건인지 확인합니다.
        
        Args:
            retrieved_docs: 검색된 규제 문서
            assigned_level: 할당된 레벨
        
        Returns:
            True: fallback 조건 (규제 증거 부족으로 Level 2 할당)
            False: 규제 증거 기반 결정
        """
        # 규제 문서가 없고 Level 2인 경우
        if not retrieved_docs and assigned_level == SeverityLevel.LEVEL_2:
            return True
        
        # 규제 문서가 있지만 Level 1/3 지표가 거의 없는 경우
        if retrieved_docs:
            from severity_decision import RegulationAnalyzer
            analysis = RegulationAnalyzer.extract_severity_intent(retrieved_docs)
            
            # Level 1, 3 지표가 모두 0이고 Level 2로 할당된 경우
            if (analysis["level_1_indicators"] == 0 and 
                analysis["level_3_indicators"] == 0 and
                assigned_level == SeverityLevel.LEVEL_2):
                return True
        
        return False
    
    @staticmethod
    def build_justification_text(
        security_event: SecurityEvent,
        retrieved_docs: List[Dict[str, Any]],
        assigned_level: SeverityLevel,
        regulatory_signals: List[Dict[str, Any]],
        is_fallback: bool
    ) -> str:
        """
        인간이 읽을 수 있는 설명 텍스트를 생성합니다.
        
        Args:
            security_event: 보안 이벤트
            retrieved_docs: 규제 문서
            assigned_level: 할당된 레벨
            regulatory_signals: 규제 신호
            is_fallback: fallback 조건 여부
        
        Returns:
            설명 텍스트
        """
        level_name = {
            SeverityLevel.LEVEL_1: "Level 1 (Critical)",
            SeverityLevel.LEVEL_2: "Level 2 (High)",
            SeverityLevel.LEVEL_3: "Level 3 (Medium/Low)"
        }[assigned_level]
        
        if is_fallback:
            return (
                f"{level_name} 할당: 규제 문서 증거가 부족하여 보수적으로 Level 2로 설정되었습니다. "
                f"이벤트 특성({security_event.event_type})을 고려하여 추가 조사가 필요합니다."
            )
        
        # 규제 의도 요약
        intent_counts = {}
        for signal in regulatory_signals:
            intent = signal["intent"]
            intent_counts[intent] = intent_counts.get(intent, 0) + 1
        
        intent_summary = ", ".join([f"{intent} {count}개" 
                                   for intent, count in intent_counts.items()])
        
        # 주요 규제 참조
        main_regulations = [s["clause_id"] for s in regulatory_signals[:3] if s["clause_id"]]
        reg_refs = ", ".join(main_regulations) if main_regulations else "없음"
        
        if assigned_level == SeverityLevel.LEVEL_1:
            return (
                f"{level_name} 할당: 규제 문서({reg_refs})에서 즉시 대응이 요구됩니다. "
                f"규제 의도({intent_summary})와 이벤트 특성({security_event.event_type})이 "
                f"심각한 보안 위협을 나타냅니다."
            )
        elif assigned_level == SeverityLevel.LEVEL_2:
            return (
                f"{level_name} 할당: 완화 조치가 필요하나 즉시 서비스 종료는 불필요합니다. "
                f"규제 문서({reg_refs})의 의도({intent_summary})와 이벤트 특성을 고려하여 "
                f"신속한 대응이 필요합니다."
            )
        else:  # Level 3
            return (
                f"{level_name} 할당: 규제 문서({reg_refs})에서 모니터링 및 로깅 강화만 요구됩니다. "
                f"규제 의도({intent_summary})에 따라 즉시 대응이 필요한 위협으로 판단되지 않습니다."
            )


def build_xai(
    security_event: SecurityEvent,
    retrieved_docs: List[Dict[str, Any]],
    assigned_level: SeverityLevel
) -> Dict[str, Any]:
    """
    XAI 설명을 생성합니다.
    
    이 함수는 기존 결정 로직의 결과를 설명하는 역할만 하며,
    결정 자체를 변경하지 않습니다.
    
    Args:
        security_event: 보안 이벤트 객체
        retrieved_docs: ChromaDB에서 검색된 규제 문서 리스트
        assigned_level: 기존 로직에 의해 할당된 심각도 레벨
    
    Returns:
        {
            "assigned_level": int,  # 1, 2, or 3
            "justification": str,  # 인간이 읽을 수 있는 설명
            "triggers": {
                "event_factors": List[str],  # 이벤트 요인
                "regulatory_signals": List[Dict],  # 규제 신호
                "fallback": bool  # fallback 조건 여부
            }
        }
    """
    explainer = XAIExplainer()
    
    # 1. 이벤트 요인 추출
    event_factors = explainer.extract_event_factors(security_event)
    
    # 2. 규제 신호 추출
    regulatory_signals = explainer.extract_regulatory_signals(retrieved_docs)
    
    # 3. Fallback 조건 확인
    is_fallback = explainer.check_fallback_condition(retrieved_docs, assigned_level)
    
    # 4. 설명 텍스트 생성
    justification = explainer.build_justification_text(
        security_event,
        retrieved_docs,
        assigned_level,
        regulatory_signals,
        is_fallback
    )
    
    return {
        "assigned_level": assigned_level.value,
        "justification": justification,
        "triggers": {
            "event_factors": event_factors,
            "regulatory_signals": regulatory_signals,
            "fallback": is_fallback
        }
    }


def build_xai_from_result(
    security_event: SecurityEvent,
    retrieved_docs: List[Dict[str, Any]],
    decision_result: SeverityDecisionResult
) -> Dict[str, Any]:
    """
    SeverityDecisionResult 객체로부터 XAI 설명을 생성합니다.
    
    편의 함수: 기존 decide_severity() 결과를 XAI 형식으로 변환합니다.
    
    Args:
        security_event: 보안 이벤트 객체
        retrieved_docs: 규제 문서 리스트
        decision_result: SeverityDecisionResult 객체
    
    Returns:
        XAI 설명 딕셔너리
    """
    return build_xai(security_event, retrieved_docs, decision_result.level)

