"""
심각도 레벨 결정 로직 모듈

보안 이벤트와 검색된 규제 문서를 기반으로 Level 1/2/3을 결정하는 결정론적 로직을 제공합니다.
규제 의도를 우선시하며, 모든 결정은 설명 가능한 규칙 기반으로 수행됩니다.
"""

from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import re


class SeverityLevel(Enum):
    """심각도 레벨 정의"""
    LEVEL_1 = 1  # Critical: 즉시 응답 필요 (서비스 격리, 차단, 강제 수정)
    LEVEL_2 = 2  # High: 완화 필요하지만 즉시 종료는 아님
    LEVEL_3 = 3  # Medium/Low: 모니터링 또는 로깅 강화만


class SecurityEvent:
    """보안 이벤트 구조"""
    def __init__(
        self,
        event_type: str,
        resource_type: str,
        exposure: str,  # "public" or "internal"
        privilege_impact: bool,  # True/False
        data_sensitivity: str  # "low", "medium", "high"
    ):
        self.event_type = event_type
        self.resource_type = resource_type
        self.exposure = exposure.lower()
        self.privilege_impact = privilege_impact
        self.data_sensitivity = data_sensitivity.lower()
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리 형태로 변환"""
        return {
            "event_type": self.event_type,
            "resource_type": self.resource_type,
            "exposure": self.exposure,
            "privilege_impact": self.privilege_impact,
            "data_sensitivity": self.data_sensitivity
        }


class SeverityDecisionResult:
    """심각도 결정 결과"""
    def __init__(
        self,
        level: SeverityLevel,
        justification: str,
        triggered_factors: List[str],
        regulation_references: List[str]
    ):
        self.level = level
        self.justification = justification
        self.triggered_factors = triggered_factors
        self.regulation_references = regulation_references
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리 형태로 변환"""
        return {
            "assigned_level": self.level.value,
            "justification": self.justification,
            "triggered_factors": self.triggered_factors,
            "regulation_references": self.regulation_references
        }


class RegulationAnalyzer:
    """규제 문서 분석기 - 규제 의도와 심각도 키워드를 추출"""
    
    # Level 1을 나타내는 규제 키워드 (즉시 대응 필요)
    LEVEL_1_KEYWORDS = [
        "침해", "breach", "유출", "exposed", "exposure", "leak", "leakage",
        "즉시", "immediate", "urgent", "긴급", "emergency",
        "격리", "isolation", "차단", "block", "blocking",
        "강제", "forced", "mandatory", "의무",
        "신고", "report", "notification", "통지",
        "PII", "개인정보", "personal information",
        "관리자", "admin", "administrator", "root",
        "권한 남용", "privilege abuse", "권한 오남용"
    ]
    
    # Level 2를 나타내는 규제 키워드 (완화 필요)
    LEVEL_2_KEYWORDS = [
        "완화", "mitigation", "대응", "response", "조치", "action",
        "위협", "threat", "취약점", "vulnerability", "weakness",
        "모니터링", "monitoring", "감시", "surveillance",
        "알림", "alert", "alerting", "경보",
        "분류", "triage", "우선순위", "priority",
        "평가", "assessment", "평가", "evaluation"
    ]
    
    # Level 3을 나타내는 규제 키워드 (모니터링/로깅)
    LEVEL_3_KEYWORDS = [
        "로깅", "logging", "기록", "record",
        "감사", "audit", "auditing",
        "보관", "retention", "저장", "storage",
        "정책", "policy", "절차", "procedure",
        "문서화", "documentation"
    ]
    
    @staticmethod
    def extract_severity_intent(retrieved_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        검색된 규제 문서에서 심각도 의도를 추출합니다.
        
        Args:
            retrieved_docs: ChromaDB에서 검색된 규제 문서 리스트
                각 문서는 다음 키를 포함: "document", "id", "title", "category", "metadata"
        
        Returns:
            {
                "level_1_indicators": int,  # Level 1 지표 개수
                "level_2_indicators": int,  # Level 2 지표 개수
                "level_3_indicators": int,  # Level 3 지표 개수
                "critical_regulations": List[str],  # Level 1 관련 규제 ID 리스트
                "document_texts": List[str]  # 분석된 문서 텍스트
            }
        """
        level_1_count = 0
        level_2_count = 0
        level_3_count = 0
        critical_regulations = []
        document_texts = []
        
        for doc in retrieved_docs:
            doc_text = doc.get("document", "").lower()
            doc_id = doc.get("id", "")
            document_texts.append(doc_text)
            
            # Level 1 키워드 검사
            level_1_matches = sum(1 for keyword in RegulationAnalyzer.LEVEL_1_KEYWORDS 
                                 if keyword.lower() in doc_text)
            if level_1_matches > 0:
                level_1_count += level_1_matches
                if doc_id not in critical_regulations:
                    critical_regulations.append(doc_id)
            
            # Level 2 키워드 검사
            level_2_matches = sum(1 for keyword in RegulationAnalyzer.LEVEL_2_KEYWORDS 
                                 if keyword.lower() in doc_text)
            if level_2_matches > 0:
                level_2_count += level_2_matches
            
            # Level 3 키워드 검사
            level_3_matches = sum(1 for keyword in RegulationAnalyzer.LEVEL_3_KEYWORDS 
                                 if keyword.lower() in doc_text)
            if level_3_matches > 0:
                level_3_count += level_3_matches
        
        return {
            "level_1_indicators": level_1_count,
            "level_2_indicators": level_2_count,
            "level_3_indicators": level_3_count,
            "critical_regulations": critical_regulations,
            "document_texts": document_texts
        }
    
    @staticmethod
    def check_regulation_urgency(retrieved_docs: List[Dict[str, Any]]) -> bool:
        """
        규제 문서에서 긴급 대응이 필요한지 확인합니다.
        
        Returns:
            True: 긴급 대응 필요 (Level 1 고려)
            False: 일반 대응 가능
        """
        urgency_keywords = [
            "즉시", "immediate", "urgent", "긴급", "emergency",
            "침해", "breach", "유출", "exposed", "leak",
            "신고", "report", "notification", "통지",
            "격리", "isolation", "차단", "block"
        ]
        
        for doc in retrieved_docs:
            doc_text = doc.get("document", "").lower()
            if any(keyword.lower() in doc_text for keyword in urgency_keywords):
                return True
        
        return False


class SeverityDecisionEngine:
    """심각도 레벨 결정 엔진 - 결정론적 규칙 기반 로직"""
    
    def __init__(self):
        self.analyzer = RegulationAnalyzer()
    
    def decide_severity(
        self,
        security_event: SecurityEvent,
        retrieved_docs: List[Dict[str, Any]]
    ) -> SeverityDecisionResult:
        """
        보안 이벤트와 규제 문서를 기반으로 심각도 레벨을 결정합니다.
        
        Args:
            security_event: 보안 이벤트 객체
            retrieved_docs: ChromaDB에서 검색된 규제 문서 리스트
        
        Returns:
            SeverityDecisionResult: 결정된 심각도 레벨과 설명
        """
        # 규제 문서가 없는 경우 보수적으로 Level 2 반환
        if not retrieved_docs:
            return SeverityDecisionResult(
                level=SeverityLevel.LEVEL_2,
                justification="규제 문서 증거가 부족하여 보수적으로 Level 2로 설정",
                triggered_factors=["규제 문서 부재"],
                regulation_references=[]
            )
        
        # 규제 의도 분석
        regulation_analysis = self.analyzer.extract_severity_intent(retrieved_docs)
        is_urgent = self.analyzer.check_regulation_urgency(retrieved_docs)
        
        # 결정 요인 수집
        triggered_factors = []
        regulation_references = regulation_analysis["critical_regulations"]
        
        # ========================================================================
        # Level 1 결정 규칙 (Critical - 즉시 응답 필요)
        # ========================================================================
        level_1_conditions = []
        
        # 규칙 1: 규제에서 긴급 대응이 명시되고, 공개 노출 + 권한 영향
        if is_urgent and security_event.exposure == "public" and security_event.privilege_impact:
            level_1_conditions.append("규제 긴급성 + 공개 노출 + 권한 영향")
            triggered_factors.append("긴급 규제 요구사항")
            triggered_factors.append("공개 노출")
            triggered_factors.append("권한 영향")
        
        # 규칙 2: 고민감도 데이터 + 공개 노출 + 규제에서 침해/유출 키워드
        if (security_event.data_sensitivity == "high" and 
            security_event.exposure == "public" and
            regulation_analysis["level_1_indicators"] > 0):
            level_1_conditions.append("고민감도 데이터 + 공개 노출 + 규제 침해 지표")
            triggered_factors.append("고민감도 데이터")
            triggered_factors.append("공개 노출")
            triggered_factors.append("규제 침해 지표")
        
        # 규칙 3: 권한 영향 + 관리자 리소스 + 규제에서 즉시 대응 키워드
        if (security_event.privilege_impact and
            "admin" in security_event.resource_type.lower() and
            is_urgent):
            level_1_conditions.append("권한 영향 + 관리자 리소스 + 긴급 규제")
            triggered_factors.append("권한 영향")
            triggered_factors.append("관리자 리소스")
            triggered_factors.append("긴급 규제")
        
        # 규칙 4: 규제에서 Level 1 지표가 압도적으로 많음 (3개 이상)
        if regulation_analysis["level_1_indicators"] >= 3:
            level_1_conditions.append("규제 Level 1 지표 압도적")
            triggered_factors.append(f"Level 1 규제 지표 {regulation_analysis['level_1_indicators']}개")
        
        # Level 1 조건 충족 시
        if level_1_conditions:
            justification = (
                f"Level 1 (Critical) 할당: {'; '.join(level_1_conditions)}. "
                f"규제 문서({', '.join(regulation_references[:3])})에서 즉시 대응이 요구되며, "
                f"이벤트 특성({security_event.event_type})이 심각한 보안 위협을 나타냅니다."
            )
            return SeverityDecisionResult(
                level=SeverityLevel.LEVEL_1,
                justification=justification,
                triggered_factors=list(set(triggered_factors)),
                regulation_references=regulation_references
            )
        
        # ========================================================================
        # Level 3 결정 규칙 (Medium/Low - 모니터링/로깅만)
        # ========================================================================
        level_3_conditions = []
        
        # 규칙 1: 내부 노출 + 낮은 데이터 민감도 + 규제에서 모니터링/로깅만 언급
        if (security_event.exposure == "internal" and
            security_event.data_sensitivity == "low" and
            regulation_analysis["level_3_indicators"] > regulation_analysis["level_1_indicators"] and
            regulation_analysis["level_3_indicators"] > regulation_analysis["level_2_indicators"]):
            level_3_conditions.append("내부 노출 + 낮은 민감도 + 모니터링 규제")
            triggered_factors.append("내부 노출")
            triggered_factors.append("낮은 데이터 민감도")
            triggered_factors.append("모니터링 중심 규제")
        
        # 규칙 2: 권한 영향 없음 + 규제에서 로깅/감사만 언급
        if (not security_event.privilege_impact and
            regulation_analysis["level_3_indicators"] >= 2 and
            regulation_analysis["level_1_indicators"] == 0):
            level_3_conditions.append("권한 영향 없음 + 로깅 규제")
            triggered_factors.append("권한 영향 없음")
            triggered_factors.append("로깅 중심 규제")
        
        # Level 3 조건 충족 시
        if level_3_conditions:
            justification = (
                f"Level 3 (Medium/Low) 할당: {'; '.join(level_3_conditions)}. "
                f"규제 문서에서 모니터링 및 로깅 강화만 요구되며, "
                f"즉시 대응이 필요한 위협으로 판단되지 않습니다."
            )
            return SeverityDecisionResult(
                level=SeverityLevel.LEVEL_3,
                justification=justification,
                triggered_factors=list(set(triggered_factors)),
                regulation_references=[doc.get("id", "") for doc in retrieved_docs[:3]]
            )
        
        # ========================================================================
        # Level 2 결정 규칙 (High - 기본값 및 기타 경우)
        # ========================================================================
        # Level 1, 3 조건에 해당하지 않는 모든 경우는 Level 2
        
        level_2_factors = []
        if security_event.exposure == "public":
            level_2_factors.append("공개 노출")
        if security_event.privilege_impact:
            level_2_factors.append("권한 영향")
        if security_event.data_sensitivity in ["medium", "high"]:
            level_2_factors.append(f"{security_event.data_sensitivity} 데이터 민감도")
        if regulation_analysis["level_2_indicators"] > 0:
            level_2_factors.append("완화 조치 규제")
        
        # 규제 지표가 있는 경우
        if regulation_analysis["level_2_indicators"] > 0 or regulation_analysis["level_1_indicators"] > 0:
            justification = (
                f"Level 2 (High) 할당: 완화 조치가 필요하나 즉시 서비스 종료는 불필요합니다. "
                f"이벤트 특성({', '.join(level_2_factors)})과 규제 요구사항을 고려하여 "
                f"신속한 대응이 필요합니다."
            )
        else:
            # 규제 증거가 부족한 경우 보수적 접근
            justification = (
                f"Level 2 (High) 할당: 규제 문서 증거가 불충분하여 보수적으로 Level 2로 설정. "
                f"이벤트 특성({', '.join(level_2_factors)})을 고려하여 추가 조사가 필요합니다."
            )
        
        triggered_factors.extend(level_2_factors)
        if not triggered_factors:
            triggered_factors.append("기본 Level 2 할당")
        
        return SeverityDecisionResult(
            level=SeverityLevel.LEVEL_2,
            justification=justification,
            triggered_factors=list(set(triggered_factors)),
            regulation_references=[doc.get("id", "") for doc in retrieved_docs[:3]]
        )


# ============================================================================
# 편의 함수
# ============================================================================

def decide_severity_level(
    security_event: Dict[str, Any],
    retrieved_docs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    편의 함수: 딕셔너리 형태의 보안 이벤트를 받아 심각도 레벨을 결정합니다.
    
    Args:
        security_event: {
            "event_type": str,
            "resource_type": str,
            "exposure": str,  # "public" or "internal"
            "privilege_impact": bool,
            "data_sensitivity": str  # "low", "medium", "high"
        }
        retrieved_docs: ChromaDB 검색 결과 리스트
    
    Returns:
        {
            "assigned_level": int,  # 1, 2, or 3
            "justification": str,
            "triggered_factors": List[str],
            "regulation_references": List[str]
        }
    """
    event = SecurityEvent(
        event_type=security_event.get("event_type", ""),
        resource_type=security_event.get("resource_type", ""),
        exposure=security_event.get("exposure", "internal"),
        privilege_impact=security_event.get("privilege_impact", False),
        data_sensitivity=security_event.get("data_sensitivity", "low")
    )
    
    engine = SeverityDecisionEngine()
    result = engine.decide_severity(event, retrieved_docs)
    
    return result.to_dict()


def decide_severity_level_with_xai(
    security_event: Dict[str, Any],
    retrieved_docs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    편의 함수: 심각도 레벨 결정 + XAI 설명을 포함한 결과를 반환합니다.
    
    기존 decide_severity_level()을 호출한 후 XAI 레이어를 추가합니다.
    결정 로직은 변경하지 않고 설명만 추가합니다.
    
    Args:
        security_event: {
            "event_type": str,
            "resource_type": str,
            "exposure": str,  # "public" or "internal"
            "privilege_impact": bool,
            "data_sensitivity": str  # "low", "medium", "high"
        }
        retrieved_docs: ChromaDB 검색 결과 리스트
    
    Returns:
        {
            "assigned_level": int,  # 1, 2, or 3
            "justification": str,  # XAI 기반 설명
            "triggers": {
                "event_factors": List[str],
                "regulatory_signals": List[Dict],
                "fallback": bool
            }
        }
    """
    # XAI 모듈 import (순환 참조 방지)
    from xai_explainer import build_xai
    
    event = SecurityEvent(
        event_type=security_event.get("event_type", ""),
        resource_type=security_event.get("resource_type", ""),
        exposure=security_event.get("exposure", "internal"),
        privilege_impact=security_event.get("privilege_impact", False),
        data_sensitivity=security_event.get("data_sensitivity", "low")
    )
    
    # 기존 결정 로직 실행 (변경 없음)
    engine = SeverityDecisionEngine()
    decision_result = engine.decide_severity(event, retrieved_docs)
    
    # XAI 설명 추가 (결정 로직 변경 없이 설명만 생성)
    xai_result = build_xai(event, retrieved_docs, decision_result.level)
    
    return xai_result

