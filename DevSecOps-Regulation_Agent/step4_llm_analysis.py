"""
Step 4: LLM 기반 보안 분석 모듈

Step 1에서 True로 판정된 체크리스트 항목과 Step 2에서 검색된 RAG 규정 결과를
기반으로 LLM을 사용하여 보안 분석을 수행합니다.
"""

from typing import List, Dict, Any, Optional
from openai import OpenAI
import json
import os
from dotenv import load_dotenv

load_dotenv()


class Step4LLMAnalyzer:
    """Step 4 LLM 분석기"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Args:
            api_key: OpenAI API 키 (없으면 환경변수에서 로드)
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=self.api_key)
    
    def build_prompt(
        self,
        step1_true_items: List[Dict[str, Any]],
        step2_rag_results: List[Dict[str, Any]]
    ) -> str:
        """
        Step 1 True 항목과 Step 2 RAG 결과를 기반으로 LLM 프롬프트를 생성합니다.
        
        Args:
            step1_true_items: Step 1에서 True로 판정된 체크리스트 항목 리스트
                각 항목은 {
                    "check_id": "CHK-06",
                    "reason": "사유 설명"
                } 형태
            step2_rag_results: Step 2에서 검색된 RAG 규정 결과 리스트
                각 결과는 {
                    "section": "섹션명",
                    "no": 4,
                    "citation_key": "인용키",
                    "excerpt": "규정 발췌문"
                } 형태
        
        Returns:
            LLM 프롬프트 문자열
        """
        # Step 1 True 항목 포맷팅
        step1_section = "## Step 1: True로 판정된 체크리스트 항목\n\n"
        if not step1_true_items:
            step1_section += "True로 판정된 항목이 없습니다.\n"
        else:
            for item in step1_true_items:
                check_id = item.get("check_id", "UNKNOWN")
                reason = item.get("reason", "사유 없음")
                step1_section += f"- **{check_id}**: {reason}\n"
        
        # Step 2 RAG 결과 포맷팅
        step2_section = "\n## Step 2: 검색된 RAG 규정 결과\n\n"
        if not step2_rag_results:
            step2_section += "검색된 규정 결과가 없습니다.\n"
        else:
            for idx, result in enumerate(step2_rag_results, 1):
                section = result.get("section", "N/A")
                no = result.get("no", "N/A")
                citation_key = result.get("citation_key", "N/A")
                excerpt = result.get("excerpt", "N/A")
                step2_section += f"{idx}. **Section**: {section}, **No**: {no}, **Citation Key**: {citation_key}\n"
                step2_section += f"   **Excerpt**: {excerpt}\n\n"
        
        # LLM 프롬프트 구성
        prompt = f"""당신은 보안 규제 준수 분석 전문가입니다. 아래 제공된 정보를 기반으로 보안 분석을 수행하세요.

{step1_section}

{step2_section}

## 분석 요구사항

다음 규칙을 **반드시** 준수하세요:

1. **요약(Summary) 작성 규칙**:
   - Step 1에서 True로 판정된 항목을 중심으로 작성하세요.
   - 각 항목의 핵심 이슈와 규제 준수 여부를 요약하세요.
   - Step 1 True 항목이 없으면 "True로 판정된 체크리스트 항목이 없습니다."라고 명시하세요.

2. **권고사항(Recommendations) 작성 규칙**:
   - 각 Step 1 True 항목마다 최소 1개 이상의 citation_key를 포함해야 합니다.
   - citation_key는 반드시 Step 2 RAG 결과에서 가져온 것만 사용하세요.
   - RAG 근거가 없는 일반적인 보안 조언은 **금지**됩니다.
   - Step 2 RAG 결과에 citation_key가 없으면 해당 항목에 대한 권고사항을 작성하지 마세요.

3. **출력 포맷**:
   - 반드시 다음 JSON 구조로 출력하세요:
   {{
     "summary": "...",
     "findings": [
       {{
         "check_id": "CHK-06",
         "issue": "...",
         "evidence": [
           {{
             "section": "...",
             "no": 4,
             "citation_key": "...",
             "excerpt": "..."
           }}
         ],
         "recommendation": "..."
       }}
     ]
   }}

4. **중요 제약사항**:
   - Step 1 True 항목이 없으면 findings 배열을 비워두세요.
   - 각 finding의 evidence 배열에는 반드시 Step 2 RAG 결과에서 가져온 citation_key가 포함되어야 합니다.
   - Step 2 RAG 결과에 없는 citation_key를 사용하지 마세요.
   - 일반적인 보안 모범 사례나 RAG 결과에 없는 내용은 권고사항에 포함하지 마세요.

이제 분석을 수행하고 JSON 형식으로 결과를 출력하세요.
"""
        return prompt
    
    def analyze(
        self,
        step1_true_items: List[Dict[str, Any]],
        step2_rag_results: List[Dict[str, Any]],
        model: str = "gpt-4o",
        temperature: float = 0.3
    ) -> Dict[str, Any]:
        """
        Step 1 True 항목과 Step 2 RAG 결과를 기반으로 LLM 분석을 수행합니다.
        
        Args:
            step1_true_items: Step 1에서 True로 판정된 체크리스트 항목 리스트
            step2_rag_results: Step 2에서 검색된 RAG 규정 결과 리스트
            model: 사용할 LLM 모델 (기본값: "gpt-4o")
            temperature: LLM temperature (기본값: 0.3)
        
        Returns:
            {
                "summary": str,
                "findings": [
                    {
                        "check_id": str,
                        "issue": str,
                        "evidence": [
                            {
                                "section": str,
                                "no": int,
                                "citation_key": str,
                                "excerpt": str
                            }
                        ],
                        "recommendation": str
                    }
                ]
            }
        """
        # 프롬프트 생성
        prompt = self.build_prompt(step1_true_items, step2_rag_results)
        
        # LLM 호출
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "당신은 보안 규제 준수 분석 전문가입니다. 제공된 체크리스트 항목과 RAG 규정 결과를 기반으로 정확하고 근거 있는 분석을 수행합니다. 반드시 JSON 형식으로만 응답하세요."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=temperature,
                response_format={"type": "json_object"}
            )
            
            # 응답 파싱
            content = response.choices[0].message.content
            result = json.loads(content)
            
            # 결과 검증
            self._validate_result(result, step1_true_items, step2_rag_results)
            
            return result
            
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM 응답을 JSON으로 파싱할 수 없습니다: {e}")
        except Exception as e:
            raise RuntimeError(f"LLM 분석 중 오류 발생: {e}")
    
    def _validate_result(
        self,
        result: Dict[str, Any],
        step1_true_items: List[Dict[str, Any]],
        step2_rag_results: List[Dict[str, Any]]
    ):
        """
        LLM 결과를 검증합니다.
        
        Args:
            result: LLM 분석 결과
            step1_true_items: Step 1 True 항목 리스트
            step2_rag_results: Step 2 RAG 결과 리스트
        """
        # 필수 필드 확인
        if "summary" not in result:
            raise ValueError("결과에 'summary' 필드가 없습니다.")
        if "findings" not in result:
            raise ValueError("결과에 'findings' 필드가 없습니다.")
        
        # Step 1 True 항목이 없으면 findings가 비어있어야 함
        if not step1_true_items and result["findings"]:
            raise ValueError("Step 1 True 항목이 없는데 findings가 있습니다.")
        
        # Step 2 RAG 결과에서 citation_key 추출
        valid_citation_keys = {r.get("citation_key") for r in step2_rag_results if r.get("citation_key")}
        
        # 각 finding 검증
        for finding in result["findings"]:
            if "check_id" not in finding:
                raise ValueError("finding에 'check_id' 필드가 없습니다.")
            if "issue" not in finding:
                raise ValueError("finding에 'issue' 필드가 없습니다.")
            if "evidence" not in finding:
                raise ValueError("finding에 'evidence' 필드가 없습니다.")
            if "recommendation" not in finding:
                raise ValueError("finding에 'recommendation' 필드가 없습니다.")
            
            # evidence 검증
            if not finding["evidence"]:
                raise ValueError(f"{finding['check_id']}: evidence가 비어있습니다. 최소 1개 이상의 citation_key가 필요합니다.")
            
            # citation_key 검증
            for evidence in finding["evidence"]:
                citation_key = evidence.get("citation_key")
                if not citation_key:
                    raise ValueError(f"{finding['check_id']}: evidence에 citation_key가 없습니다.")
                if citation_key not in valid_citation_keys:
                    raise ValueError(f"{finding['check_id']}: citation_key '{citation_key}'가 Step 2 RAG 결과에 없습니다.")
            
            # check_id가 Step 1 True 항목에 있는지 확인
            check_ids = {item.get("check_id") for item in step1_true_items}
            if finding["check_id"] not in check_ids:
                raise ValueError(f"finding의 check_id '{finding['check_id']}'가 Step 1 True 항목에 없습니다.")


def analyze_with_step4(
    step1_true_items: List[Dict[str, Any]],
    step2_rag_results: List[Dict[str, Any]],
    model: str = "gpt-4o"
) -> Dict[str, Any]:
    """
    편의 함수: Step 4 LLM 분석을 수행합니다.
    
    Args:
        step1_true_items: Step 1에서 True로 판정된 체크리스트 항목 리스트
        step2_rag_results: Step 2에서 검색된 RAG 규정 결과 리스트
        model: 사용할 LLM 모델
    
    Returns:
        LLM 분석 결과
    """
    analyzer = Step4LLMAnalyzer()
    return analyzer.analyze(step1_true_items, step2_rag_results, model=model)


if __name__ == "__main__":
    # 테스트 예제
    step1_items = [
        {
            "check_id": "CHK-06",
            "reason": "S3 버킷이 공개적으로 노출되어 있습니다."
        },
        {
            "check_id": "CHK-12",
            "reason": "IAM 정책에 최소 권한 원칙이 적용되지 않았습니다."
        }
    ]
    
    step2_results = [
        {
            "section": "IAM Access Control",
            "no": 4,
            "citation_key": "IAM-05",
            "excerpt": "Employ the least privilege principle when implementing information system access."
        },
        {
            "section": "Data Protection",
            "no": 2,
            "citation_key": "DSP-03",
            "excerpt": "Protect data at rest and in transit using encryption."
        }
    ]
    
    try:
        result = analyze_with_step4(step1_items, step2_results)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"오류 발생: {e}")

