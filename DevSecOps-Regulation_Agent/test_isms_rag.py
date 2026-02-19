"""
ISMS-P 규제 문서 RAG 시스템 테스트 스크립트

이 스크립트는 ISMS-P 규제 조항을 임베딩하여 Vector DB에 저장하고,
질의 문장에 대해 관련 조항을 검색하는 기능을 테스트합니다.

사용 기술:
- OpenAI API (text-embedding-3-large)
- ChromaDB (로컬, 파일 저장 - Git 공유 가능)

ChromaDB는 ./chroma_store/ 디렉토리에 파일로 저장되며,
이 디렉토리를 Git에 커밋하면 팀원과 공유할 수 있습니다.
"""

import os
from typing import List, Dict, Any
from openai import OpenAI
import chromadb

# .env 파일에서 환경변수 로드
# .env 파일을 사용하여 API Key를 안전하게 관리합니다
from dotenv import load_dotenv
load_dotenv()  # .env 파일에서 환경변수 로드


# ============================================================================
# 환경 설정
# ============================================================================

# .env 파일에서 OpenAI API Key 불러오기
# .env 파일을 생성하고 다음 내용을 추가하세요:
#   OPENAI_API_KEY=sk-your-actual-api-key-here
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    print("❌ 오류: OPENAI_API_KEY가 설정되지 않았습니다.")
    print("   .env 파일을 생성하고 다음 내용을 추가해주세요:")
    print("   OPENAI_API_KEY=sk-your-actual-api-key-here")
    print("\n   .env.example 파일을 참고하세요.")
    raise ValueError("OPENAI_API_KEY를 .env 파일에 설정해주세요.")

# OpenAI 클라이언트 초기화
client = OpenAI(api_key=OPENAI_API_KEY)


# ============================================================================
# 임베딩 함수
# ============================================================================

def get_embeddings(texts: List[str]) -> List[List[float]]:
    """
    텍스트 리스트를 OpenAI의 text-embedding-3-large 모델로 임베딩합니다.
    
    Args:
        texts: 임베딩할 문자열 리스트
        
    Returns:
        임베딩 벡터 리스트 (각 텍스트에 대한 벡터)
    """
    try:
        # OpenAI API를 호출하여 임베딩 생성
        # model: text-embedding-3-large 사용
        response = client.embeddings.create(
            model="text-embedding-3-large",
            input=texts
        )
        
        # 응답에서 임베딩 벡터 추출
        embeddings = [item.embedding for item in response.data]
        return embeddings
    
    except Exception as e:
        error_str = str(e)
        
        # 할당량 초과 오류 처리
        if "insufficient_quota" in error_str or "429" in error_str:
            print("\n" + "=" * 70)
            print("❌ OpenAI API 할당량 초과 오류")
            print("=" * 70)
            print("현재 OpenAI API 계정의 사용 할당량을 초과했습니다.")
            print("\n해결 방법:")
            print("1. OpenAI 플랫폼(https://platform.openai.com)에서 계정 확인")
            print("2. 결제 정보 및 요금제 확인")
            print("3. 사용량 대시보드에서 할당량 상태 확인")
            print("4. 필요시 결제 정보 추가 또는 요금제 업그레이드")
            print("\n자세한 정보:")
            print("https://platform.openai.com/docs/guides/error-codes/api-errors")
            print("=" * 70 + "\n")
        
        # 인증 오류 처리
        elif "invalid_api_key" in error_str or "401" in error_str:
            print("\n" + "=" * 70)
            print("❌ OpenAI API 인증 오류")
            print("=" * 70)
            print("API Key가 유효하지 않습니다.")
            print("\n해결 방법:")
            print("1. .env 파일의 OPENAI_API_KEY가 올바른지 확인")
            print("2. API Key가 만료되지 않았는지 확인")
            print("3. OpenAI 플랫폼에서 새 API Key 생성")
            print("=" * 70 + "\n")
        
        # 기타 오류
        else:
            print(f"\n❌ 임베딩 생성 중 오류 발생: {e}")
        
        raise


# ============================================================================
# 테스트용 규제 데이터
# ============================================================================

# ISMS-P 규제 조항 샘플 데이터
# 각 문서는 텍스트와 메타데이터를 포함합니다
REGULATION_DOCUMENTS = [
    {
        "text": "접근권한은 업무상 필요한 최소한으로 부여하고, 변경 및 회수 이력을 관리해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "2.4.1",
        "category": "AccessControl"
    },
    {
        "text": "침해사고 발생 시 신속한 대응을 통해 확산을 방지하고 피해를 최소화해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "3.1.2",
        "category": "IncidentResponse"
    },
    {
        "text": "시스템 접근 및 보안 이벤트에 대한 로그를 생성하고 일정 기간 안전하게 보관해야 한다.",
        "doc_type": "ISMS-P",
        "clause_id": "4.2.3",
        "category": "Logging"
    }
]

# 검색 테스트용 질의 문장들
TEST_QUERIES = [
    "Access Key 유출 시 대응",
    "관리자 권한 오남용 사고",
    "로그 보관 및 증적"
]


# ============================================================================
# ChromaDB 초기화 및 데이터 저장
# ============================================================================

def setup_chromadb(documents: List[Dict[str, Any]]) -> chromadb.Collection:
    """
    ChromaDB를 초기화하고 문서를 저장합니다.
    파일 형태로 저장하여 Git으로 공유할 수 있습니다.
    
    Args:
        documents: 저장할 문서 리스트 (text, doc_type, clause_id, category 포함)
        
    Returns:
        ChromaDB Collection 객체
    """
    # ChromaDB 클라이언트 초기화 (파일 저장 모드)
    # PersistentClient를 사용하면 자동으로 파일로 저장됩니다
    # 이 디렉토리는 Git에 포함되어 팀원과 공유할 수 있습니다
    chroma_client = chromadb.PersistentClient(
        path="./chroma_store"
    )
    
    # 기존 collection이 있는지 확인
    try:
        collection = chroma_client.get_collection("isms_p_test")
        print("📦 기존 ChromaDB 데이터를 불러왔습니다.")
        print(f"   저장 위치: ./chroma_store\n")
        return collection
    except:
        # collection이 없으면 새로 생성
        pass
    
    # 새로운 collection 생성
    # collection 이름: "isms_p_test"
    collection = chroma_client.create_collection(
        name="isms_p_test",
        metadata={"description": "ISMS-P 규제 조항 테스트 컬렉션"}
    )
    
    print("📚 문서 임베딩 생성 중...")
    
    # 문서 텍스트 추출
    texts = [doc["text"] for doc in documents]
    
    # 임베딩 생성
    embeddings = get_embeddings(texts)
    
    print(f"✅ {len(embeddings)}개 문서의 임베딩 생성 완료")
    
    # ChromaDB에 문서 저장
    # 각 문서에 대해 ID, 임베딩, 메타데이터를 저장
    collection.add(
        embeddings=embeddings,
        documents=texts,
        metadatas=[
            {
                "doc_type": doc["doc_type"],
                "clause_id": doc["clause_id"],
                "category": doc["category"]
            }
            for doc in documents
        ],
        ids=[f"doc_{i}" for i in range(len(documents))]
    )
    
    # PersistentClient는 자동으로 파일로 저장되므로 별도의 persist() 호출 불필요
    
    print(f"✅ ChromaDB에 {len(documents)}개 문서 저장 완료")
    print(f"   저장 위치: ./chroma_store")
    print(f"   이 디렉토리를 Git에 커밋하면 팀원과 공유할 수 있습니다.\n")
    
    return collection


# ============================================================================
# 검색 함수
# ============================================================================

def search_similar_documents(
    collection: chromadb.Collection,
    query: str,
    top_k: int = 3
) -> List[Dict[str, Any]]:
    """
    질의 문장에 대해 유사한 문서를 검색합니다.
    
    Args:
        collection: ChromaDB Collection 객체
        query: 검색할 질의 문장
        top_k: 반환할 상위 결과 개수
        
    Returns:
        검색 결과 리스트 (순위, clause_id, category, distance 포함)
    """
    # 질의 문장을 임베딩
    query_embedding = get_embeddings([query])[0]
    
    # ChromaDB에서 유사도 검색 수행
    # query_embeddings: 검색할 임베딩 벡터
    # n_results: 반환할 결과 개수
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k
    )
    
    # 검색 결과를 구조화된 형태로 변환
    search_results = []
    
    # results는 딕셔너리 형태로 반환됩니다
    # 각 키에 대해 리스트의 첫 번째 요소를 가져옵니다 (단일 쿼리이므로)
    if results["ids"] and len(results["ids"][0]) > 0:
        for i in range(len(results["ids"][0])):
            result = {
                "rank": i + 1,  # 순위 (1부터 시작)
                "clause_id": results["metadatas"][0][i]["clause_id"],
                "category": results["metadatas"][0][i]["category"],
                "distance": results["distances"][0][i],  # 거리 값 (작을수록 유사)
                "document": results["documents"][0][i]  # 원본 문서 텍스트 (참고용)
            }
            search_results.append(result)
    
    return search_results


# ============================================================================
# 결과 출력 함수
# ============================================================================

def print_search_results(query: str, results: List[Dict[str, Any]]):
    """
    검색 결과를 보기 좋게 출력합니다.
    
    Args:
        query: 검색한 질의 문장
        results: 검색 결과 리스트
    """
    print("=" * 70)
    print(f"🔍 질의: {query}")
    print("=" * 70)
    
    if not results:
        print("검색 결과가 없습니다.")
        return
    
    # 각 검색 결과 출력
    for result in results:
        print(f"\n순위: {result['rank']}")
        print(f"  조항 ID: {result['clause_id']}")
        print(f"  카테고리: {result['category']}")
        print(f"  거리 (Distance): {result['distance']:.6f}")
        print(f"  문서 내용: {result['document']}")
    
    print("\n")


# ============================================================================
# 메인 실행 함수
# ============================================================================

def main():
    """
    메인 실행 함수
    RAG 시스템의 전체 워크플로우를 실행합니다.
    """
    print("=" * 70)
    print("ISMS-P 규제 문서 RAG 시스템 테스트")
    print("=" * 70)
    print()
    
    # 1. ChromaDB 초기화 및 문서 저장
    print("📦 ChromaDB 초기화 및 문서 저장 중...")
    collection = setup_chromadb(REGULATION_DOCUMENTS)
    
    # 2. 각 질의에 대해 검색 수행
    print("🔍 검색 테스트 시작\n")
    
    for query in TEST_QUERIES:
        # 검색 수행
        results = search_similar_documents(collection, query, top_k=3)
        
        # 결과 출력
        print_search_results(query, results)
    
    print("=" * 70)
    print("✅ 모든 테스트 완료")
    print("=" * 70)


# ============================================================================
# 스크립트 실행
# ============================================================================

if __name__ == "__main__":
    main()

