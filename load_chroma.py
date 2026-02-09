import json
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from dotenv import load_dotenv
load_dotenv()


# 1. JSON 로드
with open('data.json', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

# 2. ChromaDB 클라이언트 (방법 A 통일)
client = chromadb.PersistentClient(
    path="./chroma_db"
)

# 3. embedding 명시 (팀원 전원 동일)
embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
    model_name="text-embedding-3-large"
)

collection = client.get_or_create_collection(
    name="csa_ccm_v4",
    embedding_function=embedding_fn
)

ids, documents, metadatas = [], [], []

for item in json_data:
    ids.append(item['id'])
    documents.append(item['document'])

    meta = item['metadata'].copy()
    for k, v in meta.items():
        if isinstance(v, list):
            meta[k] = "|".join(v)   # 콤마보다 파이프가 안전
        elif v is None:
            meta[k] = ""
    metadatas.append(meta)

# 4. upsert
collection.upsert(
    ids=ids,
    documents=documents,
    metadatas=metadatas
)


print("✅ Chroma DB 적재 완료")
