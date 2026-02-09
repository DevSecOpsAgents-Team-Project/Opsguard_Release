import os
import chromadb

CHROMA_PERSIST_DIR = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_store")
print("CHROMA_PERSIST_DIR =", os.path.abspath(CHROMA_PERSIST_DIR))

client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

cols = client.list_collections()
print("collections =", [c.name for c in cols])

for c in cols:
    col = client.get_collection(c.name)
    print(f"- {c.name}: count={col.count()}")
    if col.count() > 0:
        sample = col.get(limit=1, include=["documents", "metadatas", "ids"])
        print("  sample_id =", sample["ids"][0])
        print("  sample_meta =", sample["metadatas"][0])
        print("  sample_doc_head =", (sample["documents"][0] or "")[:120].replace("\n"," "))
