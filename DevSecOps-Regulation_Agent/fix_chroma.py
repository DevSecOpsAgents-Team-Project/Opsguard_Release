"""
로컬/CI에서 chroma_db 메타데이터를 한 번 보정할 때 사용.
런타임에서는 src.regulation_agent.service._get_collection 이 자동으로 동일 보정을 수행한다.
"""
import os
import sys
from pathlib import Path

try:
    __import__("pysqlite3")
    sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")
except ImportError:
    pass

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from regulation_agent.chroma_repair import repair_chroma_sqlite  # noqa: E402

chroma_dir = os.environ.get("CHROMA_PERSIST_DIR", str(ROOT / "chroma_db"))
if repair_chroma_sqlite(chroma_dir):
    print("✅ chroma_db fix 완료:", chroma_dir)
else:
    print("⚠️ chroma.sqlite3 없음:", chroma_dir)
