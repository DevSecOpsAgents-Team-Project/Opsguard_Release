"""Finance Agent 전체 실행: 엔진(schema) + 시뮬레이터(dataclass) 한 번에."""
import sys
from pathlib import Path

# 프로젝트 루트를 path에 넣어서 src 패키지 로드
_root = Path(__file__).resolve().parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from src.run import run_all

if __name__ == "__main__":
    run_all()
