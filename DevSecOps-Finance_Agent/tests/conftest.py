"""Pytest configuration: path 설정 + 테스트 실행 로그."""
import logging
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

# 테스트용 로거 (콘솔/파일에서 확인 가능)
logger = logging.getLogger("finance_agent.tests")


def pytest_configure(config):
    """테스트 세션 시작 시 로그 디렉터리 생성."""
    log_dir = root / "logs"
    log_dir.mkdir(exist_ok=True)


def pytest_sessionstart(session):
    """테스트 세션 시작 시 로그."""
    logger.info("=== 테스트 세션 시작 (Finance Agent) ===")


def pytest_sessionfinish(session, exitstatus):
    """테스트 세션 종료 시 결과 로그."""
    if exitstatus == 0:
        logger.info("=== 테스트 세션 종료: 모두 통과 ===")
    else:
        logger.warning("=== 테스트 세션 종료: exitstatus=%s ===", exitstatus)


def pytest_runtest_setup(item):
    """각 테스트 시작 시 로그."""
    logger.info("테스트 실행: %s", item.nodeid)
