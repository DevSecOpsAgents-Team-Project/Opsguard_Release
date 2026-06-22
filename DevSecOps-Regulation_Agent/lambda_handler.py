"""
루트 모듈 별칭: 핸들러 설정이 lambda_handler.handler 인 배포용.

실제 로직은 lambda_router.lambda_handler (OpsGuard / document_text 분기).
"""

from __future__ import annotations

from lambda_router import lambda_handler as handler

__all__ = ["handler"]
