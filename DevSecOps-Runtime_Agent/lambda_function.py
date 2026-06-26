"""AWS Lambda entrypoint — 배포 핸들러 lambda_function.lambda_handler."""

from src.engine_handler import lambda_handler

__all__ = ["lambda_handler"]
