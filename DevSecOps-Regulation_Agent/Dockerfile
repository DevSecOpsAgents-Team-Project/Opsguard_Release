FROM --platform=linux/amd64 public.ecr.aws/lambda/python:3.11

# Chroma 클라이언트 anonymized telemetry (Lambda/오프라인에서 불필요·노이즈 방지)
ENV ANONYMIZED_TELEMETRY=False
# 배포할 때마다 바꾸면 CloudWatch에서 “지금 이미지가 올라왔는지” 바로 구분 가능
ARG OPSGUARD_IMAGE_TAG=regulation-agent-opsguard-v11
ENV OPSGUARD_IMAGE_TAG=${OPSGUARD_IMAGE_TAG}

WORKDIR ${LAMBDA_TASK_ROOT}

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY lambda_function.py .
COPY lambda_handler.py .
COPY lambda_router.py .
COPY isms_document_lambda.py .
COPY main.py .
COPY step4_llm_analysis.py .
COPY test_isms_rag.py .
COPY src ./src
COPY level_router.py .
COPY severity_decision.py .
COPY xai_explainer.py .
COPY chroma_db ./chroma_db


COPY fix_chroma.py .
RUN python fix_chroma.py

CMD ["lambda_function.lambda_handler"]