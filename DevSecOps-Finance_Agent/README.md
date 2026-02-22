# Finance Agent (A파트)

통제/스키마/재현성/정책버전/브레이크다운/해시를 담당하는 Finance Agent A파트입니다.  
XAI는 옵셔널 확장 필드로 설계되어 있으며, B파트 merge 시 스키마·엔진 충돌을 최소화합니다.

## 요구사항

- Python 3.10+
- 외부 API 호출 없음 (가격은 로컬 `policy/` JSON에서만 사용)

## 설치

```bash
pip install -r requirements.txt
```

## 테스트

프로젝트 루트에서:

```bash
pytest tests/ -v
```

## 샘플 실행

```bash
python -c "
import json
from src.engine import finance_run
with open('samples/finance_request.sample.json') as f:
    req = json.load(f)
result = finance_run(req)
print(json.dumps(result, indent=2, ensure_ascii=False))
"
```

## 디렉터리 구조

```
finance-agent/
  src/           # 엔진, 스키마 검증, 계약, 정책 로더, 가격 계산
  schemas/       # finance_request, finance_result JSON Schema
  policy/        # policy.v1.0.json 등 정책 파일
  samples/       # 샘플 요청
  tests/         # pytest
```

## 확장 (B파트 XAI)

- `engine.post_process_hook(result, request, context)` 가 no-op 확장 포인트로 존재합니다.
- B파트에서 이 hook을 오버라이드하거나, result에 `xai` 필드를 주입해도 `finance_result.schema.json`이 optional로 허용합니다.
