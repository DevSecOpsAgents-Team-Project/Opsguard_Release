# Finance Agent (A파트 + B파트 통합)

- **A파트(입출력 설계)**: 스키마 검증, 계약, 정책 로더, 엔진(dict in/out).
- **B파트(로직)**: 비용/리스크/스코어/추천, 시뮬레이터(FinanceRequest → FinanceResult).

둘 다 한 진입점에서 실행·테스트할 수 있습니다.

**합친 구조와 로직 설명**: [docs/합친_구조_및_로직.md](docs/합친_구조_및_로직.md)

## 코드 변경 확인 (Git)

- **최근 커밋 목록**: `git log --oneline -10`
- **현재 브랜치에서 수정된 파일**: `git status`
- **특정 커밋에서 바뀐 내용**: `git show <커밋해시>`
- **두 브랜치 차이**: `git diff main..finance-b` (예: main과 finance-b 비교)
- **Cursor/VS Code**: 왼쪽 **Source Control** (Ctrl+Shift+G) → 변경 파일 클릭 시 diff 확인

## 요구사항

- Python 3.10+
- 외부 API 호출 없음 (가격은 로컬 `policy/` JSON에서만 사용)

## 설치

```bash
pip install -r requirements.txt
```

## 전체 실행 (엔진 + 시뮬레이터 한 번에)

```bash
python run_all.py
```

- 엔진: 샘플 JSON → `finance_run` → schema 결과
- 시뮬레이터: `FinanceRequest` → `simulate` → 재현성·profile 변경 검증

## 전체 통합 테스트

프로젝트 루트 **DevSecOps-Finance_Agent**에서 아래 중 하나로 실행합니다.

**PowerShell:**
```powershell
cd DevSecOps-Finance_Agent
.\run_tests.ps1
```

**또는 직접 pytest:**
```bash
cd DevSecOps-Finance_Agent
python -m pytest tests/ -v
```

포함되는 테스트: 스키마 검증, 계약 거부, 정책 버전, 재현성(엔진/시뮬레이터), bridge(A↔B 연결), 시나리오 회귀(격리 금지/허용), audit 필드, constraints 정책.

### 테스트 로그 (동작 확인용)

테스트 실행 시 콘솔에 다음 로그가 출력됩니다.

- **세션**: `테스트 세션 시작`, `테스트 세션 종료: 모두 통과`
- **각 테스트**: `테스트 실행: tests/test_xxx.py::test_yyy`
- **엔진**: `엔진 실행 시작 incident_id=...`, `엔진 실행 완료 ... total=...` (실패 시 `스키마 검증 실패`, `계약 위반` 등)
- **시뮬레이터**: `시뮬레이터 실행 profile=... severity=...`, `시뮬레이터 완료 total_cost=... recommended_action=...`

상세 로그는 `logs/pytest.log`에도 기록됩니다 (`pytest.ini`의 `log_file` 설정).

## 샘플 실행 (엔진만)

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
DevSecOps-Finance_Agent/
  run_all.py     # 단일 진입점: 엔진 + 시뮬레이터 한 번에 실행
  run_tests.ps1  # 테스트 한 번에 실행 (PowerShell)
  pytest.ini     # pytest 설정
  src/
    run.py       # run_engine_sample(), run_simulator_demo(), run_all()
    engine.py    # schema 경로: finance_run(dict) -> dict
    simulator.py # dataclass 경로: simulate(FinanceRequest) -> FinanceResult
    models.py    # FinanceRequest, FinanceResult
    validate.py, schema_io.py, contract.py, policy_loader.py, pricing.py  # A파트
    cost_model.py, risk_model.py, policy.py, actions.py, scoring_engine.py, xai_generator.py  # B파트
  schemas/       # finance_request, finance_result JSON Schema
  policy/        # policy.v1.0.json 등 정책 파일
  samples/       # 샘플 요청
  tests/         # pytest (스키마/계약/정책/재현성/시뮬레이터)
```

## 확장 (B파트 XAI)

- `engine.post_process_hook(result, request, context)` 가 no-op 확장 포인트로 존재합니다.
- B파트에서 이 hook을 오버라이드하거나, result에 `xai` 필드를 주입해도 `finance_result.schema.json`이 optional로 허용합니다.
