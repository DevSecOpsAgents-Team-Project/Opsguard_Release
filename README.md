# OpsGuard

GuardDuty 보안 알림이 오면 **MCP**가 **Runtime / Finance / Regulation** Agent를 순서대로 호출하는 시스템입니다.

```
GuardDuty 알림 → MCP → Runtime / Finance / Regulation Agent
Slack 승인     → MCP-Slack-Response → Runtime / Finance
```

---

## opsguard 설치하기 (새 AWS 계정 · greenfield)

Repo를 clone한 뒤, 아래 순서대로 진행하세요.

| 단계 | 하는 일                            |
| ---- | ---------------------------------- |
| 1    | 레포 clone + PC 도구 설치          |
| 2    | AWS 로그인                         |
| 3    | Secrets 등록 (OpenAI, Slack)       |
| 4    | **chroma_db** Release에서 다운로드 |
| 5    | `samconfig.toml` 설정              |
| 6    | `sam build` → `sam deploy`         |
| 7    | Slack App URL 연결                 |

---

## 1. 레포 받기 & PC 설치

```powershell
git clone https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo.git
cd DevSecOps-Project-Repo
```

설치 목록:

- [AWS CLI](https://aws.amazon.com/cli/)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- [Docker Desktop](https://www.docker.com/) — **실행 상태 유지** (Regulation Agent Docker 빌드용)

---

## 2. AWS 로그인

```powershell
aws configure
aws sts get-caller-identity
```

Region 예: `ap-northeast-2`

필요 사용자 권한: CloudFormation, IAM, Lambda, S3, API Gateway, EventBridge, ECR, DynamoDB, WAFv2, Secrets Manager(read).

추천 : `AdministratorAccess` 권한 부여 후 설치하고, 이후 권한 삭제

---

## 3. Secrets Manager (계정당 1회)

`scripts/setup-secrets.ps1`에서 **PASTE*YOUR*...** 를 실제 값으로 바꾼 뒤:

```powershell
cd scripts
.\setup-secrets.ps1
cd ..
```

시크릿은 **반드시 JSON 형식**으로 입력하세요:

```json
{"OPENAI_API_KEY":"sk-..."}
{"SLACK_BOT_TOKEN":"xoxb-...","SLACK_WEBHOOK_URL":"https://hooks.slack.com/services/..."}
```

---

## 4. chroma_db 다운로드 (Regulation Agent RAG)

`chroma.sqlite3`는 Git에 포함되지 않습니다. **GitHub Release**에서 받으세요.

- Release 페이지: [chroma-db-v1](https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo/releases/tag/chroma-db-v1)
- 직접 다운로드: [chroma_db.zip](https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo/releases/download/chroma-db-v1/chroma_db.zip)

프로젝트 **루트**에서:

```powershell
# 방법 A: 스크립트로 다운로드 + 확인
.\scripts\prepare-chroma.ps1 -Download

# 방법 B: 수동
Invoke-WebRequest `
  -Uri "https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo/releases/download/chroma-db-v1/chroma_db.zip" `
  -OutFile chroma_db.zip
Expand-Archive chroma_db.zip -DestinationPath DevSecOps-Regulation_Agent\ -Force
.\scripts\prepare-chroma.ps1
```

`OK: DevSecOps-Regulation_Agent\chroma_db\chroma.sqlite3 exists` 가 나오면 다음 단계로.

> Release의 **Source code (zip/tar.gz)** 는 GitHub이 자동 생성한 레포 소스입니다. `chroma_db.zip`만 받으면 됩니다.

---

## 5. samconfig.toml 설정

```powershell
Copy-Item samconfig.toml.example samconfig.toml
```

`samconfig.toml`에서 `SlackChannel=C0123456789` 를 **본인 Slack 채널 ID**로 수정하세요.

---

## 6. 빌드 & 배포

프로젝트 **루트**에서:

```powershell
$env:PYTHONUTF8=1
sam validate --lint
sam build
sam deploy --guided
```

WafIpSetId
VpcFlowLogRoleArn
RegulationImageUri
S3LogBucketName 등등에 대해서는 default값을 사용하면 됩니다.
(엔터로 넘기기)

`sam deploy --guided` 질문 예시:

| 질문                     | 답                                                           |
| ------------------------ | ------------------------------------------------------------ |
| Stack Name               | `opsguard`                                                   |
| Region                   | `ap-northeast-2`                                             |
| **DeployMode**           | **`greenfield`**                                             |
| SlackChannel             | 실제 채널 ID                                                 |
| Allow IAM role creation  | `Y`                                                          |
| **Capabilities**         | `CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM` |
| Save to samconfig        | `Y`                                                          |
| Slack API 인증 없음 경고 | `Y` (배포 후 Slack URL 등록)                                 |

성공:

```
Successfully created/updated stack - opsguard
```

### 이후 코드 수정 시

```powershell
$env:PYTHONUTF8=1
sam build
sam deploy
```

---

## 7. 배포 확인 & Slack 연결

```powershell
aws cloudformation describe-stacks --stack-name opsguard --region ap-northeast-2 --query "Stacks[0].Outputs" --output table
```

| Output              | 용도                                      |
| ------------------- | ----------------------------------------- |
| `SlackEventsApiUrl` | Slack App Event Subscriptions Request URL |
| `MCPFunctionArn`    | MCP Lambda ARN                            |

Lambda 콘솔: `MCP`, `MCP-Slack-Response`, `Runtime_Agent`, `Finance_Agent`, `Regulation_Agent`

Slack App ([api.slack.com/apps](https://api.slack.com/apps)):

1. Slack App 선택 → **Event Subscriptions** → **Enable Events** 켜기
2. **Request URL** = `SlackEventsApiUrl` 입력 후 저장
3. 같은 Slack App에서 **Interactivity & Shortcuts** → **Interactivity** 켜기
4. **Request URL** = `SlackEventsApiUrl` 를 **동일하게 다시 입력** 후 저장

`Finance 계산 요청`, 승인/거절 버튼 등 Slack 버튼 액션은 **Interactivity**가 켜져 있어야 동작합니다.
Event Subscriptions만 설정하고 Interactivity를 비워두면, 메시지는 와도 버튼 클릭 시 후속 Lambda(`MCP-Slack-Response`)가 정상 호출되지 않을 수 있습니다.

Request URL 저장 시 Slack이 `challenge` 검증을 보냅니다. `MCP-Slack-Response` Lambda가 이를 응답해야 URL 등록이 성공합니다.

---

## 레포 구조

| 폴더                          | 하는 일           |
| ----------------------------- | ----------------- |
| `DevSecOps-MCP/`              | MCP, Slack 응답   |
| `DevSecOps-Runtime_Agent/`    | AWS 자동 대응     |
| `DevSecOps-Finance_Agent/`    | 비용 분석         |
| `DevSecOps-Regulation_Agent/` | 규제/RAG (Docker) |

| 파일                         | 하는 일                                |
| ---------------------------- | -------------------------------------- |
| `template.yaml`              | AWS 리소스 정의                        |
| `samconfig.toml.example`     | 배포 설정 예시                         |
| `scripts/setup-secrets.ps1`  | Secrets 등록                           |
| `scripts/prepare-chroma.ps1` | chroma_db 확인 (또는 Release 다운로드) |

---

## 자주 나는 오류

| 증상                                    | 해결                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| `template.yaml not found`               | 프로젝트 **루트**에서 실행 (`cd` 확인)                                       |
| `ROLLBACK_COMPLETE`                     | `aws cloudformation delete-stack --stack-name opsguard` 후 재배포            |
| `Could not parse SecretString JSON`     | Secrets를 `{"KEY":"value"}` 형식으로 저장                                    |
| `cp949` / `UnicodeDecodeError`          | `$env:PYTHONUTF8=1`                                                          |
| Lambda 이름 충돌                        | `ResourceNameSuffix=-dev` 추가                                               |
| IAM AccessDenied                        | 배포 사용자 권한 추가                                                        |
| Regulation Docker 빌드 실패             | Docker 실행 여부 + `prepare-chroma.ps1` 확인                                 |
| Slack Request URL HTTP 오류 / challenge | `sam build` → `sam deploy` 후 URL 재등록. `SlackEventsApiUrl` 오타·리전 확인 |

---

## 문의

GitHub Issues에 등록해 주세요.
