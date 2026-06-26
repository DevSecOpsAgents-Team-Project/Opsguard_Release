# OpsGuard - create Secrets Manager secrets (run once per AWS account)
# Usage: edit the JSON files below, then run this script in PowerShell.

$Region = "ap-northeast-2"

$OpenAiJson = @"
{"OPENAI_API_KEY":"put your openai api key here"}
"@

$SlackJson = @"
{"SLACK_BOT_TOKEN":"put your slack bot token here","SLACK_WEBHOOK_URL":"put your slack webhook url here"}
"@

$Tmp = Join-Path $env:TEMP "opsguard-secrets"
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null

$OpenAiFile = Join-Path $Tmp "opsguard-openai.json"
$SlackFile = Join-Path $Tmp "opsguard-slack.json"

# utf8NoBOM is PowerShell 6+ only; use .NET for Windows PowerShell 5.1 compatibility
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($OpenAiFile, $OpenAiJson.Trim(), $Utf8NoBom)
[System.IO.File]::WriteAllText($SlackFile, $SlackJson.Trim(), $Utf8NoBom)

Write-Host "Creating opsguard/openai ..."
aws secretsmanager create-secret --name opsguard/openai --secret-string file://$OpenAiFile --region $Region 2>$null
if ($LASTEXITCODE -ne 0) {
    aws secretsmanager put-secret-value --secret-id opsguard/openai --secret-string file://$OpenAiFile --region $Region
}

Write-Host "Creating opsguard/slack ..."
aws secretsmanager create-secret --name opsguard/slack --secret-string file://$SlackFile --region $Region 2>$null
if ($LASTEXITCODE -ne 0) {
    aws secretsmanager put-secret-value --secret-id opsguard/slack --secret-string file://$SlackFile --region $Region
}

Remove-Item $Tmp -Recurse -Force
Write-Host "Done. Verify with: aws secretsmanager get-secret-value --secret-id opsguard/openai --region $Region"
