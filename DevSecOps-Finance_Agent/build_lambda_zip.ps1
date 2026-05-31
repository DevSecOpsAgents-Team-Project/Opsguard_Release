# Finance Agent Lambda 배포 zip 생성 (Windows)
# Usage: .\build_lambda_zip.ps1
# Optional: .\build_lambda_zip.ps1 -PythonVersion 3.12 -Output finance-agent.zip

param(
    [string]$PythonVersion = "3.11",
    [string]$Platform = "manylinux2014_x86_64",
    [string]$Output = "finance-agent.zip"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$PackageDir = Join-Path $Root "package"

Write-Host "==> Finance Agent Lambda package build"
Write-Host "    Python target: $PythonVersion ($Platform)"

if (Test-Path $PackageDir) {
    Remove-Item -Recurse -Force $PackageDir
}
New-Item -ItemType Directory -Path $PackageDir | Out-Null

Write-Host "==> Installing dependencies for Linux Lambda..."
pip install -r (Join-Path $Root "requirements.txt") -t $PackageDir `
    --platform $Platform `
    --implementation cp `
    --python-version $PythonVersion `
    --only-binary=:all: `
    --upgrade

Write-Host "==> Copying application files..."
Copy-Item (Join-Path $Root "handler.py") -Destination $PackageDir
Copy-Item (Join-Path $Root "src") -Destination $PackageDir -Recurse
Copy-Item (Join-Path $Root "policy") -Destination $PackageDir -Recurse
if (Test-Path (Join-Path $Root "schemas")) {
    Copy-Item (Join-Path $Root "schemas") -Destination $PackageDir -Recurse
}

$RequiredDirs = @("jsonschema", "rpds", "handler.py", "src", "policy")
$Missing = @()
foreach ($item in $RequiredDirs) {
    if (-not (Test-Path (Join-Path $PackageDir $item))) {
        $Missing += $item
    }
}
if ($Missing.Count -gt 0) {
    Write-Warning "Missing in package: $($Missing -join ', ')"
    Write-Warning "pip install may have failed. Try Docker build or check Python version."
}

# Compress-Archive는 zip 안 경로를 '\'로 넣어 Lambda(Linux)에서 폴더가 깨짐 → Python zipfile 사용
Write-Host "==> Creating Lambda-compatible zip (forward-slash paths)..."
$ZipPath = Join-Path $Root $Output
python (Join-Path $Root "scripts/zip_for_lambda.py") $PackageDir $ZipPath

Write-Host ""
Write-Host "Done: $ZipPath"
Write-Host "Lambda settings:"
Write-Host "  Handler  = handler.lambda_handler"
Write-Host "  Runtime  = Python $PythonVersion"
Write-Host "  Arch     = x86_64"
Write-Host ""
Write-Host "Zip root should contain: handler.py, src/, policy/, jsonschema/, rpds/, openai/, ..."
