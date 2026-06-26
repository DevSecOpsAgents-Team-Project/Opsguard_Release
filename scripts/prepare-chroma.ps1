# Regulation Agent needs chroma_db/ before sam build (not in Git - use GitHub Release).
#
# Download + verify:
#   .\scripts\prepare-chroma.ps1 -Download
#
# Verify only (already extracted):
#   .\scripts\prepare-chroma.ps1

param(
    [switch]$Download
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$ChromaDir = Join-Path $Root "DevSecOps-Regulation_Agent\chroma_db"
$ChromaSqlite = Join-Path $ChromaDir "chroma.sqlite3"
$ReleaseZipUrl = "https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo/releases/download/chroma-db-v1/chroma_db.zip"
$ReleasePage = "https://github.com/DevSecOpsAgents-Team-Project/DevSecOps-Project-Repo/releases/tag/chroma-db-v1"

if ($Download) {
    $ZipPath = Join-Path $Root "chroma_db.zip"
    Write-Host "Downloading from Release: $ReleasePage"
    Invoke-WebRequest -Uri $ReleaseZipUrl -OutFile $ZipPath
    New-Item -ItemType Directory -Force -Path (Join-Path $Root "DevSecOps-Regulation_Agent") | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath (Join-Path $Root "DevSecOps-Regulation_Agent") -Force
    Write-Host "Extracted to DevSecOps-Regulation_Agent\chroma_db\"
}

if (Test-Path $ChromaSqlite) {
    $size = (Get-Item $ChromaSqlite).Length
    Write-Host "OK: $ChromaSqlite exists ($size bytes)"
} else {
    Write-Host "MISSING: $ChromaSqlite"
    Write-Host "Download: $ReleasePage"
    Write-Host "Or run: .\scripts\prepare-chroma.ps1 -Download"
    exit 1
}
