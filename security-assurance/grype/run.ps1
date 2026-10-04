$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$SbomFile = Join-Path $ProjectRoot "data\sbom\sat_sa_sbom.json"
$ReportDir = Join-Path $ProjectRoot "data\vulnerabilities"
$ReportFile = Join-Path $ReportDir "grype_report.json"

if (-not (Test-Path $SbomFile) -or (Get-Item $SbomFile).Length -eq 0) {
    Write-Error "Generate a non-empty SBOM first: security-assurance\syft\run.ps1"
    exit 1
}
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
if (Test-Path $ReportFile) { Remove-Item $ReportFile -Force }

Push-Location $ProjectRoot
try {
    & docker compose --progress quiet --project-directory $ProjectRoot --profile assurance build grype
    if ($LASTEXITCODE -ne 0) { throw "Grype image build failed with exit code $LASTEXITCODE" }

    & docker compose --progress quiet --project-directory $ProjectRoot --profile assurance run --rm --no-deps grype
    if ($LASTEXITCODE -ne 0) { throw "Grype failed with exit code $LASTEXITCODE" }
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Pop-Location
}

if (-not (Test-Path $ReportFile) -or (Get-Item $ReportFile).Length -eq 0) {
    Write-Error "Grype did not create a non-empty report at $ReportFile"
    exit 1
}

try {
    $Report = Get-Content -Raw $ReportFile | ConvertFrom-Json
    if ($null -eq $Report.matches) { throw "Grype report is missing matches" }
}
catch {
    Remove-Item $ReportFile -Force
    Write-Error "Grype output is not valid JSON: $_"
    exit 1
}

Write-Host "Vulnerability report generated: $ReportFile"