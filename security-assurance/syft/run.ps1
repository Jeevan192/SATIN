$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$OutputDir = Join-Path $ProjectRoot "data\sbom"
$OutputFile = Join-Path $OutputDir "sat_sa_sbom.json"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

Push-Location $ProjectRoot
try {
    & docker compose --progress quiet --project-directory $ProjectRoot --profile assurance build syft
    if ($LASTEXITCODE -ne 0) { throw "Syft image build failed with exit code $LASTEXITCODE" }

    $SbomOutput = & docker compose --progress quiet --project-directory $ProjectRoot --profile assurance run --rm --no-deps syft
    if ($LASTEXITCODE -ne 0) { throw "Syft failed with exit code $LASTEXITCODE" }
    [System.IO.File]::WriteAllText(
        $OutputFile,
        ($SbomOutput -join [Environment]::NewLine),
        [System.Text.UTF8Encoding]::new($false)
    )
}
catch {
    if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
    Write-Error $_
    exit 1
}
finally {
    Pop-Location
}

if (-not (Test-Path $OutputFile) -or (Get-Item $OutputFile).Length -eq 0) {
    Write-Error "Syft did not create a non-empty SBOM at $OutputFile"
    exit 1
}

try {
    $Sbom = Get-Content -Raw $OutputFile | ConvertFrom-Json
    if ($Sbom.bomFormat -ne "CycloneDX") { throw "Unexpected SBOM format: $($Sbom.bomFormat)" }
    if ($Sbom.components.Count -eq 0) { throw "SBOM contains no components" }
}
catch {
    Remove-Item $OutputFile -Force
    Write-Error "Syft output is not valid CycloneDX JSON: $_"
    exit 1
}

Write-Host "SBOM generated: $OutputFile"