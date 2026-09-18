param(
    [switch]$SkipTests,
    [switch]$ExeOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "AutoGuard Windows releases must be built on Windows."
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        $pyExe = $py.Source
        & $pyExe -3 -m venv .venv
    } else {
        $systemPython = Get-Command python -ErrorAction Stop
        $pythonExe = $systemPython.Source
        & $pythonExe -m venv .venv
    }
}

Write-Host "[1/5] Installing build dependencies..." -ForegroundColor Cyan
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements-dev.txt

if (-not $SkipTests) {
    Write-Host "[2/5] Running AutoGuard tests..." -ForegroundColor Cyan
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Tests failed. Release build stopped." }
} else {
    Write-Host "[2/5] Tests skipped by request." -ForegroundColor Yellow
}

Write-Host "[3/5] Building AutoGuard.exe..." -ForegroundColor Cyan
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
& $python -m PyInstaller --clean --noconfirm AutoGuard.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

$exe = Join-Path $root "dist\AutoGuard.exe"
if (-not (Test-Path $exe)) { throw "Expected executable was not created: $exe" }
Write-Host "Built: $exe" -ForegroundColor Green

if ($ExeOnly) {
    Write-Host "[4/5] Installer skipped (-ExeOnly)." -ForegroundColor Yellow
    Write-Host "[5/5] Release complete." -ForegroundColor Green
    exit 0
}

Write-Host "[4/5] Looking for Inno Setup 6..." -ForegroundColor Cyan
$iscc = $null
$command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($null -ne $command) { $iscc = $command.Source }

$candidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
foreach ($candidate in $candidates) {
    if (-not $iscc -and $candidate -and (Test-Path $candidate)) { $iscc = $candidate }
}

if (-not $iscc) {
    Write-Host "Inno Setup 6 was not found. AutoGuard.exe is ready." -ForegroundColor Yellow
    Write-Host "Install Inno Setup 6, then rerun this script to create AutoGuard-Setup-1.0.0.exe." -ForegroundColor Yellow
    Write-Host "[5/5] EXE release complete; installer not built." -ForegroundColor Green
    exit 0
}

Write-Host "Building installer with: $iscc" -ForegroundColor Cyan
& $iscc (Join-Path $root "installer\AutoGuard.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compiler failed." }

$installer = Join-Path $root "dist\installer\AutoGuard-Setup-1.0.0.exe"
if (-not (Test-Path $installer)) { throw "Expected installer was not created: $installer" }
Write-Host "[5/5] Release complete." -ForegroundColor Green
Write-Host "Application: $exe" -ForegroundColor Green
Write-Host "Installer:   $installer" -ForegroundColor Green