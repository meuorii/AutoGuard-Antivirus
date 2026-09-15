$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "AutoGuard.exe must be built on Windows." }
$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Virtual environment not found. Create .venv first." }
& $python -m pip install -r requirements-dev.txt
& $python -m pytest -q
& $python -m PyInstaller --clean --noconfirm AutoGuard.spec
Write-Host "Build complete: dist\AutoGuard.exe"