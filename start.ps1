$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    python -m venv --system-site-packages .venv
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
    & $pythonPath -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
if (-not (Test-Path -LiteralPath 'artifacts\detector.joblib')) {
    & $pythonPath train.py --demo
    if ($LASTEXITCODE -ne 0) { throw 'Training failed.' }
}
Write-Host 'Open http://127.0.0.1:5000 in your browser. Press Ctrl+C to stop.'
& $pythonPath app.py
