$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$py = $null
$pyArgs = @()

if (Get-Command py -ErrorAction SilentlyContinue) {
  $py = "py"
  $pyArgs = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $py = "python"
  $pyArgs = @()
} else {
  $candidatePaths = @(
    "$env:LocalAppData\Programs\Python\Launcher\py.exe",
    "$env:LocalAppData\Programs\Python\Python312\python.exe",
    "$env:LocalAppData\Programs\Python\Python311\python.exe"
  )

  foreach ($candidate in $candidatePaths) {
    if (Test-Path $candidate) {
      $py = $candidate
      if ($candidate -like "*\\py.exe") {
        $pyArgs = @("-3")
      } else {
        $pyArgs = @()
      }
      break
    }
  }
}

if (-not $py) {
  throw "Python launcher not found (py/python)."
}

& $py @pyArgs -m pip install --upgrade pip
& $py @pyArgs -m pip install -r "requirements-build.txt"

& $py @pyArgs -m PyInstaller `
  --noconfirm `
  --onefile `
  --windowed `
  --name "env-inspector" `
  "env_inspector.py"

Write-Host "Built dist/env-inspector.exe"
