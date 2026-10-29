# Baut den Windows-Installer lokal (PowerShell, im Repo-Ordner):
#   powershell -ExecutionPolicy Bypass -File packaging\build_installer.ps1
# Voraussetzungen: Python 3.11+ (python.org), Inno Setup 6 (https://jrsoftware.org/isdl.php)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$version = python -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"
Write-Host "==> Magic Box $version"

if (-not (Test-Path .venv-build)) { python -m venv .venv-build }
$py = ".venv-build\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install ".[desktop,malware]" pyinstaller

Write-Host "==> App bündeln (PyInstaller)"
& $py -m PyInstaller --noconfirm --clean packaging\magicbox.spec

Write-Host "==> Selbsttest des Bundles"
$st = Start-Process -FilePath "dist\MagicBox\MagicBox.exe" -ArgumentList "--selftest", "dist\selftest.json" -Wait -PassThru
Get-Content dist\selftest.json
if ($st.ExitCode -ne 0) { throw "Selbsttest fehlgeschlagen" }

Write-Host "==> Installer (Inno Setup)"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
          "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 nicht gefunden – https://jrsoftware.org/isdl.php" }
& $iscc "/DAppVersion=$version" packaging\installer.iss
Write-Host "Fertig: dist\MagicBox-Setup-$version.exe"
