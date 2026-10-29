# Baut den Windows-Installer lokal (PowerShell, im Repo-Ordner):
#   powershell -ExecutionPolicy Bypass -File packaging\build_installer.ps1
# Voraussetzungen: .NET SDK 8 (https://dot.net), Inno Setup 6 (https://jrsoftware.org/isdl.php)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$version = (Select-String -Path pyproject.toml -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
Write-Host "==> Magic Box $version"

Write-Host "==> Native App bauen (WinForms, .NET Framework 4.8)"
dotnet build desktop\MagicBox\MagicBox.csproj -c Release "-p:Version=$version"
if ($LASTEXITCODE -ne 0) { throw "Build fehlgeschlagen" }

New-Item -ItemType Directory -Force dist | Out-Null
Write-Host "==> Selbsttest"
$st = Start-Process -FilePath "desktop\MagicBox\bin\Release\net48\MagicBox.exe" -ArgumentList "--selftest", "dist\selftest.json" -Wait -PassThru
Get-Content dist\selftest.json
if ($st.ExitCode -ne 0) { throw "Selbsttest fehlgeschlagen" }

Write-Host "==> Installer (Inno Setup)"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
          "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 nicht gefunden – https://jrsoftware.org/isdl.php" }
& $iscc "/DAppVersion=$version" packaging\installer.iss
Write-Host "Fertig: dist\MagicBox-Setup-$version.exe"
