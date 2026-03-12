# install.ps1 — Download and install p2pvpn on Windows.
#
# Usage (run as Administrator in PowerShell):
#   irm https://raw.githubusercontent.com/Auchrio/p2pvpn/main/install.ps1 | iex
#
# What it does:
#   1. Detects the CPU architecture (x64, arm64).
#   2. Downloads the latest release zip from GitHub.
#   3. Extracts p2pvpn.exe and wintun.dll to C:\Program Files\p2pvpn\.
#   4. Runs "p2pvpn setup" which creates a Windows service and starts the
#      daemon in setup mode.
#   5. You then open http://<machine-ip>:8080 to configure your network.

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$Repo       = "Auchrio/p2pvpn"
$InstallDir = "$env:ProgramFiles\p2pvpn"

# ── detect architecture ───────────────────────────────────────────────────────

function Get-Label {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "windows-x64"   }
        "Arm64" { return "windows-arm64" }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

$Label      = Get-Label
$ZipName    = "p2pvpn-$Label.zip"
$DownloadURL = "https://github.com/$Repo/releases/latest/download/$ZipName"

Write-Host "[*] Architecture : $Label" -ForegroundColor Cyan
Write-Host "[*] Download URL : $DownloadURL" -ForegroundColor Cyan

# ── download ──────────────────────────────────────────────────────────────────

$TmpZip = Join-Path $env:TEMP $ZipName

Write-Host "[*] Downloading $ZipName..." -ForegroundColor Cyan
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DownloadURL -OutFile $TmpZip -UseBasicParsing
} catch {
    Write-Error "Download failed. Check that a release exists at:`n  $DownloadURL"
    exit 1
}
Write-Host "[+] Downloaded successfully." -ForegroundColor Green

# ── extract ───────────────────────────────────────────────────────────────────

Write-Host "[*] Extracting to $InstallDir..." -ForegroundColor Cyan
if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

# Stop service if running so we can overwrite the binary.
sc.exe stop p2pvpn 2>$null | Out-Null
Start-Sleep -Seconds 1

Expand-Archive -Path $TmpZip -DestinationPath $InstallDir -Force
Remove-Item $TmpZip -Force

# Rename the extracted binary to p2pvpn.exe if needed.
$extracted = Get-ChildItem "$InstallDir\p2pvpn-*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($extracted) {
    Move-Item -Path $extracted.FullName -Destination "$InstallDir\p2pvpn.exe" -Force
}

Write-Host "[+] Extracted." -ForegroundColor Green

# ── add to PATH ───────────────────────────────────────────────────────────────

$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    Write-Host "[*] Adding $InstallDir to system PATH..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[+] PATH updated." -ForegroundColor Green
}

# ── setup (Windows service) ──────────────────────────────────────────────────

Write-Host "[*] Running 'p2pvpn setup' to register the Windows service..." -ForegroundColor Cyan
& "$InstallDir\p2pvpn.exe" setup

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Open  http://<this-machine-ip>:8080  in a browser to configure your network."
Write-Host ""
Write-Host "   Useful commands:"
Write-Host "     sc query p2pvpn            - check service status"
Write-Host "     p2pvpn setup --remove      - uninstall"
Write-Host ""
