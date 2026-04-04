# SecureTunnel — Windows installer script
# Right-click → "Run with PowerShell"  (no admin required)
#
# What it does:
#   1. Checks / installs Python 3.12 silently via winget
#   2. Installs Python dependencies into a local venv
#   3. Creates desktop shortcut  "SecureTunnel"
#   4. Optionally adds to Windows startup
#   5. Launches the app

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AppName    = "SecureTunnel"
$InstallDir = "$env:LOCALAPPDATA\$AppName"
$VenvDir    = "$InstallDir\.venv"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir   # one level up from installer\

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "  ► $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "    ✔ $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "    ⚠ $msg" -ForegroundColor Yellow
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor White
Write-Host "  ║       SecureTunnel  Installer        ║" -ForegroundColor White
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

# ── Step 1: Python ────────────────────────────────────────────────────────────
Write-Step "Checking Python..."

$python = $null
foreach ($candidate in @("python3", "python")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) {
                $python = $candidate
                Write-OK "Found $ver"
                break
            }
        }
    } catch {}
}

if (-not $python) {
    Write-Step "Installing Python 3.12 via winget..."
    try {
        winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $python = "python"
        Write-OK "Python 3.12 installed."
    } catch {
        Write-Host ""
        Write-Host "  Could not install Python automatically." -ForegroundColor Red
        Write-Host "  Please download Python 3.12 from https://python.org/downloads/" -ForegroundColor Yellow
        Write-Host "  Then run this script again." -ForegroundColor Yellow
        Read-Host "  Press Enter to exit"
        exit 1
    }
}

# ── Step 2: Copy files ────────────────────────────────────────────────────────
Write-Step "Copying files to $InstallDir..."

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Copy project (exclude chrome profile, __pycache__, etc.)
$exclude = @("chrome_profile", "__pycache__", "*.pyc", ".git", "dist", "build")
Get-ChildItem $ProjectDir -Exclude $exclude | ForEach-Object {
    Copy-Item $_.FullName -Destination $InstallDir -Recurse -Force
}
Write-OK "Files copied."

# ── Step 3: Virtual environment + dependencies ────────────────────────────────
Write-Step "Installing dependencies (this takes ~1 minute)..."

if (-not (Test-Path "$VenvDir\Scripts\python.exe")) {
    & $python -m venv $VenvDir
}

$pip = "$VenvDir\Scripts\pip.exe"
& $pip install -q --upgrade pip
& $pip install -q "cryptography>=43.0.0" "msgpack>=1.0" "keyring>=24.0"

# Check ML-KEM
$mlkem = & "$VenvDir\Scripts\python.exe" -c `
    "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEMParameters; print('ok')" `
    2>$null
if ($mlkem -eq "ok") {
    Write-OK "ML-KEM-768 (post-quantum) available."
} else {
    Write-Warn "ML-KEM not available — X25519-only mode (still secure)."
}

Write-OK "Dependencies installed."

# ── Step 4: Launcher wrapper script ──────────────────────────────────────────
$wrapperPath = "$InstallDir\run.bat"
@"
@echo off
cd /d "$InstallDir"
"$VenvDir\Scripts\python.exe" launcher.py
"@ | Set-Content $wrapperPath -Encoding ASCII

# ── Step 5: Desktop shortcut ──────────────────────────────────────────────────
Write-Step "Creating desktop shortcut..."

$WshShell  = New-Object -ComObject WScript.Shell
$shortcut  = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\$AppName.lnk")
$shortcut.TargetPath       = "$VenvDir\Scripts\pythonw.exe"
$shortcut.Arguments        = "`"$InstallDir\launcher.py`""
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description      = "SecureTunnel — Secure 3-node tunnel"
$shortcut.Save()
Write-OK "Desktop shortcut created."

# ── Step 6: Startup (optional) ────────────────────────────────────────────────
Write-Host ""
$addStartup = Read-Host "  Add SecureTunnel to Windows startup? [y/N]"
if ($addStartup -match "^[yYдД]") {
    $startupLink = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$AppName.lnk"
    $shortcut2  = $WshShell.CreateShortcut($startupLink)
    $shortcut2.TargetPath       = "$VenvDir\Scripts\pythonw.exe"
    $shortcut2.Arguments        = "`"$InstallDir\launcher.py`""
    $shortcut2.WorkingDirectory = $InstallDir
    $shortcut2.Save()
    Write-OK "Added to startup."
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║     Installation complete! ✅         ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Double-click  'SecureTunnel'  on your desktop to launch." -ForegroundColor White
Write-Host ""

$launch = Read-Host "  Launch SecureTunnel now? [Y/n]"
if ($launch -notmatch "^[nNнН]") {
    Start-Process "$VenvDir\Scripts\pythonw.exe" -ArgumentList "`"$InstallDir\launcher.py`"" `
                  -WorkingDirectory $InstallDir
}
