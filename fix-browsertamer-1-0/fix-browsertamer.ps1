#requires -Version 5.1

# fix-browsertamer.ps1 - BrowserTamer setup and association fixer - 1.0
# Author: Fabio Lichinchi (mukka)
# 
# THE UNLICENSE
# This is free and unencumbered software released into the public domain.
# Anyone is free to copy, modify, publish, use, compile, sell, or distribute
# this software, either in source code form or as a compiled binary, for any
# purpose, commercial or non-commercial, and by any means.
# In jurisdictions that recognize copyright laws, the author or authors of this
# software dedicate any and all copyright interest in the software to the public
# domain. We make this dedication for the benefit of the public at large and to
# the detriment of our heirs and successors. We intend this dedication to be an
# overt act of relinquishment in perpetuity of all present and future rights to
# this software under copyright law.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# For more information, please refer to: https://unlicense.org/
# -------------------------------------------------------
# BUGS & FEATURE REQUESTS
# Bug reports and feature requests are appreciated!
# Please visit the project's GitHub page, which you can find at:
#     https://alterego.cc
# -------------------------------------------------------
# DISCLAIMER
# Before diving into the code, a small reality check.
# You may find that my coding style, architecture choices, naming conventions,
# error handling, formatting, comments, lack of comments, or any number of other
# technical or aesthetic decisions do not align with your refined engineering
# sensibilities or personal definition of perfection. That's fine.
# This project exists because I built it for myself, to solve problems I
# personally had. I'm simply making it available in case someone else finds it
# useful.
# If you like it, use it. If you don't like it, don't use it. If you think you
# can do better, by all means go ahead and write your own version.
# What you should not do is show up with unsolicited lectures, passive-aggressive
# nitpicking, or clever little remarks about how you would have done things
# differently. Those contributions add exactly zero value.
# So here is the simple rule:
# Use it if it helps you. Ignore it if it doesn't. And if your main intention is
# to complain, critique for sport, or showcase your superior taste -- please take
# that energy somewhere else.
# That said, if you actually want to help in a constructive way -- improvements,
# fixes, ideas, pull requests, or thoughtful discussion -- then you're absolutely
# welcome. I'm always happy to collaborate with people who bring solutions
# instead of attitude.
# Thank you, and enjoy the code.

param(
    [switch]$SemiAuto,  # Fewer prompts - skips mid-step pauses; may still need
                        # user interaction for first-run BT config if needed
    [switch]$Manual     # Run the script (with pauses); without this or -SemiAuto, shows help and exits
)

# Guard: -SemiAuto and -Manual are mutually exclusive.
if ($SemiAuto -and $Manual) {
    Write-Host ""
    Write-Host "ERROR: -SemiAuto and -Manual cannot be used together." -ForegroundColor Red
    Write-Host "       Use one or the other." -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = "Stop"

# -- TLS / web security
# Force TLS 1.2 for all web requests in this session. On some older Windows
# configurations, PowerShell defaults to TLS 1.0/1.1 which GitHub and other
# modern endpoints reject, causing download failures even when connectivity
# is fine. This must be set before any Invoke-WebRequest or Invoke-RestMethod.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -- Elevation check
# Returns $true if the current process is running with administrator rights.
# Used at script start to BLOCK running elevated: PS-SFTA UserChoice writes must
# happen as the normal user token. Steps that need admin self-elevate via UAC.
# Named Test- per PowerShell convention for boolean-returning functions.
function Test-IsAdmin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# -- Constants mirrored from the BrowserTamer source
#
# Source references:
#   bt/globals.h      : ProtoName, PdfProtoName, CustomProtoName, PortableMarkerName
#   bt/CMakeLists.txt : APP_LONG_NAME ("Browser Tamer"), APP_SHORT_NAME ("bt"),
#                       APP_REG_DESCRIPTION
#
# Config file location (from bt/app/config.cpp):
#   BT checks for a ".portable" file next to bt.exe. If found it stores
#   config.ini next to the exe (portable mode). For winget installs bt.exe
#   lives in a winget-managed directory we must not touch, so portable mode
#   never applies here. Config is always: %LOCALAPPDATA%\bt\config.ini

$BT_APP_NAME       = "Browser Tamer"
$BT_APP_DESC       = "Redirects open URLs to a browser of your choice."
$BT_APP_SHORT      = "bt"               # APP_SHORT_NAME -> config folder name
$BT_PROTO_NAME     = "BrowserTamerHTM"  # ProtoName      -> ProgId for http/https
$BT_PDF_PROTO_NAME = "BrowserTamerPDF"  # PdfProtoName   -> ProgId for .pdf files
$BT_CUSTOM_PROTO   = "x-bt"             # CustomProtoName -> custom protocol

# -- PS-SFTA version pin
# Pinned to a specific commit instead of tracking master, so two runs of this
# script always use the same PS-SFTA code. The UserChoice hashing algorithm
# PS-SFTA uses is sensitive to implementation details; a silent upstream change
# could break association writes without any obvious error message.
#
# To update: visit https://github.com/DanysysTeam/PS-SFTA/commits/master,
# copy the SHA of the commit you want, and replace the value below.
# Verify the new SFTA.ps1 still exports: Set-PTA, Register-FTA, Get-PTA, Get-FTA.
$SFTA_COMMIT_SHA = "22a3229"  # latest known-good commit as of this script version
# SHA-256 of the SFTA.ps1 file at the pinned commit above.
# To obtain: after downloading once, run:
#   Get-FileHash "$env:LOCALAPPDATA\BrowserTamer-Fix\PS-SFTA\SFTA.ps1" -Algorithm SHA256
# Then paste the hash here. Leave empty ("") to skip verification (warns but continues).
$SFTA_SHA256     = ""  # SHA-256 of SFTA.ps1 at commit 22a3229 - fill in to enable verification

# -- ViVeTool version pin
# Pinned to a specific release tag so the download URL is deterministic and
# the same release is used on every run. Update when a new ViVeTool release
# is needed (e.g. new Windows build requires updated feature dictionaries).
#
# HOW TO FILL IN THE HASHES (strongly recommended):
#   1. Run this script once with empty hashes to let it download the files.
#   2. Then run in PowerShell:
#        Get-FileHash "$env:LOCALAPPDATA\BrowserTamer-Fix\ViVeTool.zip" -Algorithm SHA256
#        Get-FileHash "$env:LOCALAPPDATA\BrowserTamer-Fix\ViVeTool\ViVeTool.exe" -Algorithm SHA256
#        Get-FileHash "$env:LOCALAPPDATA\BrowserTamer-Fix\PS-SFTA\SFTA.ps1" -Algorithm SHA256
#   3. Paste the Hash values into the constants below and into $SFTA_SHA256 above.
# With all three hashes populated, subsequent runs are fully verified end-to-end.
# Leave a hash empty ("") to skip verification for that file (warns but continues).
$VIVETOOL_RELEASE_TAG    = "v0.3.4"
$VIVETOOL_SHA256_x64     = ""  # SHA-256 of ViVeTool-v0.3.4-IntelAmd.zip
$VIVETOOL_SHA256_ARM64   = ""  # SHA-256 of ViVeTool-v0.3.4-SnapdragonArm64.zip
$VIVETOOL_EXE_SHA256     = ""  # SHA-256 of the extracted ViVeTool.exe (same for both architectures)

# -- Help / usage

function Show-Help {
    Write-Host ""
    Write-Host "fix-browsertamer.ps1 - BrowserTamer setup and association fixer"
    Write-Host "Author: Fabio Lichinchi (mukka) - https://alterego.cc"
    Write-Host ""
    Write-Host "USAGE"
    Write-Host "  .\fix-browsertamer.ps1 -Manual"
    Write-Host "  .\fix-browsertamer.ps1 -SemiAuto"
    Write-Host ""
    Write-Host "PARAMETERS"
    Write-Host "  -Manual  Interactive mode. Pauses at each major step so you"
    Write-Host "           can read the output before continuing."
    Write-Host ""
    Write-Host "  -SemiAuto  Fewer prompts mode. Skips mid-step pauses but may still"
    Write-Host "             require user interaction if config.ini is missing (first"
    Write-Host "             run) - BrowserTamer must be launched and exited manually."
    Write-Host ""
    Write-Host "WHAT THIS SCRIPT DOES"
    Write-Host "  0.   Internet connectivity check."
    Write-Host "  1.   Install / upgrade BrowserTamer via winget."
    Write-Host "  2.   Register BrowserTamer as a virtual browser in Windows."
    Write-Host "  3.   Configure config.ini (always = y in [picker])."
    Write-Host "       Launches BT visibly for first-run setup if config.ini is missing."
    Write-Host "  4.   Check and fix UCPD registry and stop driver if needed (self-elevates via UAC)."
    Write-Host "       Self-elevates via UAC - main process stays non-elevated."
    Write-Host "       Exits with code 2 and asks for reboot if driver cannot be stopped."
    Write-Host "  5.   Prepare download paths in %LOCALAPPDATA%\BrowserTamer-Fix."
    Write-Host "  6.   Detect CPU architecture (Intel/AMD vs ARM64)."
    Write-Host "  7.   Download ViVeTool $VIVETOOL_RELEASE_TAG from pinned GitHub release."
    Write-Host "  8.   Verify SHA-256 of ZIP and extracted ViVeTool.exe; extract."
    Write-Host "  9.   Download PS-SFTA (commit $SFTA_COMMIT_SHA)."
    Write-Host " 10.   Set execution policy for this session."
    Write-Host " 11.   Run ViVeTool elevated to disable feature flags:"
    Write-Host "        44860385 (classic UCPD), 43229420 + 27623730 (UserChoiceLatest)."
    Write-Host " 12.   Load PS-SFTA in the normal (non-elevated) user session."
    Write-Host " 13.   Set HTTP, HTTPS and HTML/PDF file type defaults."
    Write-Host " 14.   Verify all associations by reading back from registry."
    Write-Host ""
    Write-Host "REQUIREMENTS"
    Write-Host "  - Windows 10/11"
    Write-Host "  - Internet connection"
    Write-Host "  - Run as NORMAL user (not elevated)."
    Write-Host "    Steps 4 (UCPD fix) and 11 (ViVeTool) self-elevate via UAC."
    Write-Host "    Running the whole script as Administrator breaks steps 13-14."
    Write-Host ""
    Write-Host "FILES DOWNLOADED TO"
    Write-Host "  %LOCALAPPDATA%\BrowserTamer-Fix\ViVeTool\"
    Write-Host "  %LOCALAPPDATA%\BrowserTamer-Fix\PS-SFTA\"
    Write-Host "  %LOCALAPPDATA%\BrowserTamer-Fix\reg-backup\"
    Write-Host "  (auto-downloaded; safe to delete after a successful run)"
    Write-Host ""
    Write-Host "CONFIG FILE"
    Write-Host "  %LOCALAPPDATA%\bt\config.ini"
    Write-Host ""
}

# If no mode is specified, show help and wait for the user to read it, then exit.
if (-not $SemiAuto -and -not $Manual) {
    Show-Help
    Read-Host "Press Enter to exit"
    exit 0
}

# -- Pause behaviour

function Wait-ForEnter {
    # No-op in SemiAuto mode; pauses with Read-Host in all other modes.
    if ($SemiAuto) { return }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Fail-AndExit {
    param([string]$Message)
    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red
    Wait-ForEnter
    exit 1
}

function Remove-IfExists {
    # Wraps Remove-Item in try/catch so a locked file (e.g. held by Explorer
    # or AV) does not abort the whole script. Prints a targeted message instead.
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            Remove-Item $Path -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Host "  Warning: could not remove $Path - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  If a previous run left tools open, close them and re-run." -ForegroundColor Yellow
        }
    }
}

# -- Registry default-value helpers
# The PowerShell registry provider's '(default)' name for the unnamed default
# value works in most situations but has edge cases across PS versions and
# registry states. The .NET RegistryKey API is the authoritative way to read
# and write the unnamed default value (empty string key name).

function Set-RegDefaultValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][object]$Value
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    # Get-Item returns a RegistryKey opened READ-ONLY by the PowerShell provider.
    # Calling SetValue on a read-only key throws "Cannot write to the registry key."
    # We must open the key with write access via the .NET API directly,
    # the same way Get-UcpdState opens for reading (but with $true = writable).
    # Strip the 'HKCU:\' or 'HKCU:/' provider prefix (always 6 chars) to get
    # the bare subkey path that the .NET registry API expects.
    $subPath = $Path.Substring(6)
    $item = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subPath, $true)
    if ($null -eq $item) { throw "Set-RegDefaultValue: could not open key for writing: $Path" }
    try {
        $item.SetValue("", $Value)
    } finally {
        $item.Close()
    }
}

function Get-RegDefaultValue {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    # Same RegistryKey handle-close discipline as Set-RegDefaultValue.
    $item = Get-Item -Path $Path -Force
    try {
        return $item.GetValue("", $null)
    } finally {
        $item.Close()
    }
}

# -- ProgId / command helpers

function Get-BtOpenCommand {
    # Returns the canonical shell\open\command string for bt.exe.
    # -WithArgument adds the quoted %1 placeholder used in ProgId handlers.
    # Without it, the string is the bare launch command used in StartMenuInternet.
    param(
        [Parameter(Mandatory = $true)][string]$BtExePath,
        [switch]$WithArgument
    )
    if ($WithArgument) { return ('"{0}" "%1"' -f $BtExePath) }
    return ('"{0}"' -f $BtExePath)
}

function Normalize-CommandString {
    # Collapses internal whitespace and trims edges so comparisons are not
    # thrown off by minor formatting differences (extra spaces, tab chars).
    param([AllowNull()][string]$Command)
    if ($null -eq $Command) { return $null }
    return ($Command.Trim() -replace '\s+', ' ')
}

function Test-ProgIdOpenCommand {
    # Reads the shell\open\command default value for a ProgId and checks that
    # it matches the expected command after normalization.
    # Returns $true only when the command is present and correct.
    param(
        [Parameter(Mandatory = $true)][string]$ProgId,
        [Parameter(Mandatory = $true)][string]$ExpectedCommand
    )
    $cmdPath = "HKCU:\Software\Classes\$ProgId\shell\open\command"
    $actual  = Get-RegDefaultValue -Path $cmdPath
    if ([string]::IsNullOrWhiteSpace($actual)) { return $false }
    return ((Normalize-CommandString $actual) -eq (Normalize-CommandString $ExpectedCommand))
}

# -- Registry backup helper
# Exports a registry key to a .reg file before the script modifies it.
# Non-fatal: if the key does not exist or export fails, we warn and continue.

function Export-RegKeyIfExists {
    param(
        [Parameter(Mandatory = $true)][string]$PsPath,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    if (-not (Test-Path $PsPath)) { return }
    $nativePath = $PsPath `
        -replace '^HKCU:', 'HKEY_CURRENT_USER' `
        -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
    try {
        & reg.exe export $nativePath $OutFile /y 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  Warning: reg.exe export returned $LASTEXITCODE for $PsPath" -ForegroundColor Yellow
            Write-Host "  Backup may be incomplete. Continuing anyway." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Warning: could not back up $PsPath - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# -- UserChoiceLatest detection
# UserChoiceLatest is a Windows 11 consumer (Home/Pro) feature introduced in
# 2025 via A/B testing. When active, Windows uses a new machine-specific hash
# scheme for associations and may ignore classic UserChoice entries written by
# tools like PS-SFTA.
#
# Returns the ProgId string stored in the UserChoiceLatest key for the given
# protocol (e.g. "http", "https"), or $null if the key is absent for that
# protocol. Absence means the feature is not active for that protocol.
#
# The key path mirrors UserChoice but uses the UserChoiceLatest subkey name:
#   HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\<Protocol>\UserChoiceLatest

function Get-UserChoiceLatestProgId {
    param([Parameter(Mandatory = $true)][string]$Protocol)
    $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoiceLatest"
    if (-not (Test-Path $keyPath)) { return $null }
    return (Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue).ProgId
}

# -- Network

function Test-InternetConnection {
    Write-Host "0. Checking internet connection..."

    # Primary check: HTTPS to a reliable host
    try {
        $null = Invoke-WebRequest -Uri "https://www.google.com" `
            -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        Write-Host "  Internet connection OK." -ForegroundColor Green
        Write-Host ""
        return $true
    } catch {}

    # Fallback: TCP connect to Google DNS on port 53
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        try {
            $tcp.Connect("8.8.8.8", 53)
            Write-Host "  Internet connection OK." -ForegroundColor Green
            Write-Host ""
            return $true
        } finally {
            $tcp.Dispose()
        }
    } catch {}

    # Second fallback: try GitHub directly since that is what we actually need
    try {
        $null = Invoke-WebRequest -Uri "https://api.github.com" `
            -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        Write-Host "  Internet connection OK (via GitHub)." -ForegroundColor Green
        Write-Host ""
        return $true
    } catch {}

    return $false
}

function Download-File {
    # Retries the download up to 3 times with a short delay between attempts.
    # Transient network issues (proxy blips, GitHub hiccups, timeouts) should
    # not abort the whole run on the first failure.
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    Write-Host "Downloading:"
    Write-Host "  $Url"
    $headers  = @{ "User-Agent" = "PowerShell-BrowserTamer-Fix" }
    $maxTries = 3
    for ($attempt = 1; $attempt -le $maxTries; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers $headers `
                -TimeoutSec 120 -ErrorAction Stop
            return   # success
        } catch {
            if ($attempt -lt $maxTries) {
                Write-Host "  Attempt $attempt failed ($($_.Exception.Message)) - retrying in 3s..." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
            } else {
                throw "Download failed after $maxTries attempts: $($_.Exception.Message)"
            }
        }
    }
}

function Test-FileSha256 {
    # Verifies a file's SHA-256 hash against an expected value.
    # Returns $true if the hash matches or if $ExpectedHash is empty (skip).
    # Returns $false and prints a warning if the hash does not match.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedHash
    )
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        Write-Host "  Note: SHA-256 verification skipped (hash not configured)." -ForegroundColor Yellow
        return $true
    }
    Write-Host "  Verifying SHA-256..."
    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($actual -ieq $ExpectedHash) {
        Write-Host "  SHA-256 OK." -ForegroundColor Green
        return $true
    }
    Write-Host "  SHA-256 MISMATCH." -ForegroundColor Red
    Write-Host "    Expected: $ExpectedHash" -ForegroundColor Red
    Write-Host "    Actual:   $actual" -ForegroundColor Red
    return $false
}

# -- Architecture detection
# IMPORTANT: $env:PROCESSOR_ARCHITECTURE returns "x86" when running under
# 32-bit PowerShell on a 64-bit OS. The correct check for OS architecture is
# $env:PROCESSOR_ARCHITEW6432 (non-empty only when WOW64 is active) and
# [Environment]::Is64BitOperatingSystem.
#
# The environment variable approach has a gap for x64 PowerShell running under
# ARM64 emulation: PROCESSOR_ARCHITECTURE reads "AMD64" and PROCESSOR_ARCHITEW6432
# is unset, so both env var checks miss it. The WMI fallback (Architecture == 12)
# is the only path that correctly identifies ARM64 in that scenario.

function Get-IsArm64 {
    # Check the native OS architecture first via .NET - immune to WOW64 masking.
    if ([Environment]::Is64BitOperatingSystem) {
        # On a genuine ARM64 OS, PROCESSOR_ARCHITECTURE will read "ARM64" in a
        # native 64-bit process, but may read "x86" or "AMD64" under emulation.
        # PROCESSOR_ARCHITEW6432 is set by WOW64 when a 32-bit process runs on
        # a 64-bit OS - if it contains ARM64 we know the host is ARM64.
        if ($env:PROCESSOR_ARCHITECTURE  -match "ARM64") { return $true }
        if ($env:PROCESSOR_ARCHITEW6432  -match "ARM64") { return $true }
    }
    # Fallback: WMI query for processor architecture (12 = ARM64).
    try {
        $cpuArch = Get-CimInstance Win32_Processor -ErrorAction Stop |
            Select-Object -First 1 -ExpandProperty Architecture
        if ($cpuArch -eq 12) { return $true }
    } catch {}
    return $false
}

# -- BrowserTamer executable locator
# Checks the two directory trees winget uses first (fast, reliable), then
# falls back to a path-restricted recursive scan. The fallback is limited to
# paths matching WinGet|BrowserTamer|aloneguid.bt to avoid picking up unrelated
# bt.exe files. Takes the most recently written match to prefer newer versions.

function Get-BrowserTamerExe {
    $possibleRoots = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
        (Join-Path $env:LOCALAPPDATA "Programs\BrowserTamer")
    )

    foreach ($root in $possibleRoots) {
        if (-not (Test-Path $root)) { continue }

        $pkg = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "aloneguid.bt*" -or $_.Name -like "*BrowserTamer*" } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1

        if ($pkg) {
            $exe = Join-Path $pkg.FullName "bt.exe"
            if (Test-Path $exe) { return $exe }
        }
    }

    $fallback = Get-ChildItem $env:LOCALAPPDATA -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq "bt.exe" -and $_.FullName -match "WinGet|BrowserTamer|aloneguid\.bt" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($fallback) { return $fallback.FullName }

    throw "bt.exe not found after BrowserTamer installation."
}

# -- BrowserTamer virtual-browser registration
# Mirrors bt/app/setup.cpp :: register_browser() + register_protocol().
#
# BT registers itself in the Windows "registered applications" system so that
# its ProgId (BrowserTamerHTM) is recognised. Normally this happens on first
# run via the fix button in BT's UI. We replicate it here so the script is
# fully self-contained and PS-SFTA can reference the ProgId successfully.
#
# All keys are under HKCU - no elevation required.

function Test-BtRegisteredAsBrowser {
    # Verifies that the registration covers the full surface the script writes.
    # Any missing or mismatched entry triggers re-registration.
    # The checks mirror Register-BtAsVirtualBrowser exactly so the two functions
    # describe the same contract.
    param([string]$BtExePath)

    $expectedOpenCmd   = Get-BtOpenCommand -BtExePath $BtExePath -WithArgument
    $expectedLaunchCmd = Get-BtOpenCommand -BtExePath $BtExePath
    $expectedCapPath   = "Software\Clients\StartMenuInternet\$BT_APP_NAME\Capabilities"
    $urlKey  = "HKCU:\Software\Clients\StartMenuInternet\$BT_APP_NAME\Capabilities\URLAssociations"
    $fileKey = "HKCU:\Software\Clients\StartMenuInternet\$BT_APP_NAME\Capabilities\FileAssociations"

    # 1. StartMenuInternet shell\open\command (bare launch, no %1)
    $socKey = "HKCU:\Software\Clients\StartMenuInternet\$BT_APP_NAME\shell\open\command"
    if (-not (Test-Path $socKey)) { return $false }
    $registered = Get-RegDefaultValue -Path $socKey
    if ((Normalize-CommandString $registered) -ne (Normalize-CommandString $expectedLaunchCmd)) { return $false }

    # 2. RegisteredApplications must point to the exact capabilities path
    $raVal = (Get-ItemProperty -Path "HKCU:\Software\RegisteredApplications" -ErrorAction SilentlyContinue)."$BT_APP_NAME"
    if ($raVal -ne $expectedCapPath) { return $false }

    # 3. URLAssociations: http, https -> BrowserTamerHTM; x-bt -> x-bt
    if (-not (Test-Path $urlKey)) { return $false }
    $urlProps = Get-ItemProperty -Path $urlKey -ErrorAction SilentlyContinue
    if ($urlProps.http  -ne $BT_PROTO_NAME)  { return $false }
    if ($urlProps.https -ne $BT_PROTO_NAME)  { return $false }
    if ($urlProps.$BT_CUSTOM_PROTO -ne $BT_CUSTOM_PROTO) { return $false }

    # 4. FileAssociations: HTML extensions -> BrowserTamerHTM; .pdf -> BrowserTamerPDF
    if (-not (Test-Path $fileKey)) { return $false }
    $fileProps = Get-ItemProperty -Path $fileKey -ErrorAction SilentlyContinue
    foreach ($ext in @(".htm",".html",".shtml",".xht",".xhtml",".mht",".mhtml")) {
        if ($fileProps.$ext -ne $BT_PROTO_NAME) { return $false }
    }
    if ($fileProps.".pdf" -ne $BT_PDF_PROTO_NAME) { return $false }

    # 5. ProgId open commands (all three must point to bt.exe with %1)
    if (-not (Test-ProgIdOpenCommand -ProgId $BT_PROTO_NAME    -ExpectedCommand $expectedOpenCmd)) { return $false }
    if (-not (Test-ProgIdOpenCommand -ProgId $BT_PDF_PROTO_NAME -ExpectedCommand $expectedOpenCmd)) { return $false }
    if (-not (Test-ProgIdOpenCommand -ProgId $BT_CUSTOM_PROTO   -ExpectedCommand $expectedOpenCmd)) { return $false }

    return $true
}

function Register-BtAsVirtualBrowser {
    param([string]$BtExePath)

    $appRoot   = "HKCU:\Software\Clients\StartMenuInternet\$BT_APP_NAME"
    $capRoot   = "$appRoot\Capabilities"
    $urlAssoc  = "$capRoot\URLAssociations"
    $fileAssoc = "$capRoot\FileAssociations"

    $launchCmd = Get-BtOpenCommand -BtExePath $BtExePath
    $openCmd   = Get-BtOpenCommand -BtExePath $BtExePath -WithArgument

    # StartMenuInternet registration
    New-Item -Path $appRoot -Force | Out-Null
    Set-RegDefaultValue -Path $appRoot -Value $BT_APP_NAME

    # Capabilities block (name, description, icon)
    New-Item -Path $capRoot -Force | Out-Null
    Set-ItemProperty -Path $capRoot -Name "ApplicationName"        -Value $BT_APP_NAME
    Set-ItemProperty -Path $capRoot -Name "ApplicationDescription" -Value $BT_APP_DESC
    Set-ItemProperty -Path $capRoot -Name "ApplicationIcon"        -Value "$BtExePath,0"

    # URL associations: http/https map to BrowserTamerHTM.
    # x-bt maps to x-bt (its own class) - NOT to BrowserTamerHTM.
    # Mapping x-bt to BrowserTamerHTM would be a type mismatch: Windows would
    # think x-bt is an HTML protocol, which is wrong and can cause routing issues.
    New-Item -Path $urlAssoc -Force | Out-Null
    Set-ItemProperty -Path $urlAssoc -Name "http"           -Value $BT_PROTO_NAME
    Set-ItemProperty -Path $urlAssoc -Name "https"          -Value $BT_PROTO_NAME
    Set-ItemProperty -Path $urlAssoc -Name $BT_CUSTOM_PROTO -Value $BT_CUSTOM_PROTO

    # File associations: HTML document types and PDF.
    # .svg and .webp are image formats - users typically have dedicated image
    # viewers for them and do not expect a browser router to claim them.
    # They are intentionally excluded from the default list.
    New-Item -Path $fileAssoc -Force | Out-Null
    foreach ($ext in @(".htm",".html",".shtml",".xht",".xhtml",".mht",".mhtml")) {
        Set-ItemProperty -Path $fileAssoc -Name $ext -Value $BT_PROTO_NAME
    }
    Set-ItemProperty -Path $fileAssoc -Name ".pdf" -Value $BT_PDF_PROTO_NAME

    # Shell open command and default icon for the StartMenuInternet entry.
    # The launch command here has no %1 - this key is the "open the app" command,
    # not a URL handler. URL/file dispatch goes through the ProgId classes below.
    New-Item -Path "$appRoot\DefaultIcon"         -Force | Out-Null
    Set-RegDefaultValue -Path "$appRoot\DefaultIcon" -Value "$BtExePath,0"
    New-Item -Path "$appRoot\shell\open\command"         -Force | Out-Null
    Set-RegDefaultValue -Path "$appRoot\shell\open\command" -Value $launchCmd

    # Register the capabilities so Windows shows BT in "Set Default Programs"
    $regAppsKey = "HKCU:\Software\RegisteredApplications"
    New-Item -Path $regAppsKey -Force | Out-Null
    Set-ItemProperty -Path $regAppsKey -Name $BT_APP_NAME `
        -Value "Software\Clients\StartMenuInternet\$BT_APP_NAME\Capabilities"

    # Classes\BrowserTamerHTM - the ProgId Windows stores in UserChoice for http/https
    # %1 is quoted to handle paths with spaces correctly.
    $htmKey = "HKCU:\Software\Classes\$BT_PROTO_NAME"
    New-Item -Path $htmKey -Force | Out-Null
    Set-RegDefaultValue -Path $htmKey -Value "$BT_APP_NAME HTML Document"
    New-Item -Path "$htmKey\DefaultIcon"         -Force | Out-Null
    Set-RegDefaultValue -Path "$htmKey\DefaultIcon" -Value "$BtExePath,0"
    New-Item -Path "$htmKey\Application"         -Force | Out-Null
    Set-ItemProperty -Path "$htmKey\Application" -Name "ApplicationName"        -Value $BT_APP_NAME
    Set-ItemProperty -Path "$htmKey\Application" -Name "ApplicationDescription" -Value $BT_APP_DESC
    New-Item -Path "$htmKey\shell\open\command"         -Force | Out-Null
    Set-RegDefaultValue -Path "$htmKey\shell\open\command" -Value $openCmd

    # Classes\BrowserTamerPDF - ProgId for PDF file handling
    $pdfKey = "HKCU:\Software\Classes\$BT_PDF_PROTO_NAME"
    New-Item -Path $pdfKey -Force | Out-Null
    Set-RegDefaultValue -Path $pdfKey -Value "$BT_APP_NAME PDF Document"
    New-Item -Path "$pdfKey\DefaultIcon"         -Force | Out-Null
    Set-RegDefaultValue -Path "$pdfKey\DefaultIcon" -Value "$BtExePath,1"
    New-Item -Path "$pdfKey\Application"         -Force | Out-Null
    Set-ItemProperty -Path "$pdfKey\Application" -Name "ApplicationName"        -Value $BT_APP_NAME
    Set-ItemProperty -Path "$pdfKey\Application" -Name "ApplicationDescription" -Value $BT_APP_DESC
    New-Item -Path "$pdfKey\shell\open\command"         -Force | Out-Null
    Set-RegDefaultValue -Path "$pdfKey\shell\open\command" -Value $openCmd

    # Classes\x-bt - BT's own custom protocol used for internal routing
    $xbtKey = "HKCU:\Software\Classes\$BT_CUSTOM_PROTO"
    New-Item -Path $xbtKey -Force | Out-Null
    Set-RegDefaultValue -Path $xbtKey -Value "URL:$BT_CUSTOM_PROTO"
    Set-ItemProperty -Path $xbtKey -Name "URL Protocol" -Value ""
    New-Item -Path "$xbtKey\shell\open\command"         -Force | Out-Null
    Set-RegDefaultValue -Path "$xbtKey\shell\open\command" -Value $openCmd
}

# -- BrowserTamer process detection
# Searches for running BT instances by process name first (fast), then validates
# the executable path only for those results. Using Get-Process without a -Name
# filter iterates every process and accessing .Path on some system/protected
# processes can throw or return inconsistently.

function Get-BtProcess {
    param([Parameter(Mandatory = $true)][string]$BtExePath)
    $candidates = Get-Process -Name "bt" -ErrorAction SilentlyContinue
    if (-not $candidates) { return $null }
    $match = $null
    foreach ($p in $candidates) {
        try {
            if ($p.Path -and $p.Path -ieq $BtExePath) {
                # If a previous match exists (two BT processes at the same path),
                # dispose it before overwriting so the handle is not leaked.
                if ($null -ne $match) { $match.Dispose() }
                $match = $p
            } else {
                # Dispose handles for processes that don't match. The caller
                # is responsible for disposing the returned (matching) process.
                $p.Dispose()
            }
        } catch {
            $p.Dispose()
        }
    }
    return $match
}

# -- BrowserTamer config.ini writer
# Config location: %LOCALAPPDATA%\bt\config.ini  (APP_SHORT_NAME = "bt")
#
# The only setting we care about is:
#   [picker]
#   always = y
#
# IMPORTANT: BT uses y/n for booleans throughout the ini - not true/false.
#
# Source: bt/bt.cpp :: open() reads g_config.picker_always. When true it sets
# show_picker = true immediately, skipping rule matching entirely and always
# showing the browser picker regardless of which URL was clicked.
#
# If config.ini does not exist yet BT has never been run on this machine.
# We launch BT visibly and guide the user to run browser discovery, save,
# and exit. We then wait for BT to fully exit - critical because BT writes
# config.ini on exit and would overwrite any changes we made while it was
# running. Only after BT exits do we merge always = y into [picker].
#
# If config.ini already exists we check that BT is not currently running
# before editing - if it is running, BT will overwrite the file on exit
# and discard our changes. We ask the user to close it first.

function Invoke-BtForFirstRun {
    param([string]$BtExePath, [string]$ConfigFile)

    # config.ini does not exist yet - BT has never been run on this machine.
    # BT reads config.ini on startup and writes it back on exit, which means
    # any changes we make to the file while BT is running get overwritten when
    # the user clicks Exit. The correct sequence is therefore:
    #   1. Guide the user to launch BT, discover browsers, save, and exit.
    #   2. Wait for BT to fully exit (the process must be gone).
    #   3. THEN merge always = y - after BT can no longer overwrite our change.

    # If BT is somehow already running before we launch it (e.g. the user opened
    # it manually), ask them to close it first so we control the process lifetime.
    $existingProc = Get-BtProcess -BtExePath $BtExePath
    if ($existingProc) {
        $existingProc.Dispose()
        Write-Host ""
        Write-Host "  BrowserTamer is already running." -ForegroundColor Yellow
        Write-Host "  Please close it, then press Enter and we will launch it fresh." -ForegroundColor Yellow
        Read-Host "  Press Enter once BrowserTamer is closed"
        $recheckProc = Get-BtProcess -BtExePath $BtExePath
        if ($recheckProc) {
            $recheckProc.Dispose()
            throw "BrowserTamer is still running. Please close it and re-run the script."
        }
    }
    Write-Host ""
    Write-Host "  BrowserTamer has not been configured yet." -ForegroundColor Yellow
    Write-Host "  We need to launch it so you can save an initial configuration." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Please do the following in the BrowserTamer window that opens:" -ForegroundColor Cyan
    Write-Host "    1. Click  'Discover system browsers'  (top toolbar)" -ForegroundColor Cyan
    Write-Host "    2. Click  'File'  then  'Save configuration'" -ForegroundColor Cyan
    Write-Host "    3. Click  'File'  then  'Exit'" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "  Press Enter here to launch BrowserTamer"

    $proc = Start-Process -FilePath $BtExePath -PassThru -ErrorAction Stop

    # Wait for BT to fully exit before we touch config.ini.
    # BT overwrites config.ini on exit - we must merge after, not before.
    # Dispose() releases the OS process handle; WaitForExit() alone does not.
    Write-Host "  Waiting for you to complete the steps and exit BrowserTamer..."
    try {
        $proc.WaitForExit()
    } finally {
        $proc.Dispose()
    }

    # Poll for config.ini to appear and its size to stabilise.
    # If bt.exe is ever a launcher that exits before the real UI process,
    # WaitForExit returns too early and we may race the config write.
    # Polling gives an extra safety margin without blocking indefinitely.
    $maxWait = 10
    $lastSize = -1
    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Path $ConfigFile) {
            $sz = (Get-Item $ConfigFile).Length
            if ($sz -eq $lastSize -and $sz -gt 0) { break }  # stable
            $lastSize = $sz
        }
    }

    if (Test-Path $ConfigFile) {
        Write-Host "  config.ini saved by BrowserTamer." -ForegroundColor Green
    } else {
        Write-Host "  config.ini was not found after BrowserTamer exited." -ForegroundColor Red
        throw "config.ini not created. Please re-run the script and follow the BrowserTamer instructions."
    }
}

function Set-BtConfig {
    param(
        [string]$BtExePath,
        [string]$ConfigDir   # %LOCALAPPDATA%\bt - pre-verified by the caller
    )

    $configFile = Join-Path $ConfigDir "config.ini"

    if (-not (Test-Path $configFile)) {
        Write-Host "  config.ini not found." -ForegroundColor Cyan
        Invoke-BtForFirstRun -BtExePath $BtExePath -ConfigFile $configFile
    }

    # Defensive guard: Invoke-BtForFirstRun either throws or returns only after
    # verifying the file exists, so this branch should never be reached in practice.
    if (-not (Test-Path $configFile)) {
        Write-Host "  config.ini not present after first-run step - this should not happen." -ForegroundColor Yellow
        return
    }

    # Safety check: if BrowserTamer is already running and config.ini exists,
    # BT will overwrite the file when it exits, discarding our changes.
    # We detect this and ask the user to close BT before we proceed.
    $btProc = Get-BtProcess -BtExePath $BtExePath
    if ($btProc) {
        $btProc.Dispose()
        Write-Host ""
        Write-Host "  BrowserTamer is currently running." -ForegroundColor Yellow
        Write-Host "  If we edit config.ini now, BT will overwrite our changes on exit." -ForegroundColor Yellow
        Write-Host "  Please close BrowserTamer, then press Enter to continue." -ForegroundColor Yellow
        Read-Host "  Press Enter once BrowserTamer is closed"

        # Re-check after the user says they closed it
        $recheckProc = Get-BtProcess -BtExePath $BtExePath
        if ($recheckProc) {
            $recheckProc.Dispose()
            throw "BrowserTamer is still running. Please close it and re-run the script."
        }
    }

    # BT is now closed - safe to edit config.ini without it overwriting our changes.
    # Wrap the read in try/catch: a locked, zero-byte, or oddly-encoded file
    # should give a clear recovery message rather than a raw exception.
    # Explicitly typed as string array - PowerShell can return a scalar
    # string instead of an array on single-line files, breaking array logic.
    [string[]]$lines = $null
    try {
        $lines = [string[]](Get-Content $configFile -Encoding UTF8 -ErrorAction Stop)
    } catch {
        Write-Host "  Failed to read config.ini: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  The file may be locked or corrupted." -ForegroundColor Red
        Write-Host "  Delete $configFile and re-run to reset it." -ForegroundColor Yellow
        throw "config.ini could not be read."
    }
    if (-not $lines) { $lines = @() }  # handle empty file
    Write-Host "  Merging always = y into [picker]..." -ForegroundColor Cyan

    # Find or create the [picker] section and set always = y.
    # BT uses y/n booleans - writing true/false would be ignored.
    # Section matching is case-insensitive and skips commented lines.
    # Key matching also skips commented lines (starting with ; or #)
    # to avoid matching disabled settings like "; always = n".
    $sectionHeader = "[picker]"
    $sectionIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $t = $lines[$i].Trim()
        if ($t.StartsWith(";") -or $t.StartsWith("#")) { continue }
        if ($t -ieq $sectionHeader) { $sectionIdx = $i; break }
    }

    if ($sectionIdx -eq -1) {
        # Section not present - append it
        $lines += ""
        $lines += $sectionHeader
        $lines += "always = y"
    } else {
        # Find next real section boundary, skipping commented lines
        $nextSectionIdx = $lines.Count
        for ($i = $sectionIdx + 1; $i -lt $lines.Count; $i++) {
            $t = $lines[$i].Trim()
            if ($t.StartsWith(";") -or $t.StartsWith("#")) { continue }
            if ($t -match '^\[.+\]') { $nextSectionIdx = $i; break }
        }

        # Look for an existing non-commented "always" key inside the section
        $keyIdx = -1
        for ($i = $sectionIdx + 1; $i -lt $nextSectionIdx; $i++) {
            $t = $lines[$i].Trim()
            if ($t.StartsWith(";") -or $t.StartsWith("#")) { continue }
            if ($t -match '^always\s*=') { $keyIdx = $i; break }
        }

        if ($keyIdx -ne -1) {
            $lines[$keyIdx] = "always = y"
        } else {
            # Insert after the section header
            $newLines = [System.Collections.Generic.List[string]]::new()
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $newLines.Add($lines[$i])
                if ($i -eq $sectionIdx) { $newLines.Add("always = y") }
            }
            $lines = $newLines.ToArray()
        }
    }

    # Write back without BOM. PowerShell 5.1's Set-Content -Encoding UTF8 adds a
    # UTF-8 BOM which some INI parsers (including older BT versions) do not expect.
    # [System.Text.UTF8Encoding]::new($false) gives genuine BOM-free UTF-8.
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllLines($configFile, $lines, $utf8NoBom)
    Write-Host "  config.ini written: $configFile" -ForegroundColor Green
}

# -- UCPD registry state
# UCPD (User Choice Protection Driver) is a Windows kernel filter driver
# introduced in the March 2024 Windows updates (KB5035845) that blocks write
# access to specific UserChoice registry keys from non-Microsoft processes.
#
# UCPD only protects these exact keys (http, https, and .pdf):
#   HKCU\...\UrlAssociations\http\UserChoice  (and https)
#   HKCU\...\FileExts\.pdf\UserChoice
#   (also the UserChoiceLatest and UserChoicePrevious siblings of each)
# Other extensions (.html, .htm, etc.) are NOT protected by UCPD.
#
# UCPD uses a process-name DenyList to block Microsoft-signed executables that
# are too useful for scripting: powershell.exe, reg.exe, rundll32.exe,
# regedit.exe, wscript.exe, cscript.exe, dllhost.exe.
#
# UCPDMgr.exe runs via the "UCPD velocity" scheduled task
# (\Microsoft\Windows\AppxDeploymentClient\UCPD velocity) after every user
# logon and after 10 minutes of system idle time. It unconditionally:
#   - Resets Start back to SYSTEM_START (1)
#   - Resets FeatureV2 back to 2 (blocking mode)
#   - Starts the driver if not running
# The task is only visible to Administrator-level processes.
# Disabling the task is therefore essential for the registry changes to persist
# across reboots -- otherwise UCPDMgr undoes them on the next logon.
#
# Desired state:
#   HKLM\...\Services\UCPD  Start     = 0x4  (SERVICE_DISABLED - never loads)
#   HKLM\...\Services\UCPD  FeatureV2 = 0x0  (passive; 0x2 = blocking mode)
#   Scheduled task "UCPD velocity"    = Disabled  (keeps UCPDMgr from undoing the above)
#
# References:
#   https://hitco.at/blog/windows-userchoice-protection-driver-ucpd/
#   https://github.com/DanysysTeam/PS-SFTA/issues/33
#
# UserChoiceLatest (PS-SFTA issue #37, Kolbicz blog April 2025):
# Microsoft introduced an additional protection layer on Windows 11 consumer
# (Home/Pro) using A/B testing. When active, Windows uses a new machine-specific
# hash scheme stored in UserChoiceLatest rather than the classic UserChoice that
# PS-SFTA writes. The feature is controlled by two flags:
#   43229420  AppDefaultHashRotation
#   27623730  AppDefaultHashRotationUpdateHashes
# Disabling both via ViVeTool (step 11) reverts Windows to the classic path.
# This is handled in Invoke-ViveToolElevated alongside the classic 44860385 flag.
# Note: this feature is A/B tested - not every Windows 11 machine will have it,
# and it is absent from Windows 10 entirely.
# References:
#   https://kolbi.cz/blog/2025/04/20/userchoicelatest-microsofts-new-protection-for-file-type-associations/
#   https://github.com/DanysysTeam/PS-SFTA/issues/37

function Get-UcpdState {
    # Use the .NET registry API instead of reg.exe text parsing to avoid
    # locale-sensitive output format differences across Windows builds.
    $regPath = "SYSTEM\CurrentControlSet\Services\UCPD"
    $key = $null
    try { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath, $false) } catch {}

    $start   = $null
    $feature = $null

    if ($key) {
        $keyExists = $true
        try {
            try { $v = $key.GetValue("Start");    if ($null -ne $v) { $start   = "0x{0:x}" -f [int]$v } } catch {}
            try { $v = $key.GetValue("FeatureV2"); if ($null -ne $v) { $feature = "0x{0:x}" -f [int]$v } } catch {}
        } finally {
            $key.Close()
        }
    } else {
        $keyExists = $false
    }

    [PSCustomObject]@{
        StartValue   = $start
        FeatureV2    = $feature
        # If the key doesn't exist, UCPD is not installed - nothing to fix.
        # If the key exists but values are wrong/missing, the driver may be active.
        # Without this guard, $null -ne "0x4" evaluates to $true, making absent
        # UCPD indistinguishable from blocked UCPD and causing a spurious UAC prompt.
        LooksBlocked = $keyExists -and ($start -ne "0x4" -or $feature -ne "0x0")
    }
}

function Get-UcpdRunning {
    $svc = Get-Service -Name "UCPD" -ErrorAction SilentlyContinue
    return ($null -ne $svc -and $svc.Status -eq "Running")
}


# -- UCPD elevation wrapper
# HKLM registry writes and stopping a protected driver both require admin rights.
# The main process stays non-elevated (required for PS-SFTA later), so this step
# spawns a short-lived elevated child that:
#   1. Sets Start=4 (DISABLED) and FeatureV2=0 in the UCPD service registry key.
#   2. Disables the "UCPD velocity" scheduled task (UCPDMgr.exe resets UCPD on
#      every logon - disabling the task makes the registry fix persist).
#   3. Stops the running driver, polling up to 10 seconds.
# Exit codes: 0 = success, 1 = registry write failed, 2 = driver still running.

function Invoke-UcpdFixElevated {
    Write-Host "  Running UCPD fix elevated for this step..."

    # Inline PowerShell commands to run in the elevated child.
    # Single-quoted here-string so no variable expansion happens in this process.
    # Output is shown (not suppressed) so the user can read it in Manual mode.
    $elevatedScript = @'
Write-Host "UCPD elevated fix - setting registry values..."
$rp = "HKLM\SYSTEM\CurrentControlSet\Services\UCPD"
& reg add $rp /v Start /t REG_DWORD /d 4 /f
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: reg add Start failed." -ForegroundColor Red; exit 1 }
& reg add $rp /v FeatureV2 /t REG_DWORD /d 0 /f
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: reg add FeatureV2 failed." -ForegroundColor Red; exit 1 }
Write-Host "Disabling UCPD velocity scheduled task..."
& schtasks.exe /change /Disable /TN "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity"
Write-Host "Stopping UCPD driver..."
& sc.exe stop UCPD
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Seconds 1
    $svc = Get-Service -Name UCPD -ErrorAction SilentlyContinue
    if ($null -eq $svc -or $svc.Status -ne "Running") { Write-Host "UCPD driver stopped (or was not running)." -ForegroundColor Green; exit 0 }
}
Write-Host "UCPD driver still running after 10s - reboot required." -ForegroundColor Yellow
exit 2
'@

    # In Manual mode append a pause so the user can read the elevated window output.
    if (-not $script:SemiAuto) {
        $elevatedScript += "`nWrite-Host `"`"`nRead-Host `"UCPD fix done - press Enter to close this window`""
    }

    # Write the script to a temp file so we avoid any command-line quoting issues.
    # GetRandomFileName does not create a file on disk (unlike GetTempFileName which
    # creates a zero-byte .tmp file that would be orphaned when we append .ps1).
    # The write is inside the try/finally so the file is always cleaned up,
    # even if Set-Content itself throws (disk full, policy, etc.).
    $tmpScript = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + ".ps1")
    $exitCode = 1   # default: assume failure
    try {
        $elevatedScript | Set-Content -Path $tmpScript -Encoding UTF8
        $proc = Start-Process -FilePath "powershell.exe" `
            -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript`"" `
            -PassThru `
            -Wait

        if ($null -eq $proc) { throw "Failed to start elevated UCPD fix process." }
        # Dispose() in finally so the handle is released even if ExitCode throws.
        try {
            $exitCode = $proc.ExitCode
        } finally {
            $proc.Dispose()
        }
    } finally {
        Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
    }

    # 0 = registry set and driver stopped (or was already not running)
    # 1 = registry write failed (UAC may have been denied)
    # 2 = registry set but driver still running after 10 seconds (needs reboot)
    return $exitCode
}

# -- ViVeTool elevation wrapper
# ViVeTool must run elevated to modify Windows feature flags.
# We spawn an elevated child PowerShell for this one step only, then return to
# the normal user context. This is required because UserChoice writes (Set-PTA,
# Register-FTA) must happen as the regular user - Windows rejects them elevated.
#
# Three feature flags are disabled:
#
#   44860385  Classic UCPD write protection (Windows 10+, March 2024 rollout).
#             Disabling this allows PS-SFTA to write UserChoice for http/https/.pdf.
#
#   43229420  AppDefaultHashRotation - activates the UserChoiceLatest mechanism.
#             When enabled, Windows uses a new machine-specific hash scheme and
#             ignores the classic UserChoice path that PS-SFTA writes to.
#             Windows 11 consumer (Home/Pro) only, A/B tested. Not in Windows 10.
#
#   27623730  AppDefaultHashRotationUpdateHashes - companion to 43229420 that
#             triggers migration of existing associations to the new scheme.
#
# Disabling 43229420 and 27623730 reverts the association model to the classic
# UserChoice path, letting PS-SFTA write valid entries as it did before.
# Source: https://kolbi.cz/blog/2025/04/20/userchoicelatest-microsofts-new-protection-for-file-type-associations/
#
# The elevated child runs each /disable command and tees output to a log file
# that the parent reads and displays. The PowerShell process exits 0 unless
# it crashes — ViVeTool's own exit codes are not propagated. ViVeTool results
# are visible in the captured output; the exit code check only catches a
# complete PowerShell crash.

function Invoke-ViveToolElevated {
    # Uses a temp .ps1 file instead of an inline -Command string to avoid
    # quoting and apostrophe-in-path issues that can break string-built commands.
    # Output is captured to a temp log file so the parent can display and preserve it.
    param([Parameter(Mandatory = $true)][string]$ViVeExePath)

    Write-Host "Running ViVeTool elevated only for this step..."

    $logFile = [System.IO.Path]::GetTempFileName()

    $cmds = @(
        "& `"$ViVeExePath`" /disable /id:44860385 2>&1 | Tee-Object -Append -FilePath `"$logFile`"",
        "& `"$ViVeExePath`" /disable /id:43229420 2>&1 | Tee-Object -Append -FilePath `"$logFile`"",
        "& `"$ViVeExePath`" /disable /id:27623730 2>&1 | Tee-Object -Append -FilePath `"$logFile`""
    )

    if ($script:SemiAuto) {
        $scriptBody = $cmds -join "`n"
    } else {
        $scriptBody = ($cmds -join "`n") + "`nWrite-Host `"`"`nRead-Host `"ViVeTool done - press Enter to close this window`""
    }

    # $logFile uses GetTempFileName which creates an actual placeholder file - that
    # is intentional (the elevated child writes to it via Tee-Object and the file
    # must pre-exist on disk). $tmpScript uses GetRandomFileName instead to avoid
    # leaving an orphaned .tmp file behind when we append the .ps1 extension.
    $tmpScript = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + ".ps1")

    try {
        $scriptBody | Set-Content -Path $tmpScript -Encoding UTF8
        $proc = Start-Process -FilePath "powershell.exe" `
            -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmpScript`"" `
            -PassThru `
            -Wait

        if ($null -eq $proc) { throw "Failed to start elevated ViVeTool process." }

        # Read and display captured ViVeTool output for visibility and debugging.
        if (Test-Path $logFile) {
            $viveOutput = Get-Content $logFile -ErrorAction SilentlyContinue
            if ($viveOutput) {
                Write-Host "  ViVeTool output:" -ForegroundColor Cyan
                foreach ($line in $viveOutput) {
                    Write-Host "    $line"
                }
            }
            # Save to the working log for post-run reference.
            $viveLogDest = Join-Path $workDir "vivetool-output.txt"
            try { Copy-Item $logFile $viveLogDest -Force -ErrorAction Stop } catch {}
        }

        # Pre-initialize to non-zero so a throw inside the try is treated as failure,
        # matching the $exitCode = 1 default in Invoke-UcpdFixElevated.
        $viveExitCode = -1
        # Dispose() in finally so the handle is released even if ExitCode throws.
        try {
            $viveExitCode = $proc.ExitCode
        } finally {
            $proc.Dispose()
        }
        if ($viveExitCode -ne 0) { throw "ViVeTool elevated step failed with exit code $viveExitCode." }
    } finally {
        Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
        Remove-Item $logFile   -Force -ErrorAction SilentlyContinue
    }
}

# -- Shell change notification
# After writing UserChoice, the Windows shell and Settings app need to be
# told that file associations have changed so they refresh their display.
# SHChangeNotify(SHCNE_ASSOCCHANGED) is the correct API call for this.
# PS-SFTA's Register-FTA already calls this internally, but we call it again
# explicitly after all writes are done to make sure Settings shows the tick.

function Invoke-SHChangeNotify {
    # Fires SHChangeNotify(SHCNE_ASSOCCHANGED) to tell the shell and Settings
    # app to refresh their association display. If this fails (unusual policy,
    # AppLocker, etc.) we print a warning so the user knows a sign-out/in may
    # be needed to see the correct default browser tick in Settings.
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")]
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);
    }
'@
    # Check whether the type was already added in this session (e.g. if the
    # script is run twice or dot-sourced). Add-Type throws on duplicates, which
    # would leave $typeAdded = $false even though the type is perfectly usable.
    $typeAdded = ([System.Management.Automation.PSTypeName]'SHChange.Notify').Type -ne $null
    if (-not $typeAdded) {
        try { Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify -ErrorAction Stop; $typeAdded = $true } catch {}
    }
    if ($typeAdded) {
        try { [SHChange.Notify]::Refresh() } catch {
            Write-Host "  Warning: SHChangeNotify failed - shell refresh may not have fired." -ForegroundColor Yellow
            Write-Host "  Sign out and back in if Settings does not show BrowserTamer ticked." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Warning: could not load Shell32 for SHChangeNotify." -ForegroundColor Yellow
        Write-Host "  Sign out and back in if Settings does not show BrowserTamer ticked." -ForegroundColor Yellow
    }
}

# =============================================================================
# Entry point
# =============================================================================

try {
    Write-Host ""
    Write-Host "BrowserTamer association fixer"
    Write-Host "=============================="
    Write-Host "Author: Fabio Lichinchi (mukka) - https://alterego.cc"
    if ($SemiAuto) {
        Write-Host "Mode: semi-automatic (fewer prompts)" -ForegroundColor Cyan
    } else {
        Write-Host "Mode: manual (pauses at each step)" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "THE UNLICENSE - free and unencumbered software released into the public domain."
    Write-Host "https://unlicense.org/"
    Write-Host ""
    Wait-ForEnter

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        throw "Unable to determine script path. Save the script as a .ps1 file and run it again."
    }

    $scriptDir = Split-Path -Parent $scriptPath

    # Warn if running from a UNC/network path. Although downloads now go to
    # %LOCALAPPDATA%, Set-Location below still uses the script directory and
    # some edge-case PowerShell operations can behave unexpectedly from \\server\share.
    if ($scriptDir -like "\\*") {
        Write-Host ""
        Write-Host "  Warning: script is running from a network path:" -ForegroundColor Yellow
        Write-Host "  $scriptDir" -ForegroundColor Yellow
        Write-Host "  Some operations may behave unexpectedly from a UNC location." -ForegroundColor Yellow
        Write-Host "  Copy the script to a local drive if you encounter problems." -ForegroundColor Yellow
        Write-Host ""
    }

    Set-Location $scriptDir

    # Elevation model:
    #   - Steps needing admin (UCPD registry writes, ViVeTool) self-elevate via
    #     Start-Process -Verb RunAs or reg.exe called from an elevated child.
    #   - Steps that must NOT run elevated (PS-SFTA UserChoice writes, steps
    #     13-14) run in this process, which must be the normal user token.
    #
    # IMPORTANT: Run this script as a NORMAL (non-elevated) user.
    # Steps 4 (UCPD fix) and 11 (ViVeTool) self-elevate via Start-Process
    # -Verb RunAs so elevation is scoped to those steps only.
    # If you run the whole script as Administrator, steps 13-14 will write
    # UserChoice into the wrong registry hive and silently fail to set
    # BrowserTamer as the default browser for the current user.
    if (Test-IsAdmin) {
        Write-Host ""
        Write-Host "  IMPORTANT: This script is running as Administrator." -ForegroundColor Red
        Write-Host "  Steps 13-14 (default browser association) will write to" -ForegroundColor Red
        Write-Host "  the wrong registry context and silently fail." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Please close this window and re-run WITHOUT elevation." -ForegroundColor Red
        Write-Host "  The script will request elevation for the steps that need it." -ForegroundColor Red
        Write-Host ""
        Read-Host "  Press Enter to exit"
        exit 1
    }

    Write-Host "Running as user: $env:USERNAME"
    Write-Host ""

    # Step 0 - internet check (everything that follows needs network access)
    if (-not (Test-InternetConnection)) {
        Write-Host "  No internet connection detected." -ForegroundColor Red
        Write-Host "  This script requires internet to download ViVeTool and PS-SFTA." -ForegroundColor Red
        Write-Host "  Please connect and re-run." -ForegroundColor Red
        Wait-ForEnter
        exit 1
    }

    # Step 1 - install or upgrade BrowserTamer via winget.
    # We check the exit code explicitly; winget returns 0 on success and
    # -1978335189 (0x8A150007) when the package is already up to date,
    # which is also fine. Anything else is treated as a real failure.
    Write-Host "1. Installing or upgrading BrowserTamer..."
    # Get-Command alone is insufficient: winget can be present but broken (missing
    # AppInstaller, stale sources, or policy restrictions). A --version probe
    # confirms it is actually functional before we rely on it for installation.
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget is not available. Install App Installer from the Microsoft Store and re-run."
    }
    $wingetVer = & winget --version 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $wingetVer) {
        throw "winget is present but not responding correctly (exit code $LASTEXITCODE). Check App Installer is up to date."
    }
    Write-Host "  winget version: $wingetVer"
    winget install --id aloneguid.bt -e --accept-source-agreements --accept-package-agreements
    $wingetExit = $LASTEXITCODE
    # 0 = success, -1978335189 = already up to date (APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE)
    if ($wingetExit -ne 0 -and $wingetExit -ne -1978335189) {
        throw "winget failed with exit code $wingetExit. Check that winget is installed and the network is reachable."
    }
    Write-Host ""
    Wait-ForEnter

    $btExe = Get-BrowserTamerExe
    Write-Host "BrowserTamer found at:"
    Write-Host "  $btExe"
    Write-Host ""

    # Working directory used for downloads and registry backups throughout the
    # script. Created here so the backup step at step 2 can use it before the
    # main download preparation at step 5.
    $workDir   = Join-Path $env:LOCALAPPDATA "BrowserTamer-Fix"
    $backupDir = Join-Path $workDir "reg-backup"
    foreach ($dir in @($workDir, $backupDir)) {
        if (-not (Test-Path $dir)) {
            try { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
            catch { throw "Cannot create working directory: $dir. Check %LOCALAPPDATA% permissions." }
        }
    }

    # Step 2 - register BT as a virtual browser in Windows
    # Must run before PS-SFTA, which needs the BrowserTamerHTM ProgId to exist.
    #
    # Back up the five registry subtrees we are about to touch so there is
    # rollback material if anything goes wrong. Export-RegKeyIfExists is
    # non-fatal: if a key does not yet exist there is nothing to back up.
    Write-Host "2. Registering BrowserTamer as a virtual browser..."
    Write-Host "  Backing up existing registry state to: $backupDir" -ForegroundColor Cyan
    $regBackups = @{
        "StartMenuInternet" = "HKCU:\Software\Clients\StartMenuInternet\$BT_APP_NAME"
        "RegisteredApplications" = "HKCU:\Software\RegisteredApplications"
        "BrowserTamerHTM"   = "HKCU:\Software\Classes\$BT_PROTO_NAME"
        "BrowserTamerPDF"   = "HKCU:\Software\Classes\$BT_PDF_PROTO_NAME"
        "x-bt"              = "HKCU:\Software\Classes\$BT_CUSTOM_PROTO"
    }
    foreach ($name in $regBackups.Keys) {
        Export-RegKeyIfExists -PsPath $regBackups[$name] `
            -OutFile (Join-Path $backupDir "$name.reg")
    }
    if (Test-BtRegisteredAsBrowser -BtExePath $btExe) {
        Write-Host "  Already registered correctly." -ForegroundColor Green
    } else {
        Write-Host "  Registration missing or stale - writing registry keys..." -ForegroundColor Yellow
        Register-BtAsVirtualBrowser -BtExePath $btExe
        if (Test-BtRegisteredAsBrowser -BtExePath $btExe) {
            Write-Host "  Registration verified OK." -ForegroundColor Green
        } else {
            throw "BrowserTamer registration could not be verified after writing."
        }
    }
    Write-Host ""
    Wait-ForEnter

    # Step 3 - ensure config.ini exists and has always = y under [picker].
    # If missing: launch BT visibly, guide the user through browser discovery,
    # save, and exit. Wait for the BT process to fully exit (critical - BT
    # overwrites config.ini on exit), then merge always = y into [picker].
    # If present: BT is not running, merge always = y into [picker] directly.
    # Preflight: verify the config directory is writable before we attempt to
    # create or edit config.ini. Catches profile-redirection, OneDrive sync
    # conflicts, and corporate locked-folder policies early.
    $btConfigDir = Join-Path $env:LOCALAPPDATA $BT_APP_SHORT
    if (-not (Test-Path $btConfigDir)) {
        try { New-Item -ItemType Directory -Path $btConfigDir -Force -ErrorAction Stop | Out-Null }
        catch { throw "Cannot create BrowserTamer config directory: $btConfigDir. Check folder permissions." }
    }
    $cfgWriteTest = Join-Path $btConfigDir ".write-test-$([System.IO.Path]::GetRandomFileName())"
    try {
        [System.IO.File]::WriteAllText($cfgWriteTest, "test")
        Remove-Item $cfgWriteTest -Force -ErrorAction SilentlyContinue
    } catch {
        throw "BrowserTamer config directory is not writable: $btConfigDir. Check folder permissions."
    }

    Write-Host "3. Configuring BrowserTamer picker..."
    Set-BtConfig -BtExePath $btExe -ConfigDir $btConfigDir
    Write-Host ""
    Wait-ForEnter

    # Step 4 - check and fix UCPD registry, driver, and velocity task state.
    # The registry and driver are checked non-elevated for display purposes.
    # Elevation always runs unconditionally so the "UCPD velocity" scheduled task
    # is always disabled - it cannot be read or disabled without admin rights,
    # and Windows can re-enable it via updates. The elevated fix is idempotent.
    Write-Host "4. Checking UCPD state..."
    $ucpd = Get-UcpdState
    Write-Host "  Start     = $($ucpd.StartValue)"
    Write-Host "  FeatureV2 = $($ucpd.FeatureV2)"
    $ucpdDriverRunning = Get-UcpdRunning
    Write-Host "  Driver running = $ucpdDriverRunning"
    # Always run the elevated fix. The registry and driver state are checked
    # non-elevated above for display purposes, but the velocity task
    # (which resets UCPD on every logon) can only be read and disabled with
    # admin rights. Running the elevated child unconditionally ensures the
    # task is always disabled, even if Windows re-enabled it since the last run.
    # The elevated child is idempotent - re-applying already-correct values
    # and re-disabling an already-disabled task is harmless.
    if ($ucpd.LooksBlocked -or $ucpdDriverRunning) {
        Write-Host "  UCPD needs attention - running elevated fix..." -ForegroundColor Yellow
    } else {
        Write-Host "  UCPD registry OK - running elevated fix to ensure velocity task is disabled..." -ForegroundColor Cyan
    }
    $ucpdResult = Invoke-UcpdFixElevated

    switch ($ucpdResult) {
        0 { Write-Host "  UCPD registry set, velocity task disabled, driver stopped (or was not running)." -ForegroundColor Green }
        1 { throw "UCPD registry fix failed in the elevated process. UAC may have been denied." }
        2 {
            Write-Host ""
            Write-Host "  UCPD registry has been fixed but the driver is still" -ForegroundColor Cyan
            Write-Host "  loaded and cannot be stopped without a reboot." -ForegroundColor Cyan
            Write-Host "  Please reboot and re-run this script to complete setup." -ForegroundColor Cyan
            Wait-ForEnter
            exit 2   # exit 2 = reboot required, setup incomplete
        }
        default { throw "Unexpected exit code from elevated UCPD fix: $ucpdResult" }
    }
    Write-Host ""
    Wait-ForEnter

    # Steps 5-9 - prepare download paths, detect architecture, download ViVeTool and PS-SFTA.
    # Downloads go to %LOCALAPPDATA%\BrowserTamer-Fix (created above after step 1) rather
    # than the script directory. This avoids failures when the script runs from read-only
    # media, a network share, a protected Downloads folder, or any path the user cannot write.
    Write-Host "5. Preparing working folders..."
    $viveZip    = Join-Path $workDir "ViVeTool.zip"
    $viveDir    = Join-Path $workDir "ViVeTool"
    $sftaDir    = Join-Path $workDir "PS-SFTA"
    $sftaScript = Join-Path $sftaDir "SFTA.ps1"

    # Verify the working directory is actually writable before attempting downloads.
    $writeTestFile = Join-Path $workDir ".write-test-$([System.IO.Path]::GetRandomFileName())"
    try {
        [System.IO.File]::WriteAllText($writeTestFile, "test")
        Remove-Item $writeTestFile -Force -ErrorAction SilentlyContinue
    } catch {
        throw "Working directory is not writable: $workDir. Check %LOCALAPPDATA% permissions."
    }

    Remove-IfExists $viveZip
    Remove-IfExists $viveDir
    Remove-IfExists $sftaDir

    $isArm64 = Get-IsArm64
    Write-Host "6. Detected architecture: $(if ($isArm64) { 'ARM64' } else { 'Intel/AMD' })"
    Write-Host ""

    Write-Host "7. Downloading ViVeTool ($VIVETOOL_RELEASE_TAG)..."
    $viveBaseUrl = "https://github.com/thebookisclosed/ViVe/releases/download/$VIVETOOL_RELEASE_TAG"
    if ($isArm64) {
        $viveUrl        = "$viveBaseUrl/ViVeTool-$VIVETOOL_RELEASE_TAG-SnapdragonArm64.zip"
        $expectedViveSha = $VIVETOOL_SHA256_ARM64
    } else {
        $viveUrl        = "$viveBaseUrl/ViVeTool-$VIVETOOL_RELEASE_TAG-IntelAmd.zip"
        $expectedViveSha = $VIVETOOL_SHA256_x64
    }
    Download-File -Url $viveUrl -OutFile $viveZip

    Write-Host "8. Verifying SHA-256 and extracting ViVeTool..."
    # Sanity check: a valid zip is at least a few KB.
    # A truncated download creates a file but Expand-Archive fails with a
    # confusing error rather than explaining what went wrong.
    $zipSize = (Get-Item $viveZip -ErrorAction SilentlyContinue).Length
    if (-not $zipSize -or $zipSize -lt 1024) {
        throw "ViVeTool zip appears truncated or empty ($zipSize bytes). Check network and retry."
    }
    if (-not (Test-FileSha256 -FilePath $viveZip -ExpectedHash $expectedViveSha)) {
        throw "ViVeTool zip SHA-256 mismatch. The download may have been tampered with. Delete $viveZip and retry."
    }
    Expand-Archive -Path $viveZip -DestinationPath $viveDir -Force

    $viveExe = Get-ChildItem $viveDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq "ViVeTool.exe" } |
        Select-Object -First 1

    if (-not $viveExe) { throw "ViVeTool.exe was not found after extraction." }

    # Verify the extracted executable separately from the ZIP.
    # A corrupt or maliciously crafted ZIP could pass archive-level checks
    # while placing a modified binary inside.
    if (-not (Test-FileSha256 -FilePath $viveExe.FullName -ExpectedHash $VIVETOOL_EXE_SHA256)) {
        throw "ViVeTool.exe SHA-256 mismatch after extraction. Delete $viveDir and retry."
    }

    # Unblock only after both ZIP and exe hashes are verified so the
    # zone-of-origin warning is not silently removed from an untrusted file.
    try { Unblock-File $viveExe.FullName -ErrorAction Stop } catch {
        Write-Host "  Note: Unblock-File failed for ViVeTool ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "  This is harmless on non-NTFS volumes or files without zone data." -ForegroundColor Yellow
    }
    Write-Host "  $($viveExe.FullName)"
    Write-Host ""

    # Step 9 - download PS-SFTA
    # URL uses the pinned commit SHA ($SFTA_COMMIT_SHA) rather than master so
    # every run of this script uses identical PS-SFTA code. See the constant
    # definition near the top of the script for how to update the pin.
    Write-Host "9. Downloading PS-SFTA (commit $SFTA_COMMIT_SHA)..."
    New-Item -ItemType Directory -Path $sftaDir -Force | Out-Null
    $sftaUrl = "https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/$SFTA_COMMIT_SHA/SFTA.ps1"
    Download-File -Url $sftaUrl -OutFile $sftaScript
    if (-not (Test-Path $sftaScript)) { throw "SFTA.ps1 was not downloaded." }

    # Content sanity check: reject obvious non-PowerShell responses.
    # A proxy block page, captive portal, or CDN error served as the file
    # would otherwise be dot-sourced directly into the current session.
    $sftaFirstLine = Get-Content $sftaScript -TotalCount 1 -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($sftaFirstLine)) {
        throw "SFTA.ps1 is empty or unreadable. The download may have failed silently. Delete $sftaScript and retry."
    }
    if ($sftaFirstLine -match '^\s*<[!?]?[a-zA-Z]') {
        throw "SFTA.ps1 looks like HTML, not PowerShell (first line: '$sftaFirstLine'). The download may have returned an error page. Delete $sftaScript and retry."
    }

    # Verify hash before unblocking. Unblock-File silently removes the
    # zone-of-origin warning, so it must not happen before trust is established.
    if (-not (Test-FileSha256 -FilePath $sftaScript -ExpectedHash $SFTA_SHA256)) {
        throw "SFTA.ps1 SHA-256 mismatch. The download may have been tampered with. Delete $sftaScript and retry."
    }
    try { Unblock-File $sftaScript -ErrorAction Stop } catch {
        Write-Host "  Note: Unblock-File failed for PS-SFTA ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "  This is harmless on non-NTFS volumes or files without zone data." -ForegroundColor Yellow
    }
    Write-Host "  $sftaScript"
    Write-Host ""
    Wait-ForEnter

    # Steps 10-12 - run ViVeTool elevated, load PS-SFTA as normal user
    Write-Host "10. Setting temporary execution policy for this session..."
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
    } catch {
        Write-Host "  Warning: could not set execution policy ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "  This may be blocked by a local or group policy." -ForegroundColor Yellow
        Write-Host "  PS-SFTA dot-source may fail. If so, run in a less restricted PowerShell session." -ForegroundColor Yellow
    }

    Write-Host "11. Running ViVeTool elevated to disable feature flags 44860385, 43229420, 27623730..."
    Invoke-ViveToolElevated -ViVeExePath $viveExe.FullName
    Write-Host ""
    Wait-ForEnter

    # PS-SFTA must run as the normal user (not elevated) because UserChoice
    # writes are per-user and Windows rejects them from an elevated process.
    # After loading, verify the expected functions exist - an upstream rename
    # or file corruption would otherwise cause confusing errors later.
    Write-Host "12. Loading PS-SFTA in the normal user session..."
    . $sftaScript
    foreach ($fn in @("Set-PTA", "Register-FTA", "Get-PTA", "Get-FTA")) {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            throw "PS-SFTA did not export expected function: $fn. The downloaded script may have changed."
        }
    }
    Write-Host "  PS-SFTA loaded OK." -ForegroundColor Green

    # File extensions this script sets as BrowserTamer defaults.
    #
    # HTML document types -> BrowserTamerHTM
    # .svg and .webp are intentionally excluded: they are image formats that users
    # typically open in dedicated image viewers rather than a browser router.
    # Claiming them here would produce unexpected behaviour for people who have
    # a preferred image editor or viewer for those types.
    # If you want BrowserTamer to handle .svg/.webp, add them back manually.
    #
    # Protocols (http, https):
    #   Set-PTA writes the ProgId + Hash to UrlAssociations UserChoice.
    #   The Hash is computed by PS-SFTA using Windows' own algorithm, so
    #   Windows accepts it and shows BrowserTamer ticked in Settings.
    #   BrowserTamerHTM is already registered in step 2 so no class work needed.
    #
    # File extensions:
    #   Register-FTA sets UserChoice + Hash for each extension.
    #   .htm .html .shtml .xht .xhtml .mht .mhtml -> BrowserTamerHTM
    #   .pdf                                       -> BrowserTamerPDF
    #
    #   Note on ProgId ownership: step 2 manually builds the BrowserTamerHTM
    #   and BrowserTamerPDF class keys. Register-FTA may update parts of those
    #   same keys (notably the shell open command). This is generally fine -
    #   both write the same exe path - but if behavior is ever surprising after
    #   a PS-SFTA update, check whether Register-FTA has overwritten class
    #   metadata (icon, ApplicationName, etc.) that step 2 set.
    #
    # After all writes, SHChangeNotify(SHCNE_ASSOCCHANGED) is fired to tell
    # the shell and Settings app to refresh their association display.

    $htmlExts = @(".htm", ".html", ".shtml", ".xht", ".xhtml", ".mht", ".mhtml")
    $pdfExts  = @(".pdf")

    # Re-validate bt.exe still exists before writing associations.
    # The path was found after winget install; if anything changed between
    # then and now (repair, path update, file missing) we catch it early.
    if (-not (Test-Path $btExe)) {
        throw "bt.exe no longer found at: $btExe. Please re-run the script."
    }

    Write-Host "13. Setting protocol and file type defaults to BrowserTamer..."

    # Back up current UserChoice defaults before PS-SFTA overwrites them.
    # This lets the user restore their previous default browser if something
    # goes wrong. Note: restoring these .reg files may be blocked by Windows
    # protections - see the NOTES section at the end for details.
    Write-Host "  Backing up current default-association state..."
    $ucBackups = @{
        "UserChoice-http"  = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http"
        "UserChoice-https" = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https"
        "UserChoice-pdf"   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf"
        "UserChoice-html"  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html"
        "UserChoice-htm"   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm"
    }
    foreach ($name in $ucBackups.Keys) {
        Export-RegKeyIfExists -PsPath $ucBackups[$name] `
            -OutFile (Join-Path $backupDir "$name.reg")
    }

    # -- UserChoiceLatest pre-flight check
    # Detect whether Windows is using the UserChoiceLatest mechanism on this machine.
    # UCL can be active per-protocol (http and https are gated independently via A/B
    # testing). We check both here as an early warning; the authoritative post-write
    # check in step 14 also checks them independently.
    # When active, Windows may ignore classic UserChoice writes from PS-SFTA.
    # Step 11 (ViVeTool) disabled the relevant feature flags; if this check still
    # shows UserChoiceLatest present, the ViVeTool change may need a reboot to take
    # effect, or the feature was re-enabled by a Windows update after step 11 ran.
    $uclHttp  = Get-UserChoiceLatestProgId -Protocol "http"
    $uclHttps = Get-UserChoiceLatestProgId -Protocol "https"
    if ($null -ne $uclHttp -or $null -ne $uclHttps) {
        $uclProtocols = @(
            if ($null -ne $uclHttp)  { "http (ProgId: $uclHttp)" }
            if ($null -ne $uclHttps) { "https (ProgId: $uclHttps)" }
        ) -join ", "
        Write-Host ""
        Write-Host "  Note: UserChoiceLatest is present for: $uclProtocols." -ForegroundColor Yellow
        Write-Host "  This is a Windows 11 consumer feature that can override classic UserChoice." -ForegroundColor Yellow
        Write-Host "  Step 11 (ViVeTool) disabled the relevant flags - if associations" -ForegroundColor Yellow
        Write-Host "  do not stick after this run, reboot and re-run the script." -ForegroundColor Yellow
        Write-Host ""
    }

    $failures    = @()   # file extensions that Register-FTA could not set
    $protocolsOk = $false

    # -- Protocol defaults (http, https)
    # Set-PTA is kept in its own try/catch so a protocol failure surfaces
    # with a specific message rather than a generic "blocked" fallback.
    # Set-PTA computes the correct Hash for UserChoice using PS-SFTA's
    # reverse-engineered implementation of Windows' own hashing algorithm.
    # Without the correct hash Windows ignores the ProgId and falls back
    # to Edge. BrowserTamerHTM is already registered in step 2.
    try {
        Set-PTA $BT_PROTO_NAME http
        Set-PTA $BT_PROTO_NAME https
        $protocolsOk = $true
    } catch {
        Write-Host ""
        Write-Host "  Protocol default write failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Possible causes:" -ForegroundColor Yellow
        Write-Host "    - UCPD driver still active (reboot may be needed after step 4)" -ForegroundColor Yellow
        Write-Host "    - UserChoiceLatest active and ViVeTool change not yet in effect (reboot)" -ForegroundColor Yellow
        Write-Host "    - Hash rejected by this Windows build" -ForegroundColor Yellow
        Write-Host "  Finish manually: Settings > Apps > Default apps > set HTTP and HTTPS." -ForegroundColor Yellow
    }

    # -- File type defaults (HTML types and PDF)
    # Each extension is tried independently so one failure does not block others.

    # HTML file types -> BrowserTamerHTM
    foreach ($ext in $htmlExts) {
        try   { Register-FTA $btExe $ext -ProgId $BT_PROTO_NAME }
        catch { $failures += $ext }
    }

    # PDF file type -> BrowserTamerPDF
    foreach ($ext in $pdfExts) {
        try   { Register-FTA $btExe $ext -ProgId $BT_PDF_PROTO_NAME }
        catch { $failures += $ext }
    }

    # Notify the shell that file associations have changed.
    # This prompts Windows Settings to refresh and show the tick.
    Invoke-SHChangeNotify

    # -- ProgId command integrity check (Layer 2 verification)
    # PS-SFTA's Register-FTA may write to the same ProgId class keys that step 2
    # built. Verify that the shell\open\command values still point to the correct
    # bt.exe after all writes are done. This catches silent overwrites or drift
    # that UserChoice readback alone cannot detect.
    Write-Host ""
    Write-Host "  Verifying ProgId command integrity..."
    $expectedOpenCmd  = Get-BtOpenCommand -BtExePath $btExe -WithArgument
    $progIdCmdResults = @{}
    foreach ($progId in @($BT_PROTO_NAME, $BT_PDF_PROTO_NAME, $BT_CUSTOM_PROTO)) {
        $progIdCmdResults[$progId] = Test-ProgIdOpenCommand -ProgId $progId -ExpectedCommand $expectedOpenCmd
        $icon = if ($progIdCmdResults[$progId]) { "[OK]" } else { "[MISMATCH]" }
        $color = if ($progIdCmdResults[$progId]) { "Green" } else { "Yellow" }
        Write-Host "  $icon $progId\shell\open\command" -ForegroundColor $color
    }
    $progIdCmdsOk = ($progIdCmdResults.Values | Where-Object { -not $_ }).Count -eq 0
    if (-not $progIdCmdsOk) {
        Write-Host ""
        Write-Host "  One or more ProgId commands do not match the expected bt.exe path." -ForegroundColor Yellow
        Write-Host "  This may indicate PS-SFTA rewrote the class metadata." -ForegroundColor Yellow
        Write-Host "  Re-running step 2 (re-registration) should correct it." -ForegroundColor Yellow
        # Re-register to restore the correct command values without aborting the run.
        Register-BtAsVirtualBrowser -BtExePath $btExe
        Write-Host "  Re-registration complete. Re-checking..." -ForegroundColor Cyan
        # Recompute so the final status accurately reflects the post-repair state.
        $progIdCmdsOk = $true
        foreach ($progId in @($BT_PROTO_NAME, $BT_PDF_PROTO_NAME, $BT_CUSTOM_PROTO)) {
            if (-not (Test-ProgIdOpenCommand -ProgId $progId -ExpectedCommand $expectedOpenCmd)) {
                $progIdCmdsOk = $false
                Write-Host "  [STILL MISMATCH] $progId\shell\open\command" -ForegroundColor Red
            }
        }
        if ($progIdCmdsOk) {
            Write-Host "  ProgId commands restored OK." -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "14. Verifying associations..."

    # Read all associations once and store results. We reuse the same values
    # for both printing and comparison, avoiding a double-query that could
    # return inconsistent results if shell state is still settling.
    $httpAssoc  = Get-PTA http
    $httpsAssoc = Get-PTA https
    Write-Host "  HTTP   -> $httpAssoc"
    Write-Host "  HTTPS  -> $httpsAssoc"

    # Read UserChoiceLatest for http/https independently (Layer 1b verification).
    # Each protocol is checked separately - if only https has the key present
    # but http does not, the mismatch still needs to be reported.
    $uclHttpPost  = Get-UserChoiceLatestProgId -Protocol "http"
    $uclHttpsPost = Get-UserChoiceLatestProgId -Protocol "https"
    $uclMismatch  = $false

    foreach ($pair in @(
        [pscustomobject]@{ Proto = "http";  Val = $uclHttpPost  },
        [pscustomobject]@{ Proto = "https"; Val = $uclHttpsPost }
    )) {
        if ($null -eq $pair.Val) { continue }   # feature absent for this protocol - fine
        if ($pair.Val -eq $BT_PROTO_NAME) {
            Write-Host "  UserChoiceLatest ($($pair.Proto)) -> $($pair.Val)" -ForegroundColor Green
        } else {
            Write-Host "  UserChoiceLatest ($($pair.Proto)) -> $($pair.Val)  [differs from UserChoice]" -ForegroundColor Yellow
            $uclMismatch = $true
        }
    }

    # Read file type associations once into a hashtable
    $ftReadback = @{}
    foreach ($ext in ($htmlExts + $pdfExts)) {
        $ftReadback[$ext] = Get-FTA $ext
        Write-Host "  $ext -> $($ftReadback[$ext])"
    }
    Write-Host ""

    # Cross-check protocols from stored values.
    # If the write succeeded but readback disagrees, retry once after a short
    # delay - Windows may update associations asynchronously.
    $readbackMatchesHttp  = ($httpAssoc  -eq $BT_PROTO_NAME)
    $readbackMatchesHttps = ($httpsAssoc -eq $BT_PROTO_NAME)
    if ($protocolsOk -and (-not $readbackMatchesHttp -or -not $readbackMatchesHttps)) {
        Start-Sleep -Seconds 2
        $httpAssoc  = Get-PTA http
        $httpsAssoc = Get-PTA https
        Write-Host "  (retried) HTTP   -> $httpAssoc"
        Write-Host "  (retried) HTTPS  -> $httpsAssoc"
    }
    $protocolsOk = ($protocolsOk -and
                    $httpAssoc  -eq $BT_PROTO_NAME -and
                    $httpsAssoc -eq $BT_PROTO_NAME)

    # Cross-check file types from stored values.
    # If the write succeeded but readback disagrees, retry once after a short
    # delay - Windows may update associations asynchronously (matches protocol retry).
    # The condition is evaluated inline from $ftReadback so that $ftMismatches is
    # only ever built once, in final (annotated) form, inside the branch that runs.
    $ftMismatches = @()
    $anyFtMismatch = (($htmlExts | Where-Object { $ftReadback[$_] -ne $BT_PROTO_NAME }).Count -gt 0) -or
                     (($pdfExts  | Where-Object { $ftReadback[$_] -ne $BT_PDF_PROTO_NAME }).Count -gt 0)

    if ($failures.Count -eq 0 -and $anyFtMismatch) {
        # Write appeared to succeed but readback disagrees - retry after a pause.
        Start-Sleep -Seconds 2
        foreach ($ext in ($htmlExts + $pdfExts)) {
            $retried = Get-FTA $ext
            $ftReadback[$ext] = $retried
            Write-Host "  (retried) $ext -> $retried"
        }
        foreach ($ext in $htmlExts) {
            if ($ftReadback[$ext] -ne $BT_PROTO_NAME) { $ftMismatches += "$ext (got: $($ftReadback[$ext]))" }
        }
        foreach ($ext in $pdfExts) {
            if ($ftReadback[$ext] -ne $BT_PDF_PROTO_NAME) { $ftMismatches += "$ext (got: $($ftReadback[$ext]))" }
        }
    } else {
        # No retry needed - build mismatch strings from stored values for reporting.
        foreach ($ext in $htmlExts) {
            if ($ftReadback[$ext] -ne $BT_PROTO_NAME) { $ftMismatches += "$ext (got: $($ftReadback[$ext]))" }
        }
        foreach ($ext in $pdfExts) {
            if ($ftReadback[$ext] -ne $BT_PDF_PROTO_NAME) { $ftMismatches += "$ext (got: $($ftReadback[$ext]))" }
        }
    }
    $fileTypesOk = ($failures.Count -eq 0 -and $ftMismatches.Count -eq 0)

    if ($protocolsOk) {
        Write-Host "  Protocols: OK" -ForegroundColor Green
        if ($uclMismatch) {
            Write-Host "  UserChoiceLatest: still differs - reboot may be needed for ViVeTool change to take effect." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Protocols: not confirmed - a reboot or manual step may be needed." -ForegroundColor Yellow
        if ($uclMismatch) {
            Write-Host "  UserChoiceLatest is still active and differs - reboot and re-run." -ForegroundColor Yellow
        }
    }

    if ($fileTypesOk) {
        Write-Host "  File types: OK" -ForegroundColor Green
    } else {
        if ($failures.Count -gt 0) {
            Write-Host "  File types: write failed for: $($failures -join ', ')" -ForegroundColor Yellow
        }
        if ($ftMismatches.Count -gt 0) {
            Write-Host "  File types: readback mismatch for: $($ftMismatches -join ', ')" -ForegroundColor Yellow
        }
        Write-Host "  Set them manually in Settings > Apps > Default apps."
    }

    if ($progIdCmdsOk) {
        Write-Host "  ProgId commands: OK" -ForegroundColor Green
    } else {
        Write-Host "  ProgId commands: re-registration attempted but commands still mismatch." -ForegroundColor Red
        Write-Host "  See [STILL MISMATCH] lines above. A manual check of the registry may be needed." -ForegroundColor Red
    }

    Write-Host ""
    # Declare success only when protocols, file types, and ProgId commands are confirmed,
    # and there is no UserChoiceLatest mismatch pending a reboot.
    $allOk = $protocolsOk -and $fileTypesOk -and $progIdCmdsOk -and (-not $uclMismatch)
    if ($allOk) {
        Write-Host "Done - registry associations written and verified." -ForegroundColor Green
        Write-Host "To confirm end-to-end: click any link and check that BrowserTamer's picker appears." -ForegroundColor Cyan
    } elseif ($protocolsOk -and (-not $uclMismatch)) {
        Write-Host "Done - protocols set; some associations may need manual attention (see above)." -ForegroundColor Yellow
    } elseif ($uclMismatch) {
        Write-Host "Done - associations written, but UserChoiceLatest still differs." -ForegroundColor Yellow
        Write-Host "Reboot and re-run the script to let the ViVeTool change take effect." -ForegroundColor Yellow
    } else {
        Write-Host "Done - setup ran but protocol associations were not confirmed." -ForegroundColor Yellow
        Write-Host "See details above. A reboot or manual step may be needed." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "NOTES" -ForegroundColor White
    Write-Host "  - When you click any link BrowserTamer should intercept it" -ForegroundColor White
    Write-Host "    and show its picker so you can choose which browser to use." -ForegroundColor White
    Write-Host "  - If Settings > Apps > Default apps does not show BrowserTamer" -ForegroundColor White
    Write-Host "    ticked, sign out and sign back in to refresh the display." -ForegroundColor White
    Write-Host ""
    Write-Host "PERSISTENCE - THIS MAY NEED TO BE RE-RUN" -ForegroundColor Yellow
    Write-Host "  Windows can undo parts of this fix automatically:" -ForegroundColor Yellow
    Write-Host "  - A Windows quality update can re-enable UCPD protection." -ForegroundColor Yellow
    Write-Host "  - A Windows feature update can restore the 'UCPD velocity'" -ForegroundColor Yellow
    Write-Host "    scheduled task, which then re-enables UCPD on next logon." -ForegroundColor Yellow
    Write-Host "  - ViVeTool feature toggles (44860385, 43229420, 27623730) may" -ForegroundColor Yellow
    Write-Host "    be reset by Windows A/B testing, especially on 24H2+." -ForegroundColor Yellow
    Write-Host "  - If BrowserTamer stops intercepting links after an update," -ForegroundColor Yellow
    Write-Host "    re-run this script. It is fully idempotent." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "REGISTRY BACKUPS" -ForegroundColor White
    Write-Host "  Backups (.reg files) were saved to:" -ForegroundColor White
    Write-Host "    $backupDir" -ForegroundColor White
    Write-Host ""
    Write-Host "  To restore BrowserTamer registration:" -ForegroundColor White
    Write-Host "    Double-click: BrowserTamerHTM.reg, BrowserTamerPDF.reg, x-bt.reg," -ForegroundColor White
    Write-Host "                  StartMenuInternet.reg, RegisteredApplications.reg" -ForegroundColor White
    Write-Host ""
    Write-Host "  To restore your PREVIOUS default browser:" -ForegroundColor White
    Write-Host "    Double-click: UserChoice-http.reg, UserChoice-https.reg" -ForegroundColor White
    Write-Host "    CAUTION: Windows may block restoring UserChoice keys directly." -ForegroundColor Yellow
    Write-Host "    If import is blocked, use Settings > Apps > Default apps instead." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  If the picker does not appear and a browser opens directly:" -ForegroundColor Yellow
    Write-Host "    1. Delete  %LOCALAPPDATA%\bt\config.ini" -ForegroundColor Yellow
    Write-Host "    2. Re-run this script" -ForegroundColor Yellow
    Write-Host "    3. When BrowserTamer opens, click 'Discover system browsers'," -ForegroundColor Yellow
    Write-Host "       then 'File' > 'Save configuration', then 'File' > 'Exit'" -ForegroundColor Yellow
    Wait-ForEnter
    exit 0
}
catch {
    Fail-AndExit $_.Exception.Message
}
