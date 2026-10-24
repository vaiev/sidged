# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# open-sidged-app.ps1: open the Sidged UI in Edge or Chrome app mode
# (turnkey WP e).
#
#   .\scripts\open-sidged-app.ps1            opens ui\shell\index.html (file://)
#   .\scripts\open-sidged-app.ps1 -Url <u>   only http:// + a loopback IP literal
#                                            (127.x.y.z or [::1]) + an explicit
#                                            port, optional plain path; no
#                                            hostname (not even localhost), no
#                                            userinfo, query or fragment.
#                                            Anything else exits 2.
#   -Print                                   print the command, do not start it.
#
# The temporary profile is removed when the browser process returns.
# Forking launchers (snap/flatpak wrappers) may lose it while the browser runs.
# A successful return within 2 s warns about this possible launcher fork.
# -Print uses <temporary-profile-dir> instead of a disposable path.
#
# Nothing here opens a listener.
param(
    [string]$Url = "",
    [switch]$Print
)
$ErrorActionPreference = "Stop"

function Refuse([string]$Why) {
    [Console]::Error.WriteLine("open-sidged-app: refused: $Why (only http://<loopback IP literal>:<port>[/path])")
    exit 2
}

if ($Url -ne "") {
    $m = [regex]::Match($Url, '^http://(\[::1\]|[0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?\z')
    if (-not $m.Success) { Refuse "not http:// with a loopback IP literal and a port" }
    $hostPart = $m.Groups[1].Value
    $port = $m.Groups[3].Value
    $rest = $m.Groups[4].Value
    if ($hostPart -ne "[::1]") {
        $octets = $hostPart.Split(".")
        if ($octets[0] -ne "127") { Refuse "host is not a loopback address" }
        foreach ($o in $octets) {
            if ($o -notmatch '^(0|[1-9][0-9]{0,2})\z' -or [int]$o -gt 255) { Refuse "invalid IPv4 literal" }
        }
    }
    if ($port -notmatch '^[1-9][0-9]{0,4}\z' -or [int]$port -gt 65535) { Refuse "port must be 1-65535" }
    if ($rest.Contains("..")) { Refuse "path must not contain .." }
    $target = $Url
} else {
    $shell = Join-Path (Split-Path -Parent $PSScriptRoot) "ui/shell/index.html"
    if (-not $Print -and -not (Test-Path -LiteralPath $shell -PathType Leaf)) {
        [Console]::Error.WriteLine("open-sidged-app: $shell not found (the offline UI shell)")
        exit 1
    }
    $target = ([System.Uri]([System.IO.Path]::GetFullPath($shell))).AbsoluteUri
}

$browser = $null
foreach ($candidate in @("msedge.exe", "msedge", "chrome.exe", "google-chrome", "chromium")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $browser = $candidate; break }
}
if (-not $browser) { $browser = "msedge.exe" }

$profileDir = "<temporary-profile-dir>"
if (-not $Print) {
    $profileDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    [System.IO.Directory]::CreateDirectory($profileDir) | Out-Null
}
try {
    $arguments = @("--app=$target", "--user-data-dir=$profileDir", "--no-first-run", "--no-default-browser-check", "--window-size=1340,880")
    if ($Print) {
        Write-Output ("$browser " + ($arguments -join " "))
        exit 0
    }
    if (-not (Get-Command $browser -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("open-sidged-app: no Edge or Chrome found; open $target yourself")
        exit 3
    }
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $browser -ArgumentList $arguments -Wait -PassThru
    $timer.Stop()
    $status = $process.ExitCode
} finally {
    if (-not $Print) { Remove-Item -LiteralPath $profileDir -Recurse -Force }
}

if ($status -eq 0 -and $timer.Elapsed.TotalSeconds -lt 2) {
    [Console]::Error.WriteLine("open-sidged-app: warning: launcher forked and the temporary profile was removed (possible: browser returned within 2 s)")
}
exit $status
