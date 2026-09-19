<#
.SYNOPSIS
  Analyse robocopy crash dumps found under a results directory with cdb (Debugging Tools for
  Windows) and write <dump>.analysis.txt / <dump>.analysis.json next to each dump.

.DESCRIPTION
  Looks for cdb.exe in the Windows Kits debugger folders; if it is missing, tries to install
  the Debugging Tools via Chocolatey. Symbols are pulled from the Microsoft public symbol
  server so the stack inside robocopy.exe resolves to function names.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResultsDir,
    [string]$SymbolCache = (Join-Path ([IO.Path]::GetTempPath()) 'symbols'),
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'

function Find-Cdb {
    $candidates = @()
    foreach ($root in @("${env:ProgramFiles(x86)}\Windows Kits", "$env:ProgramFiles\Windows Kits")) {
        if (Test-Path $root) {
            $candidates += Get-ChildItem -Path $root -Recurse -Filter cdb.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\Debuggers\\x64\\cdb\.exe$' } | Select-Object -ExpandProperty FullName
        }
    }
    if ($candidates) { return ($candidates | Sort-Object | Select-Object -Last 1) }
    $onPath = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$dumps = @(Get-ChildItem -Path $ResultsDir -Recurse -Filter *.dmp -ErrorAction SilentlyContinue)
if (-not $dumps) { Write-Host "No crash dumps under $ResultsDir - nothing to analyse."; exit 0 }
Write-Host ("Found {0} dump(s)" -f $dumps.Count)

$cdb = Find-Cdb
if (-not $cdb -and (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host 'cdb.exe not found; installing Debugging Tools for Windows via Chocolatey (best effort)'
    try { & choco install windbg -y --no-progress --limit-output | Out-Host } catch { Write-Warning $_ }
    $cdb = Find-Cdb
}
if (-not $cdb) {
    Write-Warning 'No debugger available; dumps are uploaded unanalysed.'
    foreach ($d in $dumps) { @{ dump = $d.Name; analysed = $false; reason = 'cdb.exe not available' } | ConvertTo-Json | Set-Content ($d.FullName + '.analysis.json') }
    exit 0
}
Write-Host "Using $cdb"
New-Item -ItemType Directory -Force -Path $SymbolCache | Out-Null
$sympath = "srv*$SymbolCache*https://msdl.microsoft.com/download/symbols"

foreach ($d in $dumps) {
    $txt = $d.FullName + '.analysis.txt'
    $json = $d.FullName + '.analysis.json'
    Write-Host "Analysing $($d.FullName) ($([math]::Round($d.Length / 1MB, 1)) MB)"
    $cmds = '.lines; .reload; !analyze -v; .ecxr; kvn 40; lmvm robocopy; !peb; ~*kvn 25; q'
    $p = Start-Process -FilePath $cdb -ArgumentList @('-z', ('"{0}"' -f $d.FullName), '-y', ('"{0}"' -f $sympath), '-c', ('"{0}"' -f $cmds)) -NoNewWindow -PassThru -RedirectStandardOutput $txt -RedirectStandardError ($d.FullName + '.analysis.err')
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { Write-Warning 'cdb timed out'; $p.Kill() }
    $out = if (Test-Path $txt) { Get-Content $txt -Raw } else { '' }

    function Field([string]$name) {
        if ($out -match ("(?m)^{0}:\s*(.+)$" -f [regex]::Escape($name))) { return $Matches[1].Trim() }
        return $null
    }
    $stack = $null
    if ($out -match '(?s)STACK_TEXT:\s*\r?\n(.*?)\r?\n\s*\r?\n') { $stack = ($Matches[1] -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $info = [ordered]@{
        dump              = $d.Name
        analysed          = $true
        debugger          = $cdb
        exceptionCode     = (Field 'EXCEPTION_CODE')
        exceptionCodeStr  = (Field 'EXCEPTION_CODE_STR')
        faultingIp        = $(if ($out -match '(?m)^FAULTING_IP:\s*\r?\n(.+)$') { $Matches[1].Trim() } else { $null })
        moduleName        = (Field 'MODULE_NAME')
        imageName         = (Field 'IMAGE_NAME')
        symbolName        = (Field 'SYMBOL_NAME')
        processName       = (Field 'PROCESS_NAME')
        failureBucket     = (Field 'FAILURE_BUCKET_ID')
        readAddress       = (Field 'READ_ADDRESS')
        writeAddress      = (Field 'WRITE_ADDRESS')
        errorCode         = (Field 'ERROR_CODE')
        stackText         = @($stack | Select-Object -First 30)
        osVersion         = (Field 'OSVERSION')
    }
    $info | ConvertTo-Json -Depth 4 | Set-Content $json
    Write-Host ("  exception {0} in {1} ({2}); bucket {3}" -f $info.exceptionCode, $info.moduleName, $info.symbolName, $info.failureBucket)
    if ($stack) { Write-Host '  stack:'; $stack | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" } }
}
