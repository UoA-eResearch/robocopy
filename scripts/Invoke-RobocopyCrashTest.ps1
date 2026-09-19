<#
.SYNOPSIS
  Reproduce a robocopy crash caused by an SMB session reset landing mid-file, and compare
  restartable mode (/Z) with a standard copy.

.DESCRIPTION
  Field observation: when a network device resets the SMB TCP connections of a large copy,
  robocopy running with /Z sometimes dies outright - no error line, no summary table,
  exit code -1073741819 (0xC0000005) and an Application log Event 1000 for robocopy.exe.
  Without /Z the same reset is reported as "ERROR 59 (0x0000003B) An unexpected network
  error occurred" and robocopy retries.

  This script recreates the conditions on one machine:
    1. creates an SMB share and a large random source file,
    2. runs robocopy from the local source to \\127.0.0.1\<share> (with or without /Z),
    3. when robocopy has written a chosen percentage of the big file, disrupts the SMB
       session for a few seconds (TCP reset storm on port 445, forced SMB session
       closes, or a Server-service restart),
    4. records exit code, log, summary-table presence, error/retry lines, destination
       hash, Application/SMB event-log entries and any crash dump.

  Run it as Administrator. Results are written to -OutputDir as trial-N/ folders plus
  results.json, which scripts/Write-Comparison.ps1 turns into a comparison table.
#>
[CmdletBinding()]
param(
    [ValidateSet('restartable', 'standard')]
    [string]$Mode = 'restartable',

    [ValidateSet('tcp-reset-storm', 'smb-session-close', 'server-restart', 'none')]
    [string]$Disruption = 'tcp-reset-storm',

    [int]$Trials = 3,
    [int]$FileSizeMB = 512,
    [int]$SmallFiles = 10,
    # Trial i disrupts at TriggerPercents[(i-1) mod n] percent of the big file.
    [int[]]$TriggerPercents = @(25, 50, 75),
    # How long the disruption keeps hitting the connection. Should exceed /W so that at
    # least one robocopy retry lands inside the disruption window.
    [int]$StormSeconds = 12,
    [string]$RetryArgs = '/R:5 /W:5',
    [string]$ExtraArgs = '',
    [string]$Label = $env:COMPUTERNAME,
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) 'robocopy-crash'),
    [string]$OutputDir = (Join-Path (Get-Location) 'results'),
    [string]$ShareName = 'rccrash',
    [string]$ServerName = '127.0.0.1',
    # Seconds to wait for the write threshold before disrupting anyway.
    [int]$TriggerTimeoutSeconds = 90,
    # Seconds to wait for robocopy to finish after the disruption.
    [int]$CompletionTimeoutSeconds = 600,
    # auto: attach Sysinternals ProcDump only when Windows Error Reporting is disabled by policy
    # on this machine. on: always attach (gives a dump even where WER is off, but a debugger
    # being attached means WER never runs, so no Event 1000). off: rely on WER LocalDumps.
    [ValidateSet('auto', 'on', 'off')]
    [string]$ProcDump = 'auto',
    [switch]$KeepShare
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step([string]$Message) {
    Write-Host ("[{0:HH:mm:ss.fff}] {1}" -f (Get-Date), $Message)
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EnvironmentInfo {
    $rc = Get-Item (Join-Path $env:SystemRoot 'System32\robocopy.exe')
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        label            = $Label
        computerName     = $env:COMPUTERNAME
        osProductName    = $cv.ProductName
        osDisplayVersion = $cv.DisplayVersion
        osBuild          = ('{0}.{1}' -f $cv.CurrentBuildNumber, $cv.UBR)
        robocopyPath     = $rc.FullName
        robocopyVersion  = $rc.VersionInfo.FileVersion
        robocopyProduct  = $rc.VersionInfo.ProductVersion
        robocopySize     = $rc.Length
        robocopySha256   = (Get-FileHash $rc.FullName -Algorithm SHA256).Hash
        powershell       = $PSVersionTable.PSVersion.ToString()
        isAdmin          = (Test-IsAdmin)
        smbClientConfig  = (Get-SmbClientConfiguration | Select-Object EnableMultiChannel, RequireSecuritySignature, EnableSecuritySignature, SessionTimeout, ExtendedSessionTimeout, DirectoryCacheLifetime | ConvertTo-Json -Compress)
        timestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Initialize-Helpers {
    if (-not ('RcNet' -as [type])) {
        Write-Step 'Compiling native helpers'
        Add-Type -Path (Join-Path $script:ScriptDir 'RobocopyCrashHelpers.cs')
    }
}

function Initialize-Share([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    Start-Service LanmanServer -ErrorAction SilentlyContinue
    if (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue) {
        Remove-SmbShare -Name $ShareName -Force -Confirm:$false
    }
    New-SmbShare -Name $ShareName -Path $Path -FullAccess 'Everyone' -CachingMode None | Out-Null
    $unc = "\\$ServerName\$ShareName"
    Write-Step "Share $unc -> $Path"
    # Prove the share is reachable over the loopback SMB path before starting.
    $probe = Join-Path $unc '.probe'
    Set-Content -Path $probe -Value 'ok'
    Remove-Item $probe -Force
    $conn = Get-SmbConnection -ServerName $ServerName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) { Write-Step ("SMB connection: dialect {0}, user {1}" -f $conn.Dialect, $conn.UserName) }
    $tcp = [RcNet]::CountConnections(445)
    Write-Step "Client-side TCP connections to port 445: $tcp"
    return $unc
}

function Initialize-SourceData([string]$Src, [int]$SizeMB, [int]$SmallCount) {
    $big = Join-Path $Src 'big.bin'
    if ((Test-Path $big) -and ((Get-Item $big).Length -eq ($SizeMB * 1MB))) { return $big }
    Write-Step "Generating $SizeMB MB random source file"
    New-Item -ItemType Directory -Force -Path $Src, (Join-Path $Src 'small') | Out-Null
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $chunk = New-Object byte[] 1MB
    $rng.GetBytes($chunk)
    $fs = [IO.File]::Create($big)
    try {
        for ($i = 0; $i -lt $SizeMB; $i++) {
            # Stamp each chunk with its index so a resume at the wrong offset changes the hash.
            [BitConverter]::GetBytes([int64]$i).CopyTo($chunk, 0)
            $fs.Write($chunk, 0, $chunk.Length)
        }
    } finally { $fs.Dispose() }
    for ($i = 1; $i -le $SmallCount; $i++) {
        $p = Join-Path $Src ('small\file{0:D3}.bin' -f $i)
        [BitConverter]::GetBytes([int64](1000 + $i)).CopyTo($chunk, 0)
        [IO.File]::WriteAllBytes($p, $chunk)
    }
    return $big
}

function Initialize-CrashDumps([string]$DumpDir) {
    New-Item -ItemType Directory -Force -Path $DumpDir | Out-Null
    # WER LocalDumps: full user-mode dump of robocopy.exe on an unhandled exception.
    $wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    New-Item -Path $wer -Force | Out-Null
    Set-ItemProperty -Path $wer -Name DontShowUI -Value 1 -Type DWord
    Set-ItemProperty -Path $wer -Name Disabled -Value 0 -Type DWord
    $ld = Join-Path $wer 'LocalDumps\robocopy.exe'
    New-Item -Path $ld -Force | Out-Null
    Set-ItemProperty -Path $ld -Name DumpFolder -Value $DumpDir -Type ExpandString
    Set-ItemProperty -Path $ld -Name DumpCount -Value 10 -Type DWord
    Set-ItemProperty -Path $ld -Name DumpType -Value 2 -Type DWord
    $policyDisabled = $false
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
    if (Test-Path $pol) {
        $v = (Get-ItemProperty $pol -ErrorAction SilentlyContinue).PSObject.Properties['Disabled']
        if ($v -and $v.Value -eq 1) {
            $policyDisabled = $true
            Write-Warning 'Windows Error Reporting is disabled by policy; re-enabling it for this run'
            try { Set-ItemProperty -Path $pol -Name Disabled -Value 0 -Type DWord } catch { }
        }
    }
    $svc = Get-Service WerSvc -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq 'Disabled') {
        Write-Warning 'WerSvc is disabled; setting it to Manual'
        try { Set-Service WerSvc -StartupType Manual } catch { }
    }
    # Make sure robocopy inherits the default error mode so an access violation reaches WER.
    $prevMode = [RcIo]::ResetErrorMode()
    Write-Step ("Error mode was 0x{0:X} (now 0); WER policy-disabled: {1}; WerSvc: {2}" -f $prevMode, $policyDisabled, $(if ($svc) { $svc.StartType } else { 'missing' }))
    return [ordered]@{ policyDisabled = $policyDisabled; werSvcStartType = $(if ($svc) { $svc.StartType.ToString() } else { $null }); previousErrorMode = ('0x{0:X}' -f $prevMode) }
}

function Get-ProcDump([string]$ToolDir) {
    New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
    $exe = Join-Path $ToolDir 'procdump64.exe'
    if (Test-Path $exe) { return $exe }
    try {
        Write-Step 'Downloading Sysinternals ProcDump'
        $zip = Join-Path $ToolDir 'Procdump.zip'
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Procdump.zip' -OutFile $zip -TimeoutSec 60
        Expand-Archive -Path $zip -DestinationPath $ToolDir -Force
        if (Test-Path $exe) { return $exe }
    } catch {
        Write-Warning "ProcDump unavailable ($($_.Exception.Message)); relying on WER LocalDumps only"
    }
    return $null
}

function Invoke-Disruption([string]$Kind, [int]$Seconds) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    switch ($Kind) {
        'tcp-reset-storm' {
            # Abort every client-side TCP connection to port 445 every 2 ms for the window.
            $r = [RcNet]::Storm(445, $Seconds * 1000, 2, $false)
            $first = if ($r.Records.Count) { $r.Records[0].ElapsedMs } else { $null }
            return [ordered]@{
                kind = $Kind; durationMs = $r.DurationMs; iterations = $r.Iterations
                resets = $r.Resets; failures = $r.Failures; firstResetMs = $first
                sample = @($r.Records | Select-Object -First 25 | ForEach-Object {
                        [ordered]@{ t = $_.ElapsedMs; local = "$($_.LocalAddr):$($_.LocalPort)"; remote = "$($_.RemoteAddr):$($_.RemotePort)"; state = $_.State; result = $_.Result } })
            }
        }
        'smb-session-close' {
            $closed = 0; $iterations = 0
            while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
                $iterations++
                foreach ($s in @(Get-SmbSession -ErrorAction SilentlyContinue)) {
                    try { Close-SmbSession -SessionId $s.SessionId -Force -Confirm:$false -ErrorAction Stop; $closed++ } catch { }
                }
                Start-Sleep -Milliseconds 50
            }
            return [ordered]@{ kind = $Kind; durationMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); iterations = $iterations; sessionsClosed = $closed }
        }
        'server-restart' {
            Restart-Service LanmanServer -Force
            $restartMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
            Start-Sleep -Seconds $Seconds
            return [ordered]@{ kind = $Kind; durationMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); serviceRestartMs = $restartMs }
        }
        default {
            Start-Sleep -Seconds $Seconds
            return [ordered]@{ kind = 'none'; durationMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1) }
        }
    }
}

function Read-RobocopyLog([string]$Path) {
    $raw = if (Test-Path $Path) { [IO.File]::ReadAllText($Path) } else { '' }
    $lines = $raw -split "[\r\n]+" | Where-Object { $_.Trim() -ne '' }
    $errors = @($lines | Where-Object { $_ -match '^\s*\d{4}/\d\d/\d\d \d\d:\d\d:\d\d ERROR (\d+) \(0x[0-9A-Fa-f]+\)' })
    $errorCodes = @($errors | ForEach-Object { if ($_ -match 'ERROR (\d+) \(') { [int]$Matches[1] } } | Group-Object | ForEach-Object { [ordered]@{ code = [int]$_.Name; count = $_.Count } })
    $errorText = @($lines | Where-Object { $_ -match '^\s*(An unexpected|The specified network|The network|The semaphore|The handle|The I/O|Access is denied|The system cannot)' } | Select-Object -Unique)
    $retries = @($lines | Where-Object { $_ -match 'Retrying\.\.\.' }).Count
    $retryLimit = [bool]($lines | Where-Object { $_ -match 'RETRY LIMIT EXCEEDED' })
    $summaryHeader = [bool]($lines | Where-Object { $_ -match '^\s*Total\s+Copied\s+Skipped\s+Mismatch\s+FAILED\s+Extras' })
    $ended = [bool]($lines | Where-Object { $_ -match '^\s*Ended : ' })
    $summary = @{}
    foreach ($row in $(if ($summaryHeader) { 'Dirs', 'Files', 'Bytes' } else { @() })) {
        $m = $lines | Where-Object { $_ -match ("^\s*{0}\s*:\s+(.+)$" -f $row) } | Select-Object -Last 1
        if ($m -and $m -match ("^\s*{0}\s*:\s+(.+)$" -f $row)) { $summary[$row] = ($Matches[1] -replace '\s+', ' ').Trim() }
    }
    $pct = $null
    $pctMatches = [regex]::Matches($raw, '(\d{1,3}(?:\.\d)?)%')
    if ($pctMatches.Count) { $pct = [double]$pctMatches[$pctMatches.Count - 1].Groups[1].Value }
    $pctBeforeFirstError = $null
    if ($errors.Count) {
        $idx = $raw.IndexOf($errors[0])
        if ($idx -gt 0) {
            $before = [regex]::Matches($raw.Substring(0, $idx), '(\d{1,3}(?:\.\d)?)%')
            if ($before.Count) { $pctBeforeFirstError = [double]$before[$before.Count - 1].Groups[1].Value }
        }
    }
    $tail = @($lines | Select-Object -Last 12)
    [ordered]@{
        lines               = $lines.Count
        errorLines          = $errors.Count
        errorCodes          = $errorCodes
        errorMessages       = $errorText
        retries             = $retries
        retryLimitExceeded  = $retryLimit
        summaryTablePresent = $summaryHeader
        endedLinePresent    = $ended
        summary             = $summary
        lastProgressPercent = $pct
        progressBeforeFirstError = $pctBeforeFirstError
        firstErrorLine      = $(if ($errors.Count) { $errors[0].Trim() } else { $null })
        tail                = $tail
    }
}

function Get-EventsSince([datetime]$Since, [string]$OutFile) {
    $logs = @(
        'Application',
        'Microsoft-Windows-SMBClient/Connectivity', 'Microsoft-Windows-SMBClient/Operational', 'Microsoft-Windows-SMBClient/Security',
        'Microsoft-Windows-SMBServer/Connectivity', 'Microsoft-Windows-SMBServer/Operational', 'Microsoft-Windows-SMBServer/Security',
        'Microsoft-Windows-WER-Diag/Operational'
    )
    $all = @()
    foreach ($log in $logs) {
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $Since } -ErrorAction Stop
            if ($log -eq 'Application') { $ev = $ev | Where-Object { ($_.ProviderName -in @('Application Error', 'Windows Error Reporting', 'Application Hang')) -or ($_.Message -match 'robocopy') } }
            $all += @($ev | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('o'); log = $log; id = $_.Id; level = $_.LevelDisplayName; provider = $_.ProviderName; message = $_.Message } })
        } catch { }
    }
    $all = @($all | Sort-Object { $_.time })
    $all | ForEach-Object { "{0} [{1}] {2} {3} ({4})`n{5}`n" -f $_.time, $_.log, $_.id, $_.level, $_.provider, $_.message } | Set-Content -Path $OutFile -Encoding UTF8
    $appErrors = @($all | Where-Object { ($_.log -eq 'Application') -and ($_.id -in @(1000, 1001)) -and ($_.message -match 'robocopy') })
    [ordered]@{
        total              = $all.Count
        byLog              = @($all | Group-Object log | ForEach-Object { [ordered]@{ log = $_.Name; count = $_.Count; ids = @($_.Group | Group-Object id | ForEach-Object { "$($_.Name)x$($_.Count)" }) } })
        applicationErrors  = @($appErrors | ForEach-Object { [ordered]@{ id = $_.id; time = $_.time; message = ($_.message -replace '\s+', ' ').Substring(0, [math]::Min(600, ($_.message -replace '\s+', ' ').Length)) } })
        event1000Present   = [bool]($appErrors | Where-Object { $_.id -eq 1000 })
    }
}

function Get-FaultInfo($AppErrors) {
    # Event 1000 message: "Faulting application name: robocopy.exe, version: ..., Exception code: 0xc0000005, Fault offset: ..., Faulting module name: ..."
    foreach ($e in $AppErrors) {
        if ($e.id -ne 1000) { continue }
        $m = $e.message
        $info = [ordered]@{}
        if ($m -match 'Exception code:\s*(0x[0-9a-fA-F]+)') { $info.exceptionCode = $Matches[1] }
        if ($m -match 'Faulting module name:\s*([^,]+)') { $info.faultingModule = $Matches[1].Trim() }
        if ($m -match 'Fault offset:\s*(0x[0-9a-fA-F]+)') { $info.faultOffset = $Matches[1] }
        if ($m -match 'version:\s*([0-9.]+)') { $info.appVersion = $Matches[1] }
        return $info
    }
    return $null
}

# ---------------------------------------------------------------------------------------

if (-not (Test-IsAdmin)) { throw 'Run this script from an elevated (Administrator) session.' }

Initialize-Helpers
New-Item -ItemType Directory -Force -Path $WorkDir, $OutputDir | Out-Null
$srcDir = Join-Path $WorkDir 'src'
$dstDir = Join-Path $WorkDir 'dst'
$dumpDir = Join-Path $WorkDir 'dumps'
$toolDir = Join-Path $WorkDir 'tools'

$envInfo = Get-EnvironmentInfo
$envInfo.mode = $Mode; $envInfo.disruption = $Disruption
Write-Step ("{0} build {1}, robocopy {2}" -f $envInfo.osProductName, $envInfo.osBuild, $envInfo.robocopyVersion)

$werInfo = Initialize-CrashDumps $dumpDir
$useProcDump = ($ProcDump -eq 'on') -or (($ProcDump -eq 'auto') -and $werInfo.policyDisabled)
$procdumpExe = if ($useProcDump) { Get-ProcDump $toolDir } else { $null }
$envInfo.wer = $werInfo; $envInfo.procDumpMode = $ProcDump; $envInfo.procDumpAttached = [bool]$procdumpExe
$envInfo | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDir 'environment.json')
$big = Initialize-SourceData $srcDir $FileSizeMB $SmallFiles
$bigHash = (Get-FileHash $big -Algorithm SHA256).Hash
$unc = Initialize-Share $dstDir

$modeArg = if ($Mode -eq 'restartable') { '/Z' } else { '' }
$results = @()

try {
    for ($t = 1; $t -le $Trials; $t++) {
        $pct = $TriggerPercents[($t - 1) % $TriggerPercents.Count]
        $trialDir = Join-Path $OutputDir ("trial-{0}" -f $t)
        New-Item -ItemType Directory -Force -Path $trialDir | Out-Null
        Get-ChildItem $dstDir -Force | Remove-Item -Recurse -Force
        Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Remove-Item -Force

        $log = Join-Path $trialDir 'robocopy.log'
        $errLog = Join-Path $trialDir 'robocopy.stderr.log'
        $argLine = ('"{0}" "{1}" /E /COPY:DAT /DCOPY:T {2} {3} {4}' -f $srcDir, $unc, $modeArg, $RetryArgs, $ExtraArgs) -replace '\s+', ' '
        $threshold = [uint64]($FileSizeMB * 1MB * $pct / 100)

        Write-Step ("=== Trial {0}/{1}: mode={2} disruption={3} trigger={4}% ({5:N0} bytes) ===" -f $t, $Trials, $Mode, $Disruption, $pct, $threshold)
        Write-Step "robocopy $argLine"
        $t0 = Get-Date
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $proc = Start-Process -FilePath 'robocopy.exe' -ArgumentList $argLine -PassThru -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError $errLog
        $pdProc = $null
        if ($procdumpExe) {
            # Second-chance (unhandled) exceptions produce a full dump via the debugger API,
            # independent of WER policy on the machine.
            $pdProc = Start-Process -FilePath $procdumpExe -ArgumentList ('-accepteula -e -ma {0} "{1}"' -f $proc.Id, $dumpDir) -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $trialDir 'procdump.log')
        }

        # Wait until robocopy has written the requested share of the big file.
        $triggered = $false; $written = [uint64]0; $destSizeAtTrigger = $null
        while (-not $proc.HasExited) {
            try { $written = [RcIo]::WriteBytes($proc) } catch { }
            if ($written -ge $threshold) { $triggered = $true; break }
            if ($sw.Elapsed.TotalSeconds -ge $TriggerTimeoutSeconds) { Write-Warning 'Trigger timeout - disrupting anyway'; $triggered = $true; break }
            Start-Sleep -Milliseconds 2
        }
        $triggerMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
        $disruptionInfo = $null
        if ($triggered) {
            try { $destSizeAtTrigger = (Get-Item (Join-Path $dstDir 'big.bin') -ErrorAction Stop).Length } catch { }
            Write-Step ("Trigger at {0} ms: robocopy has written {1:N0} bytes ({2:N1}% of big file), dest size {3}; starting {4} for {5}s" -f $triggerMs, $written, ($written * 100.0 / ($FileSizeMB * 1MB)), $destSizeAtTrigger, $Disruption, $StormSeconds)
            $disruptionInfo = Invoke-Disruption $Disruption $StormSeconds
            Write-Step ("Disruption finished: {0}" -f (($disruptionInfo | ConvertTo-Json -Compress -Depth 3) -replace '"sample":\[.*\]', '"sample":[...]'))
        } else {
            Write-Warning ("robocopy exited after {0} ms before reaching the trigger ({1:N0} bytes written). Use a larger -FileSizeMB." -f $triggerMs, $written)
        }

        if (-not $proc.WaitForExit($CompletionTimeoutSeconds * 1000)) {
            Write-Warning 'robocopy did not finish in time; killing it'
            $proc.Kill()
            $proc.WaitForExit()
            $timedOut = $true
        } else { $timedOut = $false }
        $sw.Stop()
        $exitCode = $proc.ExitCode
        if ($pdProc) { $pdProc.WaitForExit(30000) | Out-Null; if (-not $pdProc.HasExited) { $pdProc.Kill() } }
        Start-Sleep -Seconds 3   # let WER / event log catch up

        $logInfo = Read-RobocopyLog $log
        $dstBig = Join-Path $dstDir 'big.bin'
        $dstHash = if (Test-Path $dstBig) { (Get-FileHash $dstBig -Algorithm SHA256).Hash } else { $null }
        $dstSize = if (Test-Path $dstBig) { (Get-Item $dstBig).Length } else { 0 }
        $events = Get-EventsSince $t0 (Join-Path $trialDir 'events.txt')
        $dumps = @(Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue)
        $dumpNames = @()
        foreach ($d in $dumps) {
            $dest = Join-Path $trialDir $d.Name
            Move-Item $d.FullName $dest -Force
            $dumpNames += $d.Name
        }
        Copy-Item (Join-Path $OutputDir 'environment.json') $trialDir -Force

        $crashed = ($exitCode -lt 0) -or ($exitCode -gt 16)
        $outcome = if ($timedOut) { 'timeout' }
                   elseif ($crashed) { 'crash' }
                   elseif ($exitCode -ge 8) { 'failed' }
                   elseif ($logInfo.errorLines -gt 0) { 'recovered' }
                   else { 'clean' }

        $result = [ordered]@{
            label                = $Label
            mode                 = $Mode
            restartable          = ($Mode -eq 'restartable')
            disruption           = $Disruption
            trial                = $t
            startedUtc           = $t0.ToUniversalTime().ToString('o')
            commandLine          = "robocopy $argLine"
            fileSizeMB           = $FileSizeMB
            triggerPercent       = $pct
            triggered            = $triggered
            triggerMs            = $triggerMs
            bytesWrittenAtTrigger = $written
            percentWrittenAtTrigger = [math]::Round($written * 100.0 / ($FileSizeMB * 1MB), 1)
            destSizeAtTrigger    = $destSizeAtTrigger
            disruptionInfo       = $disruptionInfo
            durationMs           = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
            exitCode             = $exitCode
            exitCodeHex          = ('0x{0:X8}' -f [int32]$exitCode)
            timedOut             = $timedOut
            crashed              = $crashed
            outcome              = $outcome
            log                  = $logInfo
            destHashMatches      = ($dstHash -eq $bigHash)
            destSize             = $dstSize
            events               = $events
            faultInfo            = (Get-FaultInfo $events.applicationErrors)
            dumps                = $dumpNames
            procdumpAttached     = [bool]$pdProc
        }
        $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $trialDir 'trial.json')
        $results += $result

        Write-Step ("Trial {0} result: outcome={1} exit={2} ({3}) summaryTable={4} errors={5} retries={6} hashOK={7} event1000={8} dumps={9}" -f $t, $outcome, $exitCode, $result.exitCodeHex, $logInfo.summaryTablePresent, $logInfo.errorLines, $logInfo.retries, $result.destHashMatches, $events.event1000Present, $dumpNames.Count)
        if ($logInfo.firstErrorLine) { Write-Step ("First error: {0}" -f $logInfo.firstErrorLine) }
        Write-Host '--- log tail ---'; $logInfo.tail | ForEach-Object { Write-Host "  $_" }; Write-Host '----------------'
    }
} finally {
    if (-not $KeepShare) { Remove-SmbShare -Name $ShareName -Force -Confirm:$false -ErrorAction SilentlyContinue }
}

$results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDir 'results.json')
Write-Step ("Done: {0} trials, {1} crash(es), {2} with errors, results in {3}" -f $results.Count, @($results | Where-Object { $_.crashed }).Count, @($results | Where-Object { $_.log.errorLines -gt 0 }).Count, $OutputDir)
