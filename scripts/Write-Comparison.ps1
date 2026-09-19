<#
.SYNOPSIS
  Turn trial.json files produced by Invoke-RobocopyCrashTest.ps1 into a Markdown comparison
  of restartable (/Z) versus standard robocopy runs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResultsDir,
    [string]$OutFile,
    [switch]$StepSummary
)

$ErrorActionPreference = 'Stop'

$trials = @(Get-ChildItem -Path $ResultsDir -Recurse -Filter trial.json | ForEach-Object {
        $t = Get-Content $_.FullName -Raw | ConvertFrom-Json
        $dir = $_.DirectoryName
        $analysis = Get-ChildItem -Path $dir -Filter '*.analysis.json' -ErrorAction SilentlyContinue | Select-Object -First 1
        $t | Add-Member -NotePropertyName analysis -NotePropertyValue $(if ($analysis) { Get-Content $analysis.FullName -Raw | ConvertFrom-Json } else { $null }) -Force
        $envFile = Join-Path $dir 'environment.json'
        $t | Add-Member -NotePropertyName environment -NotePropertyValue $(if (Test-Path $envFile) { Get-Content $envFile -Raw | ConvertFrom-Json } else { $null }) -Force
        $t
    } | Sort-Object label, disruption, @{ Expression = { if ($_.restartable) { 0 } else { 1 } } }, trial)

$md = New-Object Text.StringBuilder
function L([string]$s = '') { [void]$md.AppendLine($s) }
function Yn($b) { if ($b) { 'yes' } else { 'no' } }
function Prop($o, [string]$name) { if ($null -ne $o -and $o.PSObject.Properties[$name]) { $o.$name } else { $null } }

if (-not $trials) {
    L '## Robocopy /Z crash reproduction'
    L
    L "No trial results were found under ``$ResultsDir``."
} else {
    L '## Robocopy /Z crash reproduction: restartable (/Z) vs standard'
    L
    $envs = @($trials | ForEach-Object { $_.environment } | Where-Object { $_ } | Group-Object label)
    if ($envs) {
        L '| Runner | OS | Build | Arch | robocopy.exe version |'
        L '|---|---|---|---|---|'
        foreach ($g in $envs) { $e = $g.Group[0]; L ("| {0} | {1} {2} | {3} | {4} | {5} |" -f $e.label, $e.osProductName, $e.osDisplayVersion, $e.osBuild, (Prop $e 'architecture'), $e.robocopyVersion) }
        L
    }

    L '### Outcome by mode'
    L
    L 'A *crash* is an exit code outside robocopy''s 0-16 range (for example -1073741819 = 0xC0000005) or a run that ended without printing its summary table. *Recovered* means robocopy logged errors and retried but finished with exit code < 8.'
    L
    L '| Mode | Trials | Crashed | Failed (exit >= 8) | Recovered after errors | Clean (no error seen) | Dest hash OK | Event 1000 | Dumps |'
    L '|---|---|---|---|---|---|---|---|---|'
    foreach ($g in ($trials | Group-Object restartable | Sort-Object { -[int][bool]::Parse($_.Name) })) {
        $rows = $g.Group
        $name = if ([bool]::Parse($g.Name)) { 'restartable (`/Z`)' } else { 'standard (no `/Z`)' }
        L ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |" -f $name, $rows.Count,
            @($rows | Where-Object outcome -eq 'crash').Count,
            @($rows | Where-Object outcome -eq 'failed').Count,
            @($rows | Where-Object outcome -eq 'recovered').Count,
            @($rows | Where-Object outcome -eq 'clean').Count,
            @($rows | Where-Object destHashMatches).Count,
            @($rows | Where-Object { $_.events.event1000Present }).Count,
            @($rows | Where-Object { $_.dumps.Count -gt 0 }).Count)
    }
    L

    L '### Outcome by runner, disruption and mode'
    L
    L '| Runner | Disruption | Mode | Trials | Crashed | Failed | Recovered | Clean | Errors logged (total) | Retries (total) |'
    L '|---|---|---|---|---|---|---|---|---|---|'
    foreach ($g in ($trials | Group-Object label, disruption, restartable | Sort-Object { $_.Group[0].label }, { $_.Group[0].disruption }, { -[int][bool]$_.Group[0].restartable })) {
        $rows = $g.Group; $r = $rows[0]
        L ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |" -f $r.label, $r.disruption, $(if ($r.restartable) { '`/Z`' } else { 'none' }), $rows.Count,
            @($rows | Where-Object outcome -eq 'crash').Count, @($rows | Where-Object outcome -eq 'failed').Count,
            @($rows | Where-Object outcome -eq 'recovered').Count, @($rows | Where-Object outcome -eq 'clean').Count,
            ($rows | Measure-Object -Property { $_.log.errorLines } -Sum).Sum, ($rows | Measure-Object -Property { $_.log.retries } -Sum).Sum)
    }
    L

    L '### Every trial'
    L
    L '| Runner | Disruption | Mode | Trial | Disrupted at | Resets / closes | Exit code | Outcome | Summary table | Errors | Retries | Progress before 1st error | Hash OK | Event 1000 | Dump analysis |'
    L '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|'
    foreach ($t in $trials) {
        $di = $t.disruptionInfo
        $hits = if ($null -eq $di) { '-' }
                elseif ($null -ne (Prop $di 'resets')) { "$($di.resets) RST" + $(if ((Prop $di 'graceMs')) { " (grace $($di.graceMs) ms)" } else { '' }) }
                elseif ($null -ne (Prop $di 'sessionsClosed')) { "$($di.sessionsClosed) closes" }
                elseif ($null -ne (Prop $di 'serviceRestartMs')) { 'service restart' } else { '-' }
        $at = if ($t.triggered) { ("{0}% ({1} ms)" -f $t.percentWrittenAtTrigger, $t.triggerMs) } else { 'not reached' }
        $errs = if ($t.log.errorLines) { ("{0} ({1})" -f $t.log.errorLines, (($t.log.errorCodes | ForEach-Object { "ERROR $($_.code)x$($_.count)" }) -join ', ')) } else { '0' }
        $an = $t.analysis
        $fi = $t.faultInfo
        $crashDetail = if ($an -and (Prop $an 'analysed')) { ('{0} in {1} `{2}`' -f $an.exceptionCode, $an.moduleName, $an.symbolName) }
                       elseif ($fi) { ("{0} in {1} +{2}" -f (Prop $fi 'exceptionCode'), (Prop $fi 'faultingModule'), (Prop $fi 'faultOffset')) }
                       elseif ($t.dumps.Count) { 'dump (unanalysed)' } else { '-' }
        $outcome = switch ($t.outcome) { 'crash' { '**CRASH**' } 'failed' { 'failed' } 'recovered' { 'recovered' } 'clean' { 'clean' } default { $t.outcome } }
        L ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} ({7}) | {8} | {9} | {10} | {11} | {12} | {13} | {14} | {15} |" -f $t.label, $t.disruption, $(if ($t.restartable) { '`/Z`' } else { 'none' }), $t.trial, $at, $hits,
            $t.exitCode, $t.exitCodeHex, $outcome, (Yn $t.log.summaryTablePresent), $errs, $t.log.retries,
            $(if ($null -ne $t.log.progressBeforeFirstError) { "$($t.log.progressBeforeFirstError)%" } else { '-' }),
            (Yn $t.destHashMatches), (Yn $t.events.event1000Present), $crashDetail)
    }
    L

    $crashes = @($trials | Where-Object outcome -eq 'crash')
    if ($crashes) {
        L '### Crash details'
        L
        foreach ($c in $crashes) {
            L ("#### {0} / {1} / {2} / trial {3}" -f $c.label, $c.disruption, $(if ($c.restartable) { '/Z' } else { 'no /Z' }), $c.trial)
            L
            L ("- Command: ``{0}``" -f $c.commandLine)
            L ("- Exit code {0} ({1}); summary table printed: {2}; ran {3} ms" -f $c.exitCode, $c.exitCodeHex, (Yn $c.log.summaryTablePresent), $c.durationMs)
            L ("- Last progress printed: {0}%" -f $c.log.lastProgressPercent)
            if ($c.faultInfo) { L ("- Event 1000: exception {0} in {1} at offset {2}" -f (Prop $c.faultInfo 'exceptionCode'), (Prop $c.faultInfo 'faultingModule'), (Prop $c.faultInfo 'faultOffset')) }
            if ($c.analysis -and (Prop $c.analysis 'analysed')) {
                L ("- Debugger: {0} ({1}) at ``{2}``; bucket ``{3}``" -f $c.analysis.exceptionCode, $c.analysis.exceptionCodeStr, $c.analysis.symbolName, $c.analysis.failureBucket)
                if ($c.analysis.stackText) { L; L '```'; $c.analysis.stackText | ForEach-Object { L $_ }; L '```' }
            }
            if ($c.log.tail) { L; L 'Log tail:'; L; L '```'; $c.log.tail | ForEach-Object { L $_ }; L '```' }
            L
        }
    }

    L '### Reading the result'
    L
    $z = @($trials | Where-Object restartable); $nz = @($trials | Where-Object { -not $_.restartable })
    $zc = @($z | Where-Object outcome -eq 'crash').Count; $nzc = @($nz | Where-Object outcome -eq 'crash').Count
    $zn = @($z | Where-Object { $_.log.errorLines -gt 0 -or $_.outcome -ne 'clean' }).Count
    $nzn = @($nz | Where-Object { $_.log.errorLines -gt 0 -or $_.outcome -ne 'clean' }).Count
    L ("- ``/Z``: {0} of {1} trials crashed; {2} saw the disruption at all (errors, retries or failure)." -f $zc, $z.Count, $zn)
    L ("- no ``/Z``: {0} of {1} trials crashed; {2} saw the disruption at all." -f $nzc, $nz.Count, $nzn)
    if ($zc -gt 0 -and $nzc -eq 0) { L; L '**Restartable mode crashed and standard mode did not: the crash path is specific to `/Z`.**' }
    elseif ($zc -eq 0 -and $nzc -eq 0) { L; L 'No crash reproduced in this run. If neither mode logged errors either, the disruption did not reach robocopy (the SMB redirector may have reconnected transparently): try a longer `storm_seconds`, a larger file, or the other disruption method.' }
    elseif ($zc -gt 0 -and $nzc -gt 0) { L; L 'Both modes crashed, so the failure is not specific to `/Z` in this environment.' }
    L
}

$text = $md.ToString()
if ($OutFile) { Set-Content -Path $OutFile -Value $text -Encoding UTF8; Write-Host "Wrote $OutFile" }
if ($StepSummary -and $env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $text -Encoding UTF8 }
if (-not $OutFile -and -not $StepSummary) { Write-Output $text }
