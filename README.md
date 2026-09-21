# robocopy `/Z` crash reproduction

A GitHub Actions workflow (Windows runners) that reproduces robocopy dying mid-copy when an
SMB session is reset while it is running in restartable mode (`/Z`), and compares the
behaviour with and without `/Z`.

## The problem

Large multi-file copies from a Windows 10 client to an SMB file server were failing while an
upstream network device kept injecting TCP resets into the client's SMB connections for
roughly ten seconds at a time. Two different failure modes were seen in the robocopy logs:

| Options | What happened |
|---|---|
| `/E /Z /R:5 /W:10` | `ERROR 59 (0x0000003B) An unexpected network error occurred`, then `Waiting 10 seconds... Retrying...`. Each retry reconnected, copied for about a second and was reset again. Robocopy stayed alive and eventually gave up or finished. |
| `/E /Z /R:5 /W:15` | **Robocopy crashed.** Twice, at 21 % and 54 % of a 450 MB file, the prompt came back mid-file with no error line and no summary table, which robocopy never does on a normal exit (even `RETRY LIMIT EXCEEDED` prints the summary). `$LASTEXITCODE` was `-1073741819` (`0xC0000005`, access violation) and the Application log had Event 1000 for `robocopy.exe`. |

The working hypothesis is that a session reset landing mid-file in restartable mode is the
crash path: the reopen-and-seek code that `/Z` uses to resume a partially copied file hits
an error it does not handle and the process dies. Nothing is printed because the code that
would print the error is in the dead process. Without `/Z` the same reset is an ordinary
error that robocopy reports and retries; the file restarts from zero on the next attempt.

That hypothesis is what this workflow tests.

## What the workflow does

`.github/workflows/robocopy-crash.yml` runs a matrix of Windows runner x disruption method x
mode (`restartable` = with `/Z`, `standard` = without). Each job runs
`scripts/Invoke-RobocopyCrashTest.ps1`, which on the runner:

1. Creates an SMB share on the runner and a large source file of random data (default 512 MB,
   each 1 MB chunk stamped with its index so a resume at the wrong offset changes the hash),
   plus a handful of small files.
2. Configures Windows Error Reporting LocalDumps so an unhandled exception in `robocopy.exe`
   leaves a full user-mode dump (and clears the inherited error mode so WER is reachable).
   If WER is disabled by policy on the machine, Sysinternals ProcDump is attached instead.
3. Runs `robocopy <src> \\127.0.0.1\<share> /E /COPY:DAT /DCOPY:T [/Z] /R:5 /W:5`
   and polls the process's I/O counters until it has written a chosen percentage of the big
   file (25 %, 50 % and 75 % on successive trials).
4. Disrupts the SMB session for `storm_seconds` (default 12 s, longer than `/W` so at least
   one retry lands inside the window):
   - `tcp-reset-storm` (default): every 2 ms, every client-side TCP connection to port 445 is
     aborted with `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)`, which sends a TCP RST to the peer.
     Each reconnect the SMB redirector makes is reset again, the same shape as a
     brute-force block on a network device. `reset_grace_ms` (default `0,10,100`, cycled per
     trial) lets each reconnect live that long before it is reset, so negotiate and
     authentication complete and the copy briefly resumes, as seen from a device that
     resets a few milliseconds after the authenticate.
     The storm only touches connections to the test server's address; the machine's other
     SMB sessions are left alone.
   - `smb-session-close`: `Close-SmbSession -Force` on the server side in a loop.
   - `server-restart`: restarts the Server (LanmanServer) service once.
   - `none`: control run.
   `server_profile: nas` first turns off oplocks, leasing, durable handles and multichannel on
   the loopback SMB server (and restores them afterwards), so it behaves like a NAS that offers
   none of those and the redirector cannot recover a reset transparently.
5. Waits for robocopy to exit and records, per trial: exit code (signed and hex), whether the
   summary table was printed, `ERROR n` lines and retry count, the last progress percentage
   printed before the first error, SHA-256 match of the destination file, Application log
   Events 1000/1001, SMB client/server event-log entries, the number of resets sent, and any
   crash dump.

`scripts/Invoke-DumpAnalysis.ps1` then runs `cdb` (`!analyze -v`, exception context, stacks)
with Microsoft public symbols over any dump, and `scripts/Write-Comparison.ps1` writes the
per-job summary. The final `compare` job merges every artifact into a single table in the
run summary and uploads it as `comparison.md`.

## Running it

**Actions > Robocopy /Z crash reproduction > Run workflow.** Defaults: `windows-2022`,
`windows-2025` and `windows-11-arm` (a Windows 11 client build, the closest hosted runner to the
Windows 10 client in the field), disruptions `tcp-reset-storm` and `smb-session-close`, 3 trials per job,
512 MB file, 12 s storm. Inputs let you change runners, disruption methods, number of trials,
trigger percentages, file size, storm length, retry options, extra robocopy options
(for example `/MT:8` or `/IPG:2`) and the dump-capture mode. The workflow also runs on
pushes that touch the workflow or `scripts/`.

Artifacts per job: `robocopy.log`, `robocopy.stderr.log`, `events.txt`, `trial.json`,
`environment.json` and, on a crash, `*.dmp` with `*.analysis.txt` / `*.analysis.json`.

### Running the harness by hand

On any Windows machine, from an elevated PowerShell (5.1 or 7):

```powershell
.\scripts\Invoke-RobocopyCrashTest.ps1 -Mode restartable -Disruption tcp-reset-storm -Trials 3 -OutputDir .\results-z
.\scripts\Invoke-RobocopyCrashTest.ps1 -Mode standard    -Disruption tcp-reset-storm -Trials 3 -OutputDir .\results-std
.\scripts\Invoke-DumpAnalysis.ps1 -ResultsDir .\results-z
.\scripts\Write-Comparison.ps1 -ResultsDir . -OutFile comparison.md
```

The harness creates a share called `rccrash`, writes WER LocalDumps registry values for
`robocopy.exe`, and removes the share when it finishes.

## Reading the comparison

- **Crashed**: exit code outside robocopy's 0 to 16 range, typically `-1073741819`
  (`0xC0000005`), with no summary table. The dump analysis column names the faulting
  function inside `robocopy.exe`.
- **Recovered**: robocopy logged `ERROR 59` / `ERROR 64` lines and retried, then finished with
  exit code below 8. This is the expected behaviour without `/Z`.
- **Failed**: exit code 8 or above (retries exhausted).
- **Clean**: no error at all. If both modes are clean, the disruption never reached robocopy
  (the SMB redirector reconnected transparently); use a longer `storm_seconds`, a larger
  file or the other disruption method.
- **Hash OK**: whether the destination file is byte-identical to the source, which checks
  that a `/Z` resume actually resumed at the right offset.

## Results so far

Three full runs on hosted runners (3 trials per cell, 512 MB file, 12 s disruption,
`/R:5 /W:5`; the later runs with reset grace delays of 0, 10 and 100 ms across the trials):

| Runner | robocopy.exe | Disruption | `/Z` trials | no-`/Z` trials |
|---|---|---|---|---|
| windows-2022 (Server 2022, 20348) | 10.0.20348.1 | tcp-reset-storm | 9 recovered, 0 crashed | 9 recovered, 0 crashed |
| windows-2022 | 10.0.20348.1 | smb-session-close | 9 recovered, 0 crashed | 9 recovered, 0 crashed |
| windows-2025 (Server 2025, 26100) | 10.0.26100.1 | tcp-reset-storm | 9 recovered, 0 crashed | 9 recovered, 0 crashed |
| windows-2025 | 10.0.26100.1 | smb-session-close | 9 recovered, 0 crashed | 9 recovered, 0 crashed |
| windows-11-arm (Windows 11 client, 26200, ARM64) | 10.0.26100.1 | tcp-reset-storm | 3 recovered, 0 crashed | 3 recovered, 0 crashed |
| windows-11-arm | 10.0.26100.1 | smb-session-close | 3 recovered, 0 crashed | 3 recovered, 0 crashed |
| Windows 10 21H2 VM (19044, by hand) | 10.0.19041.1 | tcp-reset-storm | 3 recovered, 0 crashed | not run |
| windows-2022, `server_profile: nas`, 20 ms grace | 10.0.20348.1 | tcp-reset-storm | 3 recovered, 0 crashed | 3 recovered, 0 crashed |

What the run showed:

- Every trial hit the disruption where intended: the first `ERROR 59 (0x0000003B) An
  unexpected network error occurred` (or `ERROR 6 The handle is invalid` for session closes)
  was logged at the trigger percentage, robocopy waited `/W`, retried inside the window, was
  hit again, and finished once the window ended. Exit code 1, summary table printed,
  destination hash correct, in both modes.
- No crash, no Event 1000, no dump, on either Server build, on the Windows 11 ARM64
  client build, or on a Windows 10 21H2 VM running the harness by hand with the same
  robocopy 10.0.19041.1 binary as the field machine. A mid-file reset in `/Z` mode is handled
  cleanly by every build tested, so the field crash is not a generic `/Z` reopen bug; it needs
  something the loopback setup does not provide (see "What is still different" below).
- With `/Z` the destination file is pre-extended to its full size as soon as the copy starts,
  which is why the harness measures progress from the process's I/O counters rather than
  the destination file size.
- `/Z` is much slower even on loopback: 25 % of the file took about 1.6 s with `/Z` versus
  about 0.1 s without on Server 2022, and about 16 s with `/Z` on the ARM64 Windows 11 runner
  (roughly 6 to 12 MB/s). The registry on that image reports the product name as
  "Windows 10 Enterprise" although the build (26200) is Windows 11.
- The SMB redirector only attempted 3 reconnects per 12 s window, one per robocopy retry,
  whether the reset landed 1 ms, 15 ms or 108 ms after the reconnect. The field capture
  showed the client reconnecting hundreds of times in 10 s, so something on that client
  (or the redirector's behaviour on Windows 10) retries far more aggressively than the
  Server builds do here; `/R` and `/W` bound what this harness can generate.

### What is still different from the field

- **Reconnect storm.** Against the loopback server the redirector reconnects once per robocopy
  retry and then hands robocopy a clean error. The field capture showed the client
  reconnecting hundreds of times in 10 s, each reconnect getting through negotiate and
  authentication before the reset. That gives robocopy many more failure moments per file,
  including ones that land inside the `/Z` restart-record writes rather than the data writes.
  `reset_grace_ms` reproduces the timing of each reset but not the client's reconnect loop.
- **Server behaviour.** The field NAS grants no oplocks and returned authentication failures
  on some sessions; the Windows SMB server grants oplocks, leases and durable handles and never
  fails authentication. `server_profile: nas` removes the first difference; with it applied
  (oplocks, leasing, multichannel off, durable-handle timeout 0) robocopy still recovered.
- **Sample size.** The field crash happened twice in a run of many files. A few dozen trials
  cannot rule out a race with a low per-reset probability.

## Caveats

- A hosted runner copies over loopback to its own SMB server, so timing differs from a real
  client and file server, and the reset is injected on the client rather than by a device in
  the path. The disruption is designed to look the same to robocopy (a TCP RST during a
  write, then repeated resets of every reconnect), but a non-reproduction here does not prove
  the field crash cannot happen.
- Windows Server 2022 / 2025 ship different `robocopy.exe` builds from Windows 10 22H2. The
  `environment.json` in each artifact records the exact version tested.

## Mitigation while the network problem is being fixed

Drop `/Z` (a mid-file reset then costs a re-copy of that file, not the job), make `/W`
longer than the block period so a retry does not land inside it, avoid `/MT`, use `/FFT`
so reruns resume instead of re-copying, log with `/LOG+:` and wrap robocopy in a loop that
treats any exit code below 0 or 8 and above as "wait, then run again".
