// Native helpers compiled at runtime by Invoke-RobocopyCrashTest.ps1 (Add-Type).
//
// RcNet  - enumerates the IPv4 TCP table and force-deletes connection blocks with
//          SetTcpEntry(MIB_TCP_STATE_DELETE_TCB). Deleting a TCB makes the stack send a
//          TCP RST to the peer, which is how we imitate a network device that resets
//          SMB connections mid-copy.
// RcIo   - reads a process's I/O counters so the harness can tell how far robocopy has
//          got through the big file before triggering the disruption.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class RcNet
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    public class ResetRecord
    {
        public double ElapsedMs;
        public string LocalAddr;
        public int LocalPort;
        public string RemoteAddr;
        public int RemotePort;
        public uint State;
        public uint Result;
    }

    public class StormResult
    {
        public int Iterations;
        public int Resets;
        public int Failures;
        public double DurationMs;
        public List<ResetRecord> Records = new List<ResetRecord>();
    }

    const uint MIB_TCP_STATE_LISTEN = 2;
    const uint MIB_TCP_STATE_TIME_WAIT = 11;
    const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetTcpTable(IntPtr pTcpTable, ref uint pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    static int Port(uint dwPort)
    {
        // dwLocalPort / dwRemotePort hold the port in network byte order in the low 16 bits.
        return (int)(((dwPort & 0xFF) << 8) | ((dwPort >> 8) & 0xFF));
    }

    static string Addr(uint dwAddr)
    {
        var b = BitConverter.GetBytes(dwAddr);
        return b[0] + "." + b[1] + "." + b[2] + "." + b[3];
    }

    public static List<MIB_TCPROW> GetRows()
    {
        uint size = 0;
        GetTcpTable(IntPtr.Zero, ref size, true);
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint r = GetTcpTable(buf, ref size, true);
            if (r != 0) throw new Win32Exception((int)r, "GetTcpTable failed");
            int n = Marshal.ReadInt32(buf);
            var rows = new List<MIB_TCPROW>(n);
            IntPtr p = IntPtr.Add(buf, 4);
            int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW));
            for (int i = 0; i < n; i++)
            {
                rows.Add((MIB_TCPROW)Marshal.PtrToStructure(p, typeof(MIB_TCPROW)));
                p = IntPtr.Add(p, rowSize);
            }
            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    static bool AddrMatches(uint dwAddr, string[] targets)
    {
        if (targets == null || targets.Length == 0) return true;
        string a = Addr(dwAddr);
        foreach (var t in targets) if (t == a) return true;
        return false;
    }

    /// Count the client-side connections to the given remote port and target addresses (for diagnostics).
    public static int CountConnections(int port, string[] targets)
    {
        int n = 0;
        foreach (var row in GetRows())
            if (Port(row.dwRemotePort) == port && AddrMatches(row.dwRemoteAddr, targets)
                && row.dwState != MIB_TCP_STATE_LISTEN && row.dwState != MIB_TCP_STATE_TIME_WAIT) n++;
        return n;
    }

    /// For durationMs, every intervalMs, abort every TCP connection whose remote port is `port`
    /// and whose remote address is one of `targets` (the test server only - never the machine's
    /// other SMB sessions). Each new reconnect the SMB redirector makes is reset again, like a
    /// brute-force block on a security device.
    /// graceMs > 0 leaves each connection alone until it has existed for that long, so the
    /// reconnect can finish negotiate/session setup (and even copy a little) before the reset
    /// lands - the pattern seen from a network device that resets shortly after authentication.
    public static StormResult Storm(int port, string[] targets, int durationMs, int intervalMs, int graceMs)
    {
        var result = new StormResult();
        var sw = Stopwatch.StartNew();
        var firstSeen = new Dictionary<string, double>();
        while (sw.ElapsedMilliseconds < durationMs)
        {
            result.Iterations++;
            List<MIB_TCPROW> rows;
            try { rows = GetRows(); } catch { Thread.Sleep(intervalMs); continue; }
            double now = sw.Elapsed.TotalMilliseconds;
            foreach (var row in rows)
            {
                int rp = Port(row.dwRemotePort), lp = Port(row.dwLocalPort);
                if (rp != port) continue;
                if (!AddrMatches(row.dwRemoteAddr, targets)) continue;
                if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwState == MIB_TCP_STATE_TIME_WAIT) continue;
                if (graceMs > 0)
                {
                    string key = row.dwLocalAddr + ":" + lp + ">" + row.dwRemoteAddr + ":" + rp;
                    double seen;
                    if (!firstSeen.TryGetValue(key, out seen)) { firstSeen[key] = now; continue; }
                    if (now - seen < graceMs) continue;
                    firstSeen.Remove(key);
                }
                var r = row;
                r.dwState = MIB_TCP_STATE_DELETE_TCB;
                uint res = SetTcpEntry(ref r);
                if (res == 0) result.Resets++; else result.Failures++;
                if (result.Records.Count < 5000)
                {
                    result.Records.Add(new ResetRecord
                    {
                        ElapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1),
                        LocalAddr = Addr(row.dwLocalAddr), LocalPort = lp,
                        RemoteAddr = Addr(row.dwRemoteAddr), RemotePort = rp,
                        State = row.dwState, Result = res
                    });
                }
            }
            Thread.Sleep(intervalMs);
        }
        result.DurationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
        return result;
    }
}

public static class RcIo
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS lpIoCounters);

    /// Bytes the process has written so far through WriteFile (destination file plus a little stdout).
    public static ulong WriteBytes(Process p)
    {
        IO_COUNTERS c;
        if (!GetProcessIoCounters(p.Handle, out c)) throw new Win32Exception();
        return c.WriteTransferCount;
    }

    [DllImport("kernel32.dll")]
    static extern uint SetErrorMode(uint uMode);

    [DllImport("kernel32.dll")]
    static extern uint GetErrorMode();

    /// Child processes inherit the parent's error mode. SEM_NOGPFAULTERRORBOX (0x2) would stop an
    /// unhandled exception in robocopy from reaching Windows Error Reporting, so clear it here
    /// before launching robocopy. Returns the previous mode.
    public static uint ResetErrorMode()
    {
        return SetErrorMode(0);
    }

    public static uint CurrentErrorMode()
    {
        return GetErrorMode();
    }
}
