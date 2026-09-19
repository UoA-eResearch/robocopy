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

    /// Count the client-side connections to the given remote port (for diagnostics).
    public static int CountConnections(int port)
    {
        int n = 0;
        foreach (var row in GetRows())
            if (Port(row.dwRemotePort) == port && row.dwState != MIB_TCP_STATE_LISTEN && row.dwState != MIB_TCP_STATE_TIME_WAIT) n++;
        return n;
    }

    /// For durationMs, every intervalMs, abort every TCP connection whose remote port is `port`
    /// (i.e. every client-side SMB connection when port == 445). Each new reconnect the SMB
    /// redirector makes is reset again, like a brute-force block on a security device.
    public static StormResult Storm(int port, int durationMs, int intervalMs, bool includeServerSide)
    {
        var result = new StormResult();
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < durationMs)
        {
            result.Iterations++;
            List<MIB_TCPROW> rows;
            try { rows = GetRows(); } catch { Thread.Sleep(intervalMs); continue; }
            foreach (var row in rows)
            {
                int rp = Port(row.dwRemotePort), lp = Port(row.dwLocalPort);
                bool match = rp == port || (includeServerSide && lp == port);
                if (!match) continue;
                if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwState == MIB_TCP_STATE_TIME_WAIT) continue;
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
