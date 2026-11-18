#requires -Version 5.1
#requires -RunAsAdministrator
# For local execution change Audit to LogoffDisconnected below.
[ValidateSet('Audit','LogoffDisconnected')][string]$Mode = 'Audit'
$ErrorActionPreference = 'Stop'

function Test-LogoffCandidate($Session) {
    return ($Session.Id -gt 0 -and $Session.State -eq 4 -and
        -not $Session.IsConsole -and -not [string]::IsNullOrWhiteSpace($Session.User))
}

$native = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace WinHUBRdp {
 public class Session {
  public int Id; public int State; public short Protocol; public string User; public string Domain; public string Station; public bool IsConsole;
 }
 public static class Native {
  [StructLayout(LayoutKind.Sequential)]
  private struct Entry { public int Id; public IntPtr Name; public int State; }
  [DllImport("wtsapi32.dll", EntryPoint="WTSEnumerateSessionsW", ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool Enumerate(IntPtr server, int reserved, int version, out IntPtr buffer, out int count);
  [DllImport("wtsapi32.dll", EntryPoint="WTSQuerySessionInformationW", ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool Query(IntPtr server, int id, int kind, out IntPtr buffer, out int bytes);
  [DllImport("wtsapi32.dll", ExactSpelling=true)] private static extern void WTSFreeMemory(IntPtr buffer);
  [DllImport("wtsapi32.dll", ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool WTSLogoffSession(IntPtr server, int id, [MarshalAs(UnmanagedType.Bool)] bool wait);
  [DllImport("kernel32.dll", ExactSpelling=true)] private static extern uint WTSGetActiveConsoleSessionId();
  private static string Text(int id, int kind) {
   IntPtr p; int bytes;
   if (!Query(IntPtr.Zero, id, kind, out p, out bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
   try { return p == IntPtr.Zero ? "" : Marshal.PtrToStringUni(p) ?? ""; } finally { if(p != IntPtr.Zero) WTSFreeMemory(p); }
  }
  private static int Number(int id, int kind, bool small) {
   IntPtr p; int bytes;
   if (!Query(IntPtr.Zero, id, kind, out p, out bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    if(p == IntPtr.Zero || bytes < (small ? 2 : 4)) throw new InvalidOperationException("Incomplete WTS response.");
    return small ? Marshal.ReadInt16(p) : Marshal.ReadInt32(p);
   } finally { if(p != IntPtr.Zero) WTSFreeMemory(p); }
  }
  public static Session Read(int id) {
   string station=Text(id,6);
   return new Session {Id=id, State=Number(id,8,false), Protocol=(short)Number(id,16,true), User=Text(id,5), Domain=Text(id,7), Station=station,
    IsConsole=(uint)id==WTSGetActiveConsoleSessionId() || string.Equals(station,"Console",StringComparison.OrdinalIgnoreCase)};
  }
  public static int[] SessionIds() {
   IntPtr p; int count;
   if(!Enumerate(IntPtr.Zero,0,1,out p,out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    var ids=new List<int>(); int size=Marshal.SizeOf(typeof(Entry));
    for(int i=0;i<count;i++) {
     var e=(Entry)Marshal.PtrToStructure(IntPtr.Add(p,checked(i*size)),typeof(Entry));
     if(e.Id>0) ids.Add(e.Id);
    }
    return ids.ToArray();
   } finally { if(p != IntPtr.Zero) WTSFreeMemory(p); }
  }
  public static void Logoff(int id) {
   if(id<=0) throw new InvalidOperationException("Cannot log off session zero.");
   if(!WTSLogoffSession(IntPtr.Zero,id,true)) throw new Win32Exception(Marshal.GetLastWin32Error());
  }
 }
}
'@

$results = New-Object 'System.Collections.Generic.List[object]'
try {
    Add-Type -TypeDefinition $native -Language CSharp
    foreach ($id in [WinHUBRdp.Native]::SessionIds()) {
        $row = [ordered]@{ session_id=$id; user=''; status='Skipped'; connection_state=$null; protocol=$null; station=''; is_console=$null; message='' }
        try {
            $session = [WinHUBRdp.Native]::Read($id)
            $row.user = if ($session.Domain) { $session.Domain + '\' + $session.User } else { $session.User }
            $row.connection_state = $session.State
            $row.protocol = $session.Protocol
            $row.station = $session.Station
            $row.is_console = $session.IsConsole
            if ($session.Id -gt 0 -and $session.State -eq 0 -and -not [string]::IsNullOrWhiteSpace($session.User)) {
                $row.status = 'Active'
                $row.message = 'Active user session; left running.'
            } elseif (-not (Test-LogoffCandidate $session)) {
                $row.message = if ($session.IsConsole) { 'Console session; excluded.' } else { 'Not a disconnected user session with a non-empty username and positive ID.' }
            } elseif ($Mode -eq 'Audit') {
                $row.status = 'WouldLogoff'
                $row.message = 'Disconnected non-console user session; no changes made.'
            } else {
                # Re-query immediately before logoff: skip users who reconnected.
                $current = [WinHUBRdp.Native]::Read($id)
                if ((Test-LogoffCandidate $current) -and $current.User -eq $session.User -and $current.Domain -eq $session.Domain) {
                    [WinHUBRdp.Native]::Logoff($id)
                    $row.status = 'LoggedOff'
                    $row.message = 'Synchronous WTS logoff completed.'
                } else { $row.message = 'Session state or identity changed; skipped.' }
            }
        } catch {
            $row.status = 'Failed'
            $row.message = $_.Exception.Message
        }
        $results.Add([pscustomobject]$row)
    }
    $failed = @($results | Where-Object { $_.status -eq 'Failed' }).Count
    [ordered]@{
        host_name=$env:COMPUTERNAME; mode=$Mode
        status=$(if ($failed) { 'PartialFailure' } else { 'Success' })
        active=@($results | Where-Object { $_.status -eq 'Active' }).Count
        logged_off=@($results | Where-Object { $_.status -eq 'LoggedOff' }).Count
        would_logoff=@($results | Where-Object { $_.status -eq 'WouldLogoff' }).Count
        failed=$failed; sessions=@($results.ToArray())
    } | ConvertTo-Json -Depth 5 -Compress
    if ($failed) { exit 1 }
    exit 0
} catch {
    @{host_name=$env:COMPUTERNAME; mode=$Mode; status='Failed'; error=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 1
}
