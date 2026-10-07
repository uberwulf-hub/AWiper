<#
.SYNOPSIS
    AWiper - system cleanup and disk space analyzer with a WPF interface.

.DESCRIPTION
    AWiper bundles the most useful parts of tools like CCleaner and SpaceMonger:

      * Dashboard    - drive usage gauges, system summary, quick actions
      * Cleaner      - analyze / clean temp files, caches, update leftovers, dumps, recycle bin
      * Space Map    - SpaceMonger-style nested treemap of any drive or folder (drill down, recycle)
      * Large Files  - the 1,000 largest files from the last scan, searchable, recycle or export
      * Recovery     - restore from any user's Recycle Bin, find deleted files in shadow-copy snapshots,
                       deep scan with Windows File Recovery, per-drive recoverability (SSD/TRIM) check
      * Startup      - enable / disable startup entries (same StartupApproved switches Task Manager uses)
      * Programs     - installed software list with size, search and uninstall
      * Debloat      - remove preinstalled Store apps, turn off ads, suggestions, Copilot and other extras
      * Tools        - quick fixes (DNS, Group Policy, Explorer), repair (SFC, DISM, Windows Update reset,
                       ConfigMgr client), maintenance (component store, restore point, hibernation), activity log

    AWiper can also work on another computer over PowerShell remoting (WinRM). Pick the target from
    the button in the title bar; credentials can be saved to Windows Credential Manager.

    On launch AWiper asks for administrator rights (UAC). If the prompt is declined or
    elevation is not possible, it keeps running with standard permissions and simply
    disables the items that need admin rights.

    Nothing is deleted without an Analyze/confirm step. Files removed from the Space Map
    and Large Files views go to the Recycle Bin. Browser history, cookies and saved
    passwords are never touched.

.PARAMETER NoElevate
    Skip the UAC prompt and run with the current permissions.

.PARAMETER ShowConsole
    Keep the PowerShell console window visible (useful for troubleshooting).

.PARAMETER Elevated
    Internal - set when AWiper relaunches itself elevated, prevents a prompt loop.

.EXAMPLE
    .\AWiper.ps1
    Prompts for admin rights, then opens the AWiper window.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\AWiper.ps1 -NoElevate

.NOTES
    Name    : AWiper.ps1
    Version : 1.2.0
    Author  : Andrew Saulls
    Requires: Windows 10/11, Windows PowerShell 5.1 or PowerShell 7+ (Windows)
    Log     : %LOCALAPPDATA%\AWiper\AWiper.log
#>
[CmdletBinding()]
param(
    [switch]$NoElevate,
    [switch]$ShowConsole,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$script:AppVersion = '1.2.0'

#region ---------------------------------------------------------------- Elevation / STA
function Test-AWAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AWRelaunchArgs {
    param([switch]$AddElevated, [switch]$AddNoElevate)
    $list = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    if ($AddElevated)  { $list += '-Elevated' }
    if ($AddNoElevate) { $list += '-NoElevate' }
    if ($ShowConsole)  { $list += '-ShowConsole' }
    $list
}

function Invoke-AWElevation {
    # Returns $true if an elevated copy was started, $false if UAC was declined / unavailable.
    if (-not $PSCommandPath) { return $false }
    $exe = (Get-Process -Id $PID).Path
    $style = if ($ShowConsole) { 'Normal' } else { 'Hidden' }
    try {
        Start-Process -FilePath $exe -ArgumentList (Get-AWRelaunchArgs -AddElevated) -Verb RunAs -WindowStyle $style -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

$script:IsAdmin = Test-AWAdmin
$script:ElevationNote = ''

if (-not $script:IsAdmin -and -not $Elevated -and -not $NoElevate) {
    if (Invoke-AWElevation) { exit }
    $script:ElevationNote = 'Admin prompt was declined or unavailable - running with standard permissions.'
}
elseif (-not $script:IsAdmin -and $Elevated) {
    $script:ElevationNote = 'Elevation did not grant admin rights - running with standard permissions.'
}
elseif (-not $script:IsAdmin) {
    $script:ElevationNote = 'Running with standard permissions (-NoElevate).'
}

# WPF needs a single-threaded apartment. Relaunch with -STA if needed (same permission level).
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if ($PSCommandPath) {
        $exe = (Get-Process -Id $PID).Path
        Start-Process -FilePath $exe -ArgumentList (Get-AWRelaunchArgs -AddNoElevate) | Out-Null
        exit
    }
    throw 'AWiper must run in an STA thread. Start PowerShell with -STA.'
}
#endregion

#region ---------------------------------------------------------------- Assemblies + native helpers
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, Microsoft.VisualBasic

if (-not ('AWiper.DiskScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace AWiper
{
    public static class Fmt
    {
        public static string Size(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            string[] u = { "KB", "MB", "GB", "TB", "PB" };
            double d = bytes / 1024.0; int i = 0;
            while (d >= 1024 && i < u.Length - 1) { d /= 1024; i++; }
            string f = d >= 100 ? "0" : (d >= 10 ? "0.0" : "0.00");
            return d.ToString(f, CultureInfo.InvariantCulture) + " " + u[i];
        }
    }

    public class DiskNode
    {
        public DiskNode() { Children = new List<DiskNode>(); }
        public string Name { get; set; }
        public string FullPath { get; set; }
        public long Size { get; set; }
        public long FileCount { get; set; }
        public bool IsDir { get; set; }
        public bool IsGroup { get; set; }
        public DiskNode Parent { get; set; }
        public List<DiskNode> Children { get; set; }
        public string SizeText { get { return Fmt.Size(Size); } }
        public double PercentOfParent
        {
            get { return (Parent == null || Parent.Size <= 0) ? 100.0 : Size * 100.0 / Parent.Size; }
        }
        public string Kind { get { return IsGroup ? "Small files" : (IsDir ? "Folder" : "File"); } }
    }

    public class FileEntry
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public string Folder { get; set; }
        public string Extension { get; set; }
        public long Size { get; set; }
        public DateTime Modified { get; set; }
        public bool IsChecked { get; set; }
        public string Status { get; set; }
        public string SizeText { get { return Fmt.Size(Size); } }
        public string ModifiedText { get { return Modified == DateTime.MinValue ? "" : Modified.ToString("yyyy-MM-dd HH:mm"); } }
    }

    public class RecycleEntry
    {
        public bool IsChecked { get; set; }
        public string Name { get; set; }
        public string OriginalPath { get; set; }
        public string Folder { get; set; }
        public string Owner { get; set; }
        public string IPath { get; set; }
        public string RPath { get; set; }
        public bool IsDir { get; set; }
        public long Size { get; set; }
        public DateTime Deleted { get; set; }
        public string SizeText { get { return Fmt.Size(Size); } }
        public string DeletedText { get { return Deleted == DateTime.MinValue ? "" : Deleted.ToString("yyyy-MM-dd HH:mm"); } }
        public string Kind { get { return IsDir ? "Folder" : "File"; } }
    }

    public class AppEntry
    {
        public string Name { get; set; }
        public string Package { get; set; }
        public string FullName { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string Category { get; set; }
        public string Note { get; set; }
        public bool Recommended { get; set; }
        public bool Provisioned { get; set; }
        public bool IsChecked { get; set; }
    }

    public class ExtStat
    {
        public string Extension { get; set; }
        public long Size { get; set; }
        public long Count { get; set; }
        public double Percent { get; set; }
        public double RelPercent { get; set; }
        public string SizeText { get { return Fmt.Size(Size); } }
        public string PercentText { get { return Percent.ToString("0.0", CultureInfo.InvariantCulture) + "%"; } }
    }

    public class TreeRect
    {
        public DiskNode Node { get; set; }
        public double X { get; set; }
        public double Y { get; set; }
        public double W { get; set; }
        public double H { get; set; }
    }

    public class DiskScanner
    {
        public long FilesScanned;
        public long FoldersScanned;
        public long BytesScanned;
        public long Errors;
        public volatile bool Cancel;
        public volatile string CurrentPath = "";
        public long SmallFileThreshold = 1048576;
        public int TopCount = 1000;
        public double ElapsedSeconds;
        public bool Completed;
        public DiskNode Root;
        public List<FileEntry> TopFiles = new List<FileEntry>();
        public List<ExtStat> ExtensionList = new List<ExtStat>();

        private List<FileEntry> top = new List<FileEntry>();
        private long topMin = 0;
        private Dictionary<string, ExtStat> ext = new Dictionary<string, ExtStat>(StringComparer.OrdinalIgnoreCase);

        private static int CompareFiles(FileEntry a, FileEntry b) { return b.Size.CompareTo(a.Size); }
        private static int CompareNodes(DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); }

        public DiskNode Scan(string path)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var di = new DirectoryInfo(path);
            var root = new DiskNode();
            root.Name = di.FullName; root.FullPath = di.FullName; root.IsDir = true;
            Root = root;
            try { ScanDir(di, root, 0); }
            finally
            {
                top.Sort(CompareFiles);
                if (top.Count > TopCount) top.RemoveRange(TopCount, top.Count - TopCount);
                TopFiles = top;
                var list = new List<ExtStat>(ext.Values);
                list.Sort(delegate (ExtStat a, ExtStat b) { return b.Size.CompareTo(a.Size); });
                long max = list.Count > 0 ? list[0].Size : 0;
                foreach (var e in list)
                {
                    e.Percent = root.Size > 0 ? e.Size * 100.0 / root.Size : 0;
                    e.RelPercent = max > 0 ? e.Size * 100.0 / max : 0;
                }
                ExtensionList = list;
                ElapsedSeconds = sw.Elapsed.TotalSeconds;
                Completed = !Cancel;
            }
            return root;
        }

        private void AddTop(FileInfo f, long len)
        {
            if (top.Count >= TopCount && len <= topMin) return;
            var fe = new FileEntry();
            fe.Name = f.Name; fe.FullPath = f.FullName; fe.Size = len;
            try { fe.Folder = f.DirectoryName; } catch { fe.Folder = ""; }
            try { fe.Extension = f.Extension.ToLowerInvariant(); } catch { fe.Extension = ""; }
            try { fe.Modified = f.LastWriteTime; } catch { fe.Modified = DateTime.MinValue; }
            top.Add(fe);
            if (top.Count >= TopCount * 2)
            {
                top.Sort(CompareFiles);
                top.RemoveRange(TopCount, top.Count - TopCount);
                topMin = top[top.Count - 1].Size;
            }
        }

        private void ScanDir(DirectoryInfo di, DiskNode node, int depth)
        {
            if (Cancel || depth > 256) return;
            CurrentPath = di.FullName;
            FoldersScanned++;
            FileSystemInfo[] entries;
            try { entries = di.GetFileSystemInfos(); }
            catch { Errors++; return; }

            long smallSize = 0; long smallCount = 0;
            foreach (FileSystemInfo e in entries)
            {
                if (Cancel) break;
                var d = e as DirectoryInfo;
                if (d != null)
                {
                    FileAttributes attr;
                    try { attr = d.Attributes; } catch { Errors++; continue; }
                    if ((attr & FileAttributes.ReparsePoint) != 0) continue;   // junctions / symlinks
                    var child = new DiskNode();
                    child.Name = d.Name; child.FullPath = d.FullName; child.IsDir = true; child.Parent = node;
                    ScanDir(d, child, depth + 1);
                    node.Children.Add(child);
                    node.Size += child.Size; node.FileCount += child.FileCount;
                    continue;
                }
                var f = e as FileInfo;
                if (f == null) continue;
                long len;
                try { len = f.Length; } catch { Errors++; continue; }
                FilesScanned++; BytesScanned += len;
                node.Size += len; node.FileCount++;

                string x;
                try { x = f.Extension; } catch { x = ""; }
                if (string.IsNullOrEmpty(x)) x = "(none)";
                ExtStat st;
                if (!ext.TryGetValue(x, out st)) { st = new ExtStat(); st.Extension = x.ToLowerInvariant(); ext[x] = st; }
                st.Size += len; st.Count++;

                AddTop(f, len);

                if (len >= SmallFileThreshold)
                {
                    var fn = new DiskNode();
                    fn.Name = f.Name; fn.FullPath = f.FullName; fn.Size = len; fn.FileCount = 1; fn.Parent = node;
                    node.Children.Add(fn);
                }
                else { smallSize += len; smallCount++; }
            }
            if (smallCount > 0)
            {
                var g = new DiskNode();
                g.Name = smallCount + (smallCount == 1 ? " small file" : " small files");
                g.FullPath = di.FullName; g.Size = smallSize; g.FileCount = smallCount; g.IsGroup = true; g.Parent = node;
                node.Children.Add(g);
            }
            node.Children.Sort(CompareNodes);
        }
    }

    public static class Treemap
    {
        // Squarified treemap (Bruls, Huizing, van Wijk).
        public static List<TreeRect> Layout(List<DiskNode> nodes, double x, double y, double w, double h)
        {
            var result = new List<TreeRect>();
            if (nodes == null || w <= 1 || h <= 1) return result;
            var items = new List<DiskNode>();
            double total = 0;
            foreach (var n in nodes) { if (n.Size > 0) { items.Add(n); total += n.Size; } }
            if (items.Count == 0 || total <= 0) return result;
            items.Sort(delegate (DiskNode a, DiskNode b) { return b.Size.CompareTo(a.Size); });

            double scale = (w * h) / total;
            var areas = new double[items.Count];
            for (int i = 0; i < items.Count; i++) areas[i] = items[i].Size * scale;

            int start = 0;
            while (start < items.Count && w > 0.5 && h > 0.5)
            {
                double side = Math.Min(w, h);
                int end = start; double rowSum = 0; double worst = double.MaxValue;
                while (end < items.Count)
                {
                    double s = rowSum + areas[end];
                    double wv = Worst(areas, start, end, s, side);
                    if (end > start && wv > worst) break;
                    rowSum = s; worst = wv; end++;
                }
                if (w >= h)
                {
                    double colW = rowSum / h; double cy = y;
                    for (int i = start; i < end; i++)
                    {
                        double ih = areas[i] / colW;
                        result.Add(Make(items[i], x, cy, colW, ih)); cy += ih;
                    }
                    x += colW; w -= colW;
                }
                else
                {
                    double rowH = rowSum / w; double cx = x;
                    for (int i = start; i < end; i++)
                    {
                        double iw = areas[i] / rowH;
                        result.Add(Make(items[i], cx, y, iw, rowH)); cx += iw;
                    }
                    y += rowH; h -= rowH;
                }
                start = end;
            }
            return result;
        }

        private static double Worst(double[] a, int s, int e, double sum, double side)
        {
            double max = 0, min = double.MaxValue;
            for (int i = s; i <= e; i++) { if (a[i] > max) max = a[i]; if (a[i] < min) min = a[i]; }
            double s2 = sum * sum, w2 = side * side;
            return Math.Max(w2 * max / s2, s2 / (w2 * min));
        }

        private static TreeRect Make(DiskNode n, double x, double y, double w, double h)
        {
            var r = new TreeRect(); r.Node = n; r.X = x; r.Y = y; r.W = w; r.H = h; return r;
        }
    }

    // Windows Credential Manager (generic credentials), used for saved remote connections.
    public static class CredMan
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags; public uint Type; public string TargetName; public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist;
            public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
        }
        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite(ref CREDENTIAL cred, uint flags);
        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, uint type, uint flags, out IntPtr cred);
        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDelete(string target, uint type, uint flags);
        [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr creds);
        [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr buffer);

        private const uint Generic = 1, PersistLocalMachine = 2;

        public static void Write(string target, string user, string password)
        {
            byte[] blob = System.Text.Encoding.Unicode.GetBytes(password ?? "");
            var c = new CREDENTIAL();
            c.Type = Generic; c.TargetName = target; c.UserName = user; c.Persist = PersistLocalMachine;
            c.Comment = "Saved by AWiper for remote connections";
            c.CredentialBlobSize = (uint)blob.Length;
            c.CredentialBlob = Marshal.AllocHGlobal(Math.Max(1, blob.Length));
            try
            {
                Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
                if (!CredWrite(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(c.CredentialBlob); }
        }

        // Returns { user, password } or null.
        public static string[] Read(string target)
        {
            IntPtr p;
            if (!CredRead(target, Generic, 0, out p)) return null;
            try
            {
                var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
                string pw = c.CredentialBlobSize > 0 ? Marshal.PtrToStringUni(c.CredentialBlob, (int)c.CredentialBlobSize / 2) : "";
                return new string[] { c.UserName, pw };
            }
            finally { CredFree(p); }
        }

        public static bool Delete(string target) { return CredDelete(target, Generic, 0); }

        public static string[] List(string filter)
        {
            uint n; IntPtr arr;
            var names = new List<string>();
            if (!CredEnumerate(filter, 0, out n, out arr)) return names.ToArray();
            try
            {
                for (int i = 0; i < n; i++)
                {
                    IntPtr cp = Marshal.ReadIntPtr(arr, i * IntPtr.Size);
                    var c = (CREDENTIAL)Marshal.PtrToStructure(cp, typeof(CREDENTIAL));
                    names.Add(c.TargetName);
                }
            }
            finally { CredFree(arr); }
            return names.ToArray();
        }
    }

    public static class Native
    {
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern int SHEmptyRecycleBin(IntPtr hwnd, string root, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumePathName(string fileName, System.Text.StringBuilder volumePath, uint length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string mountPoint, System.Text.StringBuilder volumeName, uint length);

        // Stable identity of the volume holding a path (\\?\Volume{GUID}\), so two drive letters or a
        // mounted folder pointing at the same volume are still detected as the same disk.
        public static string VolumeId(string path)
        {
            var root = new System.Text.StringBuilder(1024);
            if (!GetVolumePathName(path, root, 1024)) return null;
            var name = new System.Text.StringBuilder(1024);
            if (!GetVolumeNameForVolumeMountPoint(root.ToString(), name, 1024)) return root.ToString().ToUpperInvariant();
            return name.ToString().ToUpperInvariant();
        }

        public static bool OwnsConsole()
        {
            try { var l = new uint[8]; return GetConsoleProcessList(l, 8) <= 1; } catch { return false; }
        }
    }
}
'@
}

# Hide the console only when AWiper owns it (double-click / elevated relaunch), never a shared terminal.
if (-not $ShowConsole -and [AWiper.Native]::OwnsConsole()) {
    $hwnd = [AWiper.Native]::GetConsoleWindow()
    if ($hwnd -ne [IntPtr]::Zero) { [void][AWiper.Native]::ShowWindow($hwnd, 0) }
}
#endregion

#region ---------------------------------------------------------------- Paths, state, logging
$script:DataDir   = Join-Path $env:LOCALAPPDATA 'AWiper'
$script:LogFile   = Join-Path $script:DataDir 'AWiper.log'
$script:StateFile = Join-Path $script:DataDir 'state.json'
if (-not (Test-Path -LiteralPath $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }

$script:State = @{ TotalFreed = [long]0; Cleans = 0; LastClean = ''; RecentTargets = @() }
try {
    if (Test-Path -LiteralPath $script:StateFile) {
        $j = Get-Content -LiteralPath $script:StateFile -Raw | ConvertFrom-Json
        $script:State.TotalFreed = [long]$j.TotalFreed
        $script:State.Cleans     = [int]$j.Cleans
        $script:State.LastClean  = if ($j.LastClean -is [datetime]) { $j.LastClean.ToString('o') } else { [string]$j.LastClean }
        if ($j.RecentTargets) { $script:State.RecentTargets = @($j.RecentTargets | ForEach-Object { [string]$_ }) }
    }
} catch { }

function Save-AWState {
    try { $script:State | ConvertTo-Json | Set-Content -LiteralPath $script:StateFile -Encoding UTF8 } catch { }
}

$Sync = [hashtable]::Synchronized(@{})
$Sync.Log      = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$Sync.Status   = ''
$Sync.Progress = -1
$Sync.Scanning = $false

function Write-AWLog {
    param([string]$Message, [string]$Level = 'INFO')
    $Sync.Log.Enqueue(('{0:HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message))
}

function Format-AWSize([long]$Bytes) { [AWiper.Fmt]::Size($Bytes) }
#endregion

#region ---------------------------------------------------------------- Worker library (runs inside background runspaces)
$Sync.WorkerLib = @'
function Write-WLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0:HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message
    # On a remote machine the line travels back on the information stream (see Invoke-WTarget).
    if ($Sync.Remote) { Write-Information -MessageData $line -InformationAction SilentlyContinue }
    else { $Sync.Log.Enqueue($line) }
}

function Format-WSize([long]$Bytes) {
    if ($Bytes -lt 1024) { return "$Bytes B" }
    $u = 'KB', 'MB', 'GB', 'TB', 'PB'; $d = $Bytes / 1024.0; $i = 0
    while ($d -ge 1024 -and $i -lt $u.Count - 1) { $d /= 1024; $i++ }
    $f = if ($d -ge 100) { '0' } elseif ($d -ge 10) { '0.0' } else { '0.00' }
    $d.ToString($f, [Globalization.CultureInfo]::InvariantCulture) + ' ' + $u[$i]
}

# Runs a script block on the current target: locally, or over WinRM when $Target is set.
# Remotely, this worker library is loaded first so the same helper functions are available.
function Invoke-WTarget {
    param([scriptblock]$Script, [object[]]$ArgumentList = @())
    if (-not $Target) { return & $Script @ArgumentList }
    $wrapper = {
        param($Lib, $Body, $Argz)
        $Sync = @{ Remote = $true }
        . ([scriptblock]::Create($Lib))
        & ([scriptblock]::Create($Body)) @Argz
    }
    $p = @{ ComputerName = $Target.Host; ScriptBlock = $wrapper; ArgumentList = @($Sync.WorkerLib, $Script.ToString(), $ArgumentList); ErrorAction = 'Stop' }
    if ($Target.Credential) { $p.Credential = $Target.Credential }
    Invoke-Command @p 6>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.InformationRecord]) { $Sync.Log.Enqueue(('{0}  [{1}]' -f $_.MessageData, $Target.Host)) }
        else { $_ }
    }
}

# Every user's Recycle Bin on every local drive. Each deleted item is a $I file (metadata) plus a
# $R file or folder (content). $I v1 (Vista-8.1): fixed 520-byte path at offset 24. $I v2 (Win10+):
# path length in characters (including the null) at offset 24, path at 28.
function Get-WRecycleItems {
    $names = @{}
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if (-not $d.IsReady -or ($d.DriveType -ne 'Fixed' -and $d.DriveType -ne 'Removable')) { continue }
        $root = Join-Path $d.RootDirectory.FullName '$Recycle.Bin'
        $bins = @()
        try { $bins = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop) } catch { continue }
        foreach ($bin in $bins) {
            $ifiles = @()
            try { $ifiles = @(Get-ChildItem -LiteralPath $bin.FullName -Force -File -Filter '$I*' -ErrorAction Stop) }
            catch {
                # Other users' bins are expected to be off-limits without admin rights.
                if ($admin) { Write-WLog "Recycle Bin of $($bin.Name) on $($d.Name) is not readable: $($_.Exception.Message)" 'WARN' }
                continue
            }
            if (-not $names.ContainsKey($bin.Name)) {
                $names[$bin.Name] = try { (New-Object System.Security.Principal.SecurityIdentifier $bin.Name).Translate([System.Security.Principal.NTAccount]).Value } catch { $bin.Name }
            }
            foreach ($i in $ifiles) {
                try {
                    $b = [System.IO.File]::ReadAllBytes($i.FullName)
                    if ($b.Length -lt 28) { continue }
                    $ver = [BitConverter]::ToInt64($b, 0)
                    if ($ver -eq 1) { $path = [System.Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)) }
                    elseif ($ver -eq 2) {
                        $n = [BitConverter]::ToInt32($b, 24)
                        $path = [System.Text.Encoding]::Unicode.GetString($b, 28, [Math]::Max(0, [Math]::Min($n * 2, $b.Length - 28)))
                    }
                    else { continue }
                    $path = $path.Split([char]0)[0]
                    $r = Join-Path $bin.FullName ('$R' + $i.Name.Substring(2))
                    if (-not $path -or -not (Test-Path -LiteralPath $r)) { continue }
                    $del = try { [DateTime]::FromFileTime([BitConverter]::ToInt64($b, 16)) } catch { [DateTime]::MinValue }
                    [pscustomobject]@{
                        IPath = $i.FullName; RPath = $r; OriginalPath = $path; Size = [BitConverter]::ToInt64($b, 8); Deleted = $del
                        IsDir = (Test-Path -LiteralPath $r -PathType Container); Owner = $names[$bin.Name]
                    }
                } catch { Write-WLog "Skipped $($i.FullName): $($_.Exception.Message)" 'WARN' }
            }
        }
    }
}

# Moves a recycled item back out. Never overwrites: a name clash gets " (restored)", " (restored 2)"...
function Restore-WRecycleItem([string]$IPath, [string]$RPath, [string]$Destination) {
    $dest = $Destination
    if (Test-Path -LiteralPath $dest) {
        $dir = Split-Path $Destination -Parent
        $isDir = Test-Path -LiteralPath $RPath -PathType Container
        $base = if ($isDir) { Split-Path $Destination -Leaf } else { [System.IO.Path]::GetFileNameWithoutExtension($Destination) }
        $ext  = if ($isDir) { '' } else { [System.IO.Path]::GetExtension($Destination) }
        $n = 1
        do {
            $suffix = if ($n -eq 1) { ' (restored)' } else { " (restored $n)" }
            $dest = Join-Path $dir ($base + $suffix + $ext); $n++
        } while (Test-Path -LiteralPath $dest)
    }
    $parent = Split-Path $dest -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $sameVolume = [System.IO.Path]::GetPathRoot($RPath) -eq [System.IO.Path]::GetPathRoot($dest)
    if (Test-Path -LiteralPath $RPath -PathType Container) {
        if ($sameVolume) { [System.IO.Directory]::Move($RPath, $dest) }
        else { Copy-Item -LiteralPath $RPath -Destination $dest -Recurse -ErrorAction Stop; Remove-Item -LiteralPath $RPath -Recurse -Force }
    } else {
        if ($sameVolume) { [System.IO.File]::Move($RPath, $dest) }
        else { Copy-Item -LiteralPath $RPath -Destination $dest -ErrorAction Stop; Remove-Item -LiteralPath $RPath -Force }
    }
    Remove-Item -LiteralPath $IPath -Force -ErrorAction SilentlyContinue
    Write-WLog "Restored $dest"
    $dest
}

# Drive facts that decide whether deleted data can still be on the disk.
function Get-WRecoveryDrives {
    $trim = $null
    try {
        $o = (& fsutil.exe behavior query DisableDeleteNotify 2>&1) -join "`n"
        if ($o -match 'NTFS DisableDeleteNotify\s*=\s*(\d)') { $trim = $Matches[1] -eq '0' }
    } catch { }
    $phys = @{}
    try { foreach ($p in (Get-PhysicalDisk -ErrorAction Stop)) { $phys[[string]$p.DeviceId] = $p } } catch { }
    foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and "$($_.DriveType)" -in 'Fixed', 'Removable' } | Sort-Object DriveLetter)) {
        $p = $null
        try { $p = $phys[[string](Get-Partition -DriveLetter $v.DriveLetter -ErrorAction Stop).DiskNumber] } catch { }
        [pscustomobject]@{
            Drive = "$($v.DriveLetter):"; Label = [string]$v.FileSystemLabel; FS = [string]$(if ($v.FileSystem) { $v.FileSystem } else { $v.FileSystemType })
            Size = [long]$v.Size; Free = [long]$v.SizeRemaining; Type = [string]$v.DriveType
            Media = [string]$(if ($p) { $p.MediaType } else { '' }); Bus = [string]$(if ($p) { $p.BusType } else { '' })
            Model = [string]$(if ($p) { $p.FriendlyName } else { '' }); Trim = $trim
        }
    }
}

function Get-WRegValue([string]$Path, [string]$Name) {
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        $k.GetValue($(if ($Name -eq '(default)') { '' } else { $Name }), $null)
    } catch { $null }
}

function Test-WTweak($Tweak) {
    foreach ($v in $Tweak.Values) {
        $cur = Get-WRegValue $v.Path $v.Name
        if ($null -eq $cur -or "$cur" -ne "$($v.Value)") { return $false }
    }
    $true
}

function Set-WTweak($Tweak, [bool]$Apply) {
    foreach ($v in $Tweak.Values) {
        if ($Apply -or $null -ne $v.Revert) {
            $val = if ($Apply) { $v.Value } else { $v.Revert }
            if (-not (Test-Path -LiteralPath $v.Path)) { New-Item -Path $v.Path -Force | Out-Null }
            if ($v.Name -eq '(default)') { Set-Item -LiteralPath $v.Path -Value $val }
            else { New-ItemProperty -LiteralPath $v.Path -Name $v.Name -PropertyType $v.Type -Value $val -Force | Out-Null }
        }
        elseif ($v.Name -ne '(default)') {
            Remove-ItemProperty -LiteralPath $v.Path -Name $v.Name -ErrorAction SilentlyContinue
        }
    }
    if (-not $Apply) {
        foreach ($k in $Tweak.RemoveKeys) { if ($k -like 'HK*:\Software\Classes\CLSID\{*}') { Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue } }
    }
    Write-WLog ('{0} tweak: {1}' -f $(if ($Apply) { 'Applied' } else { 'Reverted' }), $Tweak.Name)
}

function Resolve-WTarget([string]$Path) {
    $p = [Environment]::ExpandEnvironmentVariables($Path)
    if ($p -match '[\*\?]') {
        @(Get-Item -Path $p -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.FullName })
    }
    elseif (Test-Path -LiteralPath $p -PathType Container) { @($p) }
    else { @() }
}

function Get-WTargetFiles($Target) {
    $filter  = if ($Target.Filter) { $Target.Filter } else { '*' }
    $recurse = $Target.Recurse -ne $false
    $cutoff  = if ($Target.MinAgeHours) { (Get-Date).AddHours(-[double]$Target.MinAgeHours) } else { $null }
    foreach ($root in (Resolve-WTarget $Target.Path)) {
        $files = Get-ChildItem -LiteralPath $root -Filter $filter -File -Force -Recurse:$recurse -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            if ($cutoff -and $f.LastWriteTime -gt $cutoff) { continue }
            $f
        }
    }
}

function Remove-WEmptyDirs([string]$Root) {
    $dirs = Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } -Descending
    foreach ($d in $dirs) {
        try {
            if (-not [System.IO.Directory]::EnumerateFileSystemEntries($d.FullName).GetEnumerator().MoveNext()) {
                [System.IO.Directory]::Delete($d.FullName)
            }
        } catch { }
    }
}

function Get-WRecycleFolders {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -eq 'Fixed' -and $d.IsReady) {
            $rb = Join-Path $d.RootDirectory.FullName ('$Recycle.Bin\' + $sid)
            if (Test-Path -LiteralPath $rb) { $rb }
        }
    }
}

function Test-WProcess($Item) {
    if (-not $Item.Process) { return $false }
    [bool](Get-Process -Name $Item.Process -ErrorAction SilentlyContinue)
}

function Measure-WItem($Item) {
    $res = @{ Id = $Item.Id; Name = $Item.Name; Group = $Item.Group; Files = 0; Bytes = [long]0; Note = '' }
    if (Test-WProcess $Item) { $res.Note = "$($Item.ProcessLabel) is running - close it before cleaning" }
    switch ($Item.Kind) {
        'Files' {
            foreach ($t in $Item.Targets) {
                foreach ($f in (Get-WTargetFiles $t)) { $res.Files++; $res.Bytes += $f.Length }
            }
        }
        'RecycleBin' {
            foreach ($rb in (Get-WRecycleFolders)) {
                foreach ($f in (Get-ChildItem -LiteralPath $rb -Force -Recurse -File -ErrorAction SilentlyContinue)) {
                    if ($f.Name -eq 'desktop.ini') { continue }
                    if ($f.Name -like '$R*' -or $f.DirectoryName -ne $rb) { $res.Files++ }
                    $res.Bytes += $f.Length
                }
            }
        }
        'Action' { if (-not $res.Note) { $res.Note = 'Action - runs during clean' } }
    }
    $res
}

function Invoke-WClean($Item) {
    $res = @{ Id = $Item.Id; Name = $Item.Name; Group = $Item.Group; Files = 0; Bytes = [long]0; Failed = 0; Note = '' }
    if (Test-WProcess $Item) {
        $res.Note = "Skipped - $($Item.ProcessLabel) is running"
        Write-WLog "$($Item.Name): skipped, $($Item.ProcessLabel) is running" 'WARN'
        return $res
    }

    $svcStopped = $false
    if ($Item.Service) {
        $svc = Get-Service -Name $Item.Service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            try { Stop-Service -Name $Item.Service -Force -ErrorAction Stop; $svcStopped = $true; Write-WLog "Stopped service $($Item.Service)" }
            catch { Write-WLog "Could not stop $($Item.Service): $($_.Exception.Message)" 'WARN' }
        }
    }

    try {
        switch ($Item.Kind) {
            'Files' {
                foreach ($t in $Item.Targets) {
                    foreach ($f in (Get-WTargetFiles $t)) {
                        $len = $f.Length
                        try {
                            if ($f.IsReadOnly) { $f.IsReadOnly = $false }
                            $f.Delete()
                            $res.Files++; $res.Bytes += $len
                        } catch { $res.Failed++ }
                    }
                    if ($t.Recurse -ne $false) {
                        foreach ($root in (Resolve-WTarget $t.Path)) { Remove-WEmptyDirs $root }
                    }
                }
            }
            'RecycleBin' {
                $m = Measure-WItem $Item
                [void][AWiper.Native]::SHEmptyRecycleBin([IntPtr]::Zero, $null, 7)
                $res.Files = $m.Files; $res.Bytes = $m.Bytes
            }
            'Action' {
                switch ($Item.Action) {
                    'FlushDns'  { & ipconfig.exe /flushdns | Out-Null; $res.Note = 'DNS resolver cache flushed' }
                    'Clipboard' { [System.Windows.Forms.Clipboard]::Clear(); $res.Note = 'Clipboard cleared' }
                }
            }
        }
    }
    finally {
        if ($svcStopped) {
            try { Start-Service -Name $Item.Service -ErrorAction Stop; Write-WLog "Restarted service $($Item.Service)" }
            catch { Write-WLog "Could not restart $($Item.Service): $($_.Exception.Message)" 'WARN' }
        }
    }

    if ($res.Failed -gt 0 -and -not $res.Note) { $res.Note = "$($res.Failed) file(s) in use or locked - skipped" }
    Write-WLog ("{0}: removed {1} file(s), {2}" -f $Item.Name, $res.Files, (Format-WSize $res.Bytes))
    $res
}
'@
#endregion

#region ---------------------------------------------------------------- Cleaner rules
function New-AWRule {
    param($Id, $Group, $Name, $Desc, [string]$Kind = 'Files', $Targets = @(), [bool]$Admin = $false, [bool]$Default = $true,
          $Service, $Process, $ProcessLabel, $Action)
    @{ Id = $Id; Group = $Group; Name = $Name; Desc = $Desc; Kind = $Kind; Targets = @($Targets); Admin = $Admin; Default = $Default
       Service = $Service; Process = $Process; ProcessLabel = $ProcessLabel; Action = $Action }
}
function T([string]$Path, [string]$Filter = '*', [bool]$Recurse = $true, [int]$MinAgeHours = 0) {
    @{ Path = $Path; Filter = $Filter; Recurse = $Recurse; MinAgeHours = $MinAgeHours }
}

$chromium = { param($base) @( (T "$base\User Data\*\Cache\Cache_Data"), (T "$base\User Data\*\Code Cache"), (T "$base\User Data\*\GPUCache"), (T "$base\User Data\ShaderCache") ) }

$script:CleanerRules = @(
    New-AWRule 'UserTemp'   'Windows' 'User temp files'         'Files in your %TEMP% folder older than 24 hours.' -Targets (T '%TEMP%' -MinAgeHours 24)
    New-AWRule 'WinTemp'    'Windows' 'Windows temp files'      'Files in C:\Windows\Temp older than 24 hours.' -Targets (T '%SystemRoot%\Temp' -MinAgeHours 24) -Admin $true
    New-AWRule 'Recycle'    'Windows' 'Recycle Bin'             'Empties the Recycle Bin on all fixed drives.' -Kind 'RecycleBin'
    New-AWRule 'Thumbs'     'Windows' 'Thumbnail cache'         'Explorer thumbnail databases (rebuilt automatically; files in use are skipped).' -Targets (T '%LOCALAPPDATA%\Microsoft\Windows\Explorer' 'thumbcache_*.db' $false)
    New-AWRule 'WerUser'    'Windows' 'Error reports (user)'    'Windows Error Reporting archives for your account.' -Targets (T '%LOCALAPPDATA%\Microsoft\Windows\WER')
    New-AWRule 'WerSys'     'Windows' 'Error reports (system)'  'System-wide Windows Error Reporting queue and archives.' -Targets (T '%ProgramData%\Microsoft\Windows\WER') -Admin $true
    New-AWRule 'CrashDumps' 'Windows' 'App crash dumps'         'Application crash dumps in %LOCALAPPDATA%\CrashDumps.' -Targets (T '%LOCALAPPDATA%\CrashDumps')
    New-AWRule 'MemDumps'   'Windows' 'System memory dumps'     'Minidumps and MEMORY.DMP from blue screens.' -Targets @((T '%SystemRoot%\Minidump'), (T '%SystemRoot%' 'MEMORY.DMP' $false)) -Admin $true
    New-AWRule 'WinUpdate'  'Windows' 'Windows Update cache'    'Downloaded update packages already installed. Briefly stops the Windows Update service.' -Targets (T '%SystemRoot%\SoftwareDistribution\Download') -Admin $true -Service 'wuauserv'
    New-AWRule 'DeliveryOp' 'Windows' 'Delivery Optimization'   'Peer-to-peer update cache. Briefly stops the Delivery Optimization service.' -Targets (T '%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache') -Admin $true -Default $false -Service 'DoSvc'
    New-AWRule 'Prefetch'   'Windows' 'Prefetch data'           'Launch-optimization data. The next few app launches may be slightly slower.' -Targets (T '%SystemRoot%\Prefetch' '*.pf' $false) -Admin $true -Default $false
    New-AWRule 'WinLogs'    'Windows' 'Setup and CBS logs'      'Component servicing / DISM logs older than 24 hours.' -Targets @((T '%SystemRoot%\Logs\CBS' '*.log' $false 24), (T '%SystemRoot%\Logs\DISM' '*.log' $false 24)) -Admin $true -Default $false
    New-AWRule 'Shaders'    'Windows' 'GPU shader caches'       'DirectX, NVIDIA and AMD shader caches. Games rebuild them on next launch.' -Targets @((T '%LOCALAPPDATA%\D3DSCache'), (T '%LOCALAPPDATA%\NVIDIA\DXCache'), (T '%LOCALAPPDATA%\NVIDIA\GLCache'), (T '%LOCALAPPDATA%\AMD\DxCache')) -Default $false

    New-AWRule 'Edge'       'Browsers' 'Microsoft Edge cache'   'Cached web content, code cache and GPU cache. History, cookies and passwords are untouched.' -Targets (& $chromium '%LOCALAPPDATA%\Microsoft\Edge') -Process 'msedge' -ProcessLabel 'Edge'
    New-AWRule 'Chrome'     'Browsers' 'Google Chrome cache'    'Cached web content, code cache and GPU cache. History, cookies and passwords are untouched.' -Targets (& $chromium '%LOCALAPPDATA%\Google\Chrome') -Process 'chrome' -ProcessLabel 'Chrome'
    New-AWRule 'Brave'      'Browsers' 'Brave cache'            'Cached web content, code cache and GPU cache.' -Targets (& $chromium '%LOCALAPPDATA%\BraveSoftware\Brave-Browser') -Process 'brave' -ProcessLabel 'Brave'
    New-AWRule 'Firefox'    'Browsers' 'Firefox cache'          'Firefox cache2 folders for every profile.' -Targets (T '%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2') -Process 'firefox' -ProcessLabel 'Firefox'

    New-AWRule 'Teams'      'Applications' 'Microsoft Teams cache' 'Classic and new Teams web caches.' -Targets @((T '%APPDATA%\Microsoft\Teams\Cache'), (T '%APPDATA%\Microsoft\Teams\Service Worker\CacheStorage'), (T '%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\*\Cache')) -Process @('Teams', 'ms-teams') -ProcessLabel 'Teams' -Default $false
    New-AWRule 'Discord'    'Applications' 'Discord cache'       'Discord web, code and GPU caches.' -Targets @((T '%APPDATA%\discord\Cache'), (T '%APPDATA%\discord\Code Cache'), (T '%APPDATA%\discord\GPUCache')) -Process 'Discord' -ProcessLabel 'Discord' -Default $false
    New-AWRule 'Steam'      'Applications' 'Steam web cache'     'Steam client browser cache (not games or shader pre-caches).' -Targets (T '%LOCALAPPDATA%\Steam\htmlcache') -Process 'steam' -ProcessLabel 'Steam' -Default $false

    New-AWRule 'Recent'     'Privacy' 'Recent items list'       'Shortcuts in the Recent Items list (the files themselves are untouched).' -Targets (T '%APPDATA%\Microsoft\Windows\Recent' '*.lnk' $false) -Default $false
    New-AWRule 'Clipboard'  'Privacy' 'Clipboard'               'Clears the current clipboard contents.' -Kind 'Action' -Action 'Clipboard' -Default $false
    New-AWRule 'Dns'        'Privacy' 'DNS resolver cache'      'Flushes cached DNS lookups (ipconfig /flushdns).' -Kind 'Action' -Action 'FlushDns' -Default $false
)
#endregion

#region ---------------------------------------------------------------- Debloat catalog
# Store apps AWiper knows about. Pattern is matched against the package Name with -like.
# Recommended = pre-checked. Anything not listed only appears with "Show all apps".
function A([string]$Pattern, [string]$Name, [string]$Category, [bool]$Recommended = $true, [string]$Note = '') {
    @{ Pattern = $Pattern; Name = $Name; Category = $Category; Recommended = $Recommended; Note = $Note }
}
$script:BloatCatalog = @(
    A 'Microsoft.BingNews'                      'Microsoft News'            'Microsoft'
    A 'Microsoft.BingWeather'                   'Weather'                   'Microsoft'
    A 'Microsoft.BingFinance'                   'Money'                     'Microsoft'
    A 'Microsoft.BingSports'                    'Sports'                    'Microsoft'
    A 'Microsoft.BingSearch'                    'Bing Search'               'Microsoft'
    A 'Microsoft.BingTravel'                    'Travel'                    'Microsoft'
    A 'Microsoft.News'                          'News'                      'Microsoft'
    A 'Microsoft.GetHelp'                       'Get Help'                  'Microsoft'
    A 'Microsoft.Getstarted'                    'Tips'                      'Microsoft'
    A 'Microsoft.MicrosoftOfficeHub'            'Microsoft 365 (Office hub)' 'Microsoft'
    A 'Microsoft.MicrosoftSolitaireCollection'  'Solitaire Collection'      'Microsoft'
    A 'Microsoft.People'                        'People'                    'Microsoft'
    A 'Microsoft.PowerAutomateDesktop'          'Power Automate'            'Microsoft'
    A 'Microsoft.Todos'                         'Microsoft To Do'           'Microsoft'
    A 'Microsoft.WindowsFeedbackHub'            'Feedback Hub'              'Microsoft'
    A 'Microsoft.WindowsMaps'                   'Maps'                      'Microsoft'
    A 'Microsoft.549981C3F5F10'                 'Cortana'                   'Microsoft'
    A 'Microsoft.MixedReality.Portal'           'Mixed Reality Portal'      'Microsoft'
    A 'Microsoft.SkypeApp'                      'Skype'                     'Microsoft'
    A 'Microsoft.Office.OneNote'                'OneNote for Windows 10'    'Microsoft'
    A 'Microsoft.Office.Sway'                   'Sway'                      'Microsoft'
    A 'Microsoft.3DBuilder'                     '3D Builder'                'Microsoft'
    A 'Microsoft.Microsoft3DViewer'             '3D Viewer'                 'Microsoft'
    A 'Microsoft.Print3D'                       'Print 3D'                  'Microsoft'
    A 'Microsoft.Messaging'                     'Messaging'                 'Microsoft'
    A 'Microsoft.Wallet'                        'Wallet'                    'Microsoft'
    A 'Microsoft.NetworkSpeedTest'              'Network Speed Test'        'Microsoft'
    A 'Microsoft.MicrosoftJournal'              'Journal'                   'Microsoft'
    A 'Microsoft.ZuneVideo'                     'Movies and TV'             'Microsoft'
    A 'Microsoft.Copilot'                       'Copilot'                   'Microsoft'
    A 'Microsoft.Windows.DevHome'               'Dev Home'                  'Microsoft'
    A 'Microsoft.WindowsCommunicationsApps'     'Mail and Calendar'         'Microsoft'
    A 'Clipchamp.Clipchamp'                     'Clipchamp'                 'Microsoft'
    A 'MicrosoftCorporationII.MicrosoftFamily'  'Family Safety'             'Microsoft'
    A 'MicrosoftTeams'                          'Teams (personal)'          'Microsoft'
    A 'Microsoft.OutlookForWindows'             'Outlook (new)'             'Microsoft' $false 'Keep if you use it for mail'
    A 'MSTeams'                                 'Teams (work or school)'    'Microsoft' $false 'Keep if your organization uses Teams'
    A 'Microsoft.ZuneMusic'                     'Media Player'              'Microsoft' $false 'Default music and video player'
    A 'Microsoft.YourPhone'                     'Phone Link'                'Microsoft' $false
    A 'Microsoft.WindowsSoundRecorder'          'Sound Recorder'            'Microsoft' $false
    A 'Microsoft.MicrosoftStickyNotes'          'Sticky Notes'              'Microsoft' $false
    A 'Microsoft.WindowsAlarms'                 'Clock'                     'Microsoft' $false
    A 'MicrosoftCorporationII.QuickAssist'      'Quick Assist'              'Microsoft' $false 'Used for remote support'
    A 'Microsoft.GamingApp'                     'Xbox app'                  'Gaming'    $false 'Needed for Game Pass PC games'
    A 'Microsoft.XboxApp'                       'Xbox Console Companion'    'Gaming'
    A 'Microsoft.XboxGamingOverlay'             'Xbox Game Bar'             'Gaming'    $false 'Win+G overlay and screen capture'

    A 'SpotifyAB.SpotifyMusic'                  'Spotify'                   'Third-party'
    A 'Disney.37853FC22B2CE'                    'Disney+'                   'Third-party'
    A '4DF9E0F8.Netflix'                        'Netflix'                   'Third-party'
    A 'AmazonVideo.PrimeVideo'                  'Prime Video'               'Third-party'
    A '*.AmazonAlexa'                           'Alexa'                     'Third-party'
    A 'king.com.*'                              'King games (Candy Crush)'  'Third-party'
    A 'Facebook.*'                              'Facebook'                  'Third-party'
    A 'FACEBOOK.*'                              'Facebook'                  'Third-party'
    A '*.Instagram'                             'Instagram'                 'Third-party'
    A 'BytedancePte.Ltd.TikTok'                 'TikTok'                    'Third-party'
    A '*.Twitter'                               'X (Twitter)'               'Third-party'
    A '7EE7776C.LinkedInforWindows'             'LinkedIn'                  'Third-party'
    A '*.Duolingo-LearnLanguagesforFree'        'Duolingo'                  'Third-party'
    A '*.PicsArt-PhotoStudio'                   'PicsArt'                   'Third-party'
    A '*.Flipboard'                             'Flipboard'                 'Third-party'
    A '*.HiddenCity*'                           'Hidden City'               'Third-party'
    A '*.MarchofEmpires'                        'March of Empires'          'Third-party'
    A '*.Asphalt*'                              'Asphalt'                   'Third-party'
    A '*.CaesarsSlotsFreeCasino'                'Caesars Slots'             'Third-party'
    A '*.ROBLOXCORPORATION.ROBLOX'              'Roblox'                    'Third-party' $false
)

# Packages never offered for removal, even with "Show all apps".
$script:ProtectedApps = @(
    'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.DesktopAppInstaller', 'Microsoft.SecHealthUI',
    'Microsoft.Windows.Photos', 'Microsoft.WindowsCalculator', 'Microsoft.WindowsNotepad', 'Microsoft.WindowsTerminal',
    'Microsoft.Paint', 'Microsoft.ScreenSketch', 'Microsoft.WindowsCamera', 'Microsoft.HEIFImageExtension',
    'Microsoft.HEVCVideoExtension', 'Microsoft.VP9VideoExtensions', 'Microsoft.WebMediaExtensions', 'Microsoft.WebpImageExtension',
    'Microsoft.RawImageExtension', 'Microsoft.AV1VideoExtension', 'Microsoft.AVCEncoderVideoExtension', 'Microsoft.MPEG2VideoExtension',
    'Microsoft.Xbox.TCUI', 'Microsoft.XboxIdentityProvider', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.XboxGameOverlay',
    'Microsoft.WindowsAppRuntime*', 'Microsoft.VCLibs*', 'Microsoft.UI.Xaml*', 'Microsoft.NET.*', 'Microsoft.Services.Store.Engagement',
    'Microsoft.MicrosoftEdge*', 'Microsoft.Windows.*', 'Microsoft.AAD.BrokerPlugin', 'Microsoft.AccountsControl', 'Microsoft.LockApp',
    'Microsoft.ApplicationCompatibilityEnhancements', 'Microsoft.OneDriveSync', 'MicrosoftWindows.*', 'windows.*', 'Windows.*',
    'Microsoft.Winget.*', 'Microsoft.LanguageExperiencePack*', 'Microsoft.WidgetsPlatformRuntime', 'Microsoft.StartExperiencesApp'
)

# Registry tweaks. Each value: Path / Name / Type / Value / Revert ($null = delete the value on revert).
# RemoveKeys are deleted on revert (used where the tweak creates a key whose presence is the setting).
function New-AWTweak {
    param($Id, $Group, $Name, $Desc, $Values, [bool]$Admin = $false, [bool]$Default = $true, [bool]$Explorer = $false, $RemoveKeys = @())
    @{ Id = $Id; Group = $Group; Name = $Name; Desc = $Desc; Values = @($Values); Admin = $Admin; Default = $Default; Explorer = $Explorer; RemoveKeys = @($RemoveKeys) }
}
function RegV([string]$Path, [string]$Name, $Value, $Revert = $null, [string]$Type = 'DWord') {
    @{ Path = $Path; Name = $Name; Type = $Type; Value = $Value; Revert = $Revert }
}
$cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$classicMenu = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'

$script:Tweaks = @(
    New-AWTweak 'Telemetry' 'Privacy' 'Limit telemetry' 'Sets diagnostic data to the lowest level this edition allows (machine policy).' -Admin $true -Values @(
        (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0))
    New-AWTweak 'AdId' 'Privacy' 'Disable advertising ID' 'Stops apps from using your advertising ID and diagnostic data for personalized ads and tips.' -Values @(
        (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0 1)
        (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0 1))
    New-AWTweak 'Suggestions' 'Privacy' 'Disable tips, ads and suggestions' 'Removes suggested apps in Start, tips on the lock screen and in Settings, and silent app installs.' -Values @(
        (RegV $cdm 'SubscribedContent-338388Enabled' 0 1), (RegV $cdm 'SubscribedContent-338389Enabled' 0 1),
        (RegV $cdm 'SubscribedContent-353694Enabled' 0 1), (RegV $cdm 'SubscribedContent-353696Enabled' 0 1),
        (RegV $cdm 'SubscribedContent-310093Enabled' 0 1), (RegV $cdm 'SystemPaneSuggestionsEnabled' 0 1),
        (RegV $cdm 'SilentInstalledAppsEnabled' 0 1), (RegV $cdm 'SoftLandingEnabled' 0 1),
        (RegV $cdm 'RotatingLockScreenOverlayEnabled' 0 1),
        (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' 0 1))
    New-AWTweak 'StartRecs' 'Privacy' 'Hide Start menu recommendations' 'Stops promoted apps and websites in the Recommended section of Start.' -Values @(
        (RegV $adv 'Start_IrisRecommendations' 0 1))

    New-AWTweak 'BingSearch' 'Search and AI' 'Disable Bing in Start search' 'Start search only looks at your PC instead of sending queries to Bing.' -Admin $true -Values @(
        (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'BingSearchEnabled' 0 1)
        (RegV 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1))
    New-AWTweak 'Copilot' 'Search and AI' 'Turn off Copilot' 'Disables Windows Copilot and hides its taskbar button.' -Admin $true -Explorer $true -Values @(
        (RegV 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1)
        (RegV $adv 'ShowCopilotButton' 0 1))
    New-AWTweak 'Recall' 'Search and AI' 'Turn off Recall snapshots' 'Stops Windows Recall from saving snapshots on Copilot+ PCs.' -Admin $true -Values @(
        (RegV 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1))

    New-AWTweak 'Widgets' 'Taskbar and Explorer' 'Remove Widgets' 'Hides the Widgets (news and weather) board and its taskbar button.' -Admin $true -Explorer $true -Values @(
        (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0))
    New-AWTweak 'Chat' 'Taskbar and Explorer' 'Hide Chat button' 'Removes the Teams Chat button from the taskbar.' -Explorer $true -Values @(
        (RegV $adv 'TaskbarMn' 0 1))
    New-AWTweak 'TaskView' 'Taskbar and Explorer' 'Hide Task View button' 'Removes the Task View button. Win+Tab still works.' -Default $false -Explorer $true -Values @(
        (RegV $adv 'ShowTaskViewButton' 0 1))
    New-AWTweak 'SearchIcon' 'Taskbar and Explorer' 'Search as icon only' 'Shrinks the taskbar search box to an icon.' -Default $false -Explorer $true -Values @(
        (RegV 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'SearchboxTaskbarMode' 1 2))
    New-AWTweak 'AlignLeft' 'Taskbar and Explorer' 'Align taskbar to the left' 'Moves the Start button and taskbar icons back to the left edge.' -Default $false -Explorer $true -Values @(
        (RegV $adv 'TaskbarAl' 0 1))
    New-AWTweak 'ClassicMenu' 'Taskbar and Explorer' 'Classic right-click menu' 'Shows the full Windows 10 context menu without "Show more options".' -Default $false -Explorer $true -Values @(
        (RegV "$classicMenu\InprocServer32" '(default)' '' $null 'String')) -RemoveKeys @($classicMenu)
    New-AWTweak 'FileExt' 'Taskbar and Explorer' 'Show file extensions' 'Shows extensions like .exe and .pdf in File Explorer.' -Explorer $true -Values @(
        (RegV $adv 'HideFileExt' 0 1))
    New-AWTweak 'Hidden' 'Taskbar and Explorer' 'Show hidden files' 'Shows hidden files and folders in File Explorer.' -Default $false -Explorer $true -Values @(
        (RegV $adv 'Hidden' 1 2))
)
#endregion

#region ---------------------------------------------------------------- XAML
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AWiper" Width="1320" Height="840" MinWidth="1080" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#121628"
        FontFamily="Segoe UI" FontSize="13" Foreground="#E9ECF8"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <WindowChrome.WindowChrome>
    <WindowChrome CaptionHeight="56" ResizeBorderThickness="6" GlassFrameThickness="0" CornerRadius="0" UseAeroCaptionButtons="False"/>
  </WindowChrome.WindowChrome>

  <Window.Resources>
    <SolidColorBrush x:Key="TextBrush"   Color="#E9ECF8"/>
    <SolidColorBrush x:Key="MutedBrush"  Color="#8C95BD"/>
    <SolidColorBrush x:Key="DimBrush"    Color="#5F6890"/>
    <SolidColorBrush x:Key="TealBrush"   Color="#19C3B1"/>
    <SolidColorBrush x:Key="PurpleBrush" Color="#8B5CF6"/>
    <SolidColorBrush x:Key="LineBrush"   Color="#36406A"/>
    <SolidColorBrush x:Key="FieldBrush"  Color="#1A2039"/>
    <SolidColorBrush x:Key="HoverBrush"  Color="#2C3556"/>
    <SolidColorBrush x:Key="SelBrush"    Color="#37436F"/>
    <SolidColorBrush x:Key="TrackBrush"  Color="#3A4468"/>
    <SolidColorBrush x:Key="DangerBrush" Color="#F2617A"/>
    <SolidColorBrush x:Key="AmberBrush"  Color="#F5B94B"/>

    <LinearGradientBrush x:Key="TealGrad" StartPoint="0,0" EndPoint="1,0">
      <GradientStop Color="#12A7C9" Offset="0"/><GradientStop Color="#1ED2AE" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="PurpleGrad" StartPoint="0,0" EndPoint="1,0">
      <GradientStop Color="#6C4BEF" Offset="0"/><GradientStop Color="#9D6BFF" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="BrandGrad" StartPoint="0,0" EndPoint="1,0">
      <GradientStop Color="#1ED2AE" Offset="0"/><GradientStop Color="#9D6BFF" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="CardGrad" StartPoint="0,0" EndPoint="0,1">
      <GradientStop Color="#262D4D" Offset="0"/><GradientStop Color="#1E2442" Offset="1"/>
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="WindowGrad" StartPoint="0,0" EndPoint="1,1">
      <GradientStop Color="#1C2139" Offset="0"/><GradientStop Color="#111527" Offset="1"/>
    </LinearGradientBrush>

    <FontFamily x:Key="IconFont">Segoe Fluent Icons, Segoe MDL2 Assets</FontFamily>

    <!-- Text -->
    <Style x:Key="H1" TargetType="TextBlock">
      <Setter Property="FontSize" Value="24"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="H2" TargetType="TextBlock">
      <Setter Property="FontSize" Value="16"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Muted" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="Caps" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource DimBrush}"/><Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="Bold"/><Setter Property="Margin" Value="0,14,0,6"/>
    </Style>
    <Style x:Key="Icon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="{StaticResource IconFont}"/><Setter Property="VerticalAlignment" Value="Center"/>
    </Style>

    <!-- Card -->
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{StaticResource CardGrad}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="14"/>
      <Setter Property="Padding" Value="18"/>
    </Style>
    <Style x:Key="Pill" TargetType="Border">
      <Setter Property="CornerRadius" Value="10"/><Setter Property="Padding" Value="7,1"/>
      <Setter Property="Margin" Value="8,0,0,0"/><Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="BorderThickness" Value="1"/>
    </Style>

    <!-- Buttons -->
    <Style x:Key="BtnBase" TargetType="Button">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="Background" Value="#262E4D"/>
      <Setter Property="BorderBrush" Value="#4A5680"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,8"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#19C3B1"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.8"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="Button" BasedOn="{StaticResource BtnBase}"/>
    <Style x:Key="BtnAccent" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Background" Value="{StaticResource TealGrad}"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Effect"><Setter.Value><DropShadowEffect Color="#19C3B1" BlurRadius="16" ShadowDepth="0" Opacity="0.35"/></Setter.Value></Setter>
    </Style>
    <Style x:Key="BtnPurple" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Background" Value="{StaticResource PurpleGrad}"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Effect"><Setter.Value><DropShadowEffect Color="#8B5CF6" BlurRadius="16" ShadowDepth="0" Opacity="0.35"/></Setter.Value></Setter>
    </Style>
    <Style x:Key="BtnOutline" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="BorderBrush" Value="#8B5CF6"/>
    </Style>
    <Style x:Key="BtnChip" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Padding" Value="12,5"/><Setter Property="Margin" Value="0,0,6,0"/><Setter Property="FontSize" Value="12"/>
    </Style>
    <Style x:Key="BtnIcon" TargetType="Button" BasedOn="{StaticResource BtnBase}">
      <Setter Property="Padding" Value="10,8"/><Setter Property="FontFamily" Value="{StaticResource IconFont}"/><Setter Property="FontSize" Value="14"/>
    </Style>

    <Style x:Key="CapBtn" TargetType="Button">
      <Setter Property="Width" Value="46"/><Setter Property="Height" Value="34"/>
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="FontFamily" Value="{StaticResource IconFont}"/><Setter Property="FontSize" Value="10"/>
      <Setter Property="WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="8">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#2C3556"/><Setter Property="Foreground" Value="White"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="CapClose" TargetType="Button" BasedOn="{StaticResource CapBtn}">
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#E81123"/><Setter Property="Foreground" Value="White"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- Sidebar navigation -->
    <Style x:Key="NavBtn" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="FontSize" Value="13.5"/>
      <Setter Property="Margin" Value="0,3"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="GroupName" Value="Nav"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="10" Padding="14,10" Background="Transparent">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" FontFamily="{StaticResource IconFont}"
                           FontSize="16" Width="22" VerticalAlignment="Center"/>
                <ContentPresenter Margin="10,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#262E4D"/><Setter Property="Foreground" Value="White"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource TealGrad}"/>
                <Setter Property="Foreground" Value="White"/><Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Rounded square checkbox -->
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Grid Background="Transparent">
              <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <Border x:Name="Box" Width="18" Height="18" CornerRadius="5" BorderThickness="2" BorderBrush="#7A5AF8" Background="Transparent" VerticalAlignment="Center">
                <Path x:Name="Mark" Data="M 2.5,7 L 6,10.5 L 11.5,3.5" Stroke="White" StrokeThickness="2" Visibility="Collapsed"
                      StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round"/>
              </Border>
              <ContentPresenter Grid.Column="1" Margin="10,0,0,0" VerticalAlignment="Center"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Box" Property="Background" Value="{StaticResource PurpleGrad}"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="#9D6BFF"/>
                <Setter TargetName="Mark" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Box" Property="BorderBrush" Value="#19C3B1"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ON / OFF switch -->
    <Style x:Key="Switch" TargetType="CheckBox">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Grid Width="58" Height="24">
              <Border x:Name="Track" CornerRadius="12" Background="{StaticResource PurpleGrad}"/>
              <TextBlock x:Name="Lbl" Text="OFF" FontSize="9.5" FontWeight="Bold" Foreground="White"
                         VerticalAlignment="Center" HorizontalAlignment="Right" Margin="0,0,8,0"/>
              <Border x:Name="Knob" Width="20" Height="20" CornerRadius="10" Background="#ECEFFA" HorizontalAlignment="Left" Margin="2,0,0,0"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Track" Property="Background" Value="{StaticResource TealGrad}"/>
                <Setter TargetName="Lbl" Property="Text" Value="ON"/>
                <Setter TargetName="Lbl" Property="HorizontalAlignment" Value="Left"/>
                <Setter TargetName="Lbl" Property="Margin" Value="9,0,0,0"/>
                <Setter TargetName="Knob" Property="HorizontalAlignment" Value="Right"/>
                <Setter TargetName="Knob" Property="Margin" Value="0,0,2,0"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Progress bar -->
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="8"/>
      <Setter Property="Foreground" Value="{StaticResource TealGrad}"/>
      <Setter Property="Background" Value="{StaticResource TrackBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" CornerRadius="4" Background="{TemplateBinding Background}"/>
              <Border x:Name="PART_Indicator" CornerRadius="4" Background="{TemplateBinding Foreground}" HorizontalAlignment="Left"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsIndeterminate" Value="True">
                <Setter TargetName="PART_Indicator" Property="HorizontalAlignment" Value="Stretch"/>
                <Trigger.EnterActions>
                  <BeginStoryboard x:Name="Pulse">
                    <Storyboard>
                      <DoubleAnimation Storyboard.TargetName="PART_Indicator" Storyboard.TargetProperty="Opacity"
                                       From="0.25" To="1" Duration="0:0:0.8" AutoReverse="True" RepeatBehavior="Forever"/>
                    </Storyboard>
                  </BeginStoryboard>
                </Trigger.EnterActions>
                <Trigger.ExitActions><StopStoryboard BeginStoryboardName="Pulse"/></Trigger.ExitActions>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Text box with placeholder (Tag) -->
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource FieldBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="CaretBrush" Value="White"/>
      <Setter Property="SelectionBrush" Value="#8B5CF6"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8">
              <Grid>
                <TextBlock x:Name="Ph" Text="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}" Foreground="{StaticResource DimBrush}"
                           Margin="{TemplateBinding Padding}" VerticalAlignment="Center" IsHitTestVisible="False" Visibility="Collapsed"/>
                <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="Text" Value=""><Setter TargetName="Ph" Property="Visibility" Value="Visible"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#19C3B1"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="{StaticResource FieldBrush}"/>
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="CaretBrush" Value="White"/>
      <Setter Property="SelectionBrush" Value="#8B5CF6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#19C3B1"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Segmented choice (radio buttons that look like tabs) -->
    <Style x:Key="SegBtn" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" CornerRadius="8" Padding="12,8" Background="Transparent">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#2C3556"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource TealGrad}"/>
                <Setter Property="Foreground" Value="White"/><Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="LinkBtn" TargetType="Button">
      <Setter Property="Foreground" Value="{StaticResource TealBrush}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <TextBlock x:Name="T" Text="{TemplateBinding Content}" Foreground="{TemplateBinding Foreground}"/>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="T" Property="TextDecorations" Value="Underline"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Slim scrollbars -->
    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="10"/><Setter Property="MinWidth" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Track x:Name="PART_Track" IsDirectionReversed="True">
              <Track.Thumb>
                <Thumb>
                  <Thumb.Template>
                    <ControlTemplate TargetType="Thumb"><Border Background="#46507A" CornerRadius="4" Margin="2"/></ControlTemplate>
                  </Thumb.Template>
                </Thumb>
              </Track.Thumb>
            </Track>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/><Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="10"/><Setter Property="MinHeight" Value="10"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Track x:Name="PART_Track" IsDirectionReversed="False">
                  <Track.Thumb>
                    <Thumb>
                      <Thumb.Template>
                        <ControlTemplate TargetType="Thumb"><Border Background="#46507A" CornerRadius="4" Margin="2"/></ControlTemplate>
                      </Thumb.Template>
                    </Thumb>
                  </Track.Thumb>
                </Track>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- List views -->
    <Style TargetType="ListView">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="VirtualizingStackPanel.IsVirtualizing" Value="True"/>
    </Style>
    <Style TargetType="ListViewItem">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Margin" Value="0,1"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListViewItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="0,6">
              <GridViewRowPresenter VerticalAlignment="Center" Columns="{TemplateBinding GridView.ColumnCollection}" Content="{TemplateBinding Content}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#2A3253"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="Bd" Property="Background" Value="#37436F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="GridViewColumnHeader">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="GridViewColumnHeader">
            <Grid>
              <Border x:Name="Bd" Background="Transparent" BorderBrush="#36406A" BorderThickness="0,0,0,1" Padding="7,8">
                <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"/>
              </Border>
              <Thumb x:Name="PART_HeaderGripper" HorizontalAlignment="Right" Width="6" Cursor="SizeWE">
                <Thumb.Template><ControlTemplate TargetType="Thumb"><Border Background="Transparent"/></ControlTemplate></Thumb.Template>
              </Thumb>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter Property="Foreground" Value="White"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="6,4">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#2A3253"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="Bd" Property="Background" Value="#37436F"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ToolTip">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToolTip">
            <Border Background="#262E4D" BorderBrush="#46507A" BorderThickness="1" CornerRadius="6" Padding="9,6" MaxWidth="420">
              <ContentPresenter>
                <ContentPresenter.Resources>
                  <Style TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/></Style>
                </ContentPresenter.Resources>
              </ContentPresenter>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="CtxMenu" TargetType="ContextMenu">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ContextMenu">
            <Border Background="#232A45" BorderBrush="#46507A" BorderThickness="1" CornerRadius="8" Padding="4">
              <StackPanel IsItemsHost="True"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="CtxItem" TargetType="MenuItem">
      <Setter Property="Foreground" Value="#E9ECF8"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="MenuItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="12,7" MinWidth="170">
              <ContentPresenter ContentSource="Header" TextElement.Foreground="#E9ECF8"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="Bd" Property="Background" Value="#37436F"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Border x:Name="RootBorder" Background="{StaticResource WindowGrad}">
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="56"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="34"/>
      </Grid.RowDefinitions>

      <!-- ================= Title bar ================= -->
      <Grid Grid.Row="0">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="244"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" Margin="20,0,0,0" VerticalAlignment="Center">
          <Border Width="32" Height="32" CornerRadius="10" Background="{StaticResource TealGrad}">
            <TextBlock Text="&#xE945;" Style="{StaticResource Icon}" FontSize="16" Foreground="White" HorizontalAlignment="Center"/>
          </Border>
          <TextBlock Text="AWiper" FontSize="21" FontWeight="Bold" Margin="11,0,0,0" VerticalAlignment="Center" Foreground="{StaticResource BrandGrad}"/>
          <TextBlock x:Name="VersionText" Text="v1.0" Foreground="{StaticResource DimBrush}" FontSize="11" Margin="7,6,0,0" VerticalAlignment="Center"/>
        </StackPanel>
        <TextBlock x:Name="ViewTitle" Grid.Column="1" Text="Dashboard" FontSize="15" FontWeight="SemiBold" Foreground="{StaticResource MutedBrush}"
                   VerticalAlignment="Center" Margin="14,0,0,0"/>
        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,14,0">
          <Button x:Name="TargetBtn" Margin="0,0,10,0" Padding="11,5" FontSize="12" WindowChrome.IsHitTestVisibleInChrome="True"
                  ToolTip="Choose which computer AWiper works on">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="TargetIcon" Text="&#xE7F4;" Style="{StaticResource Icon}" FontSize="12" Foreground="{StaticResource TealBrush}"/>
              <TextBlock x:Name="TargetText" Text="This PC" Margin="7,0,0,0"/>
              <TextBlock Text="&#xE70D;" Style="{StaticResource Icon}" FontSize="9" Margin="8,1,0,0" Foreground="{StaticResource MutedBrush}"/>
            </StackPanel>
          </Button>
          <Border x:Name="AdminBadge" CornerRadius="13" Padding="11,5" BorderThickness="1" BorderBrush="#2E8F86" Background="#163A44">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="AdminIcon" Text="&#xEA18;" Style="{StaticResource Icon}" FontSize="12" Foreground="{StaticResource TealBrush}"/>
              <TextBlock x:Name="AdminText" Text="Administrator" FontSize="12" FontWeight="SemiBold" Margin="7,0,0,0" Foreground="{StaticResource TealBrush}"/>
            </StackPanel>
          </Border>
          <Button x:Name="BtnElevate" Content="Restart as admin" Style="{StaticResource BtnPurple}" Padding="12,5" FontSize="12"
                  Margin="10,0,0,0" WindowChrome.IsHitTestVisibleInChrome="True" Visibility="Collapsed"/>
        </StackPanel>
        <StackPanel Grid.Column="3" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,10,0">
          <Button x:Name="BtnMin"   Style="{StaticResource CapBtn}"   Content="&#xE921;"/>
          <Button x:Name="BtnMax"   Style="{StaticResource CapBtn}"   Content="&#xE922;"/>
          <Button x:Name="BtnClose" Style="{StaticResource CapClose}" Content="&#xE8BB;"/>
        </StackPanel>
      </Grid>

      <!-- ================= Body ================= -->
      <Grid Grid.Row="1">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="244"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- Sidebar -->
        <Border Style="{StaticResource Card}" Margin="16,0,0,0" Padding="12">
          <DockPanel>
            <StackPanel DockPanel.Dock="Bottom" Margin="6,10,6,4">
              <TextBlock Text="SYSTEM DRIVE" Style="{StaticResource Caps}" Margin="0,0,0,6"/>
              <ProgressBar x:Name="SideDriveBar" Maximum="100" Value="0" Height="6"/>
              <TextBlock x:Name="SideDriveText" Text="" Foreground="{StaticResource MutedBrush}" FontSize="12" Margin="0,7,0,0"/>
            </StackPanel>
            <StackPanel>
              <TextBlock Text="MENU" Style="{StaticResource Caps}" Margin="8,4,0,6"/>
              <RadioButton x:Name="NavHome"     Style="{StaticResource NavBtn}" Tag="&#xE80F;" Content="Dashboard" IsChecked="True"/>
              <RadioButton x:Name="NavCleaner"  Style="{StaticResource NavBtn}" Tag="&#xE74D;" Content="Cleaner"/>
              <RadioButton x:Name="NavMap"      Style="{StaticResource NavBtn}" Tag="&#xEB05;" Content="Space Map"/>
              <RadioButton x:Name="NavLarge"    Style="{StaticResource NavBtn}" Tag="&#xE7C3;" Content="Large Files"/>
              <RadioButton x:Name="NavRecovery" Style="{StaticResource NavBtn}" Tag="&#xE81C;" Content="Recovery"/>
              <TextBlock Text="SYSTEM" Style="{StaticResource Caps}" Margin="8,16,0,6"/>
              <RadioButton x:Name="NavStartup"  Style="{StaticResource NavBtn}" Tag="&#xE7E8;" Content="Startup"/>
              <RadioButton x:Name="NavPrograms" Style="{StaticResource NavBtn}" Tag="&#xE71D;" Content="Programs"/>
              <RadioButton x:Name="NavDebloat"  Style="{StaticResource NavBtn}" Tag="&#xE71C;" Content="Debloat"/>
              <RadioButton x:Name="NavTools"    Style="{StaticResource NavBtn}" Tag="&#xE90F;" Content="Tools and Log"/>
            </StackPanel>
          </DockPanel>
        </Border>

        <!-- Views -->
        <Grid Grid.Column="1" Margin="16,0,16,0">

          <!-- ===== Dashboard ===== -->
          <Grid x:Name="ViewHome">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="24,22">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="Keep this PC lean and fast" Style="{StaticResource H1}"/>
                  <TextBlock Text="Analyze junk files, map where your space went, and trim startup clutter. Nothing is removed until you review it." Style="{StaticResource Muted}" Margin="0,6,0,16" MaxWidth="560" HorizontalAlignment="Left"/>
                  <WrapPanel>
                    <Button x:Name="HomeQuick" Style="{StaticResource BtnAccent}" Margin="0,0,10,0">
                      <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE74D;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Analyze junk"/></StackPanel>
                    </Button>
                    <Button x:Name="HomeScan" Style="{StaticResource BtnPurple}" Margin="0,0,10,0">
                      <StackPanel Orientation="Horizontal"><TextBlock Text="&#xEB05;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Map system drive"/></StackPanel>
                    </Button>
                    <Button x:Name="HomeStartup" Style="{StaticResource BtnOutline}">
                      <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE7E8;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Review startup"/></StackPanel>
                    </Button>
                  </WrapPanel>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="24,0,0,0">
                  <StackPanel Margin="0,0,30,0">
                    <TextBlock Text="RECLAIMED" Style="{StaticResource Caps}" Margin="0"/>
                    <TextBlock x:Name="HomeFreed" Text="0 B" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TealBrush}"/>
                    <TextBlock x:Name="HomeCleans" Text="0 cleans" Foreground="{StaticResource MutedBrush}" FontSize="12"/>
                  </StackPanel>
                  <StackPanel>
                    <TextBlock Text="LAST CLEAN" Style="{StaticResource Caps}" Margin="0"/>
                    <TextBlock x:Name="HomeLast" Text="Never" FontSize="28" FontWeight="Bold" Foreground="#B79BFF"/>
                    <TextBlock x:Name="HomeLastSub" Text="" Foreground="{StaticResource MutedBrush}" FontSize="12"/>
                  </StackPanel>
                </StackPanel>
              </Grid>
            </Border>
            <Grid Grid.Row="1" Margin="0,16,0,0">
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="330"/></Grid.ColumnDefinitions>
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <StackPanel>
                  <TextBlock Text="DRIVES" Style="{StaticResource Caps}" Margin="4,0,0,10"/>
                  <WrapPanel x:Name="DriveCards"/>
                </StackPanel>
              </ScrollViewer>
              <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,16" VerticalAlignment="Top">
                <StackPanel>
                  <TextBlock Text="This PC" Style="{StaticResource H2}"/>
                  <StackPanel x:Name="SysInfo" Margin="0,10,0,0"/>
                </StackPanel>
              </Border>
            </Grid>
          </Grid>

          <!-- ===== Cleaner ===== -->
          <Grid x:Name="ViewCleaner" Visibility="Collapsed">
            <Grid.ColumnDefinitions><ColumnDefinition Width="330"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Style="{StaticResource Card}" Margin="0,0,0,16" Padding="16,14">
              <DockPanel>
                <Grid DockPanel.Dock="Top">
                  <TextBlock Text="Cleaning rules" Style="{StaticResource H2}" VerticalAlignment="Center"/>
                  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                    <Button x:Name="RulesDefault" Content="Defaults" Style="{StaticResource BtnChip}"/>
                    <Button x:Name="RulesAll" Content="All" Style="{StaticResource BtnChip}"/>
                    <Button x:Name="RulesNone" Content="None" Style="{StaticResource BtnChip}" Margin="0"/>
                  </StackPanel>
                </Grid>
                <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,6,0,0">
                  <StackPanel x:Name="CleanerItems" Margin="2,0,8,0"/>
                </ScrollViewer>
              </DockPanel>
            </Border>
            <Grid Grid.Column="1" Margin="16,0,0,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <Border Style="{StaticResource Card}" Padding="24,20">
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <StackPanel>
                    <TextBlock x:Name="CleanSummary" Text="Ready to analyze" FontSize="30" FontWeight="Bold"/>
                    <TextBlock x:Name="CleanSubtext" Text="Pick the rules on the left, then Analyze to see what can be removed." Style="{StaticResource Muted}" Margin="0,4,0,0"/>
                  </StackPanel>
                  <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="BtnAnalyze" Margin="0,0,10,0" Padding="20,10">
                      <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE721;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Analyze"/></StackPanel>
                    </Button>
                    <Button x:Name="BtnClean" Style="{StaticResource BtnAccent}" Padding="20,10">
                      <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE74D;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Run Cleaner"/></StackPanel>
                    </Button>
                  </StackPanel>
                  <ProgressBar x:Name="CleanProgress" Grid.Row="1" Grid.ColumnSpan="2" Margin="0,18,0,0" Maximum="100" Value="0"/>
                </Grid>
              </Border>
              <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,16,0,16" Padding="12,10">
                <DockPanel>
                  <TextBlock DockPanel.Dock="Bottom" Text="Browser history, cookies, sessions and saved passwords are never touched. Items marked ADMIN need an elevated session." Style="{StaticResource Muted}" FontSize="11.5" Margin="8,8,8,2"/>
                  <ListView x:Name="CleanResults">
                    <ListView.View>
                      <GridView>
                        <GridViewColumn Header="Item" Width="230">
                          <GridViewColumn.CellTemplate><DataTemplate>
                            <StackPanel Orientation="Horizontal">
                              <Ellipse Width="8" Height="8" Fill="{Binding Dot}" Margin="2,0,10,0" VerticalAlignment="Center"/>
                              <TextBlock Text="{Binding Name}" FontWeight="SemiBold"/>
                            </StackPanel>
                          </DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Group" Width="110" DisplayMemberBinding="{Binding Group}"/>
                        <GridViewColumn Header="Files" Width="90">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Files}" TextAlignment="Right"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Size" Width="100">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Size}" TextAlignment="Right" Foreground="#19C3B1" FontWeight="SemiBold"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Details" Width="380">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Note}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                      </GridView>
                    </ListView.View>
                  </ListView>
                </DockPanel>
              </Border>
            </Grid>
          </Grid>

          <!-- ===== Space Map ===== -->
          <Grid x:Name="ViewMap" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="12">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Button x:Name="MapUp" Style="{StaticResource BtnIcon}" Content="&#xE74A;" ToolTip="Up one level" Margin="0,0,8,0"/>
                <TextBox x:Name="MapPath" Grid.Column="1" Tag="Folder or drive to scan, e.g. C:\" Margin="0,0,8,0"/>
                <Button x:Name="MapBrowse" Grid.Column="2" Style="{StaticResource BtnIcon}" Content="&#xE838;" ToolTip="Browse for a folder" Margin="0,0,12,0"/>
                <WrapPanel x:Name="MapDrives" Grid.Column="3" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <StackPanel Grid.Column="4" Orientation="Horizontal">
                  <Button x:Name="MapScan" Style="{StaticResource BtnAccent}" Content="Scan" Padding="22,8" Margin="0,0,8,0"/>
                  <Button x:Name="MapStop" Content="Stop" IsEnabled="False"/>
                </StackPanel>
              </Grid>
            </Border>
            <Grid Grid.Row="1" Margin="0,16,0,16">
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="310"/></Grid.ColumnDefinitions>
              <Border Style="{StaticResource Card}" Padding="12">
                <Grid>
                  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                  <Grid Margin="4,0,4,10">
                    <TextBlock x:Name="MapCrumb" Text="No scan yet" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" Margin="0,0,140,0"/>
                    <TextBlock x:Name="MapCurSize" Text="" HorizontalAlignment="Right" Foreground="{StaticResource TealBrush}" FontWeight="Bold"/>
                  </Grid>
                  <Border Grid.Row="1" CornerRadius="10" Background="#151A2F" ClipToBounds="True">
                    <Grid>
                      <Canvas x:Name="MapCanvas" Background="Transparent" ClipToBounds="True"/>
                      <StackPanel x:Name="MapHint" HorizontalAlignment="Center" VerticalAlignment="Center">
                        <TextBlock Text="&#xEB05;" Style="{StaticResource Icon}" FontSize="46" Foreground="#3A4468" HorizontalAlignment="Center"/>
                        <TextBlock Text="Pick a drive or folder and press Scan" Foreground="{StaticResource MutedBrush}" Margin="0,12,0,0" HorizontalAlignment="Center"/>
                        <TextBlock Text="Double-click a folder to zoom in, right-click for actions" Foreground="{StaticResource DimBrush}" FontSize="12" Margin="0,4,0,0" HorizontalAlignment="Center"/>
                      </StackPanel>
                    </Grid>
                  </Border>
                  <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="4,10,0,0">
                    <Border Width="12" Height="12" CornerRadius="3" Background="{StaticResource PurpleGrad}"/>
                    <TextBlock Text="Folders" Foreground="{StaticResource MutedBrush}" FontSize="12" Margin="6,0,16,0"/>
                    <Border Width="12" Height="12" CornerRadius="3" Background="{StaticResource TealGrad}"/>
                    <TextBlock Text="Files (1 MB+)" Foreground="{StaticResource MutedBrush}" FontSize="12" Margin="6,0,16,0"/>
                    <Border Width="12" Height="12" CornerRadius="3" Background="#3A4468"/>
                    <TextBlock Text="Small files, grouped" Foreground="{StaticResource MutedBrush}" FontSize="12" Margin="6,0,0,0"/>
                  </StackPanel>
                </Grid>
              </Border>
              <ScrollViewer Grid.Column="1" VerticalScrollBarVisibility="Auto" Margin="16,0,0,0">
                <StackPanel>
                  <Border Style="{StaticResource Card}">
                    <StackPanel>
                      <TextBlock Text="SELECTED" Style="{StaticResource Caps}" Margin="0,0,0,6"/>
                      <TextBlock x:Name="MapSelName" Text="Nothing selected" FontSize="15" FontWeight="SemiBold" TextWrapping="Wrap"/>
                      <TextBlock x:Name="MapSelPath" Text="" Style="{StaticResource Muted}" FontSize="11.5" Margin="0,3,0,0"/>
                      <TextBlock x:Name="MapSelSize" Text="" FontSize="26" FontWeight="Bold" Foreground="{StaticResource TealBrush}" Margin="0,10,0,0"/>
                      <TextBlock x:Name="MapSelMeta" Text="" Style="{StaticResource Muted}" FontSize="12"/>
                      <WrapPanel Margin="0,12,0,0">
                        <Button x:Name="MapOpen" Content="Open" Style="{StaticResource BtnChip}" IsEnabled="False"/>
                        <Button x:Name="MapZoom" Content="Zoom in" Style="{StaticResource BtnChip}" IsEnabled="False"/>
                        <Button x:Name="MapRecycle" Content="Recycle" Style="{StaticResource BtnChip}" IsEnabled="False" BorderBrush="#F2617A"/>
                      </WrapPanel>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                    <StackPanel>
                      <TextBlock Text="LARGEST HERE" Style="{StaticResource Caps}" Margin="0,0,0,6"/>
                      <ListBox x:Name="MapTopList">
                        <ListBox.ItemTemplate>
                          <DataTemplate>
                            <Grid>
                              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                              <TextBlock Text="{Binding Name}" TextTrimming="CharacterEllipsis"/>
                              <TextBlock Grid.Column="1" Text="{Binding SizeText}" Foreground="#8C95BD" Margin="8,0,0,0"/>
                              <ProgressBar Grid.Row="1" Grid.ColumnSpan="2" Height="4" Margin="0,5,0,2" Maximum="100" Value="{Binding PercentOfParent, Mode=OneWay}"/>
                            </Grid>
                          </DataTemplate>
                        </ListBox.ItemTemplate>
                      </ListBox>
                    </StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Margin="0,14,0,0">
                    <StackPanel>
                      <TextBlock Text="FILE TYPES" Style="{StaticResource Caps}" Margin="0,0,0,6"/>
                      <ItemsControl x:Name="MapExtList">
                        <ItemsControl.ItemTemplate>
                          <DataTemplate>
                            <Grid Margin="0,4">
                              <Grid.ColumnDefinitions><ColumnDefinition Width="62"/><ColumnDefinition Width="*"/><ColumnDefinition Width="72"/></Grid.ColumnDefinitions>
                              <TextBlock Text="{Binding Extension}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                              <ProgressBar Grid.Column="1" Height="6" Maximum="100" Value="{Binding RelPercent, Mode=OneWay}" Foreground="{StaticResource PurpleGrad}" Margin="4,0,8,0"/>
                              <TextBlock Grid.Column="2" Text="{Binding SizeText}" Foreground="#8C95BD" TextAlignment="Right"/>
                            </Grid>
                          </DataTemplate>
                        </ItemsControl.ItemTemplate>
                      </ItemsControl>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </ScrollViewer>
            </Grid>
          </Grid>

          <!-- ===== Large Files ===== -->
          <Grid x:Name="ViewLarge" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="14,12">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <Grid>
                  <TextBox x:Name="LargeSearch" Tag="Search by name, folder or extension..." Padding="10,7,44,7"/>
                  <Border HorizontalAlignment="Right" Width="38" Margin="0,1,1,1" CornerRadius="0,7,7,0" Background="{StaticResource TealGrad}" IsHitTestVisible="False">
                    <TextBlock Text="&#xE721;" Style="{StaticResource Icon}" HorizontalAlignment="Center" Foreground="White"/>
                  </Border>
                </Grid>
                <TextBlock x:Name="LargeInfo" Grid.Column="1" Text="Run a scan in Space Map to list the largest files." Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="16,0"/>
                <StackPanel Grid.Column="2" Orientation="Horizontal">
                  <Button x:Name="LargeScan" Content="Scan a drive" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="LargeOpen" Content="Open location" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="LargeExport" Content="Export CSV" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="LargeRecycle" Content="Recycle checked" Style="{StaticResource BtnPurple}" Padding="14,6" FontSize="12"/>
                </StackPanel>
              </Grid>
            </Border>
            <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,16,0,16" Padding="12,10">
              <ListView x:Name="LargeList">
                <ListView.View>
                  <GridView>
                    <GridViewColumn Header="" Width="44">
                      <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Margin="4,0,0,0"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Name" Width="280">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Size" Width="100">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding SizeText}" TextAlignment="Right" Foreground="#19C3B1" FontWeight="SemiBold"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Type" Width="70" DisplayMemberBinding="{Binding Extension}"/>
                    <GridViewColumn Header="Modified" Width="130" DisplayMemberBinding="{Binding ModifiedText}"/>
                    <GridViewColumn Header="Folder" Width="460">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Folder}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                  </GridView>
                </ListView.View>
              </ListView>
            </Border>
          </Grid>

          <!-- ===== Recovery ===== -->
          <Grid x:Name="ViewRecovery" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="20,16">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="Recover deleted files" Style="{StaticResource H2}"/>
                  <TextBlock Text="Check the Recycle Bin and previous versions first. For a deep scan, stop using the drive and save what you recover to a different drive."
                             Style="{StaticResource Muted}" Margin="0,4,0,0"/>
                </StackPanel>
                <Border Grid.Column="1" Background="{StaticResource FieldBrush}" CornerRadius="10" Padding="3" Margin="16,0,0,0"
                        BorderBrush="{StaticResource LineBrush}" BorderThickness="1" VerticalAlignment="Center">
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="RecTabBin"    Style="{StaticResource SegBtn}" GroupName="RecTab" IsChecked="True" Content="Recycle Bin"/>
                    <RadioButton x:Name="RecTabShadow" Style="{StaticResource SegBtn}" GroupName="RecTab" Content="Previous versions"/>
                    <RadioButton x:Name="RecTabDeep"   Style="{StaticResource SegBtn}" GroupName="RecTab" Content="Deep scan"/>
                  </StackPanel>
                </Border>
              </Grid>
            </Border>

            <ScrollViewer Grid.Row="1" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled" Margin="0,14,0,0">
              <StackPanel x:Name="RecDrives" Orientation="Horizontal"/>
            </ScrollViewer>

            <Grid Grid.Row="2" Margin="0,14,0,16">
              <!-- Recycle Bin -->
              <Border x:Name="RecPanelBin" Style="{StaticResource Card}" Padding="14,12">
                <DockPanel>
                  <Grid DockPanel.Dock="Top" Margin="0,0,0,8">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="300"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <TextBox x:Name="BinSearch" Tag="Search by name or original location..."/>
                    <TextBlock x:Name="BinInfo" Grid.Column="1" Text="" Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="14,0"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                      <Button x:Name="BinRefresh" Content="Refresh" Style="{StaticResource BtnChip}"/>
                      <Button x:Name="BinOpen" Content="Open original folder" Style="{StaticResource BtnChip}"/>
                      <Button x:Name="BinRestoreTo" Content="Restore to..." Style="{StaticResource BtnChip}"/>
                      <Button x:Name="BinRestore" Content="Restore checked" Style="{StaticResource BtnAccent}" Padding="14,6" FontSize="12"/>
                    </StackPanel>
                  </Grid>
                  <TextBlock DockPanel.Dock="Bottom" Style="{StaticResource Muted}" FontSize="11.5" Margin="8,8,8,2"
                             Text="Items go back to where they were deleted from. If something already exists there, the restored copy gets &quot;(restored)&quot; added to its name - nothing is overwritten."/>
                  <ListView x:Name="BinList">
                    <ListView.View>
                      <GridView>
                        <GridViewColumn Header="" Width="44">
                          <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Margin="4,0,0,0"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Name" Width="230">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" ToolTip="{Binding OriginalPath}"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Type" Width="64" DisplayMemberBinding="{Binding Kind}"/>
                        <GridViewColumn Header="Size" Width="90">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding SizeText}" TextAlignment="Right" Foreground="#19C3B1" FontWeight="SemiBold"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Deleted" Width="130" DisplayMemberBinding="{Binding DeletedText}"/>
                        <GridViewColumn Header="Deleted by" Width="150">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Owner}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Original location" Width="420">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Folder}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis" ToolTip="{Binding Folder}"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                      </GridView>
                    </ListView.View>
                  </ListView>
                </DockPanel>
              </Border>

              <!-- Previous versions (shadow copies) -->
              <Grid x:Name="RecPanelShadow" Visibility="Collapsed">
                <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Border Style="{StaticResource Card}" Padding="14,12">
                  <DockPanel>
                    <Grid DockPanel.Dock="Top" Margin="0,0,0,8">
                      <TextBlock Text="Snapshots" Style="{StaticResource H2}" VerticalAlignment="Center"/>
                      <Button x:Name="ShadowRefresh" Content="Refresh" Style="{StaticResource BtnChip}" HorizontalAlignment="Right" Margin="0"/>
                    </Grid>
                    <StackPanel DockPanel.Dock="Bottom" Margin="0,10,0,0">
                      <TextBlock x:Name="ShadowNote" Text="" Style="{StaticResource Muted}" FontSize="11.5" Margin="0,0,0,10"/>
                      <WrapPanel>
                        <Button x:Name="ShadowExplore" Content="Open in Explorer" Style="{StaticResource BtnChip}"/>
                        <Button x:Name="ShadowProtect" Content="System Protection settings" Style="{StaticResource BtnChip}" Margin="0"/>
                      </WrapPanel>
                    </StackPanel>
                    <ListBox x:Name="ShadowList">
                      <ListBox.ItemTemplate>
                        <DataTemplate>
                          <StackPanel Margin="2,3">
                            <StackPanel Orientation="Horizontal">
                              <TextBlock Text="{Binding Drive}" FontWeight="Bold" Foreground="#19C3B1" Width="30"/>
                              <TextBlock Text="{Binding CreatedText}" FontWeight="SemiBold"/>
                            </StackPanel>
                            <TextBlock Text="{Binding Age}" Foreground="#8C95BD" FontSize="11.5" Margin="30,2,0,0"/>
                          </StackPanel>
                        </DataTemplate>
                      </ListBox.ItemTemplate>
                    </ListBox>
                  </DockPanel>
                </Border>
                <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,0" Padding="14,12">
                  <DockPanel>
                    <Grid DockPanel.Dock="Top" Margin="0,0,0,8">
                      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                      <TextBox x:Name="ShadowFolder" Tag="Folder to check, e.g. C:\Users\you\Documents"/>
                      <CheckBox x:Name="ShadowChanged" Grid.Column="1" Content="Include changed files" Margin="12,0"/>
                      <Button x:Name="ShadowFind" Grid.Column="2" Content="Find deleted files" Style="{StaticResource BtnAccent}" Padding="14,6" FontSize="12"/>
                    </Grid>
                    <Grid DockPanel.Dock="Bottom" Margin="0,10,0,0">
                      <TextBlock x:Name="ShadowInfo" Text="Pick a snapshot, enter a folder, and AWiper lists files that existed then but are gone now."
                                 Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="4,0,280,0"/>
                      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                        <Button x:Name="ShadowCopyTo" Content="Copy checked to..." Style="{StaticResource BtnChip}"/>
                        <Button x:Name="ShadowRestore" Content="Restore checked" Style="{StaticResource BtnAccent}" Padding="14,6" FontSize="12"/>
                      </StackPanel>
                    </Grid>
                    <ListView x:Name="ShadowResults">
                      <ListView.View>
                        <GridView>
                          <GridViewColumn Header="" Width="44">
                            <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Margin="4,0,0,0"/></DataTemplate></GridViewColumn.CellTemplate>
                          </GridViewColumn>
                          <GridViewColumn Header="Name" Width="220">
                            <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                          </GridViewColumn>
                          <GridViewColumn Header="Status" Width="80" DisplayMemberBinding="{Binding Status}"/>
                          <GridViewColumn Header="Size" Width="90">
                            <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding SizeText}" TextAlignment="Right" Foreground="#19C3B1"/></DataTemplate></GridViewColumn.CellTemplate>
                          </GridViewColumn>
                          <GridViewColumn Header="Modified" Width="130" DisplayMemberBinding="{Binding ModifiedText}"/>
                          <GridViewColumn Header="Folder" Width="380">
                            <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Folder}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis" ToolTip="{Binding Folder}"/></DataTemplate></GridViewColumn.CellTemplate>
                          </GridViewColumn>
                        </GridView>
                      </ListView.View>
                    </ListView>
                  </DockPanel>
                </Border>
              </Grid>

              <!-- Deep scan (Windows File Recovery) -->
              <Grid x:Name="RecPanelDeep" Visibility="Collapsed">
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="330"/></Grid.ColumnDefinitions>
                <Border Style="{StaticResource Card}" Padding="18,14">
                  <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="0,0,8,0">
                      <Border x:Name="WinfrBox" CornerRadius="8" Padding="12,9" Background="#163A44" BorderBrush="#2E8F86" BorderThickness="1">
                        <Grid>
                          <TextBlock x:Name="WinfrStatus" Text="Checking for Windows File Recovery..." TextWrapping="Wrap" FontSize="12.5" VerticalAlignment="Center" Margin="0,0,200,0"/>
                          <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                            <Button x:Name="WinfrInstall" Content="Install" Style="{StaticResource BtnChip}" Visibility="Collapsed"/>
                            <Button x:Name="WinfrStore" Content="Microsoft Store" Style="{StaticResource BtnChip}" Margin="0" Visibility="Collapsed"/>
                          </StackPanel>
                        </Grid>
                      </Border>

                      <TextBlock Text="SCAN THIS DRIVE" Style="{StaticResource Caps}"/>
                      <WrapPanel x:Name="DeepSources"/>

                      <TextBlock Text="SAVE RECOVERED FILES TO" Style="{StaticResource Caps}"/>
                      <Grid>
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                        <TextBox x:Name="DeepDest" Tag="A folder on a different drive, e.g. E:\Recovered"/>
                        <Button x:Name="DeepBrowse" Grid.Column="1" Style="{StaticResource BtnIcon}" Content="&#xE838;" ToolTip="Browse" Margin="8,0,0,0"/>
                      </Grid>
                      <TextBlock x:Name="DeepDestMsg" Text="" FontSize="12" Margin="2,6,0,0" TextWrapping="Wrap" Visibility="Collapsed"/>

                      <TextBlock Text="MODE" Style="{StaticResource Caps}"/>
                      <Border Background="{StaticResource FieldBrush}" CornerRadius="10" Padding="3" BorderBrush="{StaticResource LineBrush}" BorderThickness="1" HorizontalAlignment="Left">
                        <StackPanel Orientation="Horizontal">
                          <RadioButton x:Name="DeepRegular"   Style="{StaticResource SegBtn}" GroupName="DeepMode" IsChecked="True" Content="Regular" MinWidth="110"/>
                          <RadioButton x:Name="DeepExtensive" Style="{StaticResource SegBtn}" GroupName="DeepMode" Content="Extensive" MinWidth="110"/>
                        </StackPanel>
                      </Border>
                      <TextBlock x:Name="DeepModeHint" Text="" Style="{StaticResource Muted}" FontSize="12" Margin="2,6,0,0"/>

                      <TextBlock Text="WHAT TO LOOK FOR" Style="{StaticResource Caps}"/>
                      <TextBox x:Name="DeepFilter" Tag="e.g.  \Users\andre\Documents\ ;  *.jpg ;  budget*.xlsx"/>
                      <TextBlock Text="Folders end with \ and are relative to the drive. Separate several with ;. Leave empty to recover everything found (can be a lot)."
                                 Style="{StaticResource Muted}" FontSize="12" Margin="2,6,0,0"/>

                      <TextBlock Text="COMMAND" Style="{StaticResource Caps}"/>
                      <TextBox x:Name="DeepCmd" IsReadOnly="True" FontFamily="Cascadia Mono, Consolas" FontSize="12" TextWrapping="Wrap"/>

                      <StackPanel Orientation="Horizontal" Margin="0,16,0,4">
                        <Button x:Name="DeepStart" Style="{StaticResource BtnAccent}" Margin="0,0,10,0">
                          <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE81C;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Start recovery"/></StackPanel>
                        </Button>
                        <Button x:Name="DeepStop" Content="Stop" IsEnabled="False" Margin="0,0,10,0"/>
                        <Button x:Name="DeepOpenDest" Content="Open destination"/>
                      </StackPanel>
                    </StackPanel>
                  </ScrollViewer>
                </Border>
                <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,0" Padding="18,14">
                  <StackPanel>
                    <TextBlock Text="Before you start" Style="{StaticResource H2}"/>
                    <Border x:Name="DeepVerdictBox" CornerRadius="8" Padding="12,9" Margin="0,12,0,4" BorderThickness="1" Visibility="Collapsed">
                      <TextBlock x:Name="DeepVerdict" TextWrapping="Wrap" FontSize="12.5"/>
                    </Border>
                    <TextBlock Style="{StaticResource Muted}" FontSize="12.5" Margin="0,10,0,0" LineHeight="20">
                      <Run Text="1.  Stop using the drive. Every file written can overwrite what you want back."/><LineBreak/>
                      <Run Text="2.  Save recovered files to a different drive - AWiper will not let you pick the same one."/><LineBreak/>
                      <Run Text="3.  Try Regular mode first for files deleted recently from an NTFS drive. Use Extensive for USB sticks, SD cards, formatted drives or older deletions."/><LineBreak/>
                      <Run Text="4.  Internal SSDs usually erase deleted data within minutes (TRIM), so deep scans there rarely find anything. Check the Recycle Bin and previous versions first."/><LineBreak/>
                      <Run Text="5.  If the drive clicks, disconnects or shows read errors, stop and have it imaged before trying again."/>
                    </TextBlock>
                    <TextBlock Text="Deep scan uses Microsoft's free Windows File Recovery tool. Results land in a Recovery_date folder inside the destination."
                               Style="{StaticResource Muted}" FontSize="11.5" Margin="0,14,0,0"/>
                  </StackPanel>
                </Border>
              </Grid>
            </Grid>
          </Grid>

          <!-- ===== Startup ===== -->
          <Grid x:Name="ViewStartup" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="20,16">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="Startup programs" Style="{StaticResource H2}"/>
                  <TextBlock x:Name="StartupInfo" Text="Disabled items stay installed, they just won't launch when you sign in. Uses the same switches as Task Manager." Style="{StaticResource Muted}" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                  <Button x:Name="StartupOpen" Content="Open file location" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="StartupRefresh" Content="Refresh" Style="{StaticResource BtnChip}" Margin="0"/>
                </StackPanel>
              </Grid>
            </Border>
            <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,16,0,16" Padding="12,10">
              <ListView x:Name="StartupList">
                <ListView.View>
                  <GridView>
                    <GridViewColumn Header="Status" Width="86">
                      <GridViewColumn.CellTemplate><DataTemplate>
                        <CheckBox Style="{StaticResource Switch}" IsChecked="{Binding Enabled, Mode=OneWay}" IsEnabled="{Binding CanToggle}" Margin="4,0,0,0"/>
                      </DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Name" Width="220">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Scope" Width="90" DisplayMemberBinding="{Binding Scope}"/>
                    <GridViewColumn Header="Source" Width="140" DisplayMemberBinding="{Binding Location}"/>
                    <GridViewColumn Header="Command" Width="520">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Command}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis" ToolTip="{Binding Command}"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                  </GridView>
                </ListView.View>
              </ListView>
            </Border>
          </Grid>

          <!-- ===== Programs ===== -->
          <Grid x:Name="ViewPrograms" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="14,12">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <Grid>
                  <TextBox x:Name="ProgSearch" Tag="Search programs or publishers..." Padding="10,7,44,7"/>
                  <Border HorizontalAlignment="Right" Width="38" Margin="0,1,1,1" CornerRadius="0,7,7,0" Background="{StaticResource PurpleGrad}" IsHitTestVisible="False">
                    <TextBlock Text="&#xE721;" Style="{StaticResource Icon}" HorizontalAlignment="Center" Foreground="White"/>
                  </Border>
                </Grid>
                <TextBlock x:Name="ProgInfo" Grid.Column="1" Text="" Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="16,0"/>
                <StackPanel Grid.Column="2" Orientation="Horizontal">
                  <Button x:Name="ProgRefresh" Content="Refresh" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="ProgOpen" Content="Open folder" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="ProgUninstall" Content="Uninstall" Style="{StaticResource BtnPurple}" Padding="14,6" FontSize="12"/>
                </StackPanel>
              </Grid>
            </Border>
            <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,16,0,16" Padding="12,10">
              <ListView x:Name="ProgList" SelectionMode="Single">
                <ListView.View>
                  <GridView>
                    <GridViewColumn Header="Name" Width="320">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Publisher" Width="220">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Publisher}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Version" Width="130" DisplayMemberBinding="{Binding Version}"/>
                    <GridViewColumn Header="Installed" Width="100" DisplayMemberBinding="{Binding Installed}"/>
                    <GridViewColumn Header="Size" Width="90">
                      <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding SizeText}" TextAlignment="Right" Foreground="#19C3B1"/></DataTemplate></GridViewColumn.CellTemplate>
                    </GridViewColumn>
                    <GridViewColumn Header="Scope" Width="90" DisplayMemberBinding="{Binding Scope}"/>
                  </GridView>
                </ListView.View>
              </ListView>
            </Border>
          </Grid>

          <!-- ===== Debloat ===== -->
          <Grid x:Name="ViewDebloat" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="20,16">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock Text="Debloat Windows" Style="{StaticResource H2}"/>
                  <TextBlock Text="Remove preinstalled Store apps and turn off ads, suggestions and AI features. Create a restore point first if you are making a lot of changes." Style="{StaticResource Muted}" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                  <Button x:Name="DebloatRestore" Content="Create restore point" Style="{StaticResource BtnChip}"/>
                  <Button x:Name="DebloatRefresh" Content="Refresh" Style="{StaticResource BtnChip}" Margin="0"/>
                </StackPanel>
              </Grid>
            </Border>
            <Grid Grid.Row="1" Margin="0,16,0,16">
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="400"/></Grid.ColumnDefinitions>
              <Border Style="{StaticResource Card}" Padding="14,12">
                <DockPanel>
                  <Grid DockPanel.Dock="Top" Margin="0,0,0,8">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <TextBlock Text="Store apps" Style="{StaticResource H2}" VerticalAlignment="Center"/>
                    <TextBox x:Name="AppSearch" Grid.Column="1" Tag="Filter apps..." Margin="14,0,10,0"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                      <Button x:Name="AppsRecommended" Content="Recommended" Style="{StaticResource BtnChip}"/>
                      <Button x:Name="AppsNone" Content="None" Style="{StaticResource BtnChip}" Margin="0"/>
                    </StackPanel>
                  </Grid>
                  <Grid DockPanel.Dock="Bottom" Margin="0,10,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                      <CheckBox x:Name="AppsShowAll" Content="Show all apps" Margin="0,0,18,0"/>
                      <CheckBox x:Name="AppsProvisioned" Content="Also remove for new users" IsChecked="True"
                                ToolTip="Removes the provisioned copy so Windows does not reinstall the app for new accounts. Needs admin."/>
                    </StackPanel>
                    <StackPanel Grid.Column="1" Orientation="Horizontal">
                      <TextBlock x:Name="AppsInfo" Text="" Style="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,12,0"/>
                      <Button x:Name="AppsRemove" Content="Remove checked" Style="{StaticResource BtnPurple}" Padding="14,6" FontSize="12"/>
                    </StackPanel>
                  </Grid>
                  <ListView x:Name="AppList">
                    <ListView.View>
                      <GridView>
                        <GridViewColumn Header="" Width="44">
                          <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding IsChecked, Mode=TwoWay}" Margin="4,0,0,0"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="App" Width="210">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis" ToolTip="{Binding Package}"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Header="Category" Width="100" DisplayMemberBinding="{Binding Category}"/>
                        <GridViewColumn Header="Notes" Width="260">
                          <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Note}" Foreground="#8C95BD" TextTrimming="CharacterEllipsis" ToolTip="{Binding Note}"/></DataTemplate></GridViewColumn.CellTemplate>
                        </GridViewColumn>
                      </GridView>
                    </ListView.View>
                  </ListView>
                </DockPanel>
              </Border>
              <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,0" Padding="16,14">
                <DockPanel>
                  <Grid DockPanel.Dock="Top">
                    <TextBlock Text="Tweaks" Style="{StaticResource H2}" VerticalAlignment="Center"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                      <Button x:Name="TweaksDefault" Content="Defaults" Style="{StaticResource BtnChip}"/>
                      <Button x:Name="TweaksNone" Content="None" Style="{StaticResource BtnChip}" Margin="0"/>
                    </StackPanel>
                  </Grid>
                  <StackPanel DockPanel.Dock="Bottom" Margin="0,10,0,0">
                    <CheckBox x:Name="TweaksRestartExplorer" Content="Restart Explorer to apply taskbar changes" IsChecked="True" Margin="0,0,0,10"/>
                    <StackPanel Orientation="Horizontal">
                      <Button x:Name="TweaksApply" Content="Apply checked" Style="{StaticResource BtnAccent}" Padding="16,7" FontSize="12" Margin="0,0,8,0"/>
                      <Button x:Name="TweaksRevert" Content="Revert checked" Padding="16,7" FontSize="12"/>
                    </StackPanel>
                  </StackPanel>
                  <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,6,0,0">
                    <StackPanel x:Name="TweakItems" Margin="2,0,8,0"/>
                  </ScrollViewer>
                </DockPanel>
              </Border>
            </Grid>
          </Grid>

          <!-- ===== Tools ===== -->
          <Grid x:Name="ViewTools" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="230"/></Grid.RowDefinitions>
            <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,0,0,2">
              <StackPanel x:Name="ToolCards"/>
            </ScrollViewer>
            <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,2,0,16" Padding="16,12">
              <DockPanel>
                <Grid DockPanel.Dock="Top" Margin="0,0,0,10">
                  <TextBlock Text="Activity log" Style="{StaticResource H2}" VerticalAlignment="Center"/>
                  <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                    <Button x:Name="LogClear" Content="Clear view" Style="{StaticResource BtnChip}"/>
                    <Button x:Name="LogOpen" Content="Open log folder" Style="{StaticResource BtnChip}" Margin="0"/>
                  </StackPanel>
                </Grid>
                <TextBox x:Name="LogBox" IsReadOnly="True" FontFamily="Cascadia Mono, Consolas" FontSize="12" Background="#141930"
                         VerticalContentAlignment="Top" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
              </DockPanel>
            </Border>
          </Grid>
        </Grid>
      </Grid>

      <!-- ================= Status bar ================= -->
      <Grid Grid.Row="2" Margin="20,0,20,8">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="260"/></Grid.ColumnDefinitions>
        <TextBlock x:Name="StatusText" Text="Ready" Foreground="{StaticResource MutedBrush}" FontSize="12" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        <ProgressBar x:Name="StatusProgress" Grid.Column="1" Height="5" Maximum="100" Value="0" VerticalAlignment="Center" Visibility="Hidden"/>
      </Grid>

      <!-- ================= Connect dialog (overlay) ================= -->
      <Grid x:Name="ConnectOverlay" Grid.RowSpan="3" Visibility="Collapsed" Background="#B30B0E1C">
        <Border Style="{StaticResource Card}" Width="500" VerticalAlignment="Center" HorizontalAlignment="Center" Padding="26,22">
          <Border.Effect><DropShadowEffect Color="Black" BlurRadius="40" ShadowDepth="0" Opacity="0.6"/></Border.Effect>
          <StackPanel>
            <Grid>
              <StackPanel Orientation="Horizontal">
                <Border Width="34" Height="34" CornerRadius="10" Background="{StaticResource PurpleGrad}">
                  <TextBlock Text="&#xE7F4;" Style="{StaticResource Icon}" FontSize="15" Foreground="White" HorizontalAlignment="Center"/>
                </Border>
                <TextBlock Text="Connect to a computer" Style="{StaticResource H2}" FontSize="18" Margin="12,0,0,0" VerticalAlignment="Center"/>
              </StackPanel>
              <Button x:Name="ConnClose" Style="{StaticResource CapBtn}" Content="&#xE8BB;" HorizontalAlignment="Right" Width="34" Height="30"/>
            </Grid>
            <TextBlock Text="Uses PowerShell remoting (WinRM). You need admin rights on the remote PC, and remoting must be enabled there."
                       Style="{StaticResource Muted}" FontSize="12" Margin="0,10,0,4"/>

            <TextBlock Text="COMPUTER" Style="{StaticResource Caps}"/>
            <TextBox x:Name="ConnHost" Tag="Hostname, FQDN or IP address"/>
            <WrapPanel x:Name="ConnRecent" Margin="0,8,0,0"/>

            <TextBlock Text="DOMAIN (OPTIONAL)" Style="{StaticResource Caps}"/>
            <TextBox x:Name="ConnDomain" Tag="e.g. corp.contoso.com - added to short names and usernames"/>
            <TextBlock x:Name="ConnResolved" Text="" Foreground="{StaticResource DimBrush}" FontSize="11.5" Margin="2,5,0,0"/>

            <TextBlock Text="SIGN IN AS" Style="{StaticResource Caps}"/>
            <Border Background="{StaticResource FieldBrush}" CornerRadius="10" Padding="3" BorderBrush="{StaticResource LineBrush}" BorderThickness="1">
              <UniformGrid Columns="2">
                <RadioButton x:Name="ConnUseCurrent" Style="{StaticResource SegBtn}" GroupName="ConnCred" IsChecked="True">
                  <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE77B;" Style="{StaticResource Icon}" Margin="0,0,7,0"/><TextBlock x:Name="ConnCurrentText" Text="Current credentials"/></StackPanel>
                </RadioButton>
                <RadioButton x:Name="ConnUseOther" Style="{StaticResource SegBtn}" GroupName="ConnCred">
                  <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE8D7;" Style="{StaticResource Icon}" Margin="0,0,7,0"/><TextBlock Text="Other credentials"/></StackPanel>
                </RadioButton>
              </UniformGrid>
            </Border>

            <StackPanel x:Name="ConnOtherPanel" Visibility="Collapsed" Margin="0,10,0,0">
              <TextBox x:Name="ConnUser" Tag="DOMAIN\user or user@domain"/>
              <Grid Margin="0,8,0,0">
                <PasswordBox x:Name="ConnPass"/>
                <TextBlock x:Name="ConnPassHint" Text="Password" Foreground="{StaticResource DimBrush}" Margin="11,0,0,0"
                           VerticalAlignment="Center" IsHitTestVisible="False"/>
              </Grid>
              <Grid Margin="0,10,0,0">
                <CheckBox x:Name="ConnSave" Content="Save to Windows Credential Manager"/>
                <Button x:Name="ConnForget" Style="{StaticResource LinkBtn}" Content="Forget saved credentials" HorizontalAlignment="Right" Visibility="Collapsed"/>
              </Grid>
              <TextBlock x:Name="ConnSavedNote" Text="" Foreground="{StaticResource TealBrush}" FontSize="11.5" Margin="0,6,0,0" Visibility="Collapsed"/>
            </StackPanel>

            <Border x:Name="ConnMsgBox" CornerRadius="8" Padding="12,9" Margin="0,16,0,0" Background="#3A2F1E" BorderBrush="#8C6A2E" BorderThickness="1" Visibility="Collapsed">
              <StackPanel>
                <TextBlock x:Name="ConnMsg" Text="" TextWrapping="Wrap" FontSize="12" Foreground="#F5D9A8"/>
                <Button x:Name="ConnTrust" Style="{StaticResource LinkBtn}" Content="Add this computer to TrustedHosts" Margin="0,8,0,0" HorizontalAlignment="Left" Visibility="Collapsed"/>
              </StackPanel>
            </Border>
            <ProgressBar x:Name="ConnProgress" IsIndeterminate="True" Height="4" Margin="0,14,0,0" Visibility="Collapsed"/>

            <Grid Margin="0,20,0,0">
              <Button x:Name="ConnLocal" Content="Use this PC" Style="{StaticResource BtnChip}" HorizontalAlignment="Left" Margin="0"/>
              <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="ConnCancel" Content="Cancel" Margin="0,0,10,0"/>
                <Button x:Name="ConnGo" Style="{StaticResource BtnAccent}">
                  <StackPanel Orientation="Horizontal"><TextBlock Text="&#xE703;" Style="{StaticResource Icon}" Margin="0,0,8,0"/><TextBlock Text="Connect"/></StackPanel>
                </Button>
              </StackPanel>
            </Grid>
          </StackPanel>
        </Border>
      </Grid>
    </Grid>
  </Border>
</Window>
'@
#endregion

#region ---------------------------------------------------------------- Window + controls
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$ui = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object {
    $n = $_.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    if ($n) { $ui[$n] = $window.FindName($n) }
}

$script:BrushConv = New-Object System.Windows.Media.BrushConverter
function New-Brush([string]$Hex) { $b = $script:BrushConv.ConvertFromString($Hex); $b.Freeze(); $b }
$script:Res = @{
    Teal = $window.FindResource('TealBrush'); Purple = $window.FindResource('PurpleBrush')
    Muted = $window.FindResource('MutedBrush'); Dim = $window.FindResource('DimBrush')
    Danger = $window.FindResource('DangerBrush'); Amber = $window.FindResource('AmberBrush')
    TealGrad = $window.FindResource('TealGrad'); PurpleGrad = $window.FindResource('PurpleGrad')
    Track = $window.FindResource('TrackBrush')
}

# From here on, event handlers use explicit -ErrorAction Stop where a failure must be caught.
$ErrorActionPreference = 'Continue'

function Show-AWMessage([string]$Text, [string]$Icon = 'Information') {
    [void][System.Windows.MessageBox]::Show($window, $Text, 'AWiper', 'OK', $Icon)
}
function Confirm-AW([string]$Text) {
    ([System.Windows.MessageBox]::Show($window, $Text, 'AWiper', 'YesNo', 'Warning')) -eq 'Yes'
}
function Open-AWExplorer([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { Start-Process explorer.exe -ArgumentList "/select,`"$Path`"" }
    elseif (Test-Path -LiteralPath $Path) { Start-Process explorer.exe -ArgumentList "`"$Path`"" }
}
function Set-AWStatus([string]$Text) { $ui.StatusText.Text = $Text }

# Remote target: $null = this PC, otherwise @{ Host; Credential; ComputerName; OS }.
$script:Target = $null
function Test-AWRemote { [bool]$script:Target }
# Admin-only features: local admin, or a remote target (WinRM sessions are admin by default).
function Test-AWCanAdmin { $script:IsAdmin -or [bool]$script:Target }
#endregion

#region ---------------------------------------------------------------- Background task runner
$script:Jobs = New-Object System.Collections.ArrayList

function Start-AWTask {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Work,
        [hashtable]$Arguments = @{},
        [scriptblock]$OnComplete
    )
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('Sync', $Sync)
    $rs.SessionStateProxy.SetVariable('Target', $script:Target)
    foreach ($k in $Arguments.Keys) { $rs.SessionStateProxy.SetVariable($k, $Arguments[$k]) }
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript(". ([scriptblock]::Create(`$Sync.WorkerLib))`n" + $Work.ToString())
    $Sync.Status = "$Name..."
    $Sync.Progress = -1
    [void]$script:Jobs.Add([pscustomobject]@{ Name = $Name; PS = $ps; Runspace = $rs; Handle = $ps.BeginInvoke(); OnComplete = $OnComplete })
    Write-AWLog "$Name started"
}

function Update-AWLogView {
    $line = $null
    $lines = New-Object System.Collections.Generic.List[string]
    while ($Sync.Log.TryDequeue([ref]$line)) { $lines.Add($line) }
    if ($lines.Count -eq 0) { return }
    $text = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
    $ui.LogBox.AppendText($text)
    if ($ui.LogBox.LineCount -gt 3000) { $ui.LogBox.Text = ($ui.LogBox.Text -split "`r?`n" | Select-Object -Last 2000) -join [Environment]::NewLine }
    $ui.LogBox.ScrollToEnd()
    try { [System.IO.File]::AppendAllText($script:LogFile, $text) } catch { }
}

$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:Timer.Add_Tick({
    try {
        Update-AWLogView

        for ($i = $script:Jobs.Count - 1; $i -ge 0; $i--) {
            $j = $script:Jobs[$i]
            if (-not $j.Handle.IsCompleted) { continue }
            $result = $null
            try { $result = $j.PS.EndInvoke($j.Handle) }
            catch { Write-AWLog "$($j.Name) failed: $($_.Exception.Message)" 'ERROR' }
            $errs = @($j.PS.Streams.Error)
            foreach ($e in ($errs | Select-Object -First 10)) { Write-AWLog "$($j.Name): $e" 'WARN' }
            $j.PS.Dispose(); $j.Runspace.Dispose()
            $script:Jobs.RemoveAt($i)
            Write-AWLog "$($j.Name) finished"
            if ($j.OnComplete) {
                try { & $j.OnComplete $result } catch { Write-AWLog "$($j.Name) completion: $($_.Exception.Message)" 'ERROR' }
            }
        }

        if ($Sync.Scanning -and $script:Scanner) {
            $s = $script:Scanner
            $msg = 'Scanning {0:N0} files in {1:N0} folders - {2} - {3}' -f $s.FilesScanned, $s.FoldersScanned, (Format-AWSize $s.BytesScanned), $s.CurrentPath
            Set-AWStatus $msg
            if ($script:ScanExpected -gt 0) {
                $ui.StatusProgress.IsIndeterminate = $false
                $ui.StatusProgress.Value = [Math]::Min(99, $s.BytesScanned * 100.0 / $script:ScanExpected)
            } else { $ui.StatusProgress.IsIndeterminate = $true }
            $ui.StatusProgress.Visibility = 'Visible'
        }
        elseif ($script:Jobs.Count -gt 0) {
            Set-AWStatus $Sync.Status
            $ui.StatusProgress.Visibility = 'Visible'
            if ($Sync.Progress -ge 0) { $ui.StatusProgress.IsIndeterminate = $false; $ui.StatusProgress.Value = $Sync.Progress }
            else { $ui.StatusProgress.IsIndeterminate = $true }
            if ($script:CleanerBusy) { $ui.CleanProgress.Value = [Math]::Max(0, $Sync.Progress) }
        }
        elseif ($ui.StatusProgress.Visibility -eq 'Visible') {
            $ui.StatusProgress.IsIndeterminate = $false
            $ui.StatusProgress.Visibility = 'Hidden'
            Set-AWStatus $script:IdleStatus
        }
    }
    catch { Write-AWLog "UI timer: $($_.Exception.Message)" 'ERROR' }
})
$script:IdleStatus = 'Ready'
#endregion

#region ---------------------------------------------------------------- Navigation + title bar
$script:ViewTitles = @{
    Home = 'Dashboard'; Cleaner = 'Cleaner'; Map = 'Space Map'; Large = 'Large Files'; Recovery = 'Recovery'
    Startup = 'Startup'; Programs = 'Programs'; Debloat = 'Debloat'; Tools = 'Tools and Activity Log'
}
$script:Loaded = @{}

foreach ($v in $script:ViewTitles.Keys) {
    $ui["Nav$v"].Add_Checked({
        param($s, $e)
        $name = $s.Name.Substring(3)
        foreach ($k in $script:ViewTitles.Keys) { $ui["View$k"].Visibility = if ($k -eq $name) { 'Visible' } else { 'Collapsed' } }
        Update-AWViewTitle $name
        if (-not $script:Loaded[$name]) {
            $script:Loaded[$name] = $true
            switch ($name) {
                'Startup'  { Update-AWStartupList }
                'Programs' { Update-AWProgramList }
                'Debloat'  { Update-AWAppList; Update-AWTweakStatus }
                'Recovery' { Initialize-AWRecovery }
            }
        }
        if ($name -eq 'Map') { Request-AWMapRedraw }
    })
}

function Select-AWView([string]$Name) { $ui["Nav$Name"].IsChecked = $true }

# Views that always work on this PC, even when a remote computer is targeted.
$script:LocalOnlyViews = @('Home', 'Map', 'Large', 'Startup')
function Get-AWCurrentView { foreach ($k in $script:ViewTitles.Keys) { if ($ui["Nav$k"].IsChecked) { return $k } } }
function Update-AWViewTitle([string]$Name) {
    $title = $script:ViewTitles[$Name]
    if (Test-AWRemote) {
        $title += if ($script:LocalOnlyViews -contains $Name) { '   -   this PC only' } else { "   -   $($script:Target.ComputerName)" }
    }
    $ui.ViewTitle.Text = $title
}

$ui.BtnMin.Add_Click({ $window.WindowState = 'Minimized' })
$ui.BtnMax.Add_Click({ $window.WindowState = if ($window.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' } })
$ui.BtnClose.Add_Click({ $window.Close() })
$window.Add_StateChanged({
    # Borderless windows overhang the screen by the resize border when maximized.
    if ($window.WindowState -eq 'Maximized') { $ui.RootBorder.Margin = '7'; $ui.BtnMax.Content = [char]0xE923 }
    else { $ui.RootBorder.Margin = '0'; $ui.BtnMax.Content = [char]0xE922 }
})

$ui.VersionText.Text = "v$script:AppVersion"
if ($script:IsAdmin) {
    $ui.AdminText.Text = 'Administrator'
} else {
    $ui.AdminBadge.Background  = New-Brush '#3A2F1E'
    $ui.AdminBadge.BorderBrush = New-Brush '#8C6A2E'
    $ui.AdminText.Foreground   = $script:Res.Amber
    $ui.AdminIcon.Foreground   = $script:Res.Amber
    $ui.AdminText.Text = 'Standard user'
    $ui.AdminBadge.ToolTip = 'Some cleaning rules, startup entries and tools need administrator rights.'
    $ui.BtnElevate.Visibility = 'Visible'
}
$ui.BtnElevate.Add_Click({
    if (Invoke-AWElevation) { $window.Close() }
    else { Show-AWMessage 'Elevation was cancelled. AWiper will keep running with standard permissions.' }
})
#endregion

#region ---------------------------------------------------------------- Dashboard
function New-AWText([string]$Text, [double]$Size = 13, $Brush = $null, [string]$Weight = 'Normal') {
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = $Size; $t.FontWeight = $Weight
    if ($Brush) { $t.Foreground = $Brush }
    $t
}

function New-AWPill([string]$Text, [bool]$Ok = $true, [string]$Tone = '') {
    $pill = New-Object System.Windows.Controls.Border
    $pill.Style = $window.FindResource('Pill')
    if ($Tone -eq 'Teal') {
        $pill.BorderBrush = New-Brush '#2E8F86'; $fg = $script:Res.Teal
    } elseif ($Ok) {
        $pill.BorderBrush = New-Brush '#4A5680'; $fg = $script:Res.Muted
    } else {
        $pill.BorderBrush = New-Brush '#8C6A2E'; $fg = $script:Res.Amber
    }
    $pill.Child = New-AWText $Text 9 $fg 'Bold'
    $pill
}

function Get-AWFixedDrives {
    [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady }
}

function New-AWGauge([double]$Fraction, [double]$Size = 116) {
    $g = New-Object System.Windows.Controls.Grid
    $g.Width = $Size; $g.Height = $Size
    $stroke = 11
    $track = New-Object System.Windows.Shapes.Ellipse
    $track.Stroke = $script:Res.Track; $track.StrokeThickness = $stroke
    [void]$g.Children.Add($track)

    $brush = if ($Fraction -ge 0.9) { $script:Res.Danger } elseif ($Fraction -ge 0.75) { $script:Res.PurpleGrad } else { $script:Res.TealGrad }
    $r = ($Size - $stroke) / 2; $c = $Size / 2
    if ($Fraction -ge 0.999) {
        $full = New-Object System.Windows.Shapes.Ellipse
        $full.Stroke = $brush; $full.StrokeThickness = $stroke
        [void]$g.Children.Add($full)
    }
    elseif ($Fraction -gt 0.001) {
        $angle = 2 * [Math]::PI * $Fraction
        $ex = $c + $r * [Math]::Sin($angle)
        $ey = $c - $r * [Math]::Cos($angle)
        $large = if ($Fraction -gt 0.5) { 1 } else { 0 }
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $data = [string]::Format($inv, 'M {0},{1} A {2},{2} 0 {3} 1 {4},{5}', $c, ($c - $r), $r, $large, $ex, $ey)
        $arc = New-Object System.Windows.Shapes.Path
        $arc.Data = [System.Windows.Media.Geometry]::Parse($data)
        $arc.Stroke = $brush; $arc.StrokeThickness = $stroke
        $arc.StrokeStartLineCap = 'Round'; $arc.StrokeEndLineCap = 'Round'
        [void]$g.Children.Add($arc)
    }
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.HorizontalAlignment = 'Center'; $sp.VerticalAlignment = 'Center'
    $pct = New-AWText ('{0:0}%' -f ($Fraction * 100)) 24 $null 'Bold'; $pct.HorizontalAlignment = 'Center'
    $lbl = New-AWText 'used' 11 $script:Res.Muted; $lbl.HorizontalAlignment = 'Center'
    [void]$sp.Children.Add($pct); [void]$sp.Children.Add($lbl)
    [void]$g.Children.Add($sp)
    $g
}

function New-AWInfoRow([string]$Label, [string]$Value) {
    $g = New-Object System.Windows.Controls.Grid
    $g.Margin = '0,3'
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = '80'
    $c2 = New-Object System.Windows.Controls.ColumnDefinition
    $g.ColumnDefinitions.Add($c1); $g.ColumnDefinitions.Add($c2)
    $l = New-AWText $Label 12.5 $script:Res.Muted
    $v = New-AWText $Value 12.5 $null 'SemiBold'; $v.TextTrimming = 'CharacterEllipsis'; $v.ToolTip = $Value
    [System.Windows.Controls.Grid]::SetColumn($v, 1)
    [void]$g.Children.Add($l); [void]$g.Children.Add($v)
    $g
}

function New-AWDriveCard([System.IO.DriveInfo]$Drive) {
    $used = $Drive.TotalSize - $Drive.TotalFreeSpace
    $frac = if ($Drive.TotalSize -gt 0) { $used / $Drive.TotalSize } else { 0 }

    $card = New-Object System.Windows.Controls.Border
    $card.Style = $window.FindResource('Card')
    $card.Width = 340; $card.Margin = '0,0,16,16'

    $grid = New-Object System.Windows.Controls.Grid
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = 'Auto'
    $c2 = New-Object System.Windows.Controls.ColumnDefinition
    $grid.ColumnDefinitions.Add($c1); $grid.ColumnDefinitions.Add($c2)
    [void]$grid.Children.Add((New-AWGauge $frac))

    $info = New-Object System.Windows.Controls.StackPanel
    $info.Margin = '20,0,0,0'; $info.VerticalAlignment = 'Center'
    $label = if ($Drive.VolumeLabel) { $Drive.VolumeLabel } else { 'Local Disk' }
    [void]$info.Children.Add((New-AWText ("{0}  {1}" -f $Drive.Name.TrimEnd('\'), $label) 16 $null 'SemiBold'))
    [void]$info.Children.Add((New-AWText $Drive.DriveFormat 11.5 $script:Res.Dim))
    $rows = New-Object System.Windows.Controls.StackPanel; $rows.Margin = '0,8,0,10'
    [void]$rows.Children.Add((New-AWInfoRow 'Used'  (Format-AWSize $used)))
    [void]$rows.Children.Add((New-AWInfoRow 'Free'  (Format-AWSize $Drive.TotalFreeSpace)))
    [void]$rows.Children.Add((New-AWInfoRow 'Total' (Format-AWSize $Drive.TotalSize)))
    [void]$info.Children.Add($rows)
    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = 'Map this drive'; $btn.Style = $window.FindResource('BtnChip'); $btn.HorizontalAlignment = 'Left'
    $btn.Tag = $Drive.RootDirectory.FullName
    $btn.Add_Click({ param($s, $e) Select-AWView 'Map'; Start-AWMapScan $s.Tag })
    [void]$info.Children.Add($btn)
    [System.Windows.Controls.Grid]::SetColumn($info, 1)
    [void]$grid.Children.Add($info)
    $card.Child = $grid
    $card
}

function Update-AWDashboard {
    $ui.DriveCards.Children.Clear()
    foreach ($d in (Get-AWFixedDrives)) { [void]$ui.DriveCards.Children.Add((New-AWDriveCard $d)) }

    $sys = Get-AWFixedDrives | Where-Object { $_.Name -eq "$env:SystemDrive\" } | Select-Object -First 1
    if ($sys) {
        $usedPct = ($sys.TotalSize - $sys.TotalFreeSpace) * 100.0 / $sys.TotalSize
        $ui.SideDriveBar.Value = $usedPct
        $ui.SideDriveText.Text = '{0} free of {1}' -f (Format-AWSize $sys.TotalFreeSpace), (Format-AWSize $sys.TotalSize)
    }

    $ui.HomeFreed.Text  = Format-AWSize $script:State.TotalFreed
    $ui.HomeCleans.Text = '{0} clean{1} with AWiper' -f $script:State.Cleans, $(if ($script:State.Cleans -eq 1) { '' } else { 's' })
    if ($script:State.LastClean) {
        try {
            $dt = [datetime]::Parse($script:State.LastClean, [Globalization.CultureInfo]::InvariantCulture)
            $days = [int]((Get-Date) - $dt).TotalDays
            $ui.HomeLast.Text = if ($days -le 0) { 'Today' } elseif ($days -eq 1) { 'Yesterday' } else { "$days days ago" }
            $ui.HomeLastSub.Text = $dt.ToString('ddd MMM d, h:mm tt')
        } catch { $ui.HomeLast.Text = 'Unknown' }
    }

    $ui.SysInfo.Children.Clear()
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $up = (Get-Date) - $os.LastBootUpTime
        $memTotal = [long]$os.TotalVisibleMemorySize * 1KB
        $memUsed  = $memTotal - [long]$os.FreePhysicalMemory * 1KB
        $rows = [ordered]@{
            'Computer' = $env:COMPUTERNAME
            'User'     = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            'Windows'  = ($os.Caption -replace '^Microsoft\s+', '')
            'Build'    = $os.BuildNumber
            'Uptime'   = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes
            'Memory'   = '{0} of {1} in use' -f (Format-AWSize $memUsed), (Format-AWSize $memTotal)
        }
    } catch {
        $rows = [ordered]@{ 'Computer' = $env:COMPUTERNAME; 'User' = "$env:USERDOMAIN\$env:USERNAME" }
    }
    $rows['PowerShell'] = $PSVersionTable.PSVersion.ToString()
    $rows['Rights'] = if ($script:IsAdmin) { 'Administrator' } else { 'Standard user' }
    foreach ($k in $rows.Keys) { [void]$ui.SysInfo.Children.Add((New-AWInfoRow $k ([string]$rows[$k]))) }
    if ($script:ElevationNote) {
        $n = New-AWText $script:ElevationNote 12 $script:Res.Amber; $n.TextWrapping = 'Wrap'; $n.Margin = '0,10,0,0'
        [void]$ui.SysInfo.Children.Add($n)
    }
}

$ui.HomeQuick.Add_Click({ Select-AWView 'Cleaner'; Start-AWAnalyze })
$ui.HomeScan.Add_Click({ Select-AWView 'Map'; Start-AWMapScan "$env:SystemDrive\" })
$ui.HomeStartup.Add_Click({ Select-AWView 'Startup' })
#endregion

#region ---------------------------------------------------------------- Cleaner
$script:CleanerChecks = New-Object System.Collections.Generic.List[object]
$script:CleanerBusy = $false

# Rules that live in the signed-in user's profile only make sense on this PC.
function Test-AWUserScopeRule($Rule) {
    if ($Rule.Kind -eq 'RecycleBin' -or $Rule.Action -eq 'Clipboard') { return $true }
    foreach ($t in $Rule.Targets) { if ($t.Path -match '%(TEMP|LOCALAPPDATA|APPDATA|USERPROFILE)%') { return $true } }
    $false
}
function Test-AWRuleAllowed($Rule) {
    if (Test-AWRemote) { return -not (Test-AWUserScopeRule $Rule) }
    $script:IsAdmin -or -not $Rule.Admin
}

function Initialize-AWCleaner {
    $ui.CleanerItems.Children.Clear()
    $script:CleanerChecks.Clear()
    $lastGroup = ''
    foreach ($rule in $script:CleanerRules) {
        if ($rule.Group -ne $lastGroup) {
            $h = New-AWText $rule.Group.ToUpper() 11 $script:Res.Dim 'Bold'
            $h.Margin = if ($lastGroup) { '0,16,0,6' } else { '0,8,0,6' }
            [void]$ui.CleanerItems.Children.Add($h)
            $lastGroup = $rule.Group
        }
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Margin = '0,5'
        $cb.Tag = $rule
        $allowed = Test-AWRuleAllowed $rule
        $cb.IsEnabled = $allowed
        $cb.IsChecked = $rule.Default -and $allowed
        $cb.ToolTip = if ((Test-AWRemote) -and -not $allowed) { "$($rule.Desc)`n`nPer-user item - only available on this PC." } else { $rule.Desc }
        if ((Test-AWRemote) -and -not $allowed) { [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($cb, $true) }

        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        [void]$sp.Children.Add((New-AWText $rule.Name 13))
        if ($rule.Admin) { [void]$sp.Children.Add((New-AWPill 'ADMIN' (Test-AWCanAdmin))) }
        $cb.Content = $sp
        [void]$ui.CleanerItems.Children.Add($cb)
        $script:CleanerChecks.Add($cb)
    }
}

function Get-AWSelectedRules {
    @($script:CleanerChecks | Where-Object { $_.IsChecked -and $_.IsEnabled } | ForEach-Object { $_.Tag })
}

function Set-AWCleanerBusy([bool]$Busy) {
    $script:CleanerBusy = $Busy
    $ui.BtnAnalyze.IsEnabled = -not $Busy
    $ui.BtnClean.IsEnabled   = -not $Busy
    foreach ($cb in $script:CleanerChecks) { if (Test-AWRuleAllowed $cb.Tag) { $cb.IsEnabled = -not $Busy } }
}

function Show-AWCleanResults($Result, [string]$Mode) {
    $rows = New-Object System.Collections.Generic.List[object]
    [long]$total = 0; [long]$files = 0
    foreach ($r in $Result) {
        if ($null -eq $r) { continue }
        $total += [long]$r.Bytes; $files += [long]$r.Files
        $dot = if ($r.Note -match 'running|Skipped|Error') { $script:Res.Amber } elseif ([long]$r.Bytes -gt 0) { $script:Res.Teal } else { $script:Res.Dim }
        $rows.Add([pscustomobject]@{
            Name  = $r.Name
            Group = $r.Group
            Files = '{0:N0}' -f [long]$r.Files
            Size  = Format-AWSize ([long]$r.Bytes)
            Note  = $r.Note
            Dot   = $dot
            Bytes = [long]$r.Bytes
        })
    }
    $ui.CleanResults.ItemsSource = @($rows | Sort-Object Bytes -Descending)
    $ui.CleanProgress.Value = 100

    if ($Mode -eq 'Analyze') {
        $ui.CleanSummary.Text = '{0} to clean' -f (Format-AWSize $total)
        $ui.CleanSubtext.Text = '{0:N0} files across {1} rule(s). Review the list, then press Run Cleaner.' -f $files, $rows.Count
        $script:IdleStatus = "Analysis complete - $(Format-AWSize $total) can be removed"
    } else {
        $ui.CleanSummary.Text = '{0} freed' -f (Format-AWSize $total)
        $ui.CleanSubtext.Text = '{0:N0} files removed. Files that were in use were skipped safely.' -f $files
        $script:State.TotalFreed += $total
        $script:State.Cleans++
        $script:State.LastClean = (Get-Date).ToString('o')
        Save-AWState
        Update-AWDashboard
        $script:IdleStatus = "Clean complete - $(Format-AWSize $total) freed"
    }
}

function Start-AWAnalyze {
    if ($script:CleanerBusy) { return }
    $rules = Get-AWSelectedRules
    if ($rules.Count -eq 0) { Show-AWMessage 'Select at least one cleaning rule first.'; return }
    Set-AWCleanerBusy $true
    $ui.CleanSummary.Text = 'Analyzing...'
    $ui.CleanSubtext.Text = 'Measuring temp files and caches. Nothing is deleted during analysis.'
    $ui.CleanProgress.Value = 0
    Start-AWTask -Name 'Analyze' -Arguments @{ Rules = $rules } -Work {
        $i = 0
        foreach ($rule in $Rules) {
            $Sync.Status = "Analyzing: $($rule.Name)"
            $Sync.Progress = [int]($i * 100 / $Rules.Count)
            try { Invoke-WTarget { param($r) Measure-WItem $r } -ArgumentList @(, $rule) }
            catch { @{ Id = $rule.Id; Name = $rule.Name; Group = $rule.Group; Files = 0; Bytes = [long]0; Note = "Error: $($_.Exception.Message)" } }
            $i++
        }
        $Sync.Progress = 100
    } -OnComplete {
        param($Result)
        Show-AWCleanResults $Result 'Analyze'
        Set-AWCleanerBusy $false
    }
}

function Start-AWClean {
    if ($script:CleanerBusy) { return }
    $rules = Get-AWSelectedRules
    if ($rules.Count -eq 0) { Show-AWMessage 'Select at least one cleaning rule first.'; return }
    $names = ($rules | ForEach-Object { "  - $($_.Name)" }) -join "`n"
    $where = if (Test-AWRemote) { " on $($script:Target.ComputerName)" } else { '' }
    if (-not (Confirm-AW "AWiper will permanently delete the files matched by these rules$($where):`n`n$names`n`nFiles that are in use are skipped. Continue?")) { return }
    Set-AWCleanerBusy $true
    $ui.CleanSummary.Text = 'Cleaning...'
    $ui.CleanSubtext.Text = 'Removing files. Locked files are skipped automatically.'
    $ui.CleanProgress.Value = 0
    Start-AWTask -Name 'Clean' -Arguments @{ Rules = $rules } -Work {
        $i = 0
        foreach ($rule in $Rules) {
            $Sync.Status = "Cleaning: $($rule.Name)"
            $Sync.Progress = [int]($i * 100 / $Rules.Count)
            try { Invoke-WTarget { param($r) Invoke-WClean $r } -ArgumentList @(, $rule) }
            catch {
                Write-WLog "$($rule.Name): $($_.Exception.Message)" 'ERROR'
                @{ Id = $rule.Id; Name = $rule.Name; Group = $rule.Group; Files = 0; Bytes = [long]0; Note = "Error: $($_.Exception.Message)" }
            }
            $i++
        }
        $Sync.Progress = 100
    } -OnComplete {
        param($Result)
        Show-AWCleanResults $Result 'Clean'
        Set-AWCleanerBusy $false
    }
}

$ui.BtnAnalyze.Add_Click({ Start-AWAnalyze })
$ui.BtnClean.Add_Click({ Start-AWClean })
$ui.RulesAll.Add_Click({     foreach ($cb in $script:CleanerChecks) { if ($cb.IsEnabled) { $cb.IsChecked = $true } } })
$ui.RulesNone.Add_Click({    foreach ($cb in $script:CleanerChecks) { $cb.IsChecked = $false } })
$ui.RulesDefault.Add_Click({ foreach ($cb in $script:CleanerChecks) { $cb.IsChecked = $cb.IsEnabled -and $cb.Tag.Default } })
#endregion

#region ---------------------------------------------------------------- Space Map
$script:Scanner = $null
$script:MapRoot = $null
$script:MapCurrent = $null
$script:MapSelected = $null
$script:MapSelectedBorder = $null
$script:MapMaxDepth = 2
$script:ScanExpected = 0
$script:BrushCache = @{}
$script:MapPalette = @{
    Dir   = @('#4B33B5', '#6447DD', '#7E62F3', '#9A84F8')
    File  = @('#0C86A0', '#109EB2', '#16B6B1', '#3FCDBE')
    Group = @('#2A3254', '#343D62', '#3F4970', '#4A557E')
}
$script:MapEdge = New-Brush '#111527'
$script:MapSelEdge = New-Brush '#FFFFFF'

function Get-AWMapBrush($Node, [int]$Depth) {
    $kind = if ($Node.IsGroup) { 'Group' } elseif ($Node.IsDir) { 'Dir' } else { 'File' }
    $key = "$kind$Depth"
    if (-not $script:BrushCache.ContainsKey($key)) {
        $hex  = $script:MapPalette[$kind][[Math]::Min($Depth, 3)]
        $base = [System.Windows.Media.ColorConverter]::ConvertFromString($hex)
        $top  = [System.Windows.Media.Color]::FromRgb(
            [byte][Math]::Min(255, $base.R + 28), [byte][Math]::Min(255, $base.G + 28), [byte][Math]::Min(255, $base.B + 28))
        $b = New-Object System.Windows.Media.LinearGradientBrush($top, $base, 90)
        $b.Freeze()
        $script:BrushCache[$key] = $b
    }
    $script:BrushCache[$key]
}

# Shared right-click menu
$script:MapMenu = New-Object System.Windows.Controls.ContextMenu
$script:MapMenu.Style = $window.FindResource('CtxMenu')
$script:MapMenuNode = $null
function Add-AWMenuItem($Menu, [string]$Header, [scriptblock]$Action) {
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $Header; $mi.Style = $window.FindResource('CtxItem'); $mi.Tag = $Action
    $mi.Add_Click({ param($s, $e) & $s.Tag })
    [void]$Menu.Items.Add($mi)
    $mi
}
$script:MenuZoom = Add-AWMenuItem $script:MapMenu 'Zoom in'           { if ($script:MapMenuNode) { Set-AWMapCurrent $script:MapMenuNode } }
[void](Add-AWMenuItem $script:MapMenu 'Open in Explorer'              { if ($script:MapMenuNode) { Open-AWExplorer $script:MapMenuNode.FullPath } })
[void](Add-AWMenuItem $script:MapMenu 'Copy path'                     { if ($script:MapMenuNode) { [System.Windows.Clipboard]::SetText($script:MapMenuNode.FullPath) } })
$script:MenuRecycle = Add-AWMenuItem $script:MapMenu 'Send to Recycle Bin' { if ($script:MapMenuNode) { Remove-AWMapNodeToRecycle $script:MapMenuNode } }

function Select-AWMapNode($Node, $Border) {
    if ($script:MapSelectedBorder) { $script:MapSelectedBorder.BorderBrush = $script:MapEdge; $script:MapSelectedBorder.BorderThickness = 1 }
    $script:MapSelected = $Node
    $script:MapSelectedBorder = $Border
    if ($Border) { $Border.BorderBrush = $script:MapSelEdge; $Border.BorderThickness = 2 }
    if (-not $Node) {
        $ui.MapSelName.Text = 'Nothing selected'; $ui.MapSelPath.Text = ''; $ui.MapSelSize.Text = ''; $ui.MapSelMeta.Text = ''
        $ui.MapOpen.IsEnabled = $false; $ui.MapZoom.IsEnabled = $false; $ui.MapRecycle.IsEnabled = $false
        return
    }
    $ui.MapSelName.Text = $Node.Name
    $ui.MapSelPath.Text = $Node.FullPath
    $ui.MapSelSize.Text = $Node.SizeText
    $ui.MapSelMeta.Text = '{0} - {1:N0} file(s) - {2:0.0}% of parent' -f $Node.Kind, $Node.FileCount, $Node.PercentOfParent
    $ui.MapOpen.IsEnabled = $true
    $ui.MapZoom.IsEnabled = $Node.IsDir -and $Node.Children.Count -gt 0
    $ui.MapRecycle.IsEnabled = -not $Node.IsGroup -and $Node.Parent
}

function Set-AWMapCurrent($Node) {
    if (-not $Node -or -not $Node.IsDir) { return }
    $script:MapCurrent = $Node
    Select-AWMapNode $null $null
    $ui.MapTopList.ItemsSource = @($Node.Children | Select-Object -First 15)
    Show-AWTreeMap
}

function Add-AWTreeMapLevel($Node, [double]$X, [double]$Y, [double]$W, [double]$H, [int]$Depth) {
    $rects = [AWiper.Treemap]::Layout($Node.Children, $X, $Y, $W, $H)
    foreach ($r in $rects) {
        if ($script:MapElementCount -gt 4000) { return }
        if ($r.W -lt 3 -or $r.H -lt 3) { continue }
        $n = $r.Node
        $b = New-Object System.Windows.Controls.Border
        $b.Width = [Math]::Max(1, $r.W - 2); $b.Height = [Math]::Max(1, $r.H - 2)
        [System.Windows.Controls.Canvas]::SetLeft($b, $r.X + 1)
        [System.Windows.Controls.Canvas]::SetTop($b, $r.Y + 1)
        $b.CornerRadius = if ($r.W -gt 24 -and $r.H -gt 24) { '5' } else { '2' }
        $b.Background = Get-AWMapBrush $n $Depth
        $b.BorderBrush = $script:MapEdge; $b.BorderThickness = 1
        $b.Tag = $n
        $b.Cursor = 'Hand'
        $b.ToolTip = "{0}`n{1}  ({2:0.0}%)`n{3}" -f $n.Name, $n.SizeText, $n.PercentOfParent, $n.FullPath
        $b.ContextMenu = $script:MapMenu

        $canNest = $n.IsDir -and $Depth -lt $script:MapMaxDepth -and $r.W -gt 64 -and $r.H -gt 44 -and $n.Children.Count -gt 0
        if ($r.W -gt 42 -and $r.H -gt 17) {
            $sp = New-Object System.Windows.Controls.StackPanel
            $sp.Margin = '6,3,6,0'; $sp.IsHitTestVisible = $false
            $t1 = New-AWText $n.Name 11 $null 'SemiBold'
            $t1.Foreground = [System.Windows.Media.Brushes]::White; $t1.TextTrimming = 'CharacterEllipsis'
            [void]$sp.Children.Add($t1)
            if ($canNest) { $t1.Text = '{0}   {1}' -f $n.Name, $n.SizeText }
            elseif ($r.H -gt 36) {
                $t2 = New-AWText $n.SizeText 10.5; $t2.Foreground = New-Brush '#D8DCF0'; $t2.Opacity = 0.85
                [void]$sp.Children.Add($t2)
            }
            $b.Child = $sp
        }

        $b.Add_MouseLeftButtonDown({
            param($s, $e)
            if ($e.ClickCount -ge 2) { if ($s.Tag.IsDir) { Set-AWMapCurrent $s.Tag } }
            else { Select-AWMapNode $s.Tag $s }
            $e.Handled = $true
        })
        $b.Add_ContextMenuOpening({
            param($s, $e)
            $script:MapMenuNode = $s.Tag
            $script:MenuZoom.IsEnabled = $s.Tag.IsDir -and $s.Tag.Children.Count -gt 0
            $script:MenuRecycle.IsEnabled = -not $s.Tag.IsGroup -and $s.Tag.Parent
            Select-AWMapNode $s.Tag $s
        })
        [void]$ui.MapCanvas.Children.Add($b)
        $script:MapElementCount++

        if ($canNest) { Add-AWTreeMapLevel $n ($r.X + 4) ($r.Y + 20) ($r.W - 8) ($r.H - 24) ($Depth + 1) }
    }
}

function Show-AWTreeMap {
    $ui.MapCanvas.Children.Clear()
    $script:MapSelectedBorder = $null
    $node = $script:MapCurrent
    if (-not $node) { return }
    $ui.MapHint.Visibility = 'Collapsed'
    $ui.MapCrumb.Text = $node.FullPath
    $ui.MapCurSize.Text = '{0}  -  {1:N0} files' -f $node.SizeText, $node.FileCount
    $ui.MapUp.IsEnabled = [bool]$node.Parent
    $w = $ui.MapCanvas.ActualWidth; $h = $ui.MapCanvas.ActualHeight
    if ($w -lt 20 -or $h -lt 20) { return }
    $script:MapElementCount = 0
    Add-AWTreeMapLevel $node 0 0 $w $h 0
}

# Debounced redraw on resize
$script:MapRedrawTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:MapRedrawTimer.Interval = [TimeSpan]::FromMilliseconds(180)
$script:MapRedrawTimer.Add_Tick({ $script:MapRedrawTimer.Stop(); Show-AWTreeMap })
function Request-AWMapRedraw { $script:MapRedrawTimer.Stop(); $script:MapRedrawTimer.Start() }
$ui.MapCanvas.Add_SizeChanged({ Request-AWMapRedraw })
$ui.MapCanvas.Add_MouseLeftButtonDown({ Select-AWMapNode $null $null })

function Start-AWMapScan([string]$Path) {
    if ($Sync.Scanning) { return }
    if (-not $Path) { $Path = $ui.MapPath.Text }
    $Path = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($Path -match '^[A-Za-z]:$') { $Path += '\' }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Container)) { Show-AWMessage "Folder not found:`n$Path" 'Warning'; return }
    $ui.MapPath.Text = $Path

    $script:ScanExpected = 0
    try {
        $di = New-Object System.IO.DriveInfo($Path)
        if ($di.RootDirectory.FullName -eq (New-Object System.IO.DirectoryInfo($Path)).FullName) {
            $script:ScanExpected = $di.TotalSize - $di.TotalFreeSpace
        }
    } catch { }

    $script:Scanner = New-Object AWiper.DiskScanner
    $Sync.Scanning = $true
    $ui.MapScan.IsEnabled = $false; $ui.MapStop.IsEnabled = $true; $ui.LargeScan.IsEnabled = $false
    $ui.MapCanvas.Children.Clear(); $ui.MapHint.Visibility = 'Collapsed'
    $ui.MapCrumb.Text = "Scanning $Path ..."; $ui.MapCurSize.Text = ''
    Select-AWMapNode $null $null

    Start-AWTask -Name "Scan $Path" -Arguments @{ Scanner = $script:Scanner; ScanPath = $Path } -Work {
        [void]$Scanner.Scan($ScanPath)
    } -OnComplete {
        param($Result)
        $Sync.Scanning = $false
        $s = $script:Scanner
        $ui.MapScan.IsEnabled = $true; $ui.MapStop.IsEnabled = $false; $ui.LargeScan.IsEnabled = $true
        $script:MapRoot = $s.Root
        Set-AWMapCurrent $s.Root
        $ui.MapExtList.ItemsSource = @($s.ExtensionList | Select-Object -First 12)
        Update-AWLargeList
        $state = if ($s.Completed) { 'Scan complete' } else { 'Scan stopped (partial results)' }
        $script:IdleStatus = '{0}: {1:N0} files, {2} in {3:0.0}s - {4:N0} folders unreadable' -f $state, $s.FilesScanned, (Format-AWSize $s.BytesScanned), $s.ElapsedSeconds, $s.Errors
        Write-AWLog $script:IdleStatus
        if ($s.Errors -gt 0 -and -not $script:IsAdmin) { $script:IdleStatus += ' (run as admin to read protected folders)' }
    }
}

function Remove-AWMapNode($Node) {
    $p = $Node.Parent
    if (-not $p) { return }
    [void]$p.Children.Remove($Node)
    $a = $p
    while ($a) { $a.Size -= $Node.Size; $a.FileCount -= $Node.FileCount; $a = $a.Parent }
}

function Test-AWProtectedPath([string]$Path) {
    $p = $Path.TrimEnd('\')
    $protected = @(
        $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
        (Split-Path $env:USERPROFILE -Parent), $env:USERPROFILE, "$env:SystemDrive\Recovery", "$env:SystemDrive\System Volume Information"
    ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    if ($p -match '^[A-Za-z]:$') { return $true }
    foreach ($x in $protected) { if ($p -ieq $x) { return $true } }
    if ($p -like "$env:SystemRoot\*") { return $true }
    $false
}

function Send-AWToRecycle([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Container) {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
    } else {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
    }
}

function Remove-AWMapNodeToRecycle($Node) {
    if (-not $Node -or $Node.IsGroup -or -not $Node.Parent) { return }
    if (Test-AWProtectedPath $Node.FullPath) { Show-AWMessage "AWiper won't remove protected system locations:`n$($Node.FullPath)" 'Warning'; return }
    if (-not (Confirm-AW ("Send this {0} to the Recycle Bin?`n`n{1}`n{2}" -f $Node.Kind.ToLower(), $Node.FullPath, $Node.SizeText))) { return }
    try {
        Send-AWToRecycle $Node.FullPath
        Write-AWLog "Recycled $($Node.FullPath) ($($Node.SizeText))"
        Remove-AWMapNode $Node
        Set-AWMapCurrent $script:MapCurrent
    } catch {
        Show-AWMessage "Could not recycle:`n$($_.Exception.Message)" 'Error'
    }
}

$ui.MapScan.Add_Click({ Start-AWMapScan $ui.MapPath.Text })
$ui.MapPath.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { Start-AWMapScan $ui.MapPath.Text } })
$ui.MapStop.Add_Click({ if ($script:Scanner) { $script:Scanner.Cancel = $true; $ui.MapStop.IsEnabled = $false } })
$ui.MapUp.Add_Click({ if ($script:MapCurrent -and $script:MapCurrent.Parent) { Set-AWMapCurrent $script:MapCurrent.Parent } })
$ui.MapBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Choose a folder to map'
    if ($ui.MapPath.Text -and (Test-Path -LiteralPath $ui.MapPath.Text)) { $dlg.SelectedPath = $ui.MapPath.Text }
    if ($dlg.ShowDialog() -eq 'OK') { $ui.MapPath.Text = $dlg.SelectedPath; Start-AWMapScan $dlg.SelectedPath }
})
$ui.MapOpen.Add_Click({ if ($script:MapSelected) { Open-AWExplorer $script:MapSelected.FullPath } })
$ui.MapZoom.Add_Click({ if ($script:MapSelected) { Set-AWMapCurrent $script:MapSelected } })
$ui.MapRecycle.Add_Click({ if ($script:MapSelected) { Remove-AWMapNodeToRecycle $script:MapSelected } })
$ui.MapTopList.Add_SelectionChanged({ if ($ui.MapTopList.SelectedItem) { Select-AWMapNode $ui.MapTopList.SelectedItem $null } })
$ui.MapTopList.Add_MouseDoubleClick({ $n = $ui.MapTopList.SelectedItem; if ($n -and $n.IsDir) { Set-AWMapCurrent $n } })
$window.Add_PreviewMouseDown({
    param($s, $e)
    # Mouse "back" button goes up a level on the map
    if ($e.ChangedButton -eq 'XButton1' -and $ui.ViewMap.Visibility -eq 'Visible' -and $script:MapCurrent -and $script:MapCurrent.Parent) {
        Set-AWMapCurrent $script:MapCurrent.Parent; $e.Handled = $true
    }
})

function Initialize-AWMapDrives {
    $ui.MapDrives.Children.Clear()
    foreach ($d in (Get-AWFixedDrives)) {
        $b = New-Object System.Windows.Controls.Button
        $b.Content = $d.Name.TrimEnd('\'); $b.Tag = $d.RootDirectory.FullName
        $b.Style = $window.FindResource('BtnChip')
        $b.ToolTip = '{0} free of {1}' -f (Format-AWSize $d.TotalFreeSpace), (Format-AWSize $d.TotalSize)
        $b.Add_Click({ param($s, $e) Start-AWMapScan $s.Tag })
        [void]$ui.MapDrives.Children.Add($b)
    }
    $ui.MapPath.Text = "$env:SystemDrive\"
}
#endregion

#region ---------------------------------------------------------------- Large files
function Update-AWLargeList {
    if (-not $script:Scanner -or -not $script:Scanner.TopFiles) { return }
    $all = $script:Scanner.TopFiles
    $q = $ui.LargeSearch.Text.Trim()
    $items = @(if ($q) {
        $all | Where-Object { $_.Name -like "*$q*" -or $_.Folder -like "*$q*" -or $_.Extension -like "*$q*" }
    } else { $all })
    $ui.LargeList.ItemsSource = $items
    [long]$sum = 0; foreach ($f in $items) { $sum += $f.Size }
    $ui.LargeInfo.Text = '{0:N0} files - {1} total - from scan of {2}' -f $items.Count, (Format-AWSize $sum), $script:Scanner.Root.FullPath
}

function Get-AWCheckedLarge { @($script:Scanner.TopFiles | Where-Object { $_.IsChecked }) }

$ui.LargeSearch.Add_TextChanged({ Update-AWLargeList })
$ui.LargeScan.Add_Click({ Select-AWView 'Map' })
$ui.LargeOpen.Add_Click({
    $f = $ui.LargeList.SelectedItem
    if (-not $f) { $f = Get-AWCheckedLarge | Select-Object -First 1 }
    if ($f) { Open-AWExplorer $f.FullPath } else { Show-AWMessage 'Select a file first.' }
})
$ui.LargeRecycle.Add_Click({
    if (-not $script:Scanner) { return }
    $sel = Get-AWCheckedLarge
    if ($sel.Count -eq 0) { Show-AWMessage 'Tick the files you want to remove first.'; return }
    [long]$sum = 0; foreach ($f in $sel) { $sum += $f.Size }
    if (-not (Confirm-AW ("Send {0} file(s) ({1}) to the Recycle Bin?" -f $sel.Count, (Format-AWSize $sum)))) { return }
    $ok = 0; $fail = 0
    foreach ($f in $sel) {
        if (Test-AWProtectedPath $f.FullPath) { $fail++; continue }
        try {
            Send-AWToRecycle $f.FullPath
            [void]$script:Scanner.TopFiles.Remove($f)
            Write-AWLog "Recycled $($f.FullPath) ($($f.SizeText))"
            $ok++
        } catch { $fail++; Write-AWLog "Could not recycle $($f.FullPath): $($_.Exception.Message)" 'WARN' }
    }
    Update-AWLargeList
    $script:IdleStatus = "Recycled $ok file(s)" + $(if ($fail) { ", $fail failed" } else { '' }) + ' - rescan to refresh the Space Map'
    Set-AWStatus $script:IdleStatus
})
$ui.LargeExport.Add_Click({
    if (-not $script:Scanner -or -not $script:Scanner.TopFiles.Count) { Show-AWMessage 'Run a scan first.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV file (*.csv)|*.csv'
    $dlg.FileName = 'AWiper-LargeFiles-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date)
    if ($dlg.ShowDialog($window)) {
        $script:Scanner.TopFiles | Select-Object Name, Size, SizeText, Extension, ModifiedText, FullPath |
            Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
        Write-AWLog "Exported large files list to $($dlg.FileName)"
        Set-AWStatus "Exported to $($dlg.FileName)"
    }
})
#endregion

#region ---------------------------------------------------------------- Startup manager
$script:ApprovedBase = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'

function Get-AWApprovedEnabled([string]$Key, [string]$Name) {
    try {
        $v = (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name
        if ($v -is [byte[]] -and $v.Length -gt 0) { return -not ($v[0] -band 1) }
    } catch { }
    $true
}

function Get-AWStartupItems {
    $list = New-Object System.Collections.Generic.List[object]
    $sources = @(
        @{ Hive = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run';             Approved = 'Run';   Location = 'Registry Run';   Scope = 'User' }
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Approved = 'Run';   Location = 'Registry Run';   Scope = 'All users' }
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run32'; Location = 'Registry Run32'; Scope = 'All users' }
    )
    foreach ($s in $sources) {
        $path = "$($s.Hive):\$($s.Key)"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $k = Get-Item -LiteralPath $path
        $approved = "$($s.Hive):\$script:ApprovedBase\$($s.Approved)"
        foreach ($name in $k.GetValueNames()) {
            if (-not $name) { continue }
            $list.Add([pscustomobject]@{
                Name = $name; Command = [string]$k.GetValue($name); Location = $s.Location; Scope = $s.Scope
                Enabled = (Get-AWApprovedEnabled $approved $name)
                CanToggle = ($s.Hive -eq 'HKCU' -or $script:IsAdmin)
                ApprovedKey = $approved; ValueName = $name; FilePath = $null
            })
        }
    }
    $folders = @(
        @{ Path = [Environment]::GetFolderPath('Startup');       Hive = 'HKCU'; Scope = 'User' }
        @{ Path = [Environment]::GetFolderPath('CommonStartup'); Hive = 'HKLM'; Scope = 'All users' }
    )
    foreach ($f in $folders) {
        if (-not $f.Path -or -not (Test-Path -LiteralPath $f.Path)) { continue }
        $approved = "$($f.Hive):\$script:ApprovedBase\StartupFolder"
        foreach ($file in (Get-ChildItem -LiteralPath $f.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -eq 'desktop.ini') { continue }
            $cmd = $file.FullName
            if ($file.Extension -eq '.lnk') {
                try { $sh = New-Object -ComObject WScript.Shell; $t = $sh.CreateShortcut($file.FullName); if ($t.TargetPath) { $cmd = ('"{0}" {1}' -f $t.TargetPath, $t.Arguments).Trim() } } catch { }
            }
            $list.Add([pscustomobject]@{
                Name = $file.BaseName; Command = $cmd; Location = 'Startup folder'; Scope = $f.Scope
                Enabled = (Get-AWApprovedEnabled $approved $file.Name)
                CanToggle = ($f.Hive -eq 'HKCU' -or $script:IsAdmin)
                ApprovedKey = $approved; ValueName = $file.Name; FilePath = $file.FullName
            })
        }
    }
    $list | Sort-Object Name
}

function Set-AWStartupState($Item, [bool]$Enable) {
    if (-not (Test-Path -LiteralPath $Item.ApprovedKey)) { New-Item -Path $Item.ApprovedKey -Force -ErrorAction Stop | Out-Null }
    $bytes = New-Object byte[] 12
    if ($Enable) { $bytes[0] = 2 }
    else {
        $bytes[0] = 3
        [Array]::Copy([BitConverter]::GetBytes((Get-Date).ToFileTime()), 0, $bytes, 4, 8)
    }
    New-ItemProperty -LiteralPath $Item.ApprovedKey -Name $Item.ValueName -PropertyType Binary -Value $bytes -Force -ErrorAction Stop | Out-Null
}

function Update-AWStartupList {
    try {
        $items = @(Get-AWStartupItems)
        $ui.StartupList.ItemsSource = $items
        $on = @($items | Where-Object { $_.Enabled }).Count
        $ui.StartupInfo.Text = "$($items.Count) startup entries, $on enabled. Disabled items stay installed, they just won't launch at sign-in." +
            $(if (-not $script:IsAdmin) { ' All-users entries need admin rights to change.' } else { '' })
    } catch { Write-AWLog "Startup list: $($_.Exception.Message)" 'ERROR' }
}

function Get-AWExeFromCommand([string]$Command) {
    $c = [Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 1) { return $c.Substring(1, $end - 1) } }
    $m = [regex]::Match($c, '^(.+?\.(exe|cmd|bat|lnk|vbs|ps1|com))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    ($c -split '\s+')[0]
}

$ui.StartupList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
    param($s, $e)
    $cb = $e.OriginalSource
    if ($cb -isnot [System.Windows.Controls.CheckBox]) { return }
    $item = $cb.DataContext
    $want = [bool]$cb.IsChecked
    try {
        Set-AWStartupState $item $want
        $item.Enabled = $want
        Write-AWLog ("Startup item '{0}' {1}" -f $item.Name, $(if ($want) { 'enabled' } else { 'disabled' }))
        Set-AWStatus ("{0} will {1}launch at sign-in" -f $item.Name, $(if ($want) { '' } else { 'no longer ' }))
    } catch {
        $cb.IsChecked = $item.Enabled
        Show-AWMessage "Could not change '$($item.Name)':`n$($_.Exception.Message)" 'Error'
    }
})
$ui.StartupRefresh.Add_Click({ Update-AWStartupList })
$ui.StartupOpen.Add_Click({
    $it = $ui.StartupList.SelectedItem
    if (-not $it) { Show-AWMessage 'Select a startup entry first.'; return }
    $target = if ($it.FilePath) { $it.FilePath } else { Get-AWExeFromCommand $it.Command }
    if ($target -and (Test-Path -LiteralPath $target)) { Open-AWExplorer $target }
    else { Show-AWMessage "Couldn't find the file for this entry:`n$($it.Command)" 'Warning' }
})
#endregion

#region ---------------------------------------------------------------- Programs
$script:Programs = @()

function Update-AWProgramView {
    $q = $ui.ProgSearch.Text.Trim()
    $items = @(if ($q) { $script:Programs | Where-Object { $_.Name -like "*$q*" -or $_.Publisher -like "*$q*" } } else { $script:Programs })
    $ui.ProgList.ItemsSource = $items
    [long]$sum = 0; foreach ($p in $items) { $sum += $p.SizeBytes }
    $ui.ProgInfo.Text = '{0:N0} programs - {1} reported size' -f $items.Count, (Format-AWSize $sum)
}

function Update-AWProgramList {
    $ui.ProgInfo.Text = 'Loading installed programs...'
    $ui.ProgRefresh.IsEnabled = $false
    $remote = Test-AWRemote
    $ui.ProgUninstall.IsEnabled = -not $remote
    $ui.ProgOpen.IsEnabled = -not $remote
    $ui.ProgUninstall.ToolTip = if ($remote) { 'Uninstalling is only available on this PC.' } else { $null }
    Start-AWTask -Name 'Read installed programs' -Work {
        $raw = Invoke-WTarget {
            $paths = @(
                @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             S = 'Machine' }
                @{ P = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; S = 'Machine (x86)' }
                @{ P = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';             S = 'User' }
            )
            $seen = @{}
            foreach ($src in $paths) {
                foreach ($e in (Get-ItemProperty -Path $src.P -ErrorAction SilentlyContinue)) {
                    if (-not $e.DisplayName -or $e.SystemComponent -eq 1 -or $e.ParentKeyName -or $e.ReleaseType -match 'Update|Hotfix') { continue }
                    if (-not $e.UninstallString) { continue }
                    $key = "$($e.DisplayName)|$($e.DisplayVersion)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $installed = ''
                    if ($e.InstallDate -match '^\d{8}$') {
                        try { $installed = [datetime]::ParseExact($e.InstallDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') } catch { }
                    }
                    [pscustomobject]@{
                        Name = [string]$e.DisplayName; Publisher = [string]$e.Publisher; Version = [string]$e.DisplayVersion; Installed = $installed
                        SizeBytes = $(if ($e.EstimatedSize) { [long]$e.EstimatedSize * 1KB } else { [long]0 })
                        Scope = $src.S; Uninstall = [string]$e.UninstallString; Location = [string]$e.InstallLocation
                    }
                }
            }
        }
        # Rebuild locally so remote (deserialized) results bind and sort like local ones.
        foreach ($r in $raw) {
            [pscustomobject]@{
                Name = $r.Name; Publisher = $r.Publisher; Version = $r.Version; Installed = $r.Installed
                SizeBytes = [long]$r.SizeBytes; SizeText = $(if ($r.SizeBytes) { [AWiper.Fmt]::Size([long]$r.SizeBytes) } else { '' })
                Scope = $r.Scope; Uninstall = $r.Uninstall; Location = $r.Location
            }
        }
    } -OnComplete {
        param($Result)
        $script:Programs = @($Result | Where-Object { $_ } | Sort-Object Name)
        $ui.ProgRefresh.IsEnabled = $true
        Update-AWProgramView
    }
}

$ui.ProgSearch.Add_TextChanged({ Update-AWProgramView })
$ui.ProgRefresh.Add_Click({ Update-AWProgramList })
$ui.ProgOpen.Add_Click({
    $p = $ui.ProgList.SelectedItem
    if (-not $p) { Show-AWMessage 'Select a program first.'; return }
    if ($p.Location -and (Test-Path -LiteralPath $p.Location)) { Open-AWExplorer $p.Location }
    else { Show-AWMessage "$($p.Name) doesn't report an install folder." }
})
$ui.ProgUninstall.Add_Click({
    $p = $ui.ProgList.SelectedItem
    if (-not $p) { Show-AWMessage 'Select a program first.'; return }
    if (-not (Confirm-AW "Start the uninstaller for:`n`n$($p.Name) $($p.Version)`n`nThe program's own uninstaller will open.")) { return }
    try {
        $cmd = $p.Uninstall
        if ($cmd -match 'msiexec' -and $cmd -match '\{[0-9A-Fa-f\-]{36}\}') {
            Start-Process msiexec.exe -ArgumentList "/x $($Matches[0])"
        } else {
            Start-Process cmd.exe -ArgumentList "/c `"$cmd`"" -WindowStyle Hidden
        }
        Write-AWLog "Started uninstaller for $($p.Name)"
        Set-AWStatus "Uninstaller started for $($p.Name). Press Refresh when it finishes."
    } catch { Show-AWMessage "Could not start the uninstaller:`n$($_.Exception.Message)" 'Error' }
})
#endregion

#region ---------------------------------------------------------------- Shared actions
function Restart-AWExplorer {
    Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 1200
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
    Write-AWLog 'Explorer restarted'; Set-AWStatus 'Explorer restarted'
}

function Start-AWRestorePoint {
    if (-not (Test-AWCanAdmin)) { Show-AWMessage 'Creating a restore point needs administrator rights.'; return }
    Start-AWTask -Name 'Create restore point' -Work {
        $Sync.Status = 'Creating System Restore point...'
        try {
            Invoke-WTarget {
                $r = Invoke-CimMethod -Namespace root/default -ClassName SystemRestore -MethodName CreateRestorePoint `
                     -Arguments @{ Description = 'AWiper checkpoint'; RestorePointType = [uint32]12; EventType = [uint32]100 } -ErrorAction Stop
                if ($r.ReturnValue -eq 0) { Write-WLog 'Restore point created' }
                else { Write-WLog "Restore point returned code $($r.ReturnValue) (System Protection may be off for this drive)" 'WARN' }
            }
        } catch { Write-WLog "Restore point failed: $($_.Exception.Message)" 'ERROR' }
    } -OnComplete { param($r) $script:IdleStatus = 'Restore point request finished - see Activity log' }
}

# Runs a console command on the target and streams its output to the Activity log.
# Lines containing a percentage drive the progress bar. The body should end with "AWEXIT $LASTEXITCODE".
function Start-AWCommandTask([string]$Name, [scriptblock]$Body) {
    Start-AWTask -Name $Name -Arguments @{ Label = $Name; Body = $Body.ToString() } -Work {
        $Sync.Status = "$Label running..."
        Invoke-WTarget ([scriptblock]::Create($Body)) | ForEach-Object {
            foreach ($seg in (("$_" -replace "`0", '') -split "`r")) {
                $l = $seg.Trim()
                if (-not $l) { continue }
                if ($l -match '^AWEXIT (-?\d+)$') { Write-WLog "$Label finished with exit code $($Matches[1])"; continue }
                if ($l -match '(\d+(\.\d+)?)\s*%') { $Sync.Progress = [int][double]$Matches[1]; $Sync.Status = "$Label - $l"; continue }
                if ($l -notmatch '^\[=*') { Write-WLog "${Label}: $l" }
            }
        }
        "$Label finished"
    } -OnComplete {
        param($r)
        $m = @($r | Where-Object { $_ })
        $script:IdleStatus = if ($m.Count) { "$($m[-1]) - see Activity log" } else { 'Task failed - see Activity log' }
    }
}
#endregion

#region ---------------------------------------------------------------- Debloat
$script:AllApps = @()
$script:TweakChecks = New-Object System.Collections.Generic.List[object]
$script:TweakState = @{}
$script:PendingExplorerRestart = $false

# HKCU tweaks would land in the remote admin's own profile, so only machine-wide tweaks run remotely.
function Test-AWTweakRemoteOk($Tweak) { -not @($Tweak.Values | Where-Object { $_.Path -notlike 'HKLM:*' }) }
function Test-AWTweakAllowed($Tweak) {
    if (Test-AWRemote) { return Test-AWTweakRemoteOk $Tweak }
    $script:IsAdmin -or -not $Tweak.Admin
}

function Update-AWAppView {
    $q = $ui.AppSearch.Text.Trim()
    $all = [bool]$ui.AppsShowAll.IsChecked
    $items = @($script:AllApps | Where-Object { ($all -or $_.Category -ne 'Other') -and (-not $q -or $_.Name -like "*$q*" -or $_.Package -like "*$q*") })
    $ui.AppList.ItemsSource = $items
    $ui.AppsInfo.Text = '{0} app(s) shown' -f $items.Count
}

function Update-AWAppList {
    $ui.AppsInfo.Text = 'Reading installed apps...'
    $ui.AppsRemove.IsEnabled = $false
    $ui.AppsProvisioned.IsEnabled = Test-AWCanAdmin
    Start-AWTask -Name 'Read Store apps' -Arguments @{ Catalog = $script:BloatCatalog; Protected = $script:ProtectedApps; AllUsers = [bool](Test-AWCanAdmin) } -Work {
        $raw = Invoke-WTarget {
            param($AllUsers)
            if ($PSVersionTable.PSVersion.Major -ge 7) { Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
            $prov = @{}
            if ($AllUsers) {
                try { foreach ($p in (Get-AppxProvisionedPackage -Online -ErrorAction Stop)) { $prov[$p.DisplayName] = $true } }
                catch { Write-WLog "Could not read provisioned apps: $($_.Exception.Message)" 'WARN' }
            }
            $pk = if ($AllUsers) { Get-AppxPackage -AllUsers } else { Get-AppxPackage }
            foreach ($p in $pk) {
                if ($p.IsFramework -or $p.NonRemovable -or "$($p.SignatureKind)" -eq 'System') { continue }
                [pscustomobject]@{ Name = [string]$p.Name; FullName = [string]$p.PackageFullName; Version = [string]$p.Version; Publisher = [string]$p.Publisher; Prov = [bool]$prov[$p.Name] }
            }
        } -ArgumentList @($AllUsers)

        $seen = @{}
        foreach ($p in $raw) {
            if ($seen[$p.Name]) { continue }
            $seen[$p.Name] = $true
            $match = $null
            foreach ($c in $Catalog) { if ($p.Name -like $c.Pattern) { $match = $c; break } }
            if (-not $match) {
                $prot = $false
                foreach ($x in $Protected) { if ($p.Name -like $x) { $prot = $true; break } }
                if ($prot) { continue }
            }
            $e = New-Object AWiper.AppEntry
            $e.Package = $p.Name; $e.FullName = $p.FullName; $e.Version = $p.Version; $e.Publisher = $p.Publisher; $e.Provisioned = $p.Prov
            if ($match) { $e.Name = $match.Name; $e.Category = $match.Category; $e.Recommended = $match.Recommended; $e.Note = $match.Note }
            else { $e.Name = $p.Name -replace '^[^.]+\.(?=.)', ''; $e.Category = 'Other'; $e.Note = "Version $($p.Version)" }
            $e.IsChecked = $e.Recommended
            $e
        }
    } -OnComplete {
        param($Result)
        $script:AllApps = @($Result | Where-Object { $_ } | Sort-Object Category, Name)
        $ui.AppsRemove.IsEnabled = $true
        Update-AWAppView
    }
}

function Start-AWAppRemoval {
    $apps = @($script:AllApps | Where-Object { $_.IsChecked })
    if ($apps.Count -eq 0) { Show-AWMessage 'Check at least one app first.'; return }
    $prov  = [bool]$ui.AppsProvisioned.IsChecked -and (Test-AWCanAdmin)
    $scope = if (Test-AWCanAdmin) { 'for all users' } else { 'for your account' }
    $where = if (Test-AWRemote) { " on $($script:Target.ComputerName)" } else { '' }
    $list  = ($apps | Select-Object -First 20 | ForEach-Object { "  - $($_.Name)" }) -join "`n"
    if ($apps.Count -gt 20) { $list += "`n  ...and $($apps.Count - 20) more" }
    if (-not (Confirm-AW "Remove $($apps.Count) app(s) $scope$($where)?`n`n$list`n`nMost of these can be reinstalled from the Microsoft Store.")) { return }

    $ui.AppsRemove.IsEnabled = $false
    $pk = @($apps | ForEach-Object { @{ Name = $_.Name; Package = $_.Package; Provisioned = $_.Provisioned } })
    Start-AWTask -Name 'Remove Store apps' -Arguments @{ Pk = $pk; AllUsers = [bool](Test-AWCanAdmin); Prov = $prov } -Work {
        $i = 0
        foreach ($a in $Pk) {
            $Sync.Status = "Removing $($a.Name)..."
            $Sync.Progress = [int]($i * 100 / $Pk.Count); $i++
            try {
                Invoke-WTarget {
                    param($App, $AllUsers, $Prov)
                    if ($PSVersionTable.PSVersion.Major -ge 7) { Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
                    $done = $false
                    if ($AllUsers) {
                        try { Get-AppxPackage -AllUsers -Name $App.Package | Remove-AppxPackage -AllUsers -ErrorAction Stop; $done = $true }
                        catch { Write-WLog "$($App.Name): all-users removal failed ($($_.Exception.Message)), trying current user" 'WARN' }
                    }
                    if (-not $done) {
                        $mine = @(Get-AppxPackage -Name $App.Package)
                        if ($mine.Count) { $mine | Remove-AppxPackage -ErrorAction Stop }
                        else { Write-WLog "$($App.Name): not installed for this account" 'WARN' }
                    }
                    if ($Prov -and $App.Provisioned) {
                        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $App.Package } |
                            Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
                        Write-WLog "$($App.Name): removed provisioned copy (new users won't get it)"
                    }
                    Write-WLog "Removed $($App.Name)"
                } -ArgumentList @($a, $AllUsers, $Prov)
            } catch { Write-WLog "$($a.Name): $($_.Exception.Message)" 'ERROR' }
        }
        $Sync.Progress = 100
    } -OnComplete {
        param($r)
        $script:IdleStatus = 'App removal finished - see Activity log'
        Update-AWAppList
    }
}

function Initialize-AWTweaks {
    $ui.TweakItems.Children.Clear()
    $script:TweakChecks.Clear()
    $script:TweakState = @{}
    $lastGroup = ''
    foreach ($tw in $script:Tweaks) {
        if ($tw.Group -ne $lastGroup) {
            $h = New-AWText $tw.Group.ToUpper() 11 $script:Res.Dim 'Bold'
            $h.Margin = if ($lastGroup) { '0,16,0,6' } else { '0,8,0,6' }
            [void]$ui.TweakItems.Children.Add($h)
            $lastGroup = $tw.Group
        }
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Margin = '0,5'; $cb.Tag = $tw
        $allowed = Test-AWTweakAllowed $tw
        $cb.IsEnabled = $allowed
        $cb.IsChecked = $tw.Default -and $allowed
        $cb.ToolTip = if ((Test-AWRemote) -and -not $allowed) { "$($tw.Desc)`n`nPer-user setting - only available on this PC." } else { $tw.Desc }
        [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($cb, $true)

        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        [void]$sp.Children.Add((New-AWText $tw.Name 13))
        if ($tw.Admin) { [void]$sp.Children.Add((New-AWPill 'ADMIN' (Test-AWCanAdmin))) }
        $on = New-AWPill 'ON' $true 'Teal'; $on.Visibility = 'Collapsed'
        [void]$sp.Children.Add($on)
        $script:TweakState[$tw.Id] = $on
        $cb.Content = $sp
        [void]$ui.TweakItems.Children.Add($cb)
        $script:TweakChecks.Add($cb)
    }
}

function Update-AWTweakStatus {
    $list = @($script:Tweaks | Where-Object { Test-AWTweakAllowed $_ })
    Start-AWTask -Name 'Read tweak status' -Arguments @{ Tw = $list } -Work {
        Invoke-WTarget { param($Items) foreach ($t in $Items) { [pscustomobject]@{ Id = $t.Id; On = [bool](Test-WTweak $t) } } } -ArgumentList @(, $Tw)
    } -OnComplete {
        param($Result)
        foreach ($p in $script:TweakState.Values) { $p.Visibility = 'Collapsed' }
        foreach ($r in $Result) { if ($r -and $r.On -and $script:TweakState[[string]$r.Id]) { $script:TweakState[[string]$r.Id].Visibility = 'Visible' } }
    }
}

function Start-AWTweaks([bool]$Apply) {
    $sel = @($script:TweakChecks | Where-Object { $_.IsChecked -and $_.IsEnabled } | ForEach-Object { $_.Tag })
    if ($sel.Count -eq 0) { Show-AWMessage 'Check at least one tweak first.'; return }
    $verb  = if ($Apply) { 'Apply' } else { 'Revert' }
    $where = if (Test-AWRemote) { " on $($script:Target.ComputerName)" } else { '' }
    $names = ($sel | ForEach-Object { "  - $($_.Name)" }) -join "`n"
    if (-not (Confirm-AW "$verb these tweaks$($where)?`n`n$names")) { return }
    $script:PendingExplorerRestart = (-not (Test-AWRemote)) -and [bool]$ui.TweaksRestartExplorer.IsChecked -and @($sel | Where-Object { $_.Explorer }).Count -gt 0
    $ui.TweaksApply.IsEnabled = $false; $ui.TweaksRevert.IsEnabled = $false
    Start-AWTask -Name "$verb tweaks" -Arguments @{ Sel = $sel; Apply = $Apply } -Work {
        foreach ($t in $Sel) {
            $Sync.Status = "$($t.Name)..."
            try { Invoke-WTarget { param($Tw, $On) Set-WTweak $Tw $On } -ArgumentList @($t, $Apply) }
            catch { Write-WLog "$($t.Name): $($_.Exception.Message)" 'ERROR' }
        }
    } -OnComplete {
        param($r)
        $ui.TweaksApply.IsEnabled = $true; $ui.TweaksRevert.IsEnabled = $true
        if ($script:PendingExplorerRestart) { Restart-AWExplorer }
        $script:PendingExplorerRestart = $false
        $script:IdleStatus = 'Tweaks updated - some changes take effect after signing out'
        Update-AWTweakStatus
    }
}

$ui.AppSearch.Add_TextChanged({ Update-AWAppView })
$ui.AppsShowAll.Add_Checked({ Update-AWAppView })
$ui.AppsShowAll.Add_Unchecked({ Update-AWAppView })
$ui.AppsRecommended.Add_Click({ foreach ($a in $script:AllApps) { $a.IsChecked = $a.Recommended }; $ui.AppList.Items.Refresh() })
$ui.AppsNone.Add_Click({ foreach ($a in $script:AllApps) { $a.IsChecked = $false }; $ui.AppList.Items.Refresh() })
$ui.AppsRemove.Add_Click({ Start-AWAppRemoval })
$ui.DebloatRefresh.Add_Click({ Update-AWAppList; Update-AWTweakStatus })
$ui.DebloatRestore.Add_Click({ Start-AWRestorePoint })
$ui.TweaksDefault.Add_Click({ foreach ($cb in $script:TweakChecks) { $cb.IsChecked = $cb.IsEnabled -and $cb.Tag.Default } })
$ui.TweaksNone.Add_Click({ foreach ($cb in $script:TweakChecks) { $cb.IsChecked = $false } })
$ui.TweaksApply.Add_Click({ Start-AWTweaks $true })
$ui.TweaksRevert.Add_Click({ Start-AWTweaks $false })
#endregion

#region ---------------------------------------------------------------- Remote target
$script:ConnPending = $null
$script:ConnLoadedSaved = $null

function Get-AWCredTarget([string]$TargetHost) { 'AWiper:' + $TargetHost.ToLowerInvariant() }
function Get-AWSavedCred([string]$TargetHost) { try { [AWiper.CredMan]::Read((Get-AWCredTarget $TargetHost)) } catch { $null } }

# Short names get the domain appended; IPs and FQDNs are used as typed.
function Resolve-AWHost {
    $h = $ui.ConnHost.Text.Trim()
    $d = $ui.ConnDomain.Text.Trim().TrimStart('.')
    if ($h -and $d -and $h -notmatch '[.:]') { "$h.$d" } else { $h }
}
function Resolve-AWUser([string]$User) {
    $d = $ui.ConnDomain.Text.Trim().TrimStart('.')
    if (-not $User -or -not $d -or $User -match '[\\@]') { return $User }
    if ($d -match '\.') { "$User@$d" } else { "$d\$User" }
}
function Test-AWIsAddress([string]$TargetHost) { $TargetHost -match '^\d{1,3}(\.\d{1,3}){3}$' -or $TargetHost -match ':' }

function Show-AWConnMsg([string]$Text, [bool]$Trust = $false) {
    $ui.ConnMsg.Text = $Text
    $ui.ConnMsgBox.Visibility = if ($Text) { 'Visible' } else { 'Collapsed' }
    $ui.ConnTrust.Visibility = if ($Trust) { 'Visible' } else { 'Collapsed' }
}

function Update-AWRecentChips {
    $ui.ConnRecent.Children.Clear()
    $saved = @()
    try { $saved = @([AWiper.CredMan]::List('AWiper:*') | ForEach-Object { $_.Substring(7) }) } catch { }
    $hosts = @(@($script:State.RecentTargets) + $saved | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
    foreach ($h in $hosts) {
        $b = New-Object System.Windows.Controls.Button
        $b.Style = $window.FindResource('BtnChip'); $b.Margin = '0,0,6,6'; $b.Tag = $h
        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        if ($saved -contains $h.ToLowerInvariant()) {
            $k = New-AWText ([string][char]0xE8D7) 11 $script:Res.Teal; $k.FontFamily = $window.FindResource('IconFont'); $k.Margin = '0,0,6,0'
            $k.VerticalAlignment = 'Center'
            [void]$sp.Children.Add($k)
            $b.ToolTip = 'Credentials saved in Windows Credential Manager'
        }
        [void]$sp.Children.Add((New-AWText $h 12))
        $b.Content = $sp
        $b.Add_Click({ param($s, $e) $ui.ConnHost.Text = $s.Tag; $ui.ConnHost.CaretIndex = $s.Tag.Length })
        [void]$ui.ConnRecent.Children.Add($b)
    }
    $ui.ConnRecent.Visibility = if ($hosts.Count) { 'Visible' } else { 'Collapsed' }
}

function Update-AWConnSaved {
    $h = Resolve-AWHost
    $ui.ConnResolved.Text = if ($h -and $h -ne $ui.ConnHost.Text.Trim()) { "Connects to $h" } else { '' }
    $saved = if ($h) { Get-AWSavedCred $h } else { $null }
    if ($saved) {
        $ui.ConnUseOther.IsChecked = $true
        $ui.ConnUser.Text = $saved[0]; $ui.ConnPass.Password = $saved[1]; $ui.ConnSave.IsChecked = $true
        $ui.ConnForget.Visibility = 'Visible'
        $ui.ConnSavedNote.Text = "Using credentials saved in Windows Credential Manager for $h"
        $ui.ConnSavedNote.Visibility = 'Visible'
        $script:ConnLoadedSaved = $h
    } else {
        $ui.ConnForget.Visibility = 'Collapsed'; $ui.ConnSavedNote.Visibility = 'Collapsed'
        if ($script:ConnLoadedSaved) {
            $ui.ConnUser.Text = ''; $ui.ConnPass.Clear(); $ui.ConnSave.IsChecked = $false
            $script:ConnLoadedSaved = $null
        }
    }
}

function Show-AWConnect {
    Show-AWConnMsg ''
    $ui.ConnProgress.Visibility = 'Collapsed'; $ui.ConnGo.IsEnabled = $true
    $ui.ConnLocal.Visibility = if (Test-AWRemote) { 'Visible' } else { 'Collapsed' }
    $ui.ConnCurrentText.Text = "Current ($env:USERNAME)"
    if (-not $ui.ConnDomain.Text -and $env:USERDNSDOMAIN) { $ui.ConnDomain.Text = $env:USERDNSDOMAIN.ToLowerInvariant() }
    if (Test-AWRemote) { $ui.ConnHost.Text = $script:Target.Host }
    Update-AWRecentChips
    Update-AWConnSaved
    $ui.ConnectOverlay.Visibility = 'Visible'
    [void]$ui.ConnHost.Focus(); $ui.ConnHost.SelectAll()
}
function Hide-AWConnect {
    $ui.ConnectOverlay.Visibility = 'Collapsed'
    $ui.ConnPass.Clear(); $script:ConnLoadedSaved = $null
}

function Update-AWTargetUI {
    if (Test-AWRemote) {
        $ui.TargetText.Text = $script:Target.ComputerName
        $ui.TargetIcon.Foreground = $script:Res.Purple
        $ui.TargetBtn.BorderBrush = $script:Res.Purple
        $ui.TargetBtn.ToolTip = "Working on $($script:Target.ComputerName) ($($script:Target.OS)) as $($script:Target.User)`nClick to change"
        $window.Title = "AWiper - $($script:Target.ComputerName)"
    } else {
        $ui.TargetText.Text = 'This PC'
        $ui.TargetIcon.Foreground = $script:Res.Teal
        $ui.TargetBtn.ClearValue([System.Windows.Controls.Control]::BorderBrushProperty)
        $ui.TargetBtn.ToolTip = 'Choose which computer AWiper works on'
        $window.Title = 'AWiper'
    }
}

function Set-AWTarget($NewTarget) {
    $script:Target = $NewTarget
    Update-AWTargetUI
    Initialize-AWCleaner
    Initialize-AWTools
    Initialize-AWTweaks
    $ui.CleanResults.ItemsSource = $null
    $ui.CleanSummary.Text = 'Ready to analyze'
    $ui.CleanSubtext.Text = if (Test-AWRemote) { "Machine-wide rules run on $($NewTarget.ComputerName). Per-user rules are only available on this PC." } else { 'Pick the rules on the left, then Analyze to see what can be removed.' }
    $ui.CleanProgress.Value = 0
    $script:AllApps = @(); $ui.AppList.ItemsSource = $null; $script:Programs = @(); $ui.ProgList.ItemsSource = $null
    [void]$script:Loaded.Remove('Programs'); [void]$script:Loaded.Remove('Debloat'); [void]$script:Loaded.Remove('Recovery')
    $cur = Get-AWCurrentView
    Update-AWViewTitle $cur
    if ($cur -eq 'Programs') { $script:Loaded['Programs'] = $true; Update-AWProgramList }
    if ($cur -eq 'Debloat')  { $script:Loaded['Debloat'] = $true; Update-AWAppList; Update-AWTweakStatus }
    if ($cur -eq 'Recovery') { $script:Loaded['Recovery'] = $true; Initialize-AWRecovery }
    if (Test-AWRemote) {
        Write-AWLog "Target is now $($NewTarget.ComputerName) ($($NewTarget.Host)) - $($NewTarget.OS), signed in as $($NewTarget.User)"
        $script:IdleStatus = "Connected to $($NewTarget.ComputerName)"
    } else {
        Write-AWLog 'Target is now this PC'
        $script:IdleStatus = 'Working on this PC'
    }
    Set-AWStatus $script:IdleStatus
}

function Start-AWConnect {
    if ($script:Jobs.Count -gt 0) { Show-AWConnMsg 'Wait for the running task to finish before switching computers.'; return }
    $h = Resolve-AWHost
    if (-not $h) { Show-AWConnMsg 'Enter a hostname, FQDN or IP address.'; return }
    $cred = $null
    if ($ui.ConnUseOther.IsChecked) {
        $u = Resolve-AWUser $ui.ConnUser.Text.Trim()
        if (-not $u -or $ui.ConnPass.SecurePassword.Length -eq 0) { Show-AWConnMsg 'Enter a username and password, or choose Current credentials.'; return }
        $cred = New-Object System.Management.Automation.PSCredential($u, $ui.ConnPass.SecurePassword.Copy())
    }
    $script:ConnPending = @{ Host = $h; Credential = $cred; Save = ($null -ne $cred -and [bool]$ui.ConnSave.IsChecked) }
    Show-AWConnMsg ''
    $ui.ConnGo.IsEnabled = $false
    $ui.ConnProgress.Visibility = 'Visible'
    Start-AWTask -Name "Connect to $h" -Arguments @{ Cand = @{ Host = $h; Credential = $cred } } -Work {
        $Sync.Status = "Connecting to $($Cand.Host)..."
        $p = @{ ComputerName = $Cand.Host; ErrorAction = 'Stop'; ScriptBlock = {
            $os = Get-CimInstance Win32_OperatingSystem
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME; OS = ($os.Caption -replace '^Microsoft\s+', ''); User = $id.Name
                Admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            }
        } }
        if ($Cand.Credential) { $p.Credential = $Cand.Credential }
        try { @{ Ok = $true; Info = (Invoke-Command @p) } }
        catch { @{ Ok = $false; Error = $_.Exception.Message } }
    } -OnComplete { param($Result) Complete-AWConnect $Result }
}

function Complete-AWConnect($Result) {
    $ui.ConnGo.IsEnabled = $true
    $ui.ConnProgress.Visibility = 'Collapsed'
    $res = @($Result | Where-Object { $_ }) | Select-Object -Last 1
    $pend = $script:ConnPending
    if (-not $res -or -not $res.Ok) {
        $err = if ($res) { [string]$res.Error } else { 'The connection attempt failed.' }
        $isAddr = Test-AWIsAddress $pend.Host
        $hint = if ($err -match 'TrustedHosts|Kerberos|0x8009030e|0x80090311|authentication scheme') {
            if ($isAddr) { 'Connecting by IP address needs Other credentials, and the address must be in this PC''s WinRM TrustedHosts list. You can also use the computer''s name instead.' }
            else { 'Kerberos could not authenticate. Use the full name (FQDN) of a domain-joined PC, or choose Other credentials and add the computer to TrustedHosts.' }
        } elseif ($err -match 'Access is denied|access denied') {
            'Access denied. The account needs admin rights on the remote PC, or the username or password is wrong.'
        } elseif ($err -match 'cannot be resolved|cannot find the computer|could not resolve|network path|WinRM cannot complete|firewall|did not respond') {
            'The computer could not be reached. Check the name, make sure it is on, and that PowerShell remoting is enabled on it (Enable-PSRemoting -Force).'
        } else { 'Could not connect.' }
        if ($err.Length -gt 320) { $err = $err.Substring(0, 320) + '...' }
        $trust = $err -match 'TrustedHosts|Kerberos|0x8009030e|0x80090311|authentication scheme'
        Show-AWConnMsg "$hint`n`n$err" $trust
        Write-AWLog "Connect to $($pend.Host) failed: $err" 'WARN'
        return
    }
    $info = $res.Info
    if ($pend.Save) {
        try {
            [AWiper.CredMan]::Write((Get-AWCredTarget $pend.Host), $pend.Credential.UserName, $ui.ConnPass.Password)
            Write-AWLog "Saved credentials for $($pend.Host) to Windows Credential Manager"
        } catch { Write-AWLog "Could not save credentials: $($_.Exception.Message)" 'WARN' }
    }
    $script:State.RecentTargets = @(@($pend.Host) + @($script:State.RecentTargets | Where-Object { $_ -and $_ -ne $pend.Host }) | Select-Object -First 8)
    Save-AWState
    if (-not $info.Admin) { Write-AWLog "Connected to $($pend.Host) without admin rights - most actions will fail" 'WARN' }
    Hide-AWConnect
    Set-AWTarget @{ Host = $pend.Host; Credential = $pend.Credential; ComputerName = [string]$info.ComputerName; OS = [string]$info.OS; User = [string]$info.User }
}

$ui.TargetBtn.Add_Click({ Show-AWConnect })
$ui.ConnClose.Add_Click({ Hide-AWConnect })
$ui.ConnCancel.Add_Click({ Hide-AWConnect })
$ui.ConnGo.Add_Click({ Start-AWConnect })
$ui.ConnLocal.Add_Click({
    if ($script:Jobs.Count -gt 0) { Show-AWConnMsg 'Wait for the running task to finish before switching computers.'; return }
    Hide-AWConnect; Set-AWTarget $null
})
$ui.ConnPass.Add_PasswordChanged({ $ui.ConnPassHint.Visibility = if ($ui.ConnPass.SecurePassword.Length) { 'Collapsed' } else { 'Visible' } })
$ui.ConnHost.Add_TextChanged({ Update-AWConnSaved })
$ui.ConnDomain.Add_TextChanged({ Update-AWConnSaved })
$ui.ConnUseOther.Add_Checked({ $ui.ConnOtherPanel.Visibility = 'Visible' })
$ui.ConnUseCurrent.Add_Checked({ $ui.ConnOtherPanel.Visibility = 'Collapsed' })
foreach ($c in @($ui.ConnHost, $ui.ConnDomain, $ui.ConnUser, $ui.ConnPass)) {
    $c.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; if ($ui.ConnGo.IsEnabled) { Start-AWConnect } } })
}
$ui.ConnForget.Add_Click({
    $h = Resolve-AWHost
    if ($h -and (Confirm-AW "Remove the saved credentials for $h from Windows Credential Manager?")) {
        [void][AWiper.CredMan]::Delete((Get-AWCredTarget $h))
        Write-AWLog "Removed saved credentials for $h"
        $ui.ConnSave.IsChecked = $false
        Update-AWConnSaved; Update-AWRecentChips
    }
})
$ui.ConnTrust.Add_Click({
    $h = Resolve-AWHost
    if (-not $script:IsAdmin) { Show-AWConnMsg 'Changing TrustedHosts needs AWiper to run as administrator. Use "Restart as admin", then try again.'; return }
    if (-not (Confirm-AW "Add $h to this PC's WinRM TrustedHosts list?`n`nThis lets PowerShell remoting connect to it with a username and password (NTLM). Only do this for computers you trust.")) { return }
    try {
        if ((Get-Service WinRM).Status -ne 'Running') { Start-Service WinRM -ErrorAction Stop }
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $h -Concatenate -Force -ErrorAction Stop
        Write-AWLog "Added $h to WinRM TrustedHosts"
        $ui.ConnUseOther.IsChecked = $true
        Show-AWConnMsg "Added $h to TrustedHosts. Enter credentials under Other credentials and connect again."
    } catch { Show-AWConnMsg "Could not update TrustedHosts: $($_.Exception.Message)" }
})
$window.Add_PreviewKeyDown({
    param($s, $e)
    if ($e.Key -eq 'Escape' -and $ui.ConnectOverlay.Visibility -eq 'Visible') { Hide-AWConnect; $e.Handled = $true }
})
#endregion

#region ---------------------------------------------------------------- Tools
$script:ToolPanel = $null

function Add-AWToolSection([string]$Title) {
    $h = New-AWText $Title.ToUpper() 11 $script:Res.Dim 'Bold'
    $h.Margin = if ($ui.ToolCards.Children.Count) { '4,6,0,10' } else { '4,0,0,10' }
    [void]$ui.ToolCards.Children.Add($h)
    $script:ToolPanel = New-Object System.Windows.Controls.WrapPanel
    [void]$ui.ToolCards.Children.Add($script:ToolPanel)
}

function New-AWToolCard {
    param([string]$Glyph, [string]$Title, [string]$Desc, [string]$ButtonText, [bool]$Admin, [scriptblock]$Action,
          [string]$Accent = 'Teal', [bool]$Remote = $false, [string]$Unavailable = '')
    $card = New-Object System.Windows.Controls.Border
    $card.Style = $window.FindResource('Card'); $card.Width = 300; $card.Margin = '0,0,14,14'; $card.Padding = '18,16'
    $sp = New-Object System.Windows.Controls.StackPanel

    $head = New-Object System.Windows.Controls.StackPanel; $head.Orientation = 'Horizontal'
    $ico = New-Object System.Windows.Controls.Border
    $ico.Width = 34; $ico.Height = 34; $ico.CornerRadius = '10'
    $ico.Background = if ($Accent -eq 'Purple') { $script:Res.PurpleGrad } else { $script:Res.TealGrad }
    $it = New-AWText $Glyph 15; $it.FontFamily = $window.FindResource('IconFont'); $it.Foreground = [System.Windows.Media.Brushes]::White
    $it.HorizontalAlignment = 'Center'; $it.VerticalAlignment = 'Center'
    $ico.Child = $it
    [void]$head.Children.Add($ico)
    $tt = New-AWText $Title 14.5 $null 'SemiBold'; $tt.Margin = '12,0,0,0'; $tt.VerticalAlignment = 'Center'
    [void]$head.Children.Add($tt)
    $localOnly = (Test-AWRemote) -and -not $Remote
    if ($localOnly) { [void]$head.Children.Add((New-AWPill 'THIS PC' $false)) }
    elseif ($Admin) { [void]$head.Children.Add((New-AWPill 'ADMIN' (Test-AWCanAdmin))) }
    [void]$sp.Children.Add($head)

    $d = New-AWText $Desc 12.5 $script:Res.Muted; $d.TextWrapping = 'Wrap'; $d.Margin = '0,10,0,14'; $d.Height = 52
    $d.TextTrimming = 'CharacterEllipsis'; $d.ToolTip = $Desc
    [void]$sp.Children.Add($d)

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = $ButtonText; $btn.Style = $window.FindResource('BtnChip'); $btn.HorizontalAlignment = 'Left'
    $btn.Tag = $Action
    $btn.IsEnabled = -not $localOnly -and -not $Unavailable -and (-not $Admin -or (Test-AWCanAdmin))
    if ($Unavailable) { $btn.ToolTip = $Unavailable }
    elseif ($localOnly) { $btn.ToolTip = 'Only available on this PC' }
    [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($btn, $true)
    $btn.Add_Click({ param($s, $e) try { & $s.Tag } catch { Show-AWMessage $_.Exception.Message 'Error' } })
    [void]$sp.Children.Add($btn)
    $card.Child = $sp
    [void]$script:ToolPanel.Children.Add($card)
}

function Get-AWWhere { if (Test-AWRemote) { " on $($script:Target.ComputerName)" } else { '' } }

function Initialize-AWTools {
    $ui.ToolCards.Children.Clear()

    # ---------------- Quick fixes
    Add-AWToolSection 'Quick fixes'

    New-AWToolCard ([string][char]0xE774) 'Flush DNS cache' 'Clears cached name lookups. Handy after DNS or hosts-file changes.' 'Flush now' $false {
        Start-AWCommandTask 'Flush DNS' { & ipconfig.exe /flushdns 2>&1; "AWEXIT $LASTEXITCODE" }
    } -Remote $true

    New-AWToolCard ([string][char]0xE8B7) 'Group Policy update' 'Re-applies Group Policy now (gpupdate /force) instead of waiting for the next refresh.' 'Update' $false {
        Start-AWCommandTask 'Group Policy update' {
            # Answer "N" to any restart / log-off prompt. Remotely only computer policy applies.
            if ($Sync.Remote) { & cmd.exe /c 'echo N| gpupdate /target:computer /force' 2>&1 } else { & cmd.exe /c 'echo N| gpupdate /force' 2>&1 }
            "AWEXIT $LASTEXITCODE"
        }
    } -Remote $true -Unavailable $(if (-not (Test-AWRemote) -and -not (Test-Path "$env:SystemRoot\System32\gpupdate.exe")) { 'gpupdate is not available on this edition of Windows' } else { '' })

    New-AWToolCard ([string][char]0xE72C) 'Restart Explorer' 'Restarts the Windows shell. Fixes a frozen taskbar or Start menu without signing out.' 'Restart' $false {
        Restart-AWExplorer
    }

    New-AWToolCard ([string][char]0xE7AC) 'Reset default apps' 'Removes custom default-app associations (DISM), then opens Default apps where Reset restores Microsoft defaults.' 'Reset' $true {
        if (-not (Confirm-AW "Remove the custom default app associations$(Get-AWWhere)?")) { return }
        Start-AWCommandTask 'Reset default app associations' { & dism.exe /Online /Remove-DefaultAppAssociations 2>&1; "AWEXIT $LASTEXITCODE" }
        if (-not (Test-AWRemote)) { Start-Process 'ms-settings:defaultapps' }
    } -Accent 'Purple' -Remote $true

    New-AWToolCard ([string][char]0xE74D) 'Junk file cleanup' 'Temp folders, error reports, crash dumps, update and Delivery Optimization caches live in the Cleaner.' 'Open Cleaner' $false {
        Select-AWView 'Cleaner'
    } -Remote $true

    New-AWToolCard ([string][char]0xE74D) 'Empty Recycle Bin' 'Permanently removes everything in the Recycle Bin on all drives.' 'Empty' $false {
        if (Confirm-AW 'Permanently empty the Recycle Bin on all drives?') {
            [void][AWiper.Native]::SHEmptyRecycleBin([IntPtr]::Zero, $null, 7)
            Write-AWLog 'Recycle Bin emptied'; Set-AWStatus 'Recycle Bin emptied'; Update-AWDashboard
        }
    } -Accent 'Purple'

    # ---------------- Repair
    Add-AWToolSection 'Repair'

    New-AWToolCard ([string][char]0xE9F5) 'System File Checker' 'Runs sfc /scannow to find and repair corrupted Windows system files. Takes 10-20 minutes.' 'Run SFC' $true {
        if (-not (Confirm-AW "Run System File Checker$(Get-AWWhere)? This can take 10-20 minutes.")) { return }
        Start-AWCommandTask 'System File Checker' { & sfc.exe /scannow 2>&1; "AWEXIT $LASTEXITCODE" }
    } -Remote $true

    New-AWToolCard ([string][char]0xE90F) 'Repair Windows image' 'DISM /RestoreHealth repairs the component store from Windows Update. Run it when SFC cannot fix files.' 'Run DISM' $true {
        if (-not (Confirm-AW "Run DISM RestoreHealth$(Get-AWWhere)? This can take 10-30 minutes and needs internet access.")) { return }
        Start-AWCommandTask 'DISM RestoreHealth' { & dism.exe /Online /Cleanup-Image /RestoreHealth /NoRestart 2>&1; "AWEXIT $LASTEXITCODE" }
    } -Accent 'Purple' -Remote $true

    New-AWToolCard ([string][char]0xE895) 'Reset Windows Update' 'Stops update services, renames SoftwareDistribution and catroot2, then restarts them. Fixes stuck updates.' 'Reset' $true {
        if (-not (Confirm-AW "Reset the Windows Update components$(Get-AWWhere)?`n`nUpdate history shown in Settings will be cleared; installed updates are not affected.")) { return }
        Start-AWCommandTask 'Reset Windows Update' {
            $svcs = @('wuauserv', 'bits', 'cryptsvc', 'msiserver')
            foreach ($s in $svcs) {
                try { Stop-Service -Name $s -Force -ErrorAction Stop; Write-WLog "Stopped $s" }
                catch { Write-WLog "Could not stop ${s}: $($_.Exception.Message)" 'WARN' }
            }
            foreach ($d in @("$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2")) {
                $old = "$d.old"
                if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction SilentlyContinue }
                try { Rename-Item -LiteralPath $d -NewName ((Split-Path $d -Leaf) + '.old') -ErrorAction Stop; Write-WLog "Renamed $d to $old" }
                catch { Write-WLog "Could not rename ${d}: $($_.Exception.Message)" 'WARN' }
            }
            [array]::Reverse($svcs)
            foreach ($s in $svcs) {
                try { Start-Service -Name $s -ErrorAction Stop; Write-WLog "Started $s" }
                catch { Write-WLog "Could not start ${s}: $($_.Exception.Message)" 'WARN' }
            }
            'AWEXIT 0'
        }
    } -Remote $true

    $ccm = "$env:SystemRoot\CCM\ccmrepair.exe"
    New-AWToolCard ([string][char]0xE7B8) 'Repair Software Center' 'Repairs the Configuration Manager (SCCM) client that powers Software Center. Runs in the background.' 'Repair' $true {
        if (-not (Confirm-AW "Start a Configuration Manager client repair$(Get-AWWhere)?")) { return }
        Start-AWCommandTask 'ConfigMgr client repair' {
            $exe = "$env:SystemRoot\CCM\ccmrepair.exe"
            if (Test-Path -LiteralPath $exe) {
                Start-Process -FilePath $exe
                'Repair started. Progress is logged to C:\Windows\CCM\Logs\ccmrepair.log and ccmsetup.log'
                'AWEXIT 0'
            } else { 'The ConfigMgr client is not installed on this computer'; 'AWEXIT 1' }
        }
    } -Accent 'Purple' -Remote $true -Unavailable $(if (-not (Test-AWRemote) -and -not (Test-Path -LiteralPath $ccm)) { 'The Configuration Manager client is not installed on this PC' } else { '' })

    # ---------------- Maintenance
    Add-AWToolSection 'Maintenance'

    New-AWToolCard ([string][char]0xE90F) 'Component store cleanup' 'Runs DISM /StartComponentCleanup to remove superseded Windows update components. Can take 5-15 minutes.' 'Run DISM' $true {
        if (-not (Confirm-AW "Run DISM component store cleanup$(Get-AWWhere)? This can take several minutes.")) { return }
        Start-AWCommandTask 'DISM component cleanup' { & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart 2>&1; "AWEXIT $LASTEXITCODE" }
    } -Remote $true

    New-AWToolCard ([string][char]0xE777) 'Create restore point' 'Saves a System Restore checkpoint before you make bigger changes. Windows allows one every 24 hours by default.' 'Create' $true {
        Start-AWRestorePoint
    } -Accent 'Purple' -Remote $true

    $hibDesc = 'Turns off hibernation and Fast Startup and deletes hiberfil.sys. Re-enable with powercfg /h on.'
    if (-not (Test-AWRemote)) {
        try { $hf = Get-Item -LiteralPath "$env:SystemDrive\hiberfil.sys" -Force -ErrorAction Stop; $hibDesc = "Frees $(Format-AWSize $hf.Length) by deleting hiberfil.sys. Also turns off Fast Startup. Undo: powercfg /h on." }
        catch { }
    }
    New-AWToolCard ([string][char]0xE708) 'Disable hibernation' $hibDesc 'Disable' $true {
        if (-not (Confirm-AW "Turn off hibernation$(Get-AWWhere)?`n`nThis also disables Fast Startup. Sleep is not affected.")) { return }
        Start-AWCommandTask 'Disable hibernation' { & powercfg.exe /hibernate off 2>&1; "AWEXIT $LASTEXITCODE" }
    } -Remote $true

    New-AWToolCard ([string][char]0xE7C3) 'Windows Disk Cleanup' 'Opens the built-in Disk Cleanup for anything AWiper does not cover, like old Windows installations.' 'Open' $false {
        Start-Process cleanmgr.exe
    }

    New-AWToolCard ([string][char]0xEB05) 'Storage Sense' 'Opens Windows Storage settings to schedule automatic cleanup of temp files and the Recycle Bin.' 'Open settings' $false {
        Start-Process 'ms-settings:storagesense'
    } -Accent 'Purple'

    New-AWToolCard ([string][char]0xE713) 'Refresh dashboard' 'Re-reads drive space and system information after big changes.' 'Refresh' $false {
        Update-AWDashboard; Initialize-AWMapDrives; Initialize-AWTools; Set-AWStatus 'Dashboard refreshed'
    }
}

$ui.LogClear.Add_Click({ $ui.LogBox.Clear() })
$ui.LogOpen.Add_Click({ Start-Process explorer.exe -ArgumentList "`"$script:DataDir`"" })
#endregion

#region ---------------------------------------------------------------- Recovery
$script:BinItems = @()
$script:RecDrives = @()
$script:RecLoadedTabs = @{}
$script:SnapRoot = Join-Path $script:DataDir 'Snapshots'
$script:ShadowLiveRoot = ''
$script:DeepSource = $null
$script:WinfrPath = $null
$script:DeepRunning = $false
$Sync.WinfrPid = 0

# How likely a deep scan is to find anything on this drive, in plain words.
function Get-AWDriveVerdict($d) {
    if ($d.FS -eq 'ReFS') { return @{ Level = 'Bad'; Short = 'Not supported'; Text = "$($d.Drive) uses ReFS, which recovery tools don't support." } }
    # USB enclosures often hide the media type, so fall back to the model name.
    $isSsd = $d.Media -eq 'SSD' -or ($d.Media -ne 'HDD' -and $d.Model -match '\bSSD\b|NVMe')
    if ($d.Bus -in 'USB', 'SD', 'MMC') {
        if ($isSsd) { return @{ Level = 'Fair'; Short = 'Possible'; Text = "$($d.Drive) is an external SSD. Many of these pass TRIM through, so deleted data may already be erased - but it's worth a try." } }
        return @{ Level = 'Good'; Short = 'Good chance'; Text = "$($d.Drive) is removable media (USB stick, SD card or external disk), which normally isn't trimmed. Deleted files usually stay recoverable until the space is reused, so stop writing to it." }
    }
    if ($isSsd) {
        if ($d.Trim -eq $false) { return @{ Level = 'Fair'; Short = 'Possible'; Text = "$($d.Drive) is an SSD with TRIM turned off, so deleted data may still be on it." } }
        $trimNote = if ($d.Trim) { ' with TRIM on' } else { '' }
        return @{ Level = 'Bad'; Short = 'Unlikely'; Text = "$($d.Drive) is an SSD$trimNote. Windows tells the drive to erase deleted data, usually within minutes, so a deep scan rarely finds anything. Check the Recycle Bin and previous versions first." }
    }
    if ($d.Media -eq 'HDD') { return @{ Level = 'Good'; Short = 'Good chance'; Text = "$($d.Drive) is a hard disk. Deleted files stay recoverable until their space is reused, so stop writing to it." } }
    @{ Level = 'Fair'; Short = 'Unknown'; Text = "AWiper couldn't tell what kind of disk $($d.Drive) is, so recovery may or may not work." }
}

function Get-AWVerdictColors([string]$Level) {
    switch ($Level) {
        'Good'  { @{ Bg = '#163A44'; Border = '#2E8F86'; Fg = $script:Res.Teal } }
        'Bad'   { @{ Bg = '#3A1E28'; Border = '#8C3A4A'; Fg = $script:Res.Danger } }
        default { @{ Bg = '#3A2F1E'; Border = '#8C6A2E'; Fg = $script:Res.Amber } }
    }
}

function New-AWRecDriveCard($d) {
    $v = Get-AWDriveVerdict $d
    $c = Get-AWVerdictColors $v.Level
    $card = New-Object System.Windows.Controls.Border
    $card.Style = $window.FindResource('Card'); $card.Padding = '14,10'; $card.Margin = '0,0,12,0'; $card.MinWidth = 230
    $card.ToolTip = $v.Text
    $sp = New-Object System.Windows.Controls.StackPanel
    $head = New-Object System.Windows.Controls.StackPanel; $head.Orientation = 'Horizontal'
    [void]$head.Children.Add((New-AWText $d.Drive 16 $null 'Bold'))
    $lbl = New-AWText $(if ($d.Label) { $d.Label } else { 'Local Disk' }) 12.5 $script:Res.Muted; $lbl.Margin = '8,0,0,0'; $lbl.VerticalAlignment = 'Center'
    $lbl.MaxWidth = 120; $lbl.TextTrimming = 'CharacterEllipsis'
    [void]$head.Children.Add($lbl)
    $pill = New-Object System.Windows.Controls.Border
    $pill.Style = $window.FindResource('Pill'); $pill.Background = New-Brush $c.Bg; $pill.BorderBrush = New-Brush $c.Border
    $pill.Child = New-AWText $v.Short.ToUpper() 9 $c.Fg 'Bold'
    [void]$head.Children.Add($pill)
    [void]$sp.Children.Add($head)
    $kind = @($d.Media, $d.Bus | Where-Object { $_ -and $_ -ne 'Unspecified' }) -join ' / '
    if (-not $kind) { $kind = $d.Type }
    $meta = New-AWText ('{0} - {1} - {2}' -f $d.FS, (Format-AWSize $d.Size), $kind) 11.5 $script:Res.Dim
    $meta.Margin = '0,4,0,0'
    [void]$sp.Children.Add($meta)
    $card.Child = $sp
    $card
}

function Update-AWRecoveryDrives {
    Start-AWTask -Name 'Check drives for recovery' -Work {
        Invoke-WTarget { Get-WRecoveryDrives }
    } -OnComplete {
        param($Result)
        $script:RecDrives = @($Result | Where-Object { $_ })
        $ui.RecDrives.Children.Clear()
        foreach ($d in $script:RecDrives) { [void]$ui.RecDrives.Children.Add((New-AWRecDriveCard $d)) }
        Initialize-AWDeepSources
    }
}

# ---------------- Recycle Bin
function Update-AWBinView {
    $q = $ui.BinSearch.Text.Trim()
    $items = @(if ($q) { $script:BinItems | Where-Object { $_.Name -like "*$q*" -or $_.OriginalPath -like "*$q*" } } else { $script:BinItems })
    $ui.BinList.ItemsSource = $items
    [long]$sum = 0; foreach ($i in $items) { $sum += $i.Size }
    $ui.BinInfo.Text = '{0:N0} item(s) - {1}' -f $items.Count, (Format-AWSize $sum)
}

function Update-AWBinList {
    $ui.BinInfo.Text = 'Reading Recycle Bins...'
    Start-AWTask -Name 'Read Recycle Bin' -Work {
        foreach ($r in (Invoke-WTarget { Get-WRecycleItems })) {
            $e = New-Object AWiper.RecycleEntry
            $e.OriginalPath = [string]$r.OriginalPath; $e.IPath = [string]$r.IPath; $e.RPath = [string]$r.RPath
            $e.Name = Split-Path $e.OriginalPath -Leaf; $e.Folder = Split-Path $e.OriginalPath -Parent
            $e.Size = [long]$r.Size; $e.Deleted = [datetime]$r.Deleted; $e.IsDir = [bool]$r.IsDir; $e.Owner = [string]$r.Owner
            $e
        }
    } -OnComplete {
        param($Result)
        $script:BinItems = @($Result | Where-Object { $_ } | Sort-Object Deleted -Descending)
        Update-AWBinView
        if (-not $script:IsAdmin -and -not (Test-AWRemote)) { $ui.BinInfo.Text += ' - your items only (run as admin to see every user)' }
    }
}

function Start-AWBinRestore([string]$ToFolder) {
    $items = @($script:BinItems | Where-Object { $_.IsChecked })
    if ($items.Count -eq 0) { Show-AWMessage 'Check the items you want to restore first.'; return }
    $where = if ($ToFolder) { "to`n$ToFolder" } else { 'to their original locations' }
    $list = ($items | Select-Object -First 15 | ForEach-Object { "  - $($_.Name)" }) -join "`n"
    if ($items.Count -gt 15) { $list += "`n  ...and $($items.Count - 15) more" }
    if (-not (Confirm-AW "Restore $($items.Count) item(s) $where$(Get-AWWhere)?`n`n$list")) { return }
    $jobs = @($items | ForEach-Object {
        @{ IPath = $_.IPath; RPath = $_.RPath; Name = $_.Name; Dest = $(if ($ToFolder) { Join-Path $ToFolder $_.Name } else { $_.OriginalPath }) }
    })
    $ui.BinRestore.IsEnabled = $false; $ui.BinRestoreTo.IsEnabled = $false
    Start-AWTask -Name 'Restore from Recycle Bin' -Arguments @{ Jobs = $jobs } -Work {
        $i = 0; $ok = 0
        foreach ($j in $Jobs) {
            $Sync.Status = "Restoring $($j.Name)..."; $Sync.Progress = [int]($i * 100 / $Jobs.Count); $i++
            try {
                [void](Invoke-WTarget { param($a, $b, $c) Restore-WRecycleItem $a $b $c } -ArgumentList @($j.IPath, $j.RPath, $j.Dest))
                $ok++
            } catch { Write-WLog "Could not restore $($j.Name): $($_.Exception.Message)" 'ERROR' }
        }
        "Restored $ok of $($Jobs.Count) item(s)"
    } -OnComplete {
        param($r)
        $msg = @($r | Where-Object { $_ }) | Select-Object -Last 1
        $script:IdleStatus = if ($msg) { "$msg - see Activity log for details" } else { 'Restore finished - see Activity log' }
        Update-AWRecoveryButtons
        Update-AWBinList
    }
}

# ---------------- Previous versions (Volume Shadow Copies)
function Get-AWUniquePath([string]$Path, [string]$Suffix = 'restored') {
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $dir = Split-Path $Path -Parent; $base = [System.IO.Path]::GetFileNameWithoutExtension($Path); $ext = [System.IO.Path]::GetExtension($Path)
    $n = 1
    do { $p = Join-Path $dir ('{0} ({1}{2}){3}' -f $base, $Suffix, $(if ($n -gt 1) { " $n" } else { '' }), $ext); $n++ } while (Test-Path -LiteralPath $p)
    $p
}

# Snapshots are opened through directory symlinks under %LOCALAPPDATA%\AWiper\Snapshots.
# Only the links are ever removed (non-recursive delete of a reparse point), never their contents.
function Dismount-AWShadows {
    if (-not (Test-Path -LiteralPath $script:SnapRoot)) { return }
    foreach ($d in @(Get-ChildItem -LiteralPath $script:SnapRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            try { [System.IO.Directory]::Delete($d.FullName) } catch { Write-AWLog "Could not close snapshot link $($d.Name): $($_.Exception.Message)" 'WARN' }
        }
    }
}

function Mount-AWShadow($Shadow) {
    if (-not (Test-Path -LiteralPath $script:SnapRoot)) { New-Item -ItemType Directory -Path $script:SnapRoot -Force | Out-Null }
    $link = Join-Path $script:SnapRoot ('{0}_{1:yyyyMMdd-HHmmss}' -f $Shadow.Drive.TrimEnd(':'), $Shadow.Created)
    if (Test-Path -LiteralPath $link) { return $link }
    $out = & cmd.exe /c mklink /d "$link" "$($Shadow.Device)\" 2>&1
    if (-not (Test-Path -LiteralPath $link)) { throw "Could not open the snapshot: $out" }
    Write-AWLog "Opened snapshot of $($Shadow.Drive) from $($Shadow.CreatedText)"
    $link
}

function Update-AWShadowList {
    if (-not $script:IsAdmin) {
        $ui.ShadowNote.Text = 'Listing previous versions needs administrator rights. Use "Restart as admin" in the title bar.'
        $ui.ShadowList.ItemsSource = $null
        return
    }
    $ui.ShadowNote.Text = 'Looking for snapshots...'
    Start-AWTask -Name 'Read shadow copies' -Work {
        $vols = @{}
        foreach ($v in @(Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue)) { if ($v.DriveLetter) { $vols[[string]$v.DeviceID] = [string]$v.DriveLetter } }
        foreach ($s in @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)) {
            [pscustomobject]@{ Id = [string]$s.ID; Device = [string]$s.DeviceObject; Drive = [string]$vols[[string]$s.VolumeName]; Created = [datetime]$s.InstallDate }
        }
    } -OnComplete {
        param($Result)
        $now = Get-Date
        $list = @($Result | Where-Object { $_ -and $_.Drive } | Sort-Object Created -Descending | ForEach-Object {
            $days = [int]($now - $_.Created).TotalDays
            [pscustomobject]@{
                Id = $_.Id; Device = $_.Device; Drive = $_.Drive; Created = $_.Created
                CreatedText = $_.Created.ToString('ddd MMM d yyyy, h:mm tt')
                Age = if ($days -le 0) { 'Today' } elseif ($days -eq 1) { 'Yesterday' } else { "$days days ago" }
            }
        })
        $ui.ShadowList.ItemsSource = $list
        $ui.ShadowNote.Text = if ($list.Count) {
            "$($list.Count) snapshot(s). Windows makes them with restore points and big updates. Pick one, then open it or search it for deleted files."
        } else {
            'No snapshots found. Windows only keeps them when System Protection is turned on for a drive (usually just C:). Turn it on now so future deletions can be undone.'
        }
        if ($list.Count) { $ui.ShadowList.SelectedIndex = 0 }
    }
}

function Start-AWShadowFind {
    $s = $ui.ShadowList.SelectedItem
    if (-not $s) { Show-AWMessage 'Pick a snapshot on the left first.'; return }
    $folder = $ui.ShadowFolder.Text.Trim().TrimEnd('\')
    if ($folder -notmatch '^[A-Za-z]:') { Show-AWMessage 'Enter a full folder path, like C:\Users\you\Documents.'; return }
    if ($folder.Substring(0, 2) -ne $s.Drive) { Show-AWMessage "That folder is on $($folder.Substring(0, 2)), but the snapshot is of $($s.Drive). Pick a snapshot of the same drive."; return }
    try { $link = Mount-AWShadow $s } catch { Show-AWMessage $_.Exception.Message 'Error'; return }
    $rel = $folder.Substring(2).TrimStart('\')
    $snapFolder = if ($rel) { Join-Path $link $rel } else { $link }
    if (-not (Test-Path -LiteralPath $snapFolder)) { Show-AWMessage "$folder did not exist yet when this snapshot was taken."; return }
    $script:ShadowLiveRoot = $folder
    $ui.ShadowFind.IsEnabled = $false
    $ui.ShadowInfo.Text = 'Comparing the snapshot with the folder as it is now...'
    Start-AWTask -Name 'Find deleted files in snapshot' -Arguments @{ SnapFolder = $snapFolder; LiveFolder = $folder; Changed = [bool]$ui.ShadowChanged.IsChecked } -Work {
        $found = 0; $seen = 0
        foreach ($f in @(Get-ChildItem -LiteralPath $SnapFolder -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $seen++
            if ($seen % 500 -eq 0) { $Sync.Status = "Compared $seen files, $found found..." }
            $live = Join-Path $LiveFolder $f.FullName.Substring($SnapFolder.Length).TrimStart('\')
            $status = $null
            if (-not [System.IO.File]::Exists($live)) { $status = 'Deleted' }
            elseif ($Changed -and [System.IO.File]::GetLastWriteTimeUtc($live) -ne $f.LastWriteTimeUtc) { $status = 'Changed' }
            if (-not $status) { continue }
            $e = New-Object AWiper.FileEntry
            $e.Name = $f.Name; $e.FullPath = $f.FullName; $e.Folder = Split-Path $live -Parent; $e.Size = $f.Length
            $e.Modified = $f.LastWriteTime; $e.Extension = $f.Extension; $e.Status = $status; $e.IsChecked = ($status -eq 'Deleted')
            $e
            $found++
            if ($found -ge 20000) { Write-WLog 'Stopped at 20,000 results - narrow the folder to see more' 'WARN'; break }
        }
        Write-WLog "Snapshot compare: $seen file(s) checked, $found difference(s)"
    } -OnComplete {
        param($Result)
        $items = @($Result | Where-Object { $_ -is [AWiper.FileEntry] } | Sort-Object Folder, Name)
        $ui.ShadowResults.ItemsSource = $items
        $del = @($items | Where-Object { $_.Status -eq 'Deleted' }).Count
        $ui.ShadowInfo.Text = if ($items.Count) { "$del deleted, $($items.Count - $del) changed since the snapshot." } else { 'Nothing is missing - every file in the snapshot still exists here.' }
        $ui.ShadowFind.IsEnabled = $true
    }
}

function Start-AWShadowCopy([string]$ToFolder) {
    $items = @(@($ui.ShadowResults.ItemsSource) | Where-Object { $_ -and $_.IsChecked })
    if ($items.Count -eq 0) { Show-AWMessage 'Check the files you want back first.'; return }
    $s = $ui.ShadowList.SelectedItem
    $stamp = if ($s) { $s.Created.ToString('yyyy-MM-dd') } else { 'snapshot' }
    $jobs = @($items | ForEach-Object {
        if ($ToFolder) {
            $rel = $_.Folder.Substring([Math]::Min($script:ShadowLiveRoot.Length, $_.Folder.Length)).TrimStart('\')
            $dest = Join-Path (Join-Path $ToFolder $rel) $_.Name
        } elseif ($_.Status -eq 'Changed') {
            $dest = Join-Path $_.Folder ('{0} ({1}){2}' -f [System.IO.Path]::GetFileNameWithoutExtension($_.Name), $stamp, [System.IO.Path]::GetExtension($_.Name))
        } else { $dest = Join-Path $_.Folder $_.Name }
        @{ Src = $_.FullPath; Dest = $dest }
    })
    $where = if ($ToFolder) { "to`n$ToFolder" } else { 'back to their folders (older versions of changed files are saved next to the current file with the snapshot date in the name)' }
    if (-not (Confirm-AW "Copy $($items.Count) file(s) $where?`n`nNothing is overwritten.")) { return }
    Start-AWTask -Name 'Restore from snapshot' -Arguments @{ Jobs = $jobs } -Work {
        $i = 0; $ok = 0
        foreach ($j in $Jobs) {
            $Sync.Progress = [int]($i * 100 / $Jobs.Count); $i++
            try {
                $dest = $j.Dest
                if (Test-Path -LiteralPath $dest) {
                    $dir = Split-Path $dest -Parent; $b = [System.IO.Path]::GetFileNameWithoutExtension($dest); $x = [System.IO.Path]::GetExtension($dest); $n = 1
                    do { $dest = Join-Path $dir ('{0} (restored{1}){2}' -f $b, $(if ($n -gt 1) { " $n" } else { '' }), $x); $n++ } while (Test-Path -LiteralPath $dest)
                }
                $dir = Split-Path $dest -Parent
                if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                [System.IO.File]::Copy($j.Src, $dest, $false)
                Write-WLog "Restored $dest"; $ok++
            } catch { Write-WLog "Could not restore $($j.Src): $($_.Exception.Message)" 'ERROR' }
        }
        "Restored $ok of $($Jobs.Count) file(s) from the snapshot"
    } -OnComplete {
        param($r)
        $msg = @($r | Where-Object { $_ }) | Select-Object -Last 1
        $script:IdleStatus = if ($msg) { "$msg - see Activity log" } else { 'Restore finished - see Activity log' }
    }
}

# ---------------- Deep scan (Windows File Recovery front-end)
function Update-AWWinfrStatus {
    $cmd = Get-Command winfr.exe -ErrorAction SilentlyContinue
    $script:WinfrPath = if ($cmd) { $cmd.Source } else { $null }
    if ($script:WinfrPath) {
        $ui.WinfrStatus.Text = 'Windows File Recovery is installed and ready.'
        $ui.WinfrBox.Background = New-Brush '#163A44'; $ui.WinfrBox.BorderBrush = New-Brush '#2E8F86'
        $ui.WinfrInstall.Visibility = 'Collapsed'; $ui.WinfrStore.Visibility = 'Collapsed'
    } else {
        $ui.WinfrStatus.Text = "Deep scan uses Windows File Recovery, Microsoft's free recovery tool. It isn't installed yet. Install it to a drive other than the one you want to recover from if you can."
        $ui.WinfrBox.Background = New-Brush '#3A2F1E'; $ui.WinfrBox.BorderBrush = New-Brush '#8C6A2E'
        $ui.WinfrInstall.Visibility = 'Visible'; $ui.WinfrStore.Visibility = 'Visible'
    }
    Update-AWDeep
}

function Initialize-AWDeepSources {
    $ui.DeepSources.Children.Clear()
    $prev = if ($script:DeepSource) { $script:DeepSource.Drive } else { $null }
    $script:DeepSource = $null
    foreach ($d in $script:RecDrives) {
        $rb = New-Object System.Windows.Controls.RadioButton
        $rb.Style = $window.FindResource('SegBtn'); $rb.GroupName = 'DeepSrc'; $rb.Margin = '0,0,8,8'; $rb.Tag = $d
        $rb.BorderBrush = $window.FindResource('LineBrush')
        $rb.Content = '{0}  {1}' -f $d.Drive, $(if ($d.Label) { $d.Label } else { $d.FS })
        $rb.ToolTip = (Get-AWDriveVerdict $d).Text
        $rb.Add_Checked({ param($s, $e) $script:DeepSource = $s.Tag; Update-AWDeep })
        $wrap = New-Object System.Windows.Controls.Border
        $wrap.Background = $window.FindResource('FieldBrush'); $wrap.BorderBrush = $window.FindResource('LineBrush')
        $wrap.BorderThickness = 1; $wrap.CornerRadius = 10; $wrap.Padding = 3; $wrap.Margin = '0,0,8,8'
        $rb.Margin = 0; $wrap.Child = $rb
        [void]$ui.DeepSources.Children.Add($wrap)
        if ($d.Drive -eq $prev) { $rb.IsChecked = $true }
    }
    Update-AWDeep
}

# Quote one argument for a Windows command line (backslashes before a closing quote are doubled).
function Format-AWArg([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    '"' + ($Value -replace '(\\+)$', '$1$1') + '"'
}

function Get-AWDeepArgs {
    $src = $script:DeepSource
    $dest = $ui.DeepDest.Text.Trim()
    if (-not $src) { return $null }
    $d = if ($dest -match '^[A-Za-z]:\\?$') { $dest.Substring(0, 2) } else { $dest.TrimEnd('\') }
    $a = @($src.Drive, (Format-AWArg $(if ($d) { $d } else { 'X:\Recovered' })), $(if ($ui.DeepExtensive.IsChecked) { '/extensive' } else { '/regular' }))
    foreach ($f in @($ui.DeepFilter.Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $a += '/n'; $a += (Format-AWArg $f) }
    $a + '/a'
}

function Update-AWDeep {
    if (-not $ui.DeepCmd) { return }
    $src = $script:DeepSource
    $ext = [bool]$ui.DeepExtensive.IsChecked
    $hint = if ($ext) { 'Thorough scan for USB sticks, SD cards (FAT/exFAT), formatted or damaged drives and older deletions. Slower.' }
            else { 'Fast scan for files deleted recently from an NTFS drive.' }
    if ($src -and -not $ext -and $src.FS -ne 'NTFS') { $hint += " $($src.Drive) is $($src.FS) - use Extensive for it." }
    $ui.DeepModeHint.Text = $hint

    $ok = [bool]$src
    $dest = $ui.DeepDest.Text.Trim()
    $msg = ''
    if ($dest) {
        if ($dest -notmatch '^[A-Za-z]:\\?' -and $dest -notmatch '^\\\\') { $msg = 'Enter a full path, like E:\Recovered.'; $ok = $false }
        elseif ($src) {
            $sv = [AWiper.Native]::VolumeId("$($src.Drive)\")
            $dv = [AWiper.Native]::VolumeId($dest)
            if ($sv -and $dv -and $sv -eq $dv) { $msg = "That folder is on $($src.Drive), the drive you're scanning. Saving there could overwrite the files you're trying to get back. Pick a folder on a different drive."; $ok = $false }
        }
    } else { $ok = $false }
    $ui.DeepDestMsg.Text = $msg
    $ui.DeepDestMsg.Foreground = $script:Res.Danger
    $ui.DeepDestMsg.Visibility = if ($msg) { 'Visible' } else { 'Collapsed' }

    $argv = Get-AWDeepArgs
    $ui.DeepCmd.Text = if ($argv) { 'winfr ' + ($argv -join ' ') } else { 'Pick a drive to scan.' }

    if ($src) {
        $v = Get-AWDriveVerdict $src; $c = Get-AWVerdictColors $v.Level
        $ui.DeepVerdict.Text = $v.Text; $ui.DeepVerdict.Foreground = $c.Fg
        $ui.DeepVerdictBox.Background = New-Brush $c.Bg; $ui.DeepVerdictBox.BorderBrush = New-Brush $c.Border
        $ui.DeepVerdictBox.Visibility = 'Visible'
    } else { $ui.DeepVerdictBox.Visibility = 'Collapsed' }

    $ui.DeepStart.IsEnabled = $ok -and [bool]$script:WinfrPath -and $script:IsAdmin -and -not $script:DeepRunning -and -not (Test-AWRemote)
    $ui.DeepStart.ToolTip = if (-not $script:IsAdmin) { 'Deep scan needs administrator rights.' } elseif (-not $script:WinfrPath) { 'Install Windows File Recovery first.' } else { $null }
    [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($ui.DeepStart, $true)
}

function Start-AWDeepScan {
    $src = $script:DeepSource
    $argv = Get-AWDeepArgs
    if (-not $src -or -not $argv) { return }
    $dest = $ui.DeepDest.Text.Trim()
    $v = Get-AWDriveVerdict $src
    $warn = if ($v.Level -eq 'Bad') { "`n`nHeads up: $($v.Text)" } else { '' }
    $filters = @($ui.DeepFilter.Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $what = if ($filters.Count) { $filters -join ', ' } else { 'everything it can find' }
    if (-not (Confirm-AW "Scan $($src.Drive) for $what and save results to $dest?$warn`n`nAvoid using $($src.Drive) until this finishes.")) { return }
    if (-not (Test-Path -LiteralPath $dest)) { try { New-Item -ItemType Directory -Path $dest -Force | Out-Null } catch { Show-AWMessage "Could not create $($dest): $($_.Exception.Message)" 'Error'; return } }

    $script:DeepRunning = $true
    $ui.DeepStop.IsEnabled = $true
    Update-AWDeep
    Start-AWTask -Name 'Windows File Recovery' -Arguments @{ Exe = $script:WinfrPath; ArgLine = ($argv -join ' ') } -Work {
        Write-WLog "winfr $ArgLine"
        $psi = New-Object System.Diagnostics.ProcessStartInfo($Exe, $ArgLine)
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $Sync.WinfrPid = $p.Id
        $p.StandardInput.Close()
        $errText = $p.StandardError.ReadToEndAsync()
        while ($null -ne ($line = $p.StandardOutput.ReadLine())) {
            $l = ($line -replace "`0", '').Trim()
            if (-not $l) { continue }
            if ($l -match '(\d+(\.\d+)?)\s*%') { $Sync.Progress = [int][double]$Matches[1]; $Sync.Status = "Windows File Recovery - $l"; continue }
            Write-WLog "winfr: $l"
        }
        $p.WaitForExit()
        $e = ($errText.Result -replace "`0", '').Trim()
        if ($e) { foreach ($x in ($e -split "`r?`n" | Where-Object { $_.Trim() })) { Write-WLog "winfr: $x" 'WARN' } }
        $Sync.WinfrPid = 0
        "Windows File Recovery finished (exit code $($p.ExitCode))"
    } -OnComplete {
        param($r)
        $script:DeepRunning = $false
        $ui.DeepStop.IsEnabled = $false
        Update-AWDeep
        $msg = @($r | Where-Object { $_ }) | Select-Object -Last 1
        $script:IdleStatus = if ($msg) { "$msg - see Activity log" } else { 'Windows File Recovery stopped - see Activity log' }
        if (Confirm-AW "Recovery finished. Open the destination folder?`n`nRecovered files are in a Recovery_<date> folder there.") { Open-AWExplorer $ui.DeepDest.Text.Trim() }
    }
}

# ---------------- Tabs, remote handling, wiring
function Update-AWRecoveryButtons {
    $remote = Test-AWRemote
    $ui.BinRestore.IsEnabled = $true
    $ui.BinRestoreTo.IsEnabled = -not $remote
    $ui.BinOpen.IsEnabled = -not $remote
    $ui.RecTabShadow.IsEnabled = -not $remote
    $ui.RecTabDeep.IsEnabled = -not $remote
    $tip = if ($remote) { 'Only available on this PC' } else { $null }
    foreach ($c in @($ui.RecTabShadow, $ui.RecTabDeep, $ui.BinRestoreTo, $ui.BinOpen)) {
        $c.ToolTip = $tip; [System.Windows.Controls.ToolTipService]::SetShowOnDisabled($c, $true)
    }
    if ($remote -and -not $ui.RecTabBin.IsChecked) { $ui.RecTabBin.IsChecked = $true }
}

function Show-AWRecoveryTab([string]$Tab) {
    $ui.RecPanelBin.Visibility    = if ($Tab -eq 'Bin')    { 'Visible' } else { 'Collapsed' }
    $ui.RecPanelShadow.Visibility = if ($Tab -eq 'Shadow') { 'Visible' } else { 'Collapsed' }
    $ui.RecPanelDeep.Visibility   = if ($Tab -eq 'Deep')   { 'Visible' } else { 'Collapsed' }
    if (-not $script:RecLoadedTabs[$Tab]) {
        $script:RecLoadedTabs[$Tab] = $true
        if ($Tab -eq 'Shadow') { Update-AWShadowList }
        if ($Tab -eq 'Deep')   { Update-AWWinfrStatus }
    }
}

function Initialize-AWRecovery {
    $script:RecLoadedTabs = @{ Bin = $true }
    $script:BinItems = @(); $ui.BinList.ItemsSource = $null
    if (-not $ui.ShadowFolder.Text) { $ui.ShadowFolder.Text = [Environment]::GetFolderPath('MyDocuments') }
    Update-AWRecoveryButtons
    Update-AWRecoveryDrives
    Update-AWBinList
    if ($ui.RecTabShadow.IsChecked) { Show-AWRecoveryTab 'Shadow' } elseif ($ui.RecTabDeep.IsChecked) { Show-AWRecoveryTab 'Deep' }
}

$ui.RecTabBin.Add_Checked({ Show-AWRecoveryTab 'Bin' })
$ui.RecTabShadow.Add_Checked({ Show-AWRecoveryTab 'Shadow' })
$ui.RecTabDeep.Add_Checked({ Show-AWRecoveryTab 'Deep' })

$ui.BinSearch.Add_TextChanged({ Update-AWBinView })
$ui.BinRefresh.Add_Click({ Update-AWBinList })
$ui.BinRestore.Add_Click({ Start-AWBinRestore '' })
$ui.BinRestoreTo.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Restore the checked items into this folder'
    if ($dlg.ShowDialog() -eq 'OK') { Start-AWBinRestore $dlg.SelectedPath }
})
$ui.BinOpen.Add_Click({
    $i = $ui.BinList.SelectedItem
    if (-not $i) { Show-AWMessage 'Select an item first.'; return }
    if (Test-Path -LiteralPath $i.Folder) { Open-AWExplorer $i.Folder } else { Show-AWMessage "$($i.Folder) no longer exists. Restoring the item will recreate it." }
})

$ui.ShadowRefresh.Add_Click({ Update-AWShadowList })
$ui.ShadowFind.Add_Click({ Start-AWShadowFind })
$ui.ShadowFolder.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $e.Handled = $true; Start-AWShadowFind } })
$ui.ShadowRestore.Add_Click({ Start-AWShadowCopy '' })
$ui.ShadowCopyTo.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Copy the checked files into this folder (subfolders are kept)'
    if ($dlg.ShowDialog() -eq 'OK') { Start-AWShadowCopy $dlg.SelectedPath }
})
$ui.ShadowExplore.Add_Click({
    $s = $ui.ShadowList.SelectedItem
    if (-not $s) { Show-AWMessage 'Pick a snapshot first.'; return }
    try { Open-AWExplorer (Mount-AWShadow $s) } catch { Show-AWMessage $_.Exception.Message 'Error' }
})
$ui.ShadowProtect.Add_Click({ Start-Process SystemPropertiesProtection.exe })

$ui.WinfrInstall.Add_Click({
    $ui.WinfrInstall.IsEnabled = $false
    $ui.WinfrStatus.Text = 'Installing Windows File Recovery from the Microsoft Store...'
    Start-AWTask -Name 'Install Windows File Recovery' -Work {
        & winget.exe install --id 9N26S50LN705 --source msstore --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | ForEach-Object {
            $l = ("$_" -replace "`0", '').Trim()
            if ($l -and $l -notmatch '^[\s\-\\|/]+$' -and $l -notmatch '[\u2580-\u259F]') { Write-WLog "winget: $l" }
        }
        "winget exit code $LASTEXITCODE"
    } -OnComplete {
        param($r)
        $ui.WinfrInstall.IsEnabled = $true
        Update-AWWinfrStatus
        if (-not $script:WinfrPath) {
            if (Confirm-AW "Windows File Recovery didn't install automatically (see the Activity log). Open its Microsoft Store page instead?") { Start-Process 'ms-windows-store://pdp/?productid=9N26S50LN705' }
        }
    }
})
$ui.WinfrStore.Add_Click({ Start-Process 'ms-windows-store://pdp/?productid=9N26S50LN705' })
$ui.DeepBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Save recovered files here (must be on a different drive)'
    $dlg.ShowNewFolderButton = $true
    if ($dlg.ShowDialog() -eq 'OK') { $ui.DeepDest.Text = $dlg.SelectedPath }
})
$ui.DeepDest.Add_TextChanged({ Update-AWDeep })
$ui.DeepFilter.Add_TextChanged({ Update-AWDeep })
$ui.DeepRegular.Add_Checked({ Update-AWDeep })
$ui.DeepExtensive.Add_Checked({ Update-AWDeep })
$ui.DeepStart.Add_Click({ Start-AWDeepScan })
$ui.DeepStop.Add_Click({
    if ($Sync.WinfrPid -and (Confirm-AW 'Stop Windows File Recovery? Files recovered so far stay in the destination folder.')) {
        Stop-Process -Id $Sync.WinfrPid -Force -ErrorAction SilentlyContinue
        Write-AWLog 'Windows File Recovery stopped by user' 'WARN'
    }
})
$ui.DeepOpenDest.Add_Click({
    $d = $ui.DeepDest.Text.Trim()
    if ($d -and (Test-Path -LiteralPath $d)) { Open-AWExplorer $d } else { Show-AWMessage 'The destination folder does not exist yet.' }
})
#endregion

#region ---------------------------------------------------------------- Column sorting
function Enable-AWSort($ListView, [hashtable]$Map) {
    $ListView.Tag = $Map
    $ListView.AddHandler([System.Windows.Controls.GridViewColumnHeader]::ClickEvent, [System.Windows.RoutedEventHandler]{
        param($s, $e)
        $h = $e.OriginalSource
        if ($h -isnot [System.Windows.Controls.GridViewColumnHeader] -or -not $h.Column) { return }
        $prop = $s.Tag[[string]$h.Column.Header]
        if (-not $prop -or -not $s.ItemsSource) { return }
        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($s.ItemsSource)
        if (-not $view) { return }
        $dir = [System.ComponentModel.ListSortDirection]::Descending
        if ($view.SortDescriptions.Count -gt 0 -and $view.SortDescriptions[0].PropertyName -eq $prop -and
            $view.SortDescriptions[0].Direction -eq [System.ComponentModel.ListSortDirection]::Descending) {
            $dir = [System.ComponentModel.ListSortDirection]::Ascending
        }
        $view.SortDescriptions.Clear()
        $view.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription($prop, $dir)))
    })
}
Enable-AWSort $ui.LargeList    @{ Name = 'Name'; Size = 'Size'; Type = 'Extension'; Modified = 'Modified'; Folder = 'Folder' }
Enable-AWSort $ui.ProgList     @{ Name = 'Name'; Publisher = 'Publisher'; Version = 'Version'; Installed = 'Installed'; Size = 'SizeBytes'; Scope = 'Scope' }
Enable-AWSort $ui.StartupList  @{ Name = 'Name'; Scope = 'Scope'; Source = 'Location'; Status = 'Enabled' }
Enable-AWSort $ui.CleanResults @{ Item = 'Name'; Group = 'Group'; Size = 'Bytes' }
Enable-AWSort $ui.AppList      @{ App = 'Name'; Category = 'Category'; Notes = 'Note' }
Enable-AWSort $ui.BinList      @{ Name = 'Name'; Type = 'Kind'; Size = 'Size'; Deleted = 'Deleted'; 'Deleted by' = 'Owner'; 'Original location' = 'Folder' }
Enable-AWSort $ui.ShadowResults @{ Name = 'Name'; Status = 'Status'; Size = 'Size'; Modified = 'Modified'; Folder = 'Folder' }
#endregion

#region ---------------------------------------------------------------- Startup + run
$window.Add_Loaded({
    try {
        Update-AWDashboard
        Initialize-AWCleaner
        Initialize-AWMapDrives
        Initialize-AWTools
        Initialize-AWTweaks
        Dismount-AWShadows   # links left behind by a previous session that didn't close cleanly
    } catch { Write-AWLog "Startup: $($_.Exception.Message)" 'ERROR' }
    $script:Timer.Start()
    Write-AWLog ("AWiper {0} started - {1} - PowerShell {2}" -f $script:AppVersion, $(if ($script:IsAdmin) { 'administrator' } else { 'standard user' }), $PSVersionTable.PSVersion)
    if ($script:ElevationNote) { Write-AWLog $script:ElevationNote 'WARN' }
    $script:IdleStatus = if ($script:IsAdmin) { 'Ready - running as administrator' } else { 'Ready - standard permissions (admin-only items are disabled)' }
    Set-AWStatus $script:IdleStatus
})

$window.Add_Closing({
    if ($script:Scanner) { $script:Scanner.Cancel = $true }
    if ($Sync.WinfrPid) { Stop-Process -Id $Sync.WinfrPid -Force -ErrorAction SilentlyContinue }
    Dismount-AWShadows
    $script:Timer.Stop()
    Update-AWLogView
    foreach ($j in $script:Jobs) { try { $j.PS.Stop(); $j.PS.Dispose(); $j.Runspace.Dispose() } catch { } }
})

$window.Dispatcher.Add_UnhandledException({
    param($s, $e)
    Write-AWLog "Unhandled: $($e.Exception.Message)" 'ERROR'
    $e.Handled = $true
})

try {
    [void]$window.ShowDialog()
}
catch {
    $msg = "AWiper hit an error and has to close:`n`n$($_.Exception.Message)"
    try { Add-Content -LiteralPath $script:LogFile -Value ("{0:HH:mm:ss}  FATAL  {1}" -f (Get-Date), $_.Exception.ToString()) } catch { }
    [void][System.Windows.MessageBox]::Show($msg, 'AWiper', 'OK', 'Error')
}
#endregion
