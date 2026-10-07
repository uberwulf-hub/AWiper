<#
.SYNOPSIS
    AWiper - system cleanup and disk space analyzer with a WPF interface.

.DESCRIPTION
    AWiper bundles the most useful parts of tools like CCleaner and SpaceMonger:

      * Dashboard    - drive usage gauges, system summary, quick actions
      * Cleaner      - analyze / clean temp files, caches, update leftovers, dumps, recycle bin
      * Space Map    - SpaceMonger-style nested treemap of any drive or folder (drill down, recycle)
      * Large Files  - the 1,000 largest files from the last scan, searchable, recycle or export
      * Startup      - enable / disable startup entries (same StartupApproved switches Task Manager uses)
      * Programs     - installed software list with size, search and uninstall
      * Tools        - DNS flush, component store cleanup, restore point, Explorer restart, activity log

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
    Version : 1.0.0
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
$script:AppVersion = '1.0.0'

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
        public string SizeText { get { return Fmt.Size(Size); } }
        public string ModifiedText { get { return Modified == DateTime.MinValue ? "" : Modified.ToString("yyyy-MM-dd HH:mm"); } }
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

    public static class Native
    {
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern int SHEmptyRecycleBin(IntPtr hwnd, string root, uint flags);

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

$script:State = @{ TotalFreed = [long]0; Cleans = 0; LastClean = '' }
try {
    if (Test-Path -LiteralPath $script:StateFile) {
        $j = Get-Content -LiteralPath $script:StateFile -Raw | ConvertFrom-Json
        $script:State.TotalFreed = [long]$j.TotalFreed
        $script:State.Cleans     = [int]$j.Cleans
        $script:State.LastClean  = if ($j.LastClean -is [datetime]) { $j.LastClean.ToString('o') } else { [string]$j.LastClean }
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
    $Sync.Log.Enqueue(('{0:HH:mm:ss}  {1,-5}  {2}' -f (Get-Date), $Level, $Message))
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
    Write-WLog ("{0}: removed {1} file(s), {2}" -f $Item.Name, $res.Files, [AWiper.Fmt]::Size($res.Bytes))
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
              <TextBlock Text="SYSTEM" Style="{StaticResource Caps}" Margin="8,16,0,6"/>
              <RadioButton x:Name="NavStartup"  Style="{StaticResource NavBtn}" Tag="&#xE7E8;" Content="Startup"/>
              <RadioButton x:Name="NavPrograms" Style="{StaticResource NavBtn}" Tag="&#xE71D;" Content="Programs"/>
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

          <!-- ===== Tools ===== -->
          <Grid x:Name="ViewTools" Visibility="Collapsed">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <WrapPanel x:Name="ToolCards"/>
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
    Home = 'Dashboard'; Cleaner = 'Cleaner'; Map = 'Space Map'; Large = 'Large Files'
    Startup = 'Startup'; Programs = 'Programs'; Tools = 'Tools and Activity Log'
}
$script:Loaded = @{}

foreach ($v in $script:ViewTitles.Keys) {
    $ui["Nav$v"].Add_Checked({
        param($s, $e)
        $name = $s.Name.Substring(3)
        foreach ($k in $script:ViewTitles.Keys) { $ui["View$k"].Visibility = if ($k -eq $name) { 'Visible' } else { 'Collapsed' } }
        $ui.ViewTitle.Text = $script:ViewTitles[$name]
        if (-not $script:Loaded[$name]) {
            $script:Loaded[$name] = $true
            switch ($name) {
                'Startup'  { Update-AWStartupList }
                'Programs' { Update-AWProgramList }
            }
        }
        if ($name -eq 'Map') { Request-AWMapRedraw }
    })
}

function Select-AWView([string]$Name) { $ui["Nav$Name"].IsChecked = $true }

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
        $allowed = $script:IsAdmin -or -not $rule.Admin
        $cb.IsEnabled = $allowed
        $cb.IsChecked = $rule.Default -and $allowed
        $cb.ToolTip = $rule.Desc

        $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation = 'Horizontal'
        [void]$sp.Children.Add((New-AWText $rule.Name 13))
        if ($rule.Admin) {
            $pill = New-Object System.Windows.Controls.Border
            $pill.Style = $window.FindResource('Pill')
            $pill.BorderBrush = if ($script:IsAdmin) { New-Brush '#4A5680' } else { New-Brush '#8C6A2E' }
            $pill.Child = New-AWText 'ADMIN' 9 $(if ($script:IsAdmin) { $script:Res.Muted } else { $script:Res.Amber }) 'Bold'
            [void]$sp.Children.Add($pill)
        }
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
    foreach ($cb in $script:CleanerChecks) { if ($script:IsAdmin -or -not $cb.Tag.Admin) { $cb.IsEnabled = -not $Busy } }
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
            try { Measure-WItem $rule }
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
    if (-not (Confirm-AW "AWiper will permanently delete the files matched by these rules:`n`n$names`n`nFiles that are in use are skipped. Continue?")) { return }
    Set-AWCleanerBusy $true
    $ui.CleanSummary.Text = 'Cleaning...'
    $ui.CleanSubtext.Text = 'Removing files. Locked files are skipped automatically.'
    $ui.CleanProgress.Value = 0
    Start-AWTask -Name 'Clean' -Arguments @{ Rules = $rules } -Work {
        $i = 0
        foreach ($rule in $Rules) {
            $Sync.Status = "Cleaning: $($rule.Name)"
            $Sync.Progress = [int]($i * 100 / $Rules.Count)
            try { Invoke-WClean $rule }
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
    $items = if ($q) {
        @($all | Where-Object { $_.Name -like "*$q*" -or $_.Folder -like "*$q*" -or $_.Extension -like "*$q*" })
    } else { @($all) }
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
    $items = if ($q) { @($script:Programs | Where-Object { $_.Name -like "*$q*" -or $_.Publisher -like "*$q*" }) } else { @($script:Programs) }
    $ui.ProgList.ItemsSource = $items
    [long]$sum = 0; foreach ($p in $items) { $sum += $p.SizeBytes }
    $ui.ProgInfo.Text = '{0:N0} programs - {1} reported size' -f $items.Count, (Format-AWSize $sum)
}

function Update-AWProgramList {
    $ui.ProgInfo.Text = 'Loading installed programs...'
    $ui.ProgRefresh.IsEnabled = $false
    Start-AWTask -Name 'Read installed programs' -Work {
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
                $size = if ($e.EstimatedSize) { [long]$e.EstimatedSize * 1KB } else { [long]0 }
                [pscustomobject]@{
                    Name = $e.DisplayName; Publisher = $e.Publisher; Version = $e.DisplayVersion; Installed = $installed
                    SizeBytes = $size; SizeText = $(if ($size) { [AWiper.Fmt]::Size($size) } else { '' })
                    Scope = $src.S; Uninstall = $e.UninstallString; Location = $e.InstallLocation
                }
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

#region ---------------------------------------------------------------- Tools
function New-AWToolCard {
    param([string]$Glyph, [string]$Title, [string]$Desc, [string]$ButtonText, [bool]$Admin, [scriptblock]$Action, [string]$Accent = 'Teal')
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
    if ($Admin) {
        $pill = New-Object System.Windows.Controls.Border
        $pill.Style = $window.FindResource('Pill')
        $pill.BorderBrush = if ($script:IsAdmin) { New-Brush '#4A5680' } else { New-Brush '#8C6A2E' }
        $pill.Child = New-AWText 'ADMIN' 9 $(if ($script:IsAdmin) { $script:Res.Muted } else { $script:Res.Amber }) 'Bold'
        [void]$head.Children.Add($pill)
    }
    [void]$sp.Children.Add($head)

    $d = New-AWText $Desc 12.5 $script:Res.Muted; $d.TextWrapping = 'Wrap'; $d.Margin = '0,10,0,14'; $d.Height = 52
    [void]$sp.Children.Add($d)

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = $ButtonText; $btn.Style = $window.FindResource('BtnChip'); $btn.HorizontalAlignment = 'Left'
    $btn.Tag = $Action
    $btn.IsEnabled = $script:IsAdmin -or -not $Admin
    $btn.Add_Click({ param($s, $e) try { & $s.Tag } catch { Show-AWMessage $_.Exception.Message 'Error' } })
    [void]$sp.Children.Add($btn)
    $card.Child = $sp
    [void]$ui.ToolCards.Children.Add($card)
}

function Initialize-AWTools {
    $ui.ToolCards.Children.Clear()

    New-AWToolCard ([string][char]0xE774) 'Flush DNS cache' 'Clears cached name lookups. Handy after DNS or hosts-file changes.' 'Flush now' $false {
        $out = (& ipconfig.exe /flushdns) -join ' '
        Write-AWLog "ipconfig /flushdns: $($out.Trim())"
        Set-AWStatus 'DNS resolver cache flushed'
    }

    New-AWToolCard ([string][char]0xE74D) 'Empty Recycle Bin' 'Permanently removes everything in the Recycle Bin on all drives.' 'Empty' $false {
        if (Confirm-AW 'Permanently empty the Recycle Bin on all drives?') {
            [void][AWiper.Native]::SHEmptyRecycleBin([IntPtr]::Zero, $null, 7)
            Write-AWLog 'Recycle Bin emptied'; Set-AWStatus 'Recycle Bin emptied'; Update-AWDashboard
        }
    } -Accent 'Purple'

    New-AWToolCard ([string][char]0xE90F) 'Component store cleanup' 'Runs DISM /StartComponentCleanup to remove superseded Windows update components. Can take 5-15 minutes.' 'Run DISM' $true {
        if (-not (Confirm-AW 'Run DISM component store cleanup now? This can take several minutes.')) { return }
        Start-AWTask -Name 'DISM component cleanup' -Work {
            $Sync.Status = 'DISM /Online /Cleanup-Image /StartComponentCleanup running...'
            & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart 2>&1 | ForEach-Object {
                $l = "$_".Trim()
                if ($l -and $l -notmatch '^\[=*') { Write-WLog "DISM: $l" }
                if ($l -match '(\d+(\.\d+)?)%') { $Sync.Progress = [int][double]$Matches[1] }
            }
            Write-WLog "DISM exit code $LASTEXITCODE"
        } -OnComplete { param($r) $script:IdleStatus = 'Component store cleanup finished - see Activity log'; Update-AWDashboard }
    }

    New-AWToolCard ([string][char]0xE777) 'Create restore point' 'Saves a System Restore checkpoint before you make bigger changes. Windows allows one every 24 hours by default.' 'Create' $true {
        Start-AWTask -Name 'Create restore point' -Work {
            $Sync.Status = 'Creating System Restore point...'
            try {
                $r = Invoke-CimMethod -Namespace root/default -ClassName SystemRestore -MethodName CreateRestorePoint `
                     -Arguments @{ Description = 'AWiper checkpoint'; RestorePointType = [uint32]12; EventType = [uint32]100 } -ErrorAction Stop
                if ($r.ReturnValue -eq 0) { Write-WLog 'Restore point created' }
                else { Write-WLog "Restore point returned code $($r.ReturnValue) (System Protection may be off for this drive)" 'WARN' }
            } catch { Write-WLog "Restore point failed: $($_.Exception.Message)" 'ERROR' }
        } -OnComplete { param($r) $script:IdleStatus = 'Restore point request finished - see Activity log' }
    } -Accent 'Purple'

    New-AWToolCard ([string][char]0xE72C) 'Restart Explorer' 'Restarts the Windows shell. Fixes a frozen taskbar or Start menu without signing out.' 'Restart' $false {
        Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 1200
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
        Write-AWLog 'Explorer restarted'; Set-AWStatus 'Explorer restarted'
    }

    New-AWToolCard ([string][char]0xE7C3) 'Windows Disk Cleanup' 'Opens the built-in Disk Cleanup for anything AWiper does not cover, like old Windows installations.' 'Open' $false {
        Start-Process cleanmgr.exe
    }

    New-AWToolCard ([string][char]0xEB05) 'Storage Sense' 'Opens Windows Storage settings to schedule automatic cleanup of temp files and the Recycle Bin.' 'Open settings' $false {
        Start-Process 'ms-settings:storagesense'
    } -Accent 'Purple'

    New-AWToolCard ([string][char]0xE713) 'Refresh dashboard' 'Re-reads drive space and system information after big changes.' 'Refresh' $false {
        Update-AWDashboard; Initialize-AWMapDrives; Set-AWStatus 'Dashboard refreshed'
    }
}

$ui.LogClear.Add_Click({ $ui.LogBox.Clear() })
$ui.LogOpen.Add_Click({ Start-Process explorer.exe -ArgumentList "`"$script:DataDir`"" })
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
#endregion

#region ---------------------------------------------------------------- Startup + run
$window.Add_Loaded({
    try {
        Update-AWDashboard
        Initialize-AWCleaner
        Initialize-AWMapDrives
        Initialize-AWTools
    } catch { Write-AWLog "Startup: $($_.Exception.Message)" 'ERROR' }
    $script:Timer.Start()
    Write-AWLog ("AWiper {0} started - {1} - PowerShell {2}" -f $script:AppVersion, $(if ($script:IsAdmin) { 'administrator' } else { 'standard user' }), $PSVersionTable.PSVersion)
    if ($script:ElevationNote) { Write-AWLog $script:ElevationNote 'WARN' }
    $script:IdleStatus = if ($script:IsAdmin) { 'Ready - running as administrator' } else { 'Ready - standard permissions (admin-only items are disabled)' }
    Set-AWStatus $script:IdleStatus
})

$window.Add_Closing({
    if ($script:Scanner) { $script:Scanner.Cancel = $true }
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
