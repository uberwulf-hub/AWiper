<#
.SYNOPSIS
    Checks AWiper's old-files finder on a throwaway folder (no admin needed): age and size limits,
    skipped developer folders, and archives flagged as already extracted.
#>
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\AWiper.ps1'),
    [string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'AWiperOldFilesTest')
)
$ErrorActionPreference = 'Stop'
$src = [IO.File]::ReadAllText($Path)
Add-Type -TypeDefinition ([regex]::Match($src, "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value)
$Sync = [hashtable]::Synchronized(@{}); $Sync.Log = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'; $Target = $null
. ([scriptblock]::Create([regex]::Match($src, "\`$Sync.WorkerLib = @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value))
$fail = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fail++ } }

if (Test-Path $Work) { [IO.Directory]::Delete($Work, $true) }
New-Item -ItemType Directory "$Work\photos\.git", "$Work\node_modules", "$Work\setup-tool" -Force | Out-Null
$old = (Get-Date).AddDays(-400)
function Mk($p, $kb, $when) { [IO.File]::WriteAllBytes($p, (New-Object byte[] ($kb * 1KB))); $i = Get-Item $p; $i.LastWriteTime = $when; $i.LastAccessTime = $when }
Mk "$Work\old-installer.exe" 2048 $old
Mk "$Work\setup-tool.zip" 2048 $old
Mk "$Work\keep.zip" 2048 $old
Mk "$Work\photos\holiday.jpg" 2048 $old
Mk "$Work\photos\.git\pack.bin" 2048 $old
Mk "$Work\node_modules\lib.js" 2048 $old
Mk "$Work\recent.pdf" 2048 (Get-Date)
Mk "$Work\tiny.txt" 1 $old

$r = @(Get-WOldFiles @($Work) 365 1MB)
$names = @($r | ForEach-Object Name)
Check 'Finds old files, including in subfolders' ($names -contains 'old-installer.exe' -and $names -contains 'holiday.jpg')
Check 'Skips recently used files' ($names -notcontains 'recent.pdf')
Check 'Skips files below the size limit' ($names -notcontains 'tiny.txt')
Check 'Skips .git and node_modules' ($names -notcontains 'pack.bin' -and $names -notcontains 'lib.js')
Check 'Flags an archive extracted next to itself' ([bool]($r | Where-Object Name -eq 'setup-tool.zip').Extracted)
Check 'Does not flag other archives' (-not ($r | Where-Object Name -eq 'keep.zip').Extracted)
Check 'Labels files by kind' (($r | Where-Object Name -eq 'old-installer.exe').Kind -eq 'Installer')

[IO.Directory]::Delete($Work, $true)
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All checks passed' -ForegroundColor Green }
