<#
.SYNOPSIS
    Checks AWiper's folder-backup engine on throwaway folders (no admin needed): first copy, keeping
    older versions of changed and deleted files, an exact mirror, and refusing a different drive.
#>
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\AWiper.ps1'),
    [string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'AWiperBackupTest')
)
$ErrorActionPreference = 'Stop'
$src = [IO.File]::ReadAllText($Path)
Add-Type -TypeDefinition ([regex]::Match($src, "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value)
$Sync = [hashtable]::Synchronized(@{}); $Sync.Log = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'; $Target = $null
. ([scriptblock]::Create([regex]::Match($src, "\`$Sync.WorkerLib = @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value))
$fail = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fail++ } }

$s = Join-Path $Work 'src'; $d = Join-Path $Work 'dest'
if (Test-Path $Work) { [IO.Directory]::Delete($Work, $true) }
New-Item -ItemType Directory "$s\sub", $d -Force | Out-Null
'v1' | Set-Content "$s\report.txt"; 'keep' | Set-Content "$s\sub\notes.txt"; 'gone soon' | Set-Content "$s\old.txt"
$job = [pscustomobject]@{ Sources = @($s); Dest = $d; DestVolumeId = [AWiper.Native]::VolumeId($d); Keep = 3 }

$r1 = Invoke-WBackup $job
Check 'First backup succeeds' $r1.Ok
Start-Sleep -Seconds 2
'v2' | Set-Content "$s\report.txt"; [IO.File]::Delete("$s\old.txt"); 'new' | Set-Content "$s\new.txt"
$r2 = Invoke-WBackup $job
Check 'Second backup succeeds' $r2.Ok

$root = Join-Path $d "AWiper-Backup\$env:COMPUTERNAME"
$cur = Get-ChildItem "$root\current" -Directory | Select-Object -First 1
Check 'Mirror has the changed file' ((Get-Content (Join-Path $cur.FullName 'report.txt')) -eq 'v2')
Check 'Mirror has the new file' (Test-Path (Join-Path $cur.FullName 'new.txt'))
Check 'Mirror no longer has the deleted file' (-not (Test-Path (Join-Path $cur.FullName 'old.txt')))
$ver = @(Get-ChildItem "$root\versions" -Recurse -File)
Check 'Old version of the changed file was kept' (@($ver | Where-Object { $_.Name -eq 'report.txt' -and (Get-Content $_.FullName) -eq 'v1' }).Count -eq 1)
Check 'Deleted file was kept as a version' (@($ver | Where-Object { $_.Name -eq 'old.txt' }).Count -eq 1)

$bad = [pscustomobject]@{ Sources = @($s); Dest = $d; DestVolumeId = '\\?\VOLUME{00000000-0000-0000-0000-000000000000}\'; Keep = 3 }
Check 'Refuses a different drive at the destination' (-not (Invoke-WBackup $bad).Ok)

[IO.Directory]::Delete($Work, $true)
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All checks passed' -ForegroundColor Green }
