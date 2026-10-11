<#
.SYNOPSIS
    Air-gap round trip on a throwaway Resources folder (needs internet, no admin): export a needs list,
    fetch a driver for a simulated problem device from the Microsoft Update Catalog plus the baseline
    lists, then build and verify the manifest. Skips the large scan-file and Defender downloads.
#>
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\AWiper.ps1'),
    [string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'AWiperAirGapTest')
)
$ErrorActionPreference = 'Stop'
$fail = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fail++ } }
if (Test-Path $Work) { [IO.Directory]::Delete($Work, $true) }
New-Item -ItemType Directory $Work | Out-Null
$exe = (Get-Process -Id $PID).Path

& $exe -NoProfile -ExecutionPolicy Bypass -File $Path -ExportNeeds -Resources $Work 2>&1 | Out-Null
$nf = Join-Path $Work "needs\$env:COMPUTERNAME.json"
Check 'Needs list is written' (Test-Path $nf)
$n = Get-Content $nf -Raw | ConvertFrom-Json
Check 'Needs list describes this PC' ($n.Computer -eq $env:COMPUTERNAME -and $n.OS.Build -gt 0)

$src = [IO.File]::ReadAllText($Path)
Add-Type -TypeDefinition ([regex]::Match($src, "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value)
$Sync = [hashtable]::Synchronized(@{}); $Sync.Log = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'; $Target = $null
. ([scriptblock]::Create([regex]::Match($src, "\`$Sync.WorkerLib = @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value))
Remove-Item (Join-Path $Work 'needs\*.json')
[pscustomobject]@{ Computer = 'TESTPC'; OS = [pscustomobject]@{ Arch = 'x64' }; MissingUpdates = @(); Apps = @()
    ProblemDevices = @([pscustomobject]@{ Name = 'Realtek PCIe GbE (simulated)'; Code = 28; HardwareIds = @('PCI\VEN_10EC&DEV_8168&SUBSYS_00000000&REV_15') }) } |
    ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Work 'needs\TESTPC.json')
New-Item -ItemType Directory (Join-Path $Work 'defs\x64') -Force | Out-Null; 'placeholder' | Set-Content (Join-Path $Work 'defs\x64\mpam-fe.exe')
$s = Invoke-WFetch $Work $false
Check 'A driver was fetched for the problem device' ($s.Drivers -eq 1)
Check 'The driver was expanded to an .inf' (@(Get-ChildItem (Join-Path $Work 'drivers\catalog') -Recurse -Filter *.inf).Count -ge 1)
Check 'Baseline lists were fetched' ($s.Baselines -ge 1)
[void](New-WResourceManifest $Work)
$v = Test-WResourceManifest $Work
Check 'Manifest verifies' ($v.Ok -gt 0 -and $v.Bad -eq 0)
[IO.Directory]::Delete($Work, $true)
if ($fail) { Write-Host "$fail check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All checks passed' -ForegroundColor Green }
