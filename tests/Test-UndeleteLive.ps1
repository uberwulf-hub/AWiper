<#
.SYNOPSIS
    End-to-end check of AWiper's NTFS undelete on a real drive. Run from an elevated PowerShell.

.DESCRIPTION
    Writes a 256 KB test file to <Drive>\AWiperUndeleteTest, permanently deletes it, scans the
    drive with AWiper's engine (read-only), recovers the file into -Dest and compares SHA-256.

    On an SSD with TRIM enabled the recovered copy is usually all zeros - that is the expected,
    real-world result and is reported as such. Use a USB stick or hard disk to see a full recovery.

.EXAMPLE
    .\Test-UndeleteLive.ps1 -Drive H: -Dest C:\Temp\Recovered
#>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$Drive,
    [Parameter(Mandatory)][string]$Dest,
    [string]$Path = (Join-Path $PSScriptRoot '..\AWiper.ps1')
)
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell.' }

$src = [IO.File]::ReadAllText($Path)
Add-Type -TypeDefinition ([regex]::Match($src, "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value)
if ([AWiper.Native]::VolumeId("$Drive\") -eq [AWiper.Native]::VolumeId($Dest)) { throw '-Dest must be on a different drive than -Drive.' }
if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Path $Dest | Out-Null }

$dir = "$Drive\AWiperUndeleteTest"
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$name = 'awiper-undelete-{0:yyyyMMddHHmmss}.bin' -f (Get-Date)
$file = Join-Path $dir $name
$data = New-Object byte[] (256KB); (New-Object Random).NextBytes($data)
$fs = [IO.File]::Open($file, 'CreateNew'); $fs.Write($data, 0, $data.Length); $fs.Flush($true); $fs.Dispose()
$hash = (Get-FileHash $file -Algorithm SHA256).Hash
[IO.File]::Delete($file)
"Created and permanently deleted $file ($hash)"
Start-Sleep -Seconds 3

$u = New-Object AWiper.NtfsUndelete $Drive
$sw = [Diagnostics.Stopwatch]::StartNew()
$u.Open(); $u.Scan()
if ($u.Error) { throw "Scan failed: $($u.Error)" }
"Scanned {0:N0} records in {1:N1}s, {2:N0} deleted files found" -f $u.RecordsScanned, $sw.Elapsed.TotalSeconds, $u.DeletedFound

$m = 0
$hit = @($u.Filter($name, 0, 10, [ref]$m)) | Select-Object -First 1
if (-not $hit) { $u.Dispose(); throw 'The deleted test file was not found in the file table (its record may already have been reused).' }
"Found: $($hit.FullPath)  Chance: $($hit.Chance)  $($hit.Note)"

$u.Refresh()
$out = Join-Path $Dest $name
$warn = $u.Recover($hit, $out)
$u.Dispose()
$got = (Get-FileHash $out -Algorithm SHA256).Hash
if ($got -eq $hash) { "PASS - recovered copy is identical ($out)" }
elseif ($warn -match 'zeros') { "EXPECTED ON SSD - the file was found, but the drive already erased its data (TRIM). Recovered copy is zeros: $out" }
else { "PARTIAL - recovered copy differs ($got). Some clusters were probably reused. $warn" }
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
