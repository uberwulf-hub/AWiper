<#
.SYNOPSIS
    Builds a tiny synthetic NTFS volume image and runs AWiper's undelete engine against it.
    No admin rights needed. Checks detection, path rebuilding, ratings and byte-exact recovery.
#>
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\AWiper.ps1'),
    [string]$Work = (Join-Path ([IO.Path]::GetTempPath()) 'AWiperUndeleteTest')
)
if (-not (Test-Path $Work)) { New-Item -ItemType Directory -Path $Work | Out-Null }
$ErrorActionPreference = 'Stop'
$src = [IO.File]::ReadAllText($Path)
Add-Type -TypeDefinition ([regex]::Match($src, "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline').Groups[1].Value)

$cluster = 4096; $recSize = 1024; $clusters = 256
$img = New-Object byte[] ($cluster * $clusters)
function Put16($b, $o, $v) { [BitConverter]::GetBytes([uint16]$v).CopyTo($b, $o) }
function Put32($b, $o, $v) { [BitConverter]::GetBytes([uint32]$v).CopyTo($b, $o) }
function Put64($b, $o, $v) { [BitConverter]::GetBytes([int64]$v).CopyTo($b, $o) }
function Align8([int]$n) { ($n + 7) -band -8 }

# ---- boot sector
[Text.Encoding]::ASCII.GetBytes('NTFS    ').CopyTo($img, 3)
Put16 $img 0x0B 512; $img[0x0D] = 8; Put64 $img 0x28 ($clusters * 8); Put64 $img 0x30 4; $img[0x40] = 0xF6

$ft = (Get-Date '2026-09-15 10:30').ToFileTime()
function New-Rec([int]$Seq, [int]$Flags) {
    $r = New-Object byte[] $recSize
    [Text.Encoding]::ASCII.GetBytes('FILE').CopyTo($r, 0)
    Put16 $r 4 0x30; Put16 $r 6 3; Put16 $r 0x10 $Seq; Put16 $r 0x14 0x38; Put16 $r 0x16 $Flags; Put32 $r 0x1C $recSize
    @{ B = $r; At = 0x38 }
}
function Add-Resident($rec, [uint32]$Type, [byte[]]$Value) {
    $r = $rec.B; $a = $rec.At; $len = Align8 (0x18 + $Value.Length)
    Put32 $r $a $Type; Put32 $r ($a + 4) $len; $r[$a + 8] = 0; Put16 $r ($a + 0x0A) 0x18
    Put32 $r ($a + 0x10) $Value.Length; Put16 $r ($a + 0x14) 0x18
    $Value.CopyTo($r, $a + 0x18); $rec.At += $len
}
function Add-NonResident($rec, [long]$Lcn, [long]$Count, [long]$Size) {
    $r = $rec.B; $a = $rec.At; $len = 0x48
    Put32 $r $a 0x80; Put32 $r ($a + 4) $len; $r[$a + 8] = 1; Put16 $r ($a + 0x0A) 0x40
    Put64 $r ($a + 0x10) 0; Put64 $r ($a + 0x18) ($Count - 1); Put16 $r ($a + 0x20) 0x40
    Put64 $r ($a + 0x28) ($Count * $cluster); Put64 $r ($a + 0x30) $Size; Put64 $r ($a + 0x38) $Size
    $r[$a + 0x40] = 0x11; $r[$a + 0x41] = [byte]$Count; $r[$a + 0x42] = [byte]$Lcn; $r[$a + 0x43] = 0
    $rec.At += $len
}
function New-SIValue { $v = New-Object byte[] 48; Put64 $v 0 $ft; Put64 $v 8 $ft; Put64 $v 16 $ft; Put64 $v 24 $ft; ,$v }
function New-FNValue([long]$Parent, [int]$ParentSeq, [string]$Name) {
    $n = [Text.Encoding]::Unicode.GetBytes($Name); $v = New-Object byte[] (66 + $n.Length)
    Put64 $v 0 ($Parent -bor ([long]$ParentSeq -shl 48)); $v[64] = [byte]$Name.Length; $v[65] = 1; $n.CopyTo($v, 66); ,$v
}
function Finish($rec, [long]$Number) {
    $r = $rec.B; foreach ($k in 0..3) { $r[$rec.At + $k] = 255 }; Put32 $r 0x18 ($rec.At + 8)
    Put16 $r 0x30 1                                   # update sequence number
    foreach ($i in 1, 2) { $p = $i * 512 - 2; $r[0x30 + 2 * $i] = $r[$p]; $r[0x31 + 2 * $i] = $r[$p + 1]; Put16 $r $p 1 }
    $r.CopyTo($img, 4 * $cluster + $Number * $recSize)
}

# MFT: 32 records at LCN 4-11. $Bitmap data at LCN 12.
$m = New-Rec 1 1; Add-Resident $m 0x10 (New-SIValue); Add-Resident $m 0x30 (New-FNValue 5 5 '$MFT'); Add-NonResident $m 4 8 (32 * $recSize); Finish $m 0
$root = New-Rec 5 3; Add-Resident $root 0x10 (New-SIValue); Add-Resident $root 0x30 (New-FNValue 5 5 '.'); Finish $root 5
$bm = New-Rec 6 1; Add-Resident $bm 0x10 (New-SIValue); Add-Resident $bm 0x30 (New-FNValue 5 5 '$Bitmap'); Add-NonResident $bm 12 1 ($clusters / 8); Finish $bm 6
$docs = New-Rec 1 3; Add-Resident $docs 0x10 (New-SIValue); Add-Resident $docs 0x30 (New-FNValue 5 5 'Docs'); Finish $docs 24

$report = New-Object byte[] 6000; (New-Object Random 7).NextBytes($report); $report.CopyTo($img, 40 * $cluster)
$f = New-Rec 2 0; Add-Resident $f 0x10 (New-SIValue); Add-Resident $f 0x30 (New-FNValue 24 1 'report.docx'); Add-NonResident $f 40 2 6000; Finish $f 25
$note = [Text.Encoding]::UTF8.GetBytes('hello from inside the MFT record')
$f = New-Rec 2 0; Add-Resident $f 0x10 (New-SIValue); Add-Resident $f 0x30 (New-FNValue 24 1 'note.txt'); Add-Resident $f 0x80 $note; Finish $f 26
$f = New-Rec 2 0; Add-Resident $f 0x10 (New-SIValue); Add-Resident $f 0x30 (New-FNValue 24 1 'gone.bin'); Add-NonResident $f 50 1 3000; Finish $f 27
$old = New-Rec 2 2; Add-Resident $old 0x10 (New-SIValue); Add-Resident $old 0x30 (New-FNValue 5 5 'Old Photos'); Finish $old 28
$jpg = New-Object byte[] 100; for ($i = 0; $i -lt 100; $i++) { $jpg[$i] = [byte]($i + 1) }; $jpg.CopyTo($img, 60 * $cluster)
$f = New-Rec 2 0; Add-Resident $f 0x10 (New-SIValue); Add-Resident $f 0x30 (New-FNValue 28 1 'beach.jpg'); Add-NonResident $f 60 1 100; Finish $f 29
$f = New-Rec 1 1; Add-Resident $f 0x10 (New-SIValue); Add-Resident $f 0x30 (New-FNValue 24 1 'keep.txt'); Add-Resident $f 0x80 $note; Finish $f 30

# Bitmap: clusters 0-12 (boot, MFT, bitmap) and 50 (reused by another file) are allocated
$bits = New-Object byte[] ($clusters / 8); foreach ($c in (0..12) + 50) { $bits[$c -shr 3] = $bits[$c -shr 3] -bor (1 -shl ($c -band 7)) }
$bits.CopyTo($img, 12 * $cluster)

$imgPath = Join-Path $Work 'synthetic-ntfs.img'
[IO.File]::WriteAllBytes($imgPath, $img)

# ---- run the real scanner
$u = New-Object AWiper.NtfsUndelete $imgPath
$u.Open(); $u.Scan()
"Error: [$($u.Error)]  Completed: $($u.Completed)  Records: $($u.RecordsScanned)/$($u.RecordsTotal)  Deleted: $($u.DeletedFound)  Cluster: $($u.BytesPerCluster)"
$m = 0; $all = $u.Filter('', 0, 100, [ref]$m)
$all | Format-Table Name, Chance, Size, ModifiedText, Folder, Note -AutoSize | Out-String -Width 200
$m2 = 0; "Recoverable-only filter count: " + $u.Filter('', 2, 100, [ref]$m2).Count + "  search 'photos': " + $u.Filter('photos', 0, 100, [ref]$m2).Count

$out = Join-Path $Work 'synthetic-out'; if (Test-Path $out) { Get-ChildItem $out | ForEach-Object { [IO.File]::Delete($_.FullName) } } else { New-Item -ItemType Directory $out | Out-Null }
$expected = @{ 'report.docx' = $report; 'note.txt' = $note; 'beach.jpg' = $jpg }
foreach ($x in $all) {
    $dest = Join-Path $out $x.Name
    try {
        $warn = $u.Recover($x, $dest)
        $got = [IO.File]::ReadAllBytes($dest)
        $match = if ($expected.ContainsKey($x.Name)) { [Linq.Enumerable]::SequenceEqual([byte[]]$got, [byte[]]$expected[$x.Name]) } else { 'n/a' }
        "Recovered {0,-12} bytes={1,-5} identical={2} warn=[{3}] mtime={4}" -f $x.Name, $got.Length, $match, $warn, (Get-Item $dest).LastWriteTime
    } catch { "Recover {0}: {1}" -f $x.Name, $_.Exception.Message }
}
try { $u.Recover($all[0], (Join-Path $out $all[0].Name)) | Out-Null; 'Overwrite check: FAILED (overwrote)' } catch { 'Overwrite check: refused existing file - OK' }
$u.Dispose()
