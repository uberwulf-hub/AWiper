# AWiper

System cleanup, health check, debloat, recovery and repair toolkit for Windows, with a WPF interface — written as a single PowerShell script. Works on this PC or on a remote computer over PowerShell remoting, with or without a window, and **with or without internet**.

| View         | What it does |
|--------------|--------------|
| Dashboard    | Drive usage gauges, system summary, quick actions |
| Health Check | Disks, crashes, hardware errors, stability index, device problems, battery wear, antivirus, pending restart, local network |
| Cleaner      | Analyze / clean temp files, caches, error reports, crash dumps, update and Delivery Optimization caches, Recycle Bin |
| Space Map    | SpaceMonger-style nested treemap of any drive or folder (drill down, recycle) |
| Large Files  | The 1,000 largest files from the last scan — searchable, recycle or export |
| Recovery     | Recycle Bin restore, previous versions, native NTFS undelete, restore points, deep scan with Windows File Recovery |
| Startup      | Enable / disable startup entries (same `StartupApproved` switches Task Manager uses) |
| Programs     | Installed software list with size, search and uninstall |
| Debloat      | Remove preinstalled Store apps; turn off ads, suggestions, Bing in Start, Copilot, Recall, Widgets and more |
| Rebloat      | Put back removed apps, set debloat tweaks back to Windows defaults, undo history |
| Tools        | Offline kit, quick fixes, repair and maintenance (see below), plus the activity log |

### Health Check

A read-only check that works offline and on remote PCs: disk health and reliability counters, SATA SMART failure prediction, free space, blue screens and unexpected shutdowns (30 days), WHEA hardware errors, the last memory-test result, Reliability Monitor's stability index, devices with driver problems, battery wear, Defender status and definition age (or a third-party antivirus), pending restart and uptime, and whether the local gateway answers. Each row has a status, the evidence and — where it helps — a button (Cleaner, Reliability Monitor, memory test, Device Manager, Defender update). Checks whose data isn't available on the hardware show **N/A** and are never counted as healthy. Reports save as HTML or JSON.

### Tools

- **Offline kit** — find, create, verify and hash a Resources folder (see [Offline use](#offline-use))
- **Quick fixes** — flush DNS, Group Policy update (`gpupdate /force`), restart Explorer, reset default app associations, empty Recycle Bin
- **Repair** — System File Checker (`sfc /scannow`), DISM `/RestoreHealth` (from Windows Update, or offline from Windows media), .NET Framework 3.5, reset Windows Update, repair the Configuration Manager client (Software Center)
- **Maintenance** — component store cleanup, restore points, disable hibernation, Disk Cleanup, Storage Sense

### Debloat

Apps are matched against a curated list; recommended removals are pre-checked and anything you might still use (Outlook, Teams for work, Phone Link, Xbox, Quick Assist...) is left unchecked with a note. **Show all apps** lists every removable Store app except a protected core set (Store, App Installer, Photos, Calculator, codecs, runtimes...). When running as admin, apps are removed for all users and, optionally, the provisioned copy is removed so new accounts don't get it.

Tweaks show an **ON** badge when they're already applied. By default a restore point is created first (see Restore points).

### Rebloat

Changed your mind? **Rebloat** lists every catalog app that's missing for your account and puts it back:

- **Windows copy** — if the app is still on disk (provisioned, or installed for another user), it's re-registered instantly with no download (needs admin to find these copies). Works offline.
- **Microsoft Store** — otherwise it's reinstalled with `winget` using the app's verified Store ID.
- **Store search** — apps without a known ID open in the Microsoft Store so you can install them there. Apps Microsoft has retired (Cortana, People, Skype...) are only offered if a copy is still on disk.

The right-hand panel lists the debloat tweaks currently in effect and sets the checked ones back to Windows defaults. **Undo history** puts settings back *exactly* as they were before any tweak AWiper applied — from the window or the command line.

### Recovery

- **Drive check** — every drive gets a recoverability rating from its media type, bus and TRIM setting. Internal SSDs with TRIM (the Windows default) usually erase deleted data within minutes; USB sticks, SD cards and hard disks are good candidates.
- **Recycle Bin** — reads the `$Recycle.Bin` folders directly, so it shows every user's deleted items (as admin) and works on remote PCs. Restore to the original location or another folder; nothing is ever overwritten.
- **Previous versions** — lists Volume Shadow Copy snapshots (System Protection / restore points), opens one in Explorer, or compares a folder against a snapshot to list files that have since been deleted or changed, then restores them.
- **Undelete** — AWiper's own NTFS undelete. It reads the drive's master file table directly (read-only, needs admin), lists deleted files with their original folders (including deleted folders), and rates each one — *Excellent* (data stored in the file record), *Good* (all clusters still free), *Poor* (partly overwritten), *Overwritten*. Recovered files keep their folder layout and timestamps, must go to a different drive, and never overwrite anything. It can also scan a raw NTFS volume image (`.img`/`.dd`) — the safe way to work on a failing drive.
- **Restore points** — list, create (without Windows' one-per-24-hours limit), delete, turn System Protection on, and set how much space restore points may use. Optionally creates one automatically before removing apps or applying tweaks.
- **Deep scan** — a front-end for Microsoft's free [Windows File Recovery](https://apps.microsoft.com/detail/9N26S50LN705) (`winfr`): installs it if needed, builds the command, refuses to save to the drive being scanned, and streams progress to the activity log. Offline, AWiper points you to Undelete instead.

## Offline use

AWiper checks for internet at startup using the result Windows' own connectivity check (NCSI) already has. The title-bar button shows **Online**, **No internet** or **Offline mode** — click it to force offline mode (also `-Offline`). Internet-only actions are then disabled with a tooltip naming the offline alternative.

Offline alternatives come from a **Resources folder**, found automatically next to `AWiper.ps1`, at `<any drive>:\AWiper\Resources` (so a USB stick becomes a repair kit), or wherever you point it in Tools → Offline kit:

| Folder     | Used for |
|------------|----------|
| `ISO\`     | Windows install media (`.iso` or extracted files) for **DISM repair** and **.NET 3.5** with `/LimitAccess`. AWiper picks the image matching this PC's edition and warns when the media is older than the PC's updates. |
| `defs\`    | Microsoft Defender offline definitions (`x64\mpam-fe.exe`) — the Health Check's Defender button installs them. |
| `drivers\`, `updates\`, `apps\`, `appx\`, `LOF\`, `tools\` | Reserved for upcoming offline driver, update and app features; bring your own tools (Sysinternals can't be redistributed). |

**Build manifest** hashes every file into `manifest.json` (SHA-256); **Verify Resources** checks a stick against it before use.

## Command line (headless)

Any of these parameters runs AWiper without a window — from a script, a scheduled task, or against other PCs. Changes are **only previewed unless `-Yes` is given**.

```powershell
.\AWiper.ps1 -HealthCheck                                   # health check in the console
.\AWiper.ps1 -HealthCheck -Format Json -OutFile health.json # machine-readable
.\AWiper.ps1 -Analyze -Clean Default                        # how much would be cleaned
.\AWiper.ps1 -Clean Default -ApplyTweak AdId,Suggestions -Yes
.\AWiper.ps1 -RemoveApp Recommended -Yes                    # recommended Store app removals
.\AWiper.ps1 -Config .\monthly.json -Yes                    # everything from a profile
.\AWiper.ps1 -ComputerName PC042 -UseSavedCredential -Clean WinTemp,WerSys -Yes
.\AWiper.ps1 -ListRules    # also -ListTweaks, -ListApps
```

A profile is plain JSON and may only reference built-in IDs:

```json
{ "RestorePoint": "Monthly maintenance", "Clean": ["Default"], "ApplyTweaks": ["AdId", "Suggestions"],
  "RemoveApps": ["Recommended"], "HealthCheck": true }
```

Exit codes: `0` OK · `1` a step failed · `2` bad arguments · `3` health warnings · `4` health problems · `5` PowerShell is in ConstrainedLanguage mode. Headless runs never show a UAC prompt; run them from an elevated prompt (or as SYSTEM in a scheduled task) for admin-only items.

## Remote computers

Click **This PC** in the title bar to target another computer by hostname, FQDN or IP address (or use `-ComputerName` on the command line).

- **Domain (optional)** is appended to short hostnames and to usernames without a domain.
- **Current credentials** uses your Windows sign-in (Kerberos — use the computer name, not an IP).
- **Other credentials** accepts `DOMAIN\user` or `user@domain`. Tick **Save to Windows Credential Manager** to store them as a generic credential named `AWiper:<host>`; they're filled in automatically next time and can be removed from the dialog or from Credential Manager.
- Connecting by IP address or to a non-domain PC needs the target in WinRM `TrustedHosts`; the dialog offers to add it.

The remote PC needs PowerShell remoting enabled (`Enable-PSRemoting -Force`) and your account must be an administrator there.

When a remote computer is targeted, these run on it: Health Check, Tools (except Explorer, Recycle Bin, Disk Cleanup, Storage Sense, and offline media repair), machine-wide Cleaner rules, Debloat apps and machine-wide tweaks, the Programs list and Recycle Bin restore. Per-user items, Dashboard, Space Map, Large Files and Startup stay on this PC and are labelled as such.

## Safety and audit trail

- Nothing is deleted without an Analyze / confirm step; headless runs need `-Yes`.
- Files removed from the Space Map and Large Files views go to the Recycle Bin.
- Browser history, cookies and saved passwords are never touched.
- A restore point is created before app removal and tweaks (can be turned off), and every tweak's previous values go to the undo journal.
- **Action log** — every change (who, when, which computer, what, result) is appended to `%ProgramData%\AWiper\Logs\actions-<yyyy-MM>.jsonl` and, when elevated, to the Application event log (source `AWiper`) for event forwarding or a SIEM.
- **Locked-down PCs** — under App Control (WDAC) or AppLocker, unsigned scripts run in ConstrainedLanguage mode, which blocks the features AWiper needs. AWiper detects this and explains that the script must be signed by a publisher the policy trusts (keep settings in JSON profiles — editing a signed script breaks its signature).

## Tests

```powershell
.\tests\Test-Cli.ps1                                      # no admin: exercises the headless mode
.\tests\Test-UndeleteSynthetic.ps1                        # no admin: builds a tiny NTFS image and checks the undelete engine
.\tests\Test-UndeleteLive.ps1 -Drive H: -Dest C:\Temp\R   # admin: deletes a test file on H:, recovers it, compares hashes
```

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1, or PowerShell 7+ on Windows

## Usage

```powershell
.\AWiper.ps1
```

On launch AWiper asks for administrator rights (UAC). If the prompt is declined or elevation isn't possible, it keeps running with standard permissions and disables the items that need admin rights.

If script execution is blocked by policy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\AWiper.ps1
```

| Parameter      | Description |
|----------------|-------------|
| `-NoElevate`   | Skip the UAC prompt and run with the current permissions. |
| `-ShowConsole` | Keep the PowerShell console window visible (useful for troubleshooting). |
| `-Offline`     | Never use the internet; use the Resources folder. |
| `-Resources`   | Path to a Resources folder. |

See [Command line](#command-line-headless) for the headless parameters, or `Get-Help .\AWiper.ps1 -Full`.

## Data

- `%LOCALAPPDATA%\AWiper\AWiper.log` — activity log
- `%LOCALAPPDATA%\AWiper\state.json` — settings, running totals, recently used remote computers
- `%LOCALAPPDATA%\AWiper\undo.json` — undo journal (previous values of every tweak)
- `%ProgramData%\AWiper\Logs\actions-*.jsonl` — action log

Saved remote credentials live in Windows Credential Manager, never in AWiper's own files.

## Credits

The Debloat view was inspired by [Win11Debloat](https://github.com/Raphire/Win11Debloat).

## License

[MIT](LICENSE)
