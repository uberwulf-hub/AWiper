# AWiper

System cleanup, debloat and repair toolkit for Windows, with a WPF interface — written as a single PowerShell script. Works on this PC or on a remote computer over PowerShell remoting.

| View        | What it does |
|-------------|--------------|
| Dashboard   | Drive usage gauges, system summary, quick actions |
| Cleaner     | Analyze / clean temp files, caches, error reports, crash dumps, update and Delivery Optimization caches, Recycle Bin |
| Space Map   | SpaceMonger-style nested treemap of any drive or folder (drill down, recycle) |
| Large Files | The 1,000 largest files from the last scan — searchable, recycle or export |
| Recovery    | Restore from the Recycle Bin, find deleted files in previous versions, deep scan with Windows File Recovery |
| Startup     | Enable / disable startup entries (same `StartupApproved` switches Task Manager uses) |
| Programs    | Installed software list with size, search and uninstall |
| Debloat     | Remove preinstalled Store apps; turn off ads, suggestions, Bing in Start, Copilot, Recall, Widgets and more |
| Tools       | Quick fixes, repair and maintenance (see below), plus the activity log |

### Tools

- **Quick fixes** — flush DNS, Group Policy update (`gpupdate /force`), restart Explorer, reset default app associations, empty Recycle Bin
- **Repair** — System File Checker (`sfc /scannow`), DISM `/RestoreHealth`, reset Windows Update (SoftwareDistribution / catroot2), repair the Configuration Manager client (Software Center)
- **Maintenance** — component store cleanup, create a restore point, disable hibernation, Disk Cleanup, Storage Sense

### Debloat

Apps are matched against a curated list; recommended removals are pre-checked and anything you might still use (Outlook, Teams for work, Phone Link, Xbox, Quick Assist...) is left unchecked with a note. **Show all apps** lists every removable Store app except a protected core set (Store, App Installer, Photos, Calculator, codecs, runtimes...). When running as admin, apps are removed for all users and, optionally, the provisioned copy is removed so new accounts don't get it.

Tweaks show an **ON** badge when they're already applied and can be reverted.

### Recovery

- **Drive check** — every drive gets a recoverability rating from its media type, bus and TRIM setting. Internal SSDs with TRIM (the Windows default) usually erase deleted data within minutes; USB sticks, SD cards and hard disks are good candidates.
- **Recycle Bin** — reads the `$Recycle.Bin` folders directly, so it shows every user's deleted items (as admin) and works on remote PCs. Restore to the original location or another folder; nothing is ever overwritten.
- **Previous versions** — lists Volume Shadow Copy snapshots (System Protection / restore points), opens one in Explorer, or compares a folder against a snapshot to list files that have since been deleted or changed, then restores them.
- **Deep scan** — a front-end for Microsoft's free [Windows File Recovery](https://apps.microsoft.com/detail/9N26S50LN705) (`winfr`): installs it if needed, builds the command, refuses to save to the drive being scanned, and streams progress to the activity log.

## Remote computers

Click **This PC** in the title bar to target another computer by hostname, FQDN or IP address.

- **Domain (optional)** is appended to short hostnames and to usernames without a domain.
- **Current credentials** uses your Windows sign-in (Kerberos — use the computer name, not an IP).
- **Other credentials** accepts `DOMAIN\user` or `user@domain`. Tick **Save to Windows Credential Manager** to store them as a generic credential named `AWiper:<host>`; they're filled in automatically next time and can be removed from the dialog or from Credential Manager.
- Connecting by IP address or to a non-domain PC needs the target in WinRM `TrustedHosts`; the dialog offers to add it.

The remote PC needs PowerShell remoting enabled (`Enable-PSRemoting -Force`) and your account must be an administrator there.

When a remote computer is targeted, these run on it: Tools (except Explorer, Recycle Bin, Disk Cleanup, Storage Sense), machine-wide Cleaner rules, Debloat apps and machine-wide tweaks, and the Programs list. Per-user items, Dashboard, Space Map, Large Files and Startup stay on this PC and are labelled as such.

## Safety

- Nothing is deleted without an Analyze / confirm step.
- Files removed from the Space Map and Large Files views go to the Recycle Bin.
- Browser history, cookies and saved passwords are never touched.
- Debloat asks for confirmation and offers a restore point first.

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

### Parameters

| Parameter      | Description |
|----------------|-------------|
| `-NoElevate`   | Skip the UAC prompt and run with the current permissions. |
| `-ShowConsole` | Keep the PowerShell console window visible (useful for troubleshooting). |

## Data

AWiper stores its log and state in `%LOCALAPPDATA%\AWiper\`:

- `AWiper.log` — activity log
- `state.json` — running totals (space freed, number of cleans) and recently used remote computers

Saved remote credentials live in Windows Credential Manager, never in AWiper's own files.

## Credits

The Debloat view was inspired by [Win11Debloat](https://github.com/Raphire/Win11Debloat).

## License

[MIT](LICENSE)
