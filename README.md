# AWiper

System cleanup and disk space analyzer for Windows, with a WPF interface — written as a single PowerShell script.

AWiper bundles the most useful parts of tools like CCleaner and SpaceMonger:

| View        | What it does |
|-------------|--------------|
| Dashboard   | Drive usage gauges, system summary, quick actions |
| Cleaner     | Analyze / clean temp files, caches, update leftovers, dumps, Recycle Bin |
| Space Map   | SpaceMonger-style nested treemap of any drive or folder (drill down, recycle) |
| Large Files | The 1,000 largest files from the last scan — searchable, recycle or export |
| Startup     | Enable / disable startup entries (same `StartupApproved` switches Task Manager uses) |
| Programs    | Installed software list with size, search and uninstall |
| Tools       | DNS flush, component store cleanup, restore point, Explorer restart, activity log |

## Safety

- Nothing is deleted without an Analyze / confirm step.
- Files removed from the Space Map and Large Files views go to the Recycle Bin.
- Browser history, cookies and saved passwords are never touched.

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
- `state.json` — running totals (space freed, number of cleans)
