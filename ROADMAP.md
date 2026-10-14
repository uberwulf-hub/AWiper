# Computer Doctor roadmap

What's planned next, in order. Each item links to its GitHub issue, which has the details.

The research behind this list is the October 2026 deep dive. It covered:
- home-user tools (CCleaner, BleachBit, UniGetUI, WinUtil, BCUninstaller and others);
- IT and offline tools (PDQ, NinjaOne, Intune Remediations, Sysinternals, Windows LAPS);
- Windows platform changes from 2025 to 2026.

**Effort:** Easy / Moderate / Hard.
**Risk:** how much damage a bug or a wrong click could do.

## Done in the 1.10–1.11 releases

- **Recovery > Readiness:**
  - BitLocker recovery key: whether it exists, whether it's backed up, save it, add one.
  - Secure Boot 2011 → 2023 certificate status, with an opt-in update.
  - Windows RE, Quick Machine Recovery and Point-in-time Restore.
  - Restore points and backup.
  - Windows 10 ESU eligibility (consumer ESU runs to Oct 12, 2027).
  - Restart to Advanced Startup.
- **Remote targeting covers Space Map, Large Files, Startup and the Right-click menu.** Every view names the PC it's showing.

## Wave 2: finish the carry-overs

Competitors still lead on these.

| Item | Home | Work | Offline | Effort | Risk |
|---|---|---|---|---|---|
| [#1](https://github.com/uberwulf-hub/ComputerDoctor/issues/1) winget update-all with skip list, schedule and offline staging | High | High | Partly | Moderate | Medium |
| [#2](https://github.com/uberwulf-hub/ComputerDoctor/issues/2) Big-space cleanups: Windows.old, Update Cleanup, old driver packages | High | Medium | Yes | Moderate | Low–medium |
| [#3](https://github.com/uberwulf-hub/ComputerDoctor/issues/3) Autostart expansion + legacy dependency scan (WMIC, PowerShell 2.0, VBScript) | Medium | High | Yes | Moderate | Low |
| [#4](https://github.com/uberwulf-hub/ComputerDoctor/issues/4) Tweak drift: re-apply debloat settings Windows turned back on | High | Medium | Yes | Easy | Low |
| [#5](https://github.com/uberwulf-hub/ComputerDoctor/issues/5) Uninstall leftovers, quiet bulk uninstall, empty folders, broken shortcuts | Medium | Medium | Yes | Moderate | Medium |

## Wave 3: lightweight, agent-free IT management

These build on WinRM, fleet inventory and the scheduled task.

| Item | Home | Work | Offline | Effort | Risk |
|---|---|---|---|---|---|
| [#6](https://github.com/uberwulf-hub/ComputerDoctor/issues/6) Detect / remediate check packs (Intune-compatible) | Low | High | Yes | Moderate–hard | Medium |
| [#7](https://github.com/uberwulf-hub/ComputerDoctor/issues/7) Local Administrators audit + Windows LAPS health | Low | High | Yes | Easy | Medium |
| [#8](https://github.com/uberwulf-hub/ComputerDoctor/issues/8) LAN discovery + Wake-on-LAN | Low | High | Yes (LAN) | Easy–moderate | Low |
| [#9](https://github.com/uberwulf-hub/ComputerDoctor/issues/9) USB device history + removable-storage policy | Low | High | Yes | Easy | Low–medium |
| [#10](https://github.com/uberwulf-hub/ComputerDoctor/issues/10) Fleet certificate inventory | Low | Medium | Yes | Easy | Very low |

## Later

- [#11](https://github.com/uberwulf-hub/ComputerDoctor/issues/11) Security defaults view: SMB signing, NTLMv1 / TLS 1.0, Smart App Control, Controlled Folder Access
- [#12](https://github.com/uberwulf-hub/ComputerDoctor/issues/12) Default-app snapshot ("your browser changed") + per-app notification switches
- [#13](https://github.com/uberwulf-hub/ComputerDoctor/issues/13) Settings profiles: export / import, apply to the Default user profile
- [#14](https://github.com/uberwulf-hub/ComputerDoctor/issues/14) Smaller ideas: encrypted DNS presets, developer caches, triage collection, desktop info stamp

## To verify

These parts are built but not yet confirmed on real hardware or against documentation.

- [#15](https://github.com/uberwulf-hub/ComputerDoctor/issues/15) Test remote scanning against a real remote PC
- [#16](https://github.com/uberwulf-hub/ComputerDoctor/issues/16) Verify the admin-only parts of Recovery > Readiness
- [#17](https://github.com/uberwulf-hub/ComputerDoctor/issues/17) Confirm unverified registry values and event IDs
- [#18](https://github.com/uberwulf-hub/ComputerDoctor/issues/18) Replace WScript.Shell shortcut parsing (VBScript deprecation)

## Not planned

These are deliberately left out:

- **Snake oil:** registry cleaners, RAM boosters / memory optimizers and "game boosters".
- **Driver-database updaters.**
- **SSD "shredders":** overwrite passes are unreliable on SSDs and only add wear.
- **Turning off protection:** disabling Defender, UAC, SmartScreen or BitLocker as a "tweak".
- **Cloud dependencies:** VirusTotal uploads, CVE mapping and warranty lookups. They need cloud services or API keys, and the tool has to work offline.
- **Risky shortcuts:**
  - a home-made LAPS for workgroups;
  - offline SAM password resets;
  - writing BIOS settings;
  - bundled kernel drivers;
  - a home-made snapshot scheduler (Windows' Point-in-time Restore does this).
