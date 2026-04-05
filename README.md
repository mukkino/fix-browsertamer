# fix-browsertamer
PowerShell script to set BrowserTamer as your default browser on Windows 10/11.

It handles the modern Windows protections that stop default-browser changes from sticking, including the UCPD driver, UserChoiceLatest-related feature flags via ViVeTool, and correct hash-based association writes via PS-SFTA. It also registers BrowserTamer properly in Windows, fixes phantom browser discovery issues, and can now fully uninstall BrowserTamer and the script’s changes if needed. Fully idempotent — re-run after Windows updates to restore settings.

## What it does

Modern Windows uses multiple protection layers to resist programmatic changes to default browser settings. Getting BrowserTamer — or any non-Microsoft browser — to stick as your default now requires several coordinated steps that are tedious to do manually and easy to get wrong.

This script handles them in sequence:

1. Installs or upgrades BrowserTamer via `winget`
2. Lets you choose whether to install the **latest** BrowserTamer release or the **previous** one (`5.5.5`)
3. Registers BrowserTamer as a virtual browser in Windows so its ProgIds can be used for defaults
4. Repairs broken third-party `StartMenuInternet` entries that would otherwise make BrowserTamer discover phantom/broken browsers
5. Configures BrowserTamer's `config.ini` so the picker always appears and does not instantly close on focus loss
6. Disables the UCPD driver and the "UCPD velocity" scheduled task that can re-enable it at login
7. Uses [ViVeTool](https://github.com/thebookisclosed/ViVe) to disable the feature flags tied to UCPD write protection and the newer UserChoiceLatest mechanism
8. Uses [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) to write valid hashed associations for `http`, `https`, HTML file types, and PDF
9. Verifies the written associations and BrowserTamer command registrations
10. Backs up relevant registry state before making changes

It now also uses the stable WinGet symlink path for `bt.exe`, which makes the registration more resilient across BrowserTamer upgrades.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- `winget` (App Installer from the Microsoft Store)
- An internet connection (ViVeTool and PS-SFTA are downloaded automatically)
- Must be run as a **normal user, not as Administrator** — steps that require elevation self-elevate via UAC

## Usage

You can run either the batch wrapper or the PowerShell script directly.

### Batch wrapper
```bat
fix-browsertamer.bat
```

This opens a menu with:
- Install / fix (Manual mode)
- Install / fix (Semi-automatic)
- Uninstall BrowserTamer completely
- Uninstall without confirmation
- Quit

### PowerShell
```powershell
# Interactive mode — pauses at major steps so you can read the output
.\fix-browsertamer.ps1 -Manual

# Fewer prompts — runs with minimal pauses
.\fix-browsertamer.ps1 -SemiAuto

# Fully uninstall BrowserTamer and the script's changes
.\fix-browsertamer.ps1 -Uninstall

# Uninstall without confirmation prompt
.\fix-browsertamer.ps1 -Uninstall -SemiAuto
```

Running the PowerShell script without parameters now shows an interactive menu instead of just printing help and exiting.

## Uninstall

Version 1.1 adds a full uninstall mode.

It can:

- stop running `bt.exe`
- uninstall BrowserTamer via `winget`
- remove leftover package files and WinGet symlinks
- remove BrowserTamer-related registry entries from `HKCU`
- clean UserChoice entries still pointing to BrowserTamer
- remove the startup entry added by the script
- delete `%LOCALAPPDATA%\bt`
- delete `%LOCALAPPDATA%\BrowserTamer-Fix`
- self-elevate for `HKLM` cleanup when needed

## Persistence

Windows updates can undo parts of this fix. Quality updates may re-enable UCPD, feature changes may restore the velocity task or change association protections, and BrowserTamer upgrades may move the real executable path. If BrowserTamer stops intercepting links after a Windows update, re-running the script should restore everything. The script is designed to be idempotent.

## Notes

- The script only elevates the specific steps that need elevation. Do **not** run the whole script from an elevated PowerShell or Command Prompt.
- The script sets protocol defaults for `http` and `https`, plus HTML-related file types and PDF.
- The script also works around a BrowserTamer edge case where broken third-party browser registrations can create persistent phantom entries and cause incorrect picker behaviour.

## Disclaimer

This script modifies system-level registry keys, disables a Windows kernel driver, and changes internal Windows feature flags. I take no responsibility for any damage, data loss, misconfiguration, or unintended behavior that results from running it. I share it because it works for me and might work for you — but you run it at your own risk, on your own machine, with your own understanding of what it does.

If you are not comfortable with what is described above, read the [full guide](https://alterego.cc/wp/2026/03/19/fixing-browser-tamer-issues-in-windows/) first, which explains each step and the reasoning behind it in plain language before touching anything.
