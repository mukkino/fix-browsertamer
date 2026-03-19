# fix-browsertamer
PowerShell script to set Browser Tamer as your default browser on Windows 10/11. Handles UCPD driver disabling, UserChoiceLatest feature flags via ViVeTool, and correct hash-based association writes via PS-SFTA. Fully idempotent — re-run after Windows updates to restore settings

## What it does

Modern Windows uses a kernel-level driver (UCPD) and a cryptographic hash system to prevent programmatic changes to default browser settings. Getting Browser Tamer — or any non-Microsoft browser — to stick as your default now requires several coordinated steps that are tedious to do manually and easy to get wrong.

This script handles all of them in sequence:

1. Installs or upgrades Browser Tamer via winget
2. Registers Browser Tamer as a virtual browser in Windows (the registry entries Windows requires before it will accept it as a default)
3. Configures Browser Tamer's `config.ini` so the picker always appears
4. Disables the UCPD driver and the "UCPD velocity" scheduled task that re-enables it on every login
5. Uses [ViVeTool](https://github.com/thebookisclosed/ViVe) to disable the feature flags that control UCPD write protection and the UserChoiceLatest mechanism (a newer, A/B-tested protection layer on Windows 11)
6. Uses [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) to write the correct default associations for `http`, `https`, and HTML/PDF file types with the cryptographically valid hash Windows requires
7. Verifies all associations were written correctly

It also backs up your existing registry state before making any changes, so you have something to restore from if needed.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- `winget` (App Installer from the Microsoft Store)
- An internet connection (ViVeTool and PS-SFTA are downloaded automatically)
- Must be run as a **normal user, not as Administrator** — steps that require elevation self-elevate via UAC

## Usage

```powershell
# Interactive mode — pauses at each step so you can read the output
.\fix-browsertamer.ps1 -Manual

# Fewer prompts — runs with minimal pauses
.\fix-browsertamer.ps1 -SemiAuto
```

Running without either flag shows the full help text and exits. The provided fix-browsertamer.bat script is just a convenience wrapper that runs the process and lets you choose which method to use

## Persistence

Windows updates can undo parts of this fix — specifically, quality updates can re-enable UCPD and feature updates can restore the velocity task. If Browser Tamer stops intercepting links after a Windows update, re-running the script will restore everything. It is fully idempotent.

## Disclaimer

This script modifies system-level registry keys, disables a Windows kernel driver, and changes internal Windows feature flags. I take no responsibility for any damage, data loss, misconfiguration, or unintended behavior that results from running it. I share it because it works for me and might work for you — but you run it at your own risk, on your own machine, with your own understanding of what it does.

If you are not comfortable with what is described above, read the [full guide](https://alteregol.cc/) first, which explains each step and the reasoning behind it in plain language before touching anything.
