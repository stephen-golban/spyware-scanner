# Surveillance / Spyware Toolkit (Windows 10 / 11)

Two tools for a Windows PC:

1. **The scanner** — a **read-only** check for signs that someone may be monitoring the
   machine (screen recording, camera/mic spying, keyloggers, remote-access tools, and
   more). It only looks; it changes nothing and makes no network connections.
2. **The fix tool** — a **separate, guided** tool that can turn off risky settings and
   remove flagged software. It asks before every change and everything it does is
   reversible.

Keeping them separate is deliberate: the scanner stays provably "look but don't touch"
(safe to hand to anyone), while the tool that actually changes the system is opt-in and
only run by someone who knows what they're doing.

---

## What's in this pack

| File | What it is |
|------|------------|
| `1_SCAN.bat` | Double-click launcher for the scanner. |
| `2_FIX.bat` | Double-click launcher for the fix tool. |
| `3_UNDO.bat` | Reverses every change the fix tool made. |
| `scan-engine.ps1` | The scanner itself (read-only). Run by `1_SCAN.bat` — don't double-click it directly. |
| `fix-engine.ps1` | The guided remediation tool itself (makes reversible changes). Run by `2_FIX.bat` / `3_UNDO.bat`. |
| `INSTRUCTIONS.txt` | Plain-language, step-by-step guide for running **the scan** (written for a non-technical person). |
| `README.md` | This file. |

**Recommended order:** run the scan first, read the report, then — only if needed and
only on a machine you're comfortable changing — run the fix tool.

---

# PART 1 — THE SCAN (read-only)

## How to run it

Keep all the files in the same folder (they already are, in the repo) — the launchers
look for the engine scripts next to them.

1. Download the repository and extract it so you see the files together.
2. Double-click **`1_SCAN.bat`** → on "Windows protected your PC" click
   **More info → Run anyway** → click **Yes** on the admin prompt.
3. Wait 1–2 minutes. A report opens automatically and is saved to the Desktop.

> If a script refuses to run after download: right-click it → **Properties** → tick
> **Unblock** → OK. Windows flags downloaded files as blocked; this clears it.

**For a full click-by-click walkthrough of the whole toolkit — scan, fix, and
undo — see `INSTRUCTIONS.txt`.**

## What the report shows

Findings are grouped by severity so you don't drown in noise:

- **HIGH** — deserves prompt attention (e.g. *an app is using the camera right now*,
  known stalkerware present, a program running the camera from a Temp folder).
- **MEDIUM** — a human should **review** it. Many MEDIUM items are completely normal
  (Zoom/Teams use the camera; company IT may legitimately install a remote tool).
- **INFO** — context and inventory, not necessarily a problem.

### The headline check: camera & microphone history
Windows quietly records **which apps used the webcam and mic, and when**. This tool
reads that history and — importantly — can tell if something is **recording at this
very moment** (it flags those in red). This is often the fastest way to catch active
spying. (Requires Windows 10 version 1903 or newer.)

It also checks: known consumer spyware/keylogger names, remote-access tools
(AnyDesk, TeamViewer, VNC, RustDesk, ScreenConnect, and many more), **screen
recorders and silent screen-tracking / screenshot-monitoring tools** (both ordinary
recorders like OBS or Camtasia and covert "employee monitoring" suites such as
Teramind, ActivTrak, Hubstaff, Veriato, SoftActivity, and similar), autostart
persistence (Run keys, Startup folder, Scheduled Tasks, Services, Winlogon,
Image-File-Execution-Options hijacks), unsigned programs running from suspicious
folders, live network connections to known remote-control ports, RDP / Remote
Assistance / WinRM exposure, recently installed software, hosts-file tampering,
and unexpected local user accounts.

---

# PART 2 — THE FIX TOOL (makes changes)

Run this **only after** you've read the scan report and understand what you're changing.
It needs `fix-engine.ps1`, `2_FIX.bat`, and `3_UNDO.bat` together.

## How to run it
1. Double-click **`2_FIX.bat`** and approve the admin prompt.
2. It walks you through four stages, asking **y/n before every single change**:
   - **Hardening** — offer to disable Remote Assistance, Remote Desktop (RDP), and
     Xbox Game Bar background recording. Reversible.
   - **Startup items** — list what launches automatically (flagging anything that
     matches known spy/monitor/remote-tool names) and let you disable them one at a
     time. Reversible.
   - **Detected programs** — for anything matching the surveillance name lists, offer
     **[U]ninstall** (runs the program's own uninstaller), **[Q]uarantine** (stop it,
     disable its service, strip its persistence, and *move* its files aside — reversible),
     or **[S]kip**.
   - **Permanent delete** — optional and separate. You must type `DELETE` after seeing
     exactly what's in quarantine. This is the only step that can't be undone.
3. A log and a `Quarantine` folder are saved on the Desktop under `Surveillance_Fix`.

## Undo
Made a change you regret? Double-click **`3_UNDO.bat`**. It reads the undo journal and
reverses everything from the last run — restores the settings, re-enables services,
and moves quarantined files back to where they were. (The one thing it can't reverse is
a program you chose to fully **uninstall**, or a quarantine you chose to **permanently
delete**.)

## How removal is kept safe
- Config changes and "disable" actions are **reversible**.
- Removing a program **prefers the program's own uninstaller** (cleanest), and otherwise
  **quarantines by moving files**, not deleting them.
- A **path guardrail** refuses to touch the Windows folder or bare drive/Program-Files
  roots, so a mistaken match can't damage the OS.
- **Nothing is permanently deleted** unless you explicitly type `DELETE` at the end.

> **For confirmed real malware, also run Microsoft Defender Offline and/or Malwarebytes.**
> This tool disables and quarantines; a real AV engine removes infections more completely
> (locked files, boot-time removal, things that respawn). Treat this as hardening plus
> cleanup of the obvious stuff — not as a replacement for antivirus on an active infection.

---

## Honest limitations — please read

No script can catch **every** possible form of spying with certainty. It is a strong
**first pass**, not a guarantee.

The scanner can **miss**:
- A **skilled, custom-built implant** or **rootkit** designed to hide from exactly these
  kinds of checks.
- **Kernel-level or firmware/BIOS** implants.
- **Hardware** devices: a physical keylogger in-line with the keyboard, or a hidden
  camera/microphone in the room. Those need a physical inspection, not software.
- **Phone / account-based tracking** (location sharing, cloud-account access) — this
  scans the PC only.
- **Router- or network-level** interception upstream of the PC.

Go further than these tools if: the HIGH section isn't empty and you don't understand
why; there's real reason to think a specific person is involved; or the stakes are high.

Good next steps / second opinions:
- **Sysinternals Autoruns** and **Process Explorer** (free, Microsoft) — deeper look at
  everything that auto-starts and every running process.
- **Malwarebytes** — a second-opinion malware scan.
- **Microsoft Defender Offline scan** (Windows Security → Virus & threat protection →
  Scan options) — catches things that hide while Windows is running.
- A local **cybersecurity / digital-forensics professional** if the situation is serious.

## If the scan finds something serious

**Don't rush to delete.** If a specific person may be responsible, wiping things can
(a) destroy evidence and (b) tip them off — which matters most if that person has
physical access or a close relationship to the PC's owner. Prefer to:
1. **Preserve the evidence** — keep the saved HTML/TXT report; take screenshots.
2. **Get a second opinion** with the tools above.
3. **Consider professional help** rather than acting alone in the moment.

The fix tool's quarantine (move, don't delete) is designed to support this — you can
neutralise something while keeping it recoverable.

---

## Technical notes
- **Scanner:** read-only and offline. No files changed; nothing leaves the machine.
- **Fix tool:** every change asks first, is logged, and is reversible (except explicit
  uninstall / permanent delete).
- Both target **Windows PowerShell 5.1** (built into Windows 10/11) — no extra install.
- Each check is isolated, so if one part errors the rest still completes.
- Scanner reports save to the Desktop as `Surveillance_Scan_<PCNAME>_<timestamp>.html`
  and `.txt`; fix-tool logs and quarantine live in `Surveillance_Fix` on the Desktop
  (both fall back to your temp folder if the Desktop isn't writable).
