# Surveillance / Spyware Scanner (Windows 10 / 11)

A **read-only** PowerShell tool that scans a Windows PC for signs that someone may be
monitoring it — screen recording, camera/microphone spying, keyloggers, and
remote-access tools.

It **only looks**. It does **not** delete, quarantine, modify, or "clean" anything,
and it makes **no network connections** — so running it will not tip off a watcher
or destroy evidence. It writes a report to the Desktop and opens it for you.

---

## How to run it

You need two files in the same folder:

- `Scan-Surveillance.ps1` (the scanner)
- `RUN_ME_Scan.bat` (the launcher)

### Option A — USB flash drive (easiest)
1. Copy **both** files to a USB stick.
2. Plug the stick into the uncle's PC.
3. Double-click **`RUN_ME_Scan.bat`**.
4. Click **Yes** on the Windows "Do you want to allow…" (UAC) prompt — this lets the
   scan see all accounts, services, and tasks, not just the logged-in user.
5. Wait a minute or two. A report opens automatically and is also saved to the Desktop.

### Option B — from GitHub
1. Download the repo (green **Code** button → **Download ZIP**) and unzip it, **or**
   `git clone` it.
2. Then follow steps 3–5 above.

### Option C — straight from PowerShell
Open PowerShell **as Administrator** in the folder and run:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scan-Surveillance.ps1
```
The `-ExecutionPolicy Bypass` part is needed because Windows blocks unsigned scripts
by default. Running it this way only affects that one run.

---

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

## Honest limitations — please read

No script can catch **every** possible form of spying with certainty. Be realistic
about what this does and doesn't do. It is a strong **first pass**, not a guarantee.

It can **miss**:
- A **skilled, custom-built implant** or **rootkit** designed to hide itself from
  exactly these kinds of checks.
- **Kernel-level or firmware/BIOS** implants.
- **Hardware** devices: a physical keylogger plugged in-line with the keyboard, or a
  hidden camera/microphone in the room. Those are found by physically inspecting the
  machine and the space, not by software.
- **Phone / account-based tracking** (e.g. location sharing, cloud-account access) —
  this scans the PC only.
- **Router- or network-level** interception upstream of the PC.

If anything below is true, go further than this script:
- The HIGH section is non-empty and you don't understand why.
- The uncle has real reason to think a specific person is involved.
- The stakes are high.

Good next steps / second opinions:
- **Sysinternals Autoruns** and **Process Explorer** (free, from Microsoft) — deeper
  look at everything that auto-starts and every running process.
- **Malwarebytes** — a second-opinion malware scan.
- **Microsoft Defender Offline scan** (Windows Security → Virus & threat protection →
  Scan options) — catches things that hide while Windows is running.
- A local **cybersecurity / digital-forensics professional** if the situation is
  serious.

---

## If the scan finds something serious

**Don't immediately delete it.** That feels satisfying but can backfire:

1. **Preserve the evidence.** Keep the saved HTML/TXT report. If a specific person may
   be responsible, deleting the tool can (a) destroy proof and (b) tip them off that
   they've been discovered — which matters most if that person has physical access to
   the machine or a close relationship to your uncle.
2. **Get a second opinion** using the tools above before acting.
3. **Consider professional help** for removal and for advice on what to do next,
   rather than acting alone in the moment.

Take screenshots, note dates/times, and decide on a calm plan.

---

## Technical notes

- **Read-only & offline** by design. No files are changed; no data leaves the machine.
- Targets **Windows PowerShell 5.1** (built into Windows 10/11) — no extra install.
- Every check is isolated, so if one part errors, the rest of the scan still completes.
- Reports are saved to the Desktop as
  `Surveillance_Scan_<PCNAME>_<timestamp>.html` and `.txt` (falls back to your temp
  folder if the Desktop isn't writable).
