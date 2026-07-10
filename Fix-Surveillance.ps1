<#
===============================================================================
  Fix-Surveillance.ps1
  Guided, REVERSIBLE remediation companion to Scan-Surveillance.ps1
===============================================================================

  This tool ACTS on the machine (unlike the scanner, which only looks). It is
  built to be safe:

    * It asks Y/N before EVERY change - nothing is automatic.
    * Config changes (Remote Assistance, RDP, Game Bar, disabling a startup
      item / service / task) are REVERSIBLE.
    * Removing a program prefers the program's OWN uninstaller. If there is no
      uninstaller, it QUARANTINES (moves, not deletes) the files so it can be
      undone. Permanent deletion is a separate, explicit step.
    * Every change is written to a log, and an undo journal lets you roll back.

  USAGE
    Normal (guided fixes):   run RUN_ME_Fix.bat   (or this script as admin)
    Undo everything:         run UNDO_Fix.bat     (or:  Fix-Surveillance.ps1 -Undo)

  It must run as Administrator. Windows-only (PowerShell 5.1+).
  IMPORTANT: For confirmed real malware, Microsoft Defender Offline and
  Malwarebytes remove infections more thoroughly than any script. Use them too.
===============================================================================
#>

[CmdletBinding()]
param([switch]$Undo)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- paths / setup
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$desk = [Environment]::GetFolderPath('Desktop')
if (-not $desk -or -not (Test-Path -LiteralPath $desk)) { $desk = $env:TEMP }
$WorkDir       = Join-Path $desk 'Surveillance_Fix'
$QuarantineDir = Join-Path $WorkDir 'Quarantine'
$JournalPath   = Join-Path $WorkDir 'undo-journal.json'
$LogPath       = Join-Path $WorkDir ("fix-log_{0}.txt" -f $ts)
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

function Write-Log {
    param([string]$Message, [string]$Color = 'Gray')
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line -ForegroundColor $Color
    try { Add-Content -LiteralPath $LogPath -Value $line } catch {}
}

function Load-Journal {
    if (Test-Path -LiteralPath $JournalPath) {
        try { return @(Get-Content -Raw -LiteralPath $JournalPath | ConvertFrom-Json) } catch { return @() }
    }
    return @()
}
$script:Journal = @(Load-Journal)
function Save-Journal { try { ($script:Journal | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $JournalPath } catch { Write-Log "Could not write undo journal: $_" 'Yellow' } }
function Add-Journal { param($Entry) $Entry | Add-Member -NotePropertyName When -NotePropertyValue (Get-Date).ToString('o') -Force; $script:Journal += ,$Entry; Save-Journal }

function Ask {
    param([string]$Question)
    while ($true) {
        $a = (Read-Host ("  {0}  [y/n]" -f $Question)).Trim().ToLower()
        if ($a -in @('y','yes'))     { return $true }
        if ($a -in @('n','no',''))   { return $false }
    }
}

function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host ("  $Text") -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
}

# ---------------------------------------------------------------- admin check
$id    = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host ''
    Write-Host '  This tool needs Administrator rights to make changes.' -ForegroundColor Red
    Write-Host '  Please close this and run RUN_ME_Fix.bat, then click YES.' -ForegroundColor Red
    Read-Host '  Press Enter to exit'
    exit 1
}

# ---------------------------------------------------------------- reg helpers
function Get-RegVal {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
function Set-RegValReversible {
    param([string]$Path, [string]$Name, $NewValue, [string]$Type = 'DWord', [string]$Label)
    $old      = Get-RegVal -Path $Path -Name $Name
    $existed  = ($null -ne $old)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $NewValue -PropertyType $Type -Force | Out-Null
    Add-Journal ([PSCustomObject]@{ Type='Reg'; Label=$Label; Path=$Path; Name=$Name; OldValue=$old; OldExisted=$existed; RegType=$Type })
    Write-Log ("Changed [{0}] {1}\{2} -> {3} (was: {4})" -f $Label, $Path, $Name, $NewValue, $(if($existed){$old}else{'not set'})) 'Green'
}

# path guardrail: never touch Windows tree or bare roots
function Test-SafeToRemovePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Path.Trim('"')) } catch { return $false }
    $lower = $full.ToLower().TrimEnd('\')
    if (($lower -split '\\').Count -lt 3) { return $false }                 # must be >=2 levels deep
    $win = $env:SystemRoot.ToLower()
    if ($lower -eq $win -or $lower -like "$win\*") { return $false }        # anything under Windows
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:USERPROFILE,
               "$env:USERPROFILE\appdata\local", "$env:USERPROFILE\appdata\roaming", "$env:SystemDrive\") |
             Where-Object { $_ } | ForEach-Object { $_.ToLower().TrimEnd('\') }
    if ($roots -contains $lower) { return $false }                         # exact protected root only
    return $true
}

# ================================================================ UNDO MODE
if ($Undo) {
    Write-Header 'UNDO - rolling back changes from the journal'
    if ($script:Journal.Count -eq 0) { Write-Host '  Nothing to undo (no journal found).' -ForegroundColor Yellow; Read-Host '  Press Enter to exit'; exit 0 }

    # process most-recent first
    $reversed = @($script:Journal); [array]::Reverse($reversed)
    foreach ($e in $reversed) {
        try {
            switch ($e.Type) {
                'Reg' {
                    if ($e.OldExisted) {
                        if (-not (Test-Path -LiteralPath $e.Path)) { New-Item -Path $e.Path -Force | Out-Null }
                        New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $e.OldValue -PropertyType $e.RegType -Force | Out-Null
                        Write-Log ("Restored {0}\{1} = {2}" -f $e.Path, $e.Name, $e.OldValue) 'Green'
                    } else {
                        Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction SilentlyContinue
                        Write-Log ("Removed {0}\{1} (was not set originally)" -f $e.Path, $e.Name) 'Green'
                    }
                }
                'RunValue' {
                    New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $e.Value -PropertyType 'String' -Force | Out-Null
                    Write-Log ("Restored startup entry '{0}'" -f $e.Name) 'Green'
                }
                'Service' {
                    Set-Service -Name $e.Name -StartupType $e.PrevStart -ErrorAction SilentlyContinue
                    Write-Log ("Restored service '{0}' start type -> {1}" -f $e.Name, $e.PrevStart) 'Green'
                }
                'Task' {
                    Enable-ScheduledTask -TaskName $e.TaskName -TaskPath $e.TaskPath -ErrorAction SilentlyContinue | Out-Null
                    Write-Log ("Re-enabled scheduled task '{0}'" -f $e.TaskName) 'Green'
                }
                'File' {
                    if (Test-Path -LiteralPath $e.Quarantined) {
                        $parent = Split-Path -Parent $e.Original
                        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
                        Move-Item -LiteralPath $e.Quarantined -Destination $e.Original -Force
                        Write-Log ("Restored from quarantine -> {0}" -f $e.Original) 'Green'
                    }
                }
                'Uninstall' { Write-Log ("NOTE: '{0}' was uninstalled - reinstall it manually if that was a mistake." -f $e.Name) 'Yellow' }
            }
        } catch { Write-Log ("Could not undo one item ({0}): {1}" -f $e.Type, $_) 'Yellow' }
    }
    # clear the journal after a successful undo pass
    $script:Journal = @(); Save-Journal
    Write-Host ''
    Write-Host '  Undo complete. A reboot is recommended so all changes settle.' -ForegroundColor Green
    Read-Host '  Press Enter to exit'
    exit 0
}

# ================================================================ NORMAL MODE
Clear-Host
Write-Host ''
Write-Host '  SURVEILLANCE FIX - guided, reversible remediation' -ForegroundColor White
Write-Host '  Every change asks first. Undo anytime with UNDO_Fix.bat.' -ForegroundColor DarkGray
Write-Host ("  Log + quarantine folder: {0}" -f $WorkDir) -ForegroundColor DarkGray

# suspicious name patterns (compact subset - spyware / screen monitors / remote tools)
$SpywarePatterns = @('mspy','flexispy','spyzie','hoverwatch','cocospy','mobistealth','refog','spyrix','ardamax',
    'spytech','spyagent','webwatcher','veriato','spectorsoft','staffcop','ikeymonitor','kidlogger','thetruthspy',
    'realtimespy','realtime-spy','netvizor','actual keylogger','revealer keylogger','elite keylogger','perfect keylogger',
    'all in one keylogger','wolfeye','snake keylogger','darkcomet','quasar','njrat','nanocore','remcos','asyncrat')
$ScreenMonitorPatterns = @('teramind','hubstaff','time doctor','timedoctor','activtrak','kickidler','clevercontrol',
    'controlio','desktime','insightful','workpuls','monitask','sentrypc','softactivity','ekran','observeit','osmonitor',
    'imonitor','worktime','work examiner','birch grove','time champ','traqq','teamlogger','screenshotmonitor')
$RemoteToolPatterns = @('anydesk','teamviewer','rustdesk','ultravnc','tightvnc','realvnc','tigervnc','vnc server',
    'splashtop','screenconnect','connectwise control','logmein','remote utilities','rutserv','netsupport','client32',
    'ateraagent','dwservice','dwagent','aeroadmin','ammyy','radmin','dameware','meshagent','meshcentral','ninjarmm',
    'chrome remote desktop','remoting_host','supremo','getscreen','iperius remote')
$AllPatterns = $SpywarePatterns + $ScreenMonitorPatterns + $RemoteToolPatterns

function Test-Match {
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.ToLower()
    foreach ($p in $Patterns) { if ($t.Contains($p)) { return $p } }
    return $null
}

# gather inventory once
Write-Host ''
Write-Host '  Gathering current state...' -ForegroundColor DarkGray
$Procs = @()
try { $Procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine } catch {}
$Svcs = @()
try { $Svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, State, StartMode } catch {}
function Get-Installed {
    $roots = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
               'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $l = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        Get-ChildItem -Path $r -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.DisplayName) {
                $l.Add([PSCustomObject]@{
                    DisplayName     = "$($p.DisplayName)"
                    Publisher       = "$($p.Publisher)"
                    InstallLocation = "$($p.InstallLocation)"
                    UninstallString = "$($p.UninstallString)"
                })
            }
        }
    }
    return $l
}
$Installed = Get-Installed

# ---------------------------------------------------------------- 1. HARDENING
Write-Header '1. HARDENING - reversible settings'

# Remote Assistance
$raPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$ra = Get-RegVal -Path $raPath -Name 'fAllowToGetHelp'
if ($ra -eq 1) {
    Write-Host ''
    Write-Host '  Remote Assistance is ENABLED (lets someone connect to "assist").' -ForegroundColor Yellow
    if (Ask 'Disable Remote Assistance?') { Set-RegValReversible -Path $raPath -Name 'fAllowToGetHelp' -NewValue 0 -Label 'Remote Assistance' }
} else { Write-Host '  Remote Assistance already disabled - nothing to do.' -ForegroundColor Green }

# Remote Desktop (RDP)
$tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdp = Get-RegVal -Path $tsPath -Name 'fDenyTSConnections'
if ($rdp -eq 0) {
    Write-Host ''
    Write-Host '  Remote Desktop (RDP) is ENABLED (full remote control of the PC).' -ForegroundColor Yellow
    if (Ask 'Disable Remote Desktop? (say no if IT/you use it)') { Set-RegValReversible -Path $tsPath -Name 'fDenyTSConnections' -NewValue 1 -Label 'Remote Desktop (RDP)' }
} else { Write-Host '  Remote Desktop already disabled - nothing to do.' -ForegroundColor Green }

# Game Bar background recording
$gbPath = 'HKCU:\System\GameConfigStore'
$gb = Get-RegVal -Path $gbPath -Name 'GameDVR_Enabled'
if ($gb -eq 1) {
    Write-Host ''
    Write-Host '  Xbox Game Bar background recording is ON (built-in screen capture).' -ForegroundColor Yellow
    if (Ask 'Turn off Game Bar background recording?') { Set-RegValReversible -Path $gbPath -Name 'GameDVR_Enabled' -NewValue 0 -Label 'Game Bar recording' }
} else { Write-Host '  Game Bar background recording already off - nothing to do.' -ForegroundColor Green }

# ---------------------------------------------------------------- 2. STARTUP
Write-Header '2. STARTUP ITEMS - disable things that launch automatically'
Write-Host '  Disabling is reversible. Skip anything you recognise as yours.' -ForegroundColor DarkGray

$runKeys = @(
    @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';               Hive='HKCU' },
    @{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';               Hive='HKLM' },
    @{ Path='HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';   Hive='HKLM32' }
)
foreach ($rk in $runKeys) {
    if (-not (Test-Path -LiteralPath $rk.Path)) { continue }
    $props = Get-ItemProperty -LiteralPath $rk.Path
    foreach ($name in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
        $val = "$($props.$name)"
        $flag = Test-Match -Text ("$name $val") -Patterns $AllPatterns
        $tag  = if ($flag) { " [matches '$flag']" } else { '' }
        $col  = if ($flag) { 'Red' } else { 'Gray' }
        Write-Host ''
        Write-Host ("  Startup ({0}): {1}{2}" -f $rk.Hive, $name, $tag) -ForegroundColor $col
        Write-Host ("      {0}" -f $val) -ForegroundColor DarkGray
        if (Ask 'Disable this startup entry?') {
            Add-Journal ([PSCustomObject]@{ Type='RunValue'; Path=$rk.Path; Name=$name; Value=$val })
            Remove-ItemProperty -LiteralPath $rk.Path -Name $name -ErrorAction SilentlyContinue
            Write-Log ("Disabled startup entry '{0}'" -f $name) 'Green'
        }
    }
}
# Startup folder shortcuts
foreach ($sf in @([Environment]::GetFolderPath('Startup'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))) {
    if (-not ($sf -and (Test-Path -LiteralPath $sf))) { continue }
    Get-ChildItem -LiteralPath $sf -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host ''
        Write-Host ("  Startup folder shortcut: {0}" -f $_.Name) -ForegroundColor Gray
        if (Ask 'Disable (move to quarantine) this shortcut?') {
            $dest = Join-Path $QuarantineDir ("startup_" + $_.Name)
            New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
            Add-Journal ([PSCustomObject]@{ Type='File'; Original=$_.FullName; Quarantined=$dest })
            Move-Item -LiteralPath $_.FullName -Destination $dest -Force
            Write-Log ("Quarantined startup shortcut '{0}'" -f $_.Name) 'Green'
        }
    }
}

# ---------------------------------------------------------------- 3. PROGRAMS
Write-Header '3. DETECTED SURVEILLANCE-RELATED PROGRAMS'
Write-Host '  Prefer [U]ninstall. [Q]uarantine moves files aside (reversible).' -ForegroundColor DarkGray
Write-Host '  Nothing here is deleted now; permanent delete is a separate step.' -ForegroundColor DarkGray

$handled = @{}

function Quarantine-Program {
    param([string]$Name, [string]$Folder)
    # stop matching processes
    foreach ($p in $Procs) {
        $under = ($Folder -and $p.ExecutablePath -and $p.ExecutablePath.ToLower().StartsWith($Folder.ToLower()))
        $named = (Test-Match -Text ("$($p.Name) $($p.ExecutablePath)") -Patterns $AllPatterns)
        if ($under -or $named) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; Write-Log ("Stopped process {0} (PID {1})" -f $p.Name, $p.ProcessId) 'Green' } catch {}
        }
    }
    # stop + disable matching services
    foreach ($s in $Svcs) {
        $under = ($Folder -and $s.PathName -and $s.PathName.ToLower().Contains($Folder.ToLower()))
        $named = (Test-Match -Text ("$($s.Name) $($s.DisplayName) $($s.PathName)") -Patterns $AllPatterns)
        if ($under -or $named) {
            $prev = switch ($s.StartMode) { 'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {'Manual'} }
            try {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                Set-Service  -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Add-Journal ([PSCustomObject]@{ Type='Service'; Name=$s.Name; PrevStart=$prev })
                Write-Log ("Stopped + disabled service '{0}'" -f $s.Name) 'Green'
            } catch {}
        }
    }
    # move the install folder (if we can locate a safe one)
    if ($Folder -and (Test-Path -LiteralPath $Folder)) {
        if (Test-SafeToRemovePath -Path $Folder) {
            $dest = Join-Path $QuarantineDir (Split-Path $Folder -Leaf)
            if (Test-Path -LiteralPath $dest) { $dest = "$dest`_$ts" }
            New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
            try {
                Move-Item -LiteralPath $Folder -Destination $dest -Force
                Add-Journal ([PSCustomObject]@{ Type='File'; Original=$Folder; Quarantined=$dest })
                Write-Log ("Quarantined folder -> {0}" -f $dest) 'Green'
            } catch { Write-Log ("Could not move folder (likely a file is locked/in use): {0}" -f $_) 'Yellow' }
        } else {
            Write-Log ("Skipped moving '{0}' - path is protected/unsafe. Use the uninstaller instead." -f $Folder) 'Yellow'
        }
    } else {
        Write-Log ("No install folder located for '{0}'. Persistence disabled; use the uninstaller to fully remove." -f $Name) 'Yellow'
    }
}

$foundAny = $false
foreach ($app in $Installed) {
    $flag = Test-Match -Text ("$($app.DisplayName) $($app.Publisher)") -Patterns $AllPatterns
    if (-not $flag) { continue }
    if ($handled.ContainsKey($app.DisplayName)) { continue }
    $handled[$app.DisplayName] = $true
    $foundAny = $true

    Write-Host ''
    Write-Host ("  >> {0}" -f $app.DisplayName) -ForegroundColor Red
    Write-Host ("     Publisher: {0}   (matched '{1}')" -f $app.Publisher, $flag) -ForegroundColor DarkGray
    if ($app.InstallLocation) { Write-Host ("     Folder: {0}" -f $app.InstallLocation) -ForegroundColor DarkGray }
    Write-Host '     NOTE: on a WORK PC this may be sanctioned IT monitoring - be sure before removing.' -ForegroundColor Yellow

    $hasUninst = -not [string]::IsNullOrWhiteSpace($app.UninstallString)
    $choice = (Read-Host ("     Action - [U]ninstall{0} / [Q]uarantine / [S]kip" -f $(if($hasUninst){''}else{' (none available)'}))).Trim().ToUpper()

    if ($choice -eq 'U' -and $hasUninst) {
        Write-Log ("Launching uninstaller for '{0}'" -f $app.DisplayName) 'Cyan'
        try {
            $u = $app.UninstallString
            if ($u -match 'msiexec') {
                $guid = ([regex]::Match($u, '\{[0-9A-Fa-f\-]+\}')).Value
                if ($guid) { Start-Process 'msiexec.exe' -ArgumentList "/x $guid" -Wait }
                else { Start-Process 'cmd.exe' -ArgumentList '/c', $u -Wait }
            } else {
                # run the vendor uninstaller UI so the user can follow it
                Start-Process 'cmd.exe' -ArgumentList '/c', "`"$u`"" -Wait
            }
            Add-Journal ([PSCustomObject]@{ Type='Uninstall'; Name=$app.DisplayName })
            Write-Log ("Uninstaller finished for '{0}'" -f $app.DisplayName) 'Green'
        } catch { Write-Log ("Uninstaller error: {0}" -f $_) 'Yellow' }
    }
    elseif ($choice -eq 'Q') {
        Quarantine-Program -Name $app.DisplayName -Folder $app.InstallLocation
    }
    else { Write-Host '     Skipped.' -ForegroundColor DarkGray }
}

# services / processes that matched but had no installed-program entry
foreach ($s in $Svcs) {
    $flag = Test-Match -Text ("$($s.Name) $($s.DisplayName) $($s.PathName)") -Patterns $AllPatterns
    if (-not $flag) { continue }
    if ($handled.ContainsKey("svc:$($s.Name)")) { continue }
    $handled["svc:$($s.Name)"] = $true
    $foundAny = $true
    Write-Host ''
    Write-Host ("  >> Service: {0} ({1})  matched '{2}'" -f $s.DisplayName, $s.Name, $flag) -ForegroundColor Red
    Write-Host ("     Path: {0}" -f $s.PathName) -ForegroundColor DarkGray
    if (Ask 'Stop + disable this service? (reversible)') {
        $prev = switch ($s.StartMode) { 'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {'Manual'} }
        try {
            Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Add-Journal ([PSCustomObject]@{ Type='Service'; Name=$s.Name; PrevStart=$prev })
            Write-Log ("Stopped + disabled service '{0}'" -f $s.Name) 'Green'
        } catch { Write-Log ("Service change error: {0}" -f $_) 'Yellow' }
    }
}
foreach ($p in $Procs) {
    $flag = Test-Match -Text ("$($p.Name) $($p.ExecutablePath)") -Patterns $AllPatterns
    if (-not $flag) { continue }
    if ($handled.ContainsKey("proc:$($p.ExecutablePath)")) { continue }
    $handled["proc:$($p.ExecutablePath)"] = $true
    $foundAny = $true
    Write-Host ''
    Write-Host ("  >> Running: {0}  matched '{1}'" -f $p.Name, $flag) -ForegroundColor Red
    Write-Host ("     Path: {0}" -f $p.ExecutablePath) -ForegroundColor DarkGray
    if (Ask 'Stop this process and quarantine its file? (reversible)') {
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
        if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath) -and (Test-SafeToRemovePath -Path $p.ExecutablePath)) {
            $dest = Join-Path $QuarantineDir (Split-Path $p.ExecutablePath -Leaf)
            if (Test-Path -LiteralPath $dest) { $dest = "$dest`_$ts" }
            New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
            try {
                Move-Item -LiteralPath $p.ExecutablePath -Destination $dest -Force
                Add-Journal ([PSCustomObject]@{ Type='File'; Original=$p.ExecutablePath; Quarantined=$dest })
                Write-Log ("Quarantined '{0}'" -f $p.ExecutablePath) 'Green'
            } catch { Write-Log ("Could not move file (in use?): {0}" -f $_) 'Yellow' }
        }
    }
}
if (-not $foundAny) { Write-Host ''; Write-Host '  No known surveillance-related programs matched. Good.' -ForegroundColor Green }

# ---------------------------------------------------------------- 4. DELETE
Write-Header '4. PERMANENT DELETE (optional)'
if (Test-Path -LiteralPath $QuarantineDir) {
    $qItems = Get-ChildItem -LiteralPath $QuarantineDir -ErrorAction SilentlyContinue
    if ($qItems -and $qItems.Count -gt 0) {
        Write-Host '  These items are in quarantine (still recoverable):' -ForegroundColor Yellow
        $qItems | ForEach-Object { Write-Host ("    - {0}" -f $_.Name) -ForegroundColor DarkGray }
        Write-Host ''
        Write-Host '  Deleting is PERMANENT and cannot be undone. Only do this once you are' -ForegroundColor Red
        Write-Host '  sure these are not needed. If unsure, leave them here.' -ForegroundColor Red
        $c = (Read-Host '  Type DELETE to permanently erase the quarantine, or press Enter to keep it').Trim()
        if ($c -ceq 'DELETE') {
            try { Remove-Item -LiteralPath $QuarantineDir -Recurse -Force; Write-Log 'Quarantine permanently deleted.' 'Green' }
            catch { Write-Log ("Delete error: {0}" -f $_) 'Yellow' }
        } else { Write-Host '  Kept quarantine. You can delete it later or restore with UNDO_Fix.bat.' -ForegroundColor Green }
    } else { Write-Host '  Quarantine is empty - nothing to delete.' -ForegroundColor Green }
} else { Write-Host '  Nothing was quarantined.' -ForegroundColor Green }

# ---------------------------------------------------------------- done
Write-Host ''
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Write-Host '  Done.' -ForegroundColor White
Write-Host ("  Log saved to: {0}" -f $LogPath) -ForegroundColor Gray
Write-Host '  To reverse the changes made in this run, run UNDO_Fix.bat.' -ForegroundColor Gray
Write-Host '  For confirmed malware, also run a Microsoft Defender Offline scan' -ForegroundColor Gray
Write-Host '  and/or Malwarebytes - they remove infections more thoroughly.' -ForegroundColor Gray
Write-Host '  A reboot is a good idea after making changes.' -ForegroundColor Gray
Write-Host ('=' * 74) -ForegroundColor DarkCyan
Read-Host '  Press Enter to exit'
