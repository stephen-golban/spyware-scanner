<#
================================================================================
  SURVEILLANCE / SPYWARE SCANNER  (Windows 10 / 11)
================================================================================
  Purpose : Read-only scan of a Windows PC for signs of monitoring/spying:
            - Which programs have used the WEBCAM / MICROPHONE (and if any is
              recording RIGHT NOW)
            - Known consumer spyware / stalkerware / keyloggers
            - Remote-access tools (AnyDesk, TeamViewer, VNC, RustDesk, RATs...)
            - Screen recorders & silent screen-tracking / screenshot monitors
              (OBS, Camtasia... and covert tools like Teramind, ActivTrak, etc.)
            - Autostart persistence (Run keys, Startup, Scheduled Tasks,
              Services, Winlogon, Image-File-Execution-Options)
            - Suspicious processes (unsigned / running from Temp/AppData/etc.)
            - Active network connections to remote-control ports
            - RDP / Remote Assistance / WinRM exposure
            - Recently installed software, hosts-file tampering, local accounts

  SAFETY  : This script is READ-ONLY. It does NOT delete, quarantine, modify,
            or "clean" anything. It only inspects the system and writes a
            report to the Desktop. It makes NO network connections.
            Nothing here alerts a watcher or changes evidence.

  RUN     : Best run as Administrator for full coverage. Easiest way:
            double-click  RUN_ME_Scan.bat  (it will ask for admin and launch
            this file). Or from an elevated PowerShell:
              powershell -NoProfile -ExecutionPolicy Bypass -File .\Scan-Surveillance.ps1

  NOTE    : "MEDIUM" findings are things a human should REVIEW - many are
            perfectly legitimate (Zoom uses your camera; company IT may use a
            remote tool). "HIGH" findings deserve prompt attention. Read the
            report; don't panic at a long list.
================================================================================
#>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ------------------------------------------------------------------ globals ---
$script:Findings    = New-Object System.Collections.Generic.List[object]
$script:CamMicTable = New-Object System.Collections.Generic.List[object]
$script:SigCache    = @{}
$script:Processes   = @()
$script:Services    = @()
$script:Installed   = @()

# --------------------------------------------------------- indicator lists ----
# Remote-access / remote-monitoring tools (legitimate, but abusable for spying)
$RemoteToolPatterns = @(
    'anydesk','teamviewer','rustdesk','ultraviewer','aeroadmin','ammyy','splashtop',
    'screenconnect','connectwise','logmein','gotomypc','remoteutilities','rutserv','rfusclient',
    'netsupport','client32','ateraagent','dwagent','dwservice','dwrcc','dwrcs',
    'showmypc','remotepc','iperius','supremo','litemanager','radmin','dameware',
    'realvnc','tightvnc','ultravnc','tigervnc','winvnc','vncserver','tvnserver','tvnviewer',
    'parsec','nomachine','zohoassist','bomgar','beyondtrust','kaseya','ninjarmm','ninjarmmagent',
    'action1','pulseway','syncroagent','fleetdeck','meshagent','tacticalagent',
    'remoting_host','chromoting','getscreen','airdroid'
)
$RemotePublisherPatterns = @(
    'teamviewer','anydesk','philandro','realvnc','uvnc','ultravnc','tightvnc','splashtop',
    'logmein','netsupport','remote utilities','famatech','nanosystems','supremo','nomachine',
    'parsec','zoho','beyondtrust','bomgar','ninjarmm','connectwise','getscreen','aeroadmin',
    'aweray','iperius','remotepc','pro softnet','dameware'
)
# Consumer spyware / stalkerware / keyloggers (distinctive product names)
$SpywarePatterns = @(
    'mspy','flexispy','hoverwatch','spyzie','cocospy','mobistealth','umobix','eyezy','xnspy',
    'spyera','thetruthspy','ispyoo','copy9','highster','ikeymonitor','kidlogger','refog','spyrix',
    'ardamax','actualkeylogger','elitekeylogger','perfectkeylogger','spytech','spyagent',
    'realtime-spy','realtimespy','webwatcher','netvizor','staffcop','veriato','spectorsoft',
    'interguard','pcpandora','winspy','win-spy','allinonekeylogger','revealerkeylogger','wolfeye',
    'mickeylogger','keylogger','keystroke','spymaster','clevguard','kidsguard','fonemonitor',
    'actualspy','powerspy','familykeylogger','homekeylogger','invisiblekeylogger','remotespy',
    'netbull','spyhuman','snitchsoftware','pcspy','wintective'
)
# Overt RAT malware families (usually caught by AV, but list them)
$RatMalwarePatterns = @(
    'darkcomet','quasar','njrat','nanocore','remcos','asyncrat','venomrat','warzone','avemaria',
    'netwire','orcus','njw0rm','xtremerat','cybergate','blackshades','luminosity','plasmarat',
    'hworm','adwind','babylonrat','xenorat','dcrat','limerat'
)
# Screen-recording capable software (usually legit - process EXE names, exact match)
$ScreenRecorderExe = @(
    'obs64.exe','obs32.exe','obs.exe','bandicam.exe','bdcam.exe','camtasia.exe','camtasiastudio.exe',
    'camrecorder.exe','snagiteditor.exe','snagit32.exe','snagitcapture.exe','tscc.exe',
    'sharex.exe','flashback.exe','fbrecorder.exe','activepresenter.exe','screenpresso.exe','screenrec.exe',
    'loom.exe','debut.exe','fraps.exe','xsplit.core.exe','xsplit.broadcaster.exe','screentogif.exe',
    'captura.exe','ocam.exe','apowerrec.exe','icecream screen recorder.exe','iscreenrecorder.exe',
    'movaviscreenrecorder.exe','filmorascrn.exe','dxtory.exe','action.exe','mirillis action.exe',
    'zdsoftscreenrecorder.exe','ezvid.exe','tinytake.exe','gyazo.exe','greenshot.exe','lightshot.exe',
    'faststone capture.exe','fscapture.exe','psr.exe'
)
# Screen-recorder / screenshot product names (substring match against installed apps)
$ScreenRecorderPatterns = @(
    'obs studio','bandicam','camtasia','snagit','sharex','flashback express','activepresenter',
    'screenpresso','screenrec','loom','debut video','fraps','xsplit','screentogif','captura',
    'ocam','apowersoft','icecream screen','movavi screen','filmora scrn','dxtory','mirillis action',
    'zd soft','ezvid','tinytake','gyazo','greenshot','lightshot','faststone capture','screencast'
)
# Silent screen-monitoring / screenshot-capture surveillance & "employee monitoring" suites.
# These periodically grab screenshots or record the screen, often invisibly. On a company PC
# this can be sanctioned IT monitoring; on a personal machine it is a strong red flag.
$ScreenMonitorPatterns = @(
    'teramind','hubstaff','time doctor','timedoctor','activtrak','kickidler','clevercontrol',
    'controlio','desktime','insightful','workpuls','monitask','sentrypc','softactivity','soft activity',
    'ekran','observeit','osmonitor','imonitor','worktime','work examiner','workexaminer','birch grove',
    'birchgrove','time champ','timechamp','traqq','teamlogger','screenshotmonitor','screenshot monitor',
    'workstatus','desklog','trackabi','hivedesk','stealthmonitor','stealth monitor','screenspy',
    'screen spy','screencapturemonitor'
)
# Well-known ports used by remote-control software
$RatPorts = @{
    5938='TeamViewer'; 7070='AnyDesk'; 6568='AnyDesk(legacy)';
    5650='Remote Utilities'; 5655='Remote Utilities';
    5900='VNC'; 5901='VNC'; 5902='VNC'; 5903='VNC'; 5800='VNC(web)';
    21115='RustDesk'; 21116='RustDesk'; 21117='RustDesk'; 21118='RustDesk'; 21119='RustDesk';
    6129='DameWare'; 4899='Radmin'; 8040='Bomgar/BeyondTrust'
}
# Path fragments where legit software rarely runs from (user-writable = higher risk)
$StrongSuspiciousPaths = @('\appdata\local\temp\','\windows\temp\','\temp\','\users\public\',
    '\public\','\$recycle.bin\','\perflogs\','\windows\tasks\','\windows\system32\tasks\','\downloads\')
$WeakSuspiciousPaths   = @('\appdata\roaming\','\appdata\local\','\programdata\')

# ---------------------------------------------------------------- helpers -----
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor White
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}

function Add-Finding {
    param(
        [ValidateSet('HIGH','MEDIUM','INFO')][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Detail = ''
    )
    $script:Findings.Add([PSCustomObject]@{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail
    })
    switch ($Severity) { 'HIGH' {$c='Red'} 'MEDIUM' {$c='Yellow'} default {$c='Gray'} }
    Write-Host ('  [{0,-6}] {1}' -f $Severity, $Title) -ForegroundColor $c
    if ($Detail) { Write-Host ('           {0}' -f $Detail) -ForegroundColor DarkGray }
}

function Test-Match {
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.ToLower()
    foreach ($p in $Patterns) { if ($t.Contains($p.ToLower())) { return $p } }
    return $null
}

function Convert-FileTime {
    param($Value)
    try {
        if ($null -eq $Value) { return $null }
        $v = [int64]$Value
        if ($v -le 0) { return $null }
        return [DateTime]::FromFileTime($v)
    } catch { return $null }
}

function Get-SignatureInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $info = [PSCustomObject]@{ Status='Unknown'; Signer=''; Company='' }
    try {
        if (Test-Path -LiteralPath $Path) {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $info.Status = "$($sig.Status)"
            if ($sig.SignerCertificate) {
                $cn = $sig.SignerCertificate.Subject
                if ($cn -match 'CN=([^,]+)') { $cn = $Matches[1] }
                $info.Signer = $cn
            }
            try { $info.Company = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName } catch {}
        } else { $info.Status = 'FileNotFound' }
    } catch { $info.Status = 'Error' }
    $script:SigCache[$Path] = $info
    return $info
}

function Get-PathRisk {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'none' }
    $lp = $Path.ToLower()
    foreach ($s in $StrongSuspiciousPaths) { if ($lp.Contains($s)) { return 'strong' } }
    foreach ($w in $WeakSuspiciousPaths)   { if ($lp.Contains($w)) { return 'weak' } }
    return 'none'
}

function Get-ExeFromCommand {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $idx = $c.ToLower().IndexOf('.exe')
    if ($idx -ge 0) { return $c.Substring(0, $idx + 4) }
    return ($c -split '\s+')[0]
}

function Test-IsMicrosoftSigned {
    param([string]$Path)
    $s = Get-SignatureInfo -Path $Path
    if (-not $s) { return $false }
    if ($s.Status -ne 'Valid') { return $false }
    return ($s.Signer -match 'Microsoft' -or $s.Company -match 'Microsoft')
}

# ================================================================ MODULES =====

function Get-SystemInfo {
    Write-Section 'SYSTEM INFORMATION'
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host ("  Computer : {0}" -f $env:COMPUTERNAME)
    Write-Host ("  User     : {0}" -f $id.Name)
    Write-Host ("  OS       : {0} (Build {1})" -f $os.Caption, $os.BuildNumber)
    Write-Host ("  Booted   : {0}" -f $os.LastBootUpTime)
    Write-Host ("  Elevated : {0}" -f $(if($isAdmin){'YES (full coverage)'}else{'NO'}))
    if (-not $isAdmin) {
        Add-Finding INFO 'System' 'Not running as Administrator - some checks are limited' 'For a complete scan, re-run using RUN_ME_Scan.bat and approve the admin prompt.'
    }

    Write-Host '  Collecting process / service / software inventory...' -ForegroundColor DarkGray
    try { $script:Processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId } catch {}
    if (-not $script:Processes -or $script:Processes.Count -eq 0) {
        $script:Processes = Get-Process | Select-Object @{n='ProcessId';e={$_.Id}}, @{n='Name';e={$_.ProcessName}}, @{n='ExecutablePath';e={$_.Path}}, @{n='CommandLine';e={''}}, @{n='ParentProcessId';e={0}}
    }
    try { $script:Services = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, State, StartMode, StartName } catch {}
    $script:Installed = Get-InstalledPrograms
    Write-Host ("  Processes: {0}  Services: {1}  Installed apps: {2}" -f $script:Processes.Count, $script:Services.Count, $script:Installed.Count) -ForegroundColor DarkGray
}

function Get-InstalledPrograms {
    $roots = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        Get-ChildItem -Path $r -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.DisplayName) {
                $list.Add([PSCustomObject]@{
                    DisplayName     = "$($p.DisplayName)"
                    Publisher       = "$($p.Publisher)"
                    InstallDate     = "$($p.InstallDate)"
                    InstallLocation = "$($p.InstallLocation)"
                })
            }
        }
    }
    return $list
}

function Test-CameraMicUsage {
    Write-Section 'CAMERA / MICROPHONE / LOCATION ACCESS HISTORY  (key evidence)'
    Write-Host '  Windows records which apps used the camera & mic and when. If any app' -ForegroundColor Cyan
    Write-Host '  is recording right now, it will be flagged below in RED.' -ForegroundColor Cyan

    $suffix = 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
    $roots  = @('Registry::HKEY_CURRENT_USER\' + $suffix, 'Registry::HKEY_LOCAL_MACHINE\' + $suffix)
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object {
            if ($_.PSChildName -notmatch '_Classes$') {
                $roots += ('Registry::HKEY_USERS\' + $_.PSChildName + '\' + $suffix)
            }
        }
    } catch {}

    $caps = 'webcam','microphone','location'
    foreach ($root in $roots) {
        foreach ($cap in $caps) {
            $capPath = $root + '\' + $cap
            if (-not (Test-Path -LiteralPath $capPath)) { continue }
            # Packaged (Store) apps = direct child keys; plus NonPackaged child key
            Get-ChildItem -LiteralPath $capPath -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSChildName -eq 'NonPackaged') { return }
                Add-CamMicEntry -Cap $cap -KeyName $_.PSChildName -KeyPath $_.PSPath -Packaged $true
            }
            $npPath = $capPath + '\NonPackaged'
            if (Test-Path -LiteralPath $npPath) {
                Get-ChildItem -LiteralPath $npPath -ErrorAction SilentlyContinue | ForEach-Object {
                    Add-CamMicEntry -Cap $cap -KeyName $_.PSChildName -KeyPath $_.PSPath -Packaged $false
                }
            }
        }
    }

    if ($script:CamMicTable.Count -eq 0) {
        Write-Host '  No camera/microphone usage history found (or unsupported Windows build).' -ForegroundColor DarkGray
        Add-Finding INFO 'Camera/Mic' 'No camera/mic usage records found' 'Either nothing has used them, or this Windows build does not log it (needs Win10 1903+).'
        return
    }

    # Aggregate duplicates (same app across hives): keep newest LastStart
    $grouped = $script:CamMicTable | Group-Object Capability, App | ForEach-Object {
        $_.Group | Sort-Object { if ($_.LastStart) { $_.LastStart } else { [datetime]::MinValue } } -Descending | Select-Object -First 1
    }
    $script:CamMicTable = @($grouped | Sort-Object InUseNow, LastStart -Descending)

    $recentCut = (Get-Date).AddDays(-14)
    foreach ($e in $script:CamMicTable) {
        $isPath  = ($e.App -match '[A-Za-z]:\\')
        $exePath = if ($isPath) { $e.App } else { $null }
        $sig     = if ($exePath) { Get-SignatureInfo -Path $exePath } else { $null }
        $risk    = if ($exePath) { Get-PathRisk $exePath } else { 'none' }
        $spyHit  = Test-Match -Text $e.App -Patterns ($SpywarePatterns + $RatMalwarePatterns)
        $remHit  = Test-Match -Text $e.App -Patterns $RemoteToolPatterns
        $capWord = if ($e.Capability -eq 'webcam') { 'CAMERA' } elseif ($e.Capability -eq 'microphone') { 'MICROPHONE' } else { 'LOCATION' }

        if ($e.InUseNow) {
            Add-Finding HIGH 'Camera/Mic' ("IN USE RIGHT NOW: an app is accessing the {0}" -f $capWord) ("App: {0}" -f $e.App)
        }
        if ($spyHit) {
            Add-Finding HIGH 'Camera/Mic' ("Known spyware accessed the {0}" -f $capWord) ("Matched '{0}'. App: {1}  Last used: {2}" -f $spyHit, $e.App, $e.LastStart)
        }
        elseif ($exePath -and $risk -eq 'strong') {
            Add-Finding HIGH 'Camera/Mic' ("An app from a suspicious folder used the {0}" -f $capWord) ("App: {0}  Signed: {1}  Last used: {2}" -f $e.App, $(if($sig){$sig.Status}else{'?'}), $e.LastStart)
        }
        elseif ($exePath -and $sig -and $sig.Status -ne 'Valid' -and $e.LastStart -and $e.LastStart -ge $recentCut) {
            Add-Finding MEDIUM 'Camera/Mic' ("Unsigned app recently used the {0} - review" -f $capWord) ("App: {0}  Signed: {1}  Last used: {2}" -f $e.App, $sig.Status, $e.LastStart)
        }
        elseif ($remHit -and $e.Capability -ne 'location') {
            Add-Finding MEDIUM 'Camera/Mic' ("Remote-access tool used the {0} - review" -f $capWord) ("Matched '{0}'. App: {1}  Last used: {2}" -f $remHit, $e.App, $e.LastStart)
        }
    }

    # Print a compact table to console
    Write-Host ''
    Write-Host ('  {0,-11} {1,-6} {2,-19} {3}' -f 'CAPABILITY','LIVE','LAST USED','APP') -ForegroundColor Cyan
    foreach ($e in ($script:CamMicTable | Select-Object -First 40)) {
        $live = if ($e.InUseNow) { 'NOW!' } else { '' }
        $when = if ($e.LastStart) { $e.LastStart.ToString('yyyy-MM-dd HH:mm') } else { 'unknown' }
        $app  = if ($e.App.Length -gt 60) { '...' + $e.App.Substring($e.App.Length - 57) } else { $e.App }
        $col  = if ($e.InUseNow) { 'Red' } else { 'Gray' }
        Write-Host ('  {0,-11} {1,-6} {2,-19} {3}' -f $e.Capability, $live, $when, $app) -ForegroundColor $col
    }
    Add-Finding INFO 'Camera/Mic' ("{0} programs have accessed camera/mic/location (see report table)" -f $script:CamMicTable.Count) 'Full list is in the saved HTML report. Recognise them all? Unknown entries deserve a closer look.'
}

function Add-CamMicEntry {
    param($Cap, $KeyName, $KeyPath, [bool]$Packaged)
    $start = $null; $stop = $null; $rawStop = $null
    $props = Get-ItemProperty -LiteralPath $KeyPath -ErrorAction SilentlyContinue
    if ($props) {
        if ($props.PSObject.Properties.Name -contains 'LastUsedTimeStart') { $start = Convert-FileTime $props.LastUsedTimeStart }
        if ($props.PSObject.Properties.Name -contains 'LastUsedTimeStop')  { $stop  = Convert-FileTime $props.LastUsedTimeStop; $rawStop = $props.LastUsedTimeStop }
    }
    if ($null -eq $start -and $null -eq $stop -and $null -eq $rawStop) { return }
    $display = if ($Packaged) { $KeyName } else { $KeyName.Replace('#','\') }
    $inUse = $false
    try { if ($null -ne $rawStop -and [int64]$rawStop -eq 0 -and $null -ne $start) { $inUse = $true } } catch {}
    $script:CamMicTable.Add([PSCustomObject]@{
        Capability = $Cap; App = $display; Packaged = $Packaged
        LastStart = $start; LastStop = $stop; InUseNow = $inUse
    })
}

function Test-KnownSpyware {
    Write-Section 'KNOWN SPYWARE / STALKERWARE / KEYLOGGERS'
    $pat = $SpywarePatterns + $RatMalwarePatterns
    $hits = 0

    foreach ($proc in $script:Processes) {
        $h = Test-Match -Text ("{0} {1} {2}" -f $proc.Name, $proc.ExecutablePath, $proc.CommandLine) -Patterns $pat
        if ($h) { Add-Finding HIGH 'Spyware' ("Spyware/RAT process running: {0}" -f $proc.Name) ("Matched '{0}'  Path: {1}  (PID {2})" -f $h, $proc.ExecutablePath, $proc.ProcessId); $hits++ }
    }
    foreach ($svc in $script:Services) {
        $h = Test-Match -Text ("{0} {1} {2}" -f $svc.Name, $svc.DisplayName, $svc.PathName) -Patterns $pat
        if ($h) { Add-Finding HIGH 'Spyware' ("Spyware/RAT installed as a service: {0}" -f $svc.Name) ("Matched '{0}'  Path: {1}  State: {2}" -f $h, $svc.PathName, $svc.State); $hits++ }
    }
    foreach ($app in $script:Installed) {
        $h = Test-Match -Text ("{0} {1}" -f $app.DisplayName, $app.Publisher) -Patterns $pat
        if ($h) { Add-Finding HIGH 'Spyware' ("Spyware/stalkerware installed: {0}" -f $app.DisplayName) ("Matched '{0}'  Publisher: {1}" -f $h, $app.Publisher); $hits++ }
    }
    if ($hits -eq 0) { Write-Host '  No known-spyware names matched in processes, services, or installed apps.' -ForegroundColor Green }
}

function Test-RemoteAccessTools {
    Write-Section 'REMOTE-ACCESS / REMOTE-CONTROL SOFTWARE'
    Write-Host '  These let someone view/control the PC remotely. Some may be legit (IT).' -ForegroundColor Cyan
    $seen = @{}
    $hits = 0

    foreach ($app in $script:Installed) {
        $h = Test-Match -Text $app.DisplayName -Patterns $RemoteToolPatterns
        if (-not $h) { $h = Test-Match -Text $app.Publisher -Patterns $RemotePublisherPatterns }
        if ($h -and -not $seen.ContainsKey("I:$($app.DisplayName)")) {
            $seen["I:$($app.DisplayName)"] = $true
            Add-Finding MEDIUM 'RemoteAccess' ("Remote-access software installed: {0}" -f $app.DisplayName) ("Publisher: {0}" -f $app.Publisher); $hits++
        }
    }
    foreach ($svc in $script:Services) {
        $h = Test-Match -Text ("{0} {1} {2}" -f $svc.Name, $svc.DisplayName, $svc.PathName) -Patterns $RemoteToolPatterns
        if ($h) {
            $sev = if ($svc.State -eq 'Running') { 'MEDIUM' } else { 'MEDIUM' }
            Add-Finding $sev 'RemoteAccess' ("Remote-access service: {0} ({1})" -f $svc.DisplayName, $svc.State) ("Matched '{0}'  Path: {1}" -f $h, $svc.PathName); $hits++
        }
    }
    foreach ($proc in $script:Processes) {
        $h = Test-Match -Text ("{0} {1}" -f $proc.Name, $proc.ExecutablePath) -Patterns $RemoteToolPatterns
        if ($h) { Add-Finding MEDIUM 'RemoteAccess' ("Remote-access tool RUNNING: {0}" -f $proc.Name) ("Matched '{0}'  Path: {1}  (PID {2})" -f $h, $proc.ExecutablePath, $proc.ProcessId); $hits++ }
    }
    if ($hits -eq 0) { Write-Host '  No common remote-access tools detected.' -ForegroundColor Green }
}

function Test-ScreenRecording {
    Write-Section 'SCREEN RECORDING / SCREEN TRACKING'
    Write-Host '  Looking for tools that record the screen or silently capture screenshots.' -ForegroundColor Cyan
    $hits = 0

    # Build a lightweight auto-start text blob (Run keys + Startup shortcuts) for cross-checks
    $autoText = ''
    $runKeys = @(
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($rk in $runKeys) {
        try {
            $p = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
            if ($p) {
                foreach ($n in $p.PSObject.Properties.Name) {
                    if ($n -notlike 'PS*') { $autoText += (' {0}={1}' -f $n, $p.$n) }
                }
            }
        } catch {}
    }
    foreach ($sf in @([Environment]::GetFolderPath('Startup'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))) {
        try { if ($sf -and (Test-Path -LiteralPath $sf)) { Get-ChildItem -LiteralPath $sf -ErrorAction SilentlyContinue | ForEach-Object { $autoText += (' ' + $_.Name) } } } catch {}
    }
    $autoLower = $autoText.ToLower()

    # [1] Silent screen-monitoring / screenshot-surveillance suites (highest concern)
    $seenMon = @{}
    foreach ($proc in $script:Processes) {
        $h = Test-Match -Text ("{0} {1} {2}" -f $proc.Name, $proc.ExecutablePath, $proc.CommandLine) -Patterns $ScreenMonitorPatterns
        if ($h -and -not $seenMon.ContainsKey("P:$h")) {
            $seenMon["P:$h"] = $true
            Add-Finding HIGH 'ScreenCapture' ("Screen-monitoring tool RUNNING: {0}" -f $proc.Name) ("Matched '{0}'. Tools like this capture screenshots / record the screen. Path: {1} (PID {2})" -f $h, $proc.ExecutablePath, $proc.ProcessId); $hits++
        }
    }
    foreach ($svc in $script:Services) {
        $h = Test-Match -Text ("{0} {1} {2}" -f $svc.Name, $svc.DisplayName, $svc.PathName) -Patterns $ScreenMonitorPatterns
        if ($h -and -not $seenMon.ContainsKey("S:$h")) {
            $seenMon["S:$h"] = $true
            Add-Finding HIGH 'ScreenCapture' ("Screen-monitoring tool installed as a service: {0}" -f $svc.DisplayName) ("Matched '{0}'. State: {1}. Path: {2}" -f $h, $svc.State, $svc.PathName); $hits++
        }
    }
    foreach ($app in $script:Installed) {
        $h = Test-Match -Text ("{0} {1}" -f $app.DisplayName, $app.Publisher) -Patterns $ScreenMonitorPatterns
        if ($h -and -not $seenMon.ContainsKey("I:$h")) {
            $seenMon["I:$h"] = $true
            Add-Finding HIGH 'ScreenCapture' ("Screen-monitoring software installed: {0}" -f $app.DisplayName) ("Matched '{0}'. Publisher: {1}. On a work PC this may be sanctioned IT monitoring - confirm it is expected." -f $h, $app.Publisher); $hits++
        }
    }

    # [2] General screen recorders - severity depends on running / auto-start / installed-only
    foreach ($proc in $script:Processes) {
        $nm = "$($proc.Name)".ToLower()
        if ($ScreenRecorderExe -contains $nm) {
            Add-Finding MEDIUM 'ScreenCapture' ("Screen recorder is RUNNING right now: {0}" -f $proc.Name) ("Path: {0} (PID {1}). If nobody is knowingly recording, this is worth a closer look." -f $proc.ExecutablePath, $proc.ProcessId); $hits++
        }
    }
    foreach ($app in $script:Installed) {
        $h = Test-Match -Text $app.DisplayName -Patterns $ScreenRecorderPatterns
        if ($h) {
            if ($autoLower.Contains($h)) {
                Add-Finding MEDIUM 'ScreenCapture' ("Screen recorder set to auto-start: {0}" -f $app.DisplayName) ("Matched '{0}'. A recorder configured to launch automatically is unusual - confirm why." -f $h); $hits++
            } else {
                Add-Finding INFO 'ScreenCapture' ("Screen-recording software installed: {0}" -f $app.DisplayName) ("Matched '{0}'. Common and usually legitimate; listed for awareness." -f $h)
            }
        }
    }

    # [3] Built-in Windows screen-capture capability (Xbox Game Bar background recording)
    try {
        $gdvr = Get-ItemProperty -LiteralPath 'Registry::HKEY_CURRENT_USER\System\GameConfigStore' -Name 'GameDVR_Enabled' -ErrorAction SilentlyContinue
        if ($gdvr -and $gdvr.GameDVR_Enabled -eq 1) {
            Add-Finding INFO 'ScreenCapture' 'Windows Game Bar background recording capability is enabled' 'The built-in Xbox Game Bar can capture the screen. This is a common default; noted for completeness.'
        }
    } catch {}

    if ($hits -eq 0) { Write-Host '  No screen recorders or screen-monitoring tools detected.' -ForegroundColor Green }
}

function Test-Autostart {
    Write-Section 'AUTOSTART / PERSISTENCE (Run keys, Startup folder, Winlogon, IFEO)'
    $pat = $SpywarePatterns + $RatMalwarePatterns

    # ---- Run / RunOnce keys
    $runKeys = @(
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            $val = "$($p.Value)"
            $exe = Get-ExeFromCommand $val
            $spy = Test-Match -Text "$($p.Name) $val" -Patterns $pat
            $rem = Test-Match -Text "$($p.Name) $val" -Patterns $RemoteToolPatterns
            $sig = Get-SignatureInfo -Path $exe
            $risk = Get-PathRisk $exe
            if ($spy)       { Add-Finding HIGH   'Autostart' ("Spyware set to auto-start: {0}" -f $p.Name) ("Matched '{0}'  ->  {1}" -f $spy, $val) }
            elseif ($rem)   { Add-Finding MEDIUM 'Autostart' ("Remote tool set to auto-start: {0}" -f $p.Name) ("Matched '{0}'  ->  {1}" -f $rem, $val) }
            elseif ($risk -eq 'strong') { Add-Finding HIGH 'Autostart' ("Auto-start item runs from a suspicious folder: {0}" -f $p.Name) ("{0}  (signed: {1})" -f $val, $(if($sig){$sig.Status}else{'?'})) }
            elseif ($sig -and $sig.Status -notin 'Valid','FileNotFound') { Add-Finding MEDIUM 'Autostart' ("Unsigned auto-start item - review: {0}" -f $p.Name) ("{0}  (signed: {1})" -f $val, $sig.Status) }
            else            { Add-Finding INFO 'Autostart' ("Auto-start: {0}" -f $p.Name) $val }
        }
    }

    # ---- Startup folders (resolve .lnk targets)
    $startupDirs = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    )
    $sh = $null
    try { $sh = New-Object -ComObject WScript.Shell } catch {}
    foreach ($dir in $startupDirs) {
        if (-not $dir -or -not (Test-Path $dir)) { continue }
        Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $_.FullName
            if ($_.Extension -eq '.lnk' -and $sh) { try { $t = $sh.CreateShortcut($_.FullName).TargetPath; if ($t) { $target = $t } } catch {} }
            $spy = Test-Match -Text "$($_.Name) $target" -Patterns $pat
            $rem = Test-Match -Text "$($_.Name) $target" -Patterns $RemoteToolPatterns
            if ($spy)     { Add-Finding HIGH   'Autostart' ("Spyware in Startup folder: {0}" -f $_.Name) ("-> {0}" -f $target) }
            elseif ($rem) { Add-Finding MEDIUM 'Autostart' ("Remote tool in Startup folder: {0}" -f $_.Name) ("-> {0}" -f $target) }
            else          { Add-Finding INFO   'Autostart' ("Startup folder item: {0}" -f $_.Name) ("-> {0}" -f $target) }
        }
    }

    # ---- Winlogon anomalies (classic persistence)
    $wl = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe\s*$') {
            Add-Finding HIGH 'Autostart' 'Winlogon Shell has been modified (persistence)' ("Shell = {0}  (normal is 'explorer.exe')" -f $wl.Shell)
        }
        if ($wl.Userinit -and $wl.Userinit -notmatch 'userinit\.exe,?\s*$') {
            Add-Finding HIGH 'Autostart' 'Winlogon Userinit has extra entries (persistence)' ("Userinit = {0}" -f $wl.Userinit)
        }
    }

    # ---- Image File Execution Options "Debugger" hijacks
    $ifeo = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $d = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { Add-Finding HIGH 'Autostart' ("Image-File-Execution hijack on {0}" -f $_.PSChildName) ("Debugger = {0}  (launches this instead of the real program)" -f $d) }
    }
}

function Test-ScheduledTasks {
    Write-Section 'SCHEDULED TASKS (non-Microsoft)'
    $pat = $SpywarePatterns + $RatMalwarePatterns
    $tasks = $null
    try { $tasks = Get-ScheduledTask -ErrorAction Stop } catch { Write-Host '  Could not enumerate scheduled tasks (needs admin?).' -ForegroundColor DarkGray; return }
    $count = 0
    foreach ($t in $tasks) {
        if ($t.TaskPath -like '\Microsoft\*') { continue }
        $exes = @(); $args = @()
        foreach ($a in @($t.Actions)) { if ($a.Execute) { $exes += $a.Execute }; if ($a.Arguments) { $args += $a.Arguments } }
        $blob = ("{0} {1} {2} {3}" -f $t.TaskName, ($exes -join ' '), ($args -join ' '), $t.Author)
        $spy = Test-Match -Text $blob -Patterns $pat
        $rem = Test-Match -Text $blob -Patterns $RemoteToolPatterns
        $risk = 'none'; foreach ($e in $exes) { $r = Get-PathRisk $e; if ($r -eq 'strong') { $risk = 'strong' } }
        if ($spy)      { Add-Finding HIGH   'ScheduledTask' ("Spyware scheduled task: {0}{1}" -f $t.TaskPath, $t.TaskName) ("Matched '{0}'  Runs: {1}" -f $spy, ($exes -join '; ')) }
        elseif ($rem)  { Add-Finding MEDIUM 'ScheduledTask' ("Remote tool scheduled task: {0}{1}" -f $t.TaskPath, $t.TaskName) ("Runs: {0}" -f ($exes -join '; ')) }
        elseif ($risk -eq 'strong') { Add-Finding HIGH 'ScheduledTask' ("Scheduled task runs from suspicious folder: {0}{1}" -f $t.TaskPath, $t.TaskName) ("Runs: {0}" -f ($exes -join '; ')) }
        else { $count++ }
    }
    Write-Host ("  {0} other non-Microsoft tasks present (listed in report)." -f $count) -ForegroundColor DarkGray
    if ($count -gt 0) { Add-Finding INFO 'ScheduledTask' ("{0} other non-Microsoft scheduled tasks exist" -f $count) 'Review the Task Scheduler if anything looks unfamiliar.' }
}

function Test-Services {
    Write-Section 'SUSPICIOUS SERVICES (non-Microsoft, unsigned, or odd location)'
    $count = 0
    foreach ($svc in $script:Services) {
        $exe = Get-ExeFromCommand $svc.PathName
        if ([string]::IsNullOrWhiteSpace($exe)) { continue }
        if ($exe -match 'system32\\svchost' ) { continue }
        if (Test-IsMicrosoftSigned $exe) { continue }
        $risk = Get-PathRisk $exe
        $sig  = Get-SignatureInfo -Path $exe
        if ($risk -eq 'strong') { Add-Finding HIGH 'Service' ("Service runs from a suspicious folder: {0}" -f $svc.Name) ("{0}  (signed: {1})  State: {2}" -f $exe, $(if($sig){$sig.Status}else{'?'}), $svc.State); $count++ }
        elseif ($sig -and $sig.Status -notin 'Valid','FileNotFound') { Add-Finding MEDIUM 'Service' ("Unsigned service - review: {0}" -f $svc.Name) ("{0}  (signed: {1})  Signer: {2}  State: {3}" -f $exe, $sig.Status, $sig.Signer, $svc.State); $count++ }
    }
    if ($count -eq 0) { Write-Host '  No obviously suspicious services found.' -ForegroundColor Green }
}

function Test-SuspiciousProcesses {
    Write-Section 'SUSPICIOUS PROCESSES (unsigned or running from user-writable folders)'
    Write-Host '  Note: some legitimate apps (Teams, Slack, Zoom...) also run from AppData.' -ForegroundColor Cyan
    $count = 0
    foreach ($proc in $script:Processes) {
        $path = $proc.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $risk = Get-PathRisk $path
        if ($risk -eq 'none') { continue }
        $sig = Get-SignatureInfo -Path $path
        $unsigned = ($sig -and $sig.Status -notin 'Valid','FileNotFound')
        if ($risk -eq 'strong' -and $unsigned) {
            Add-Finding HIGH 'Process' ("Unsigned process from suspicious folder: {0}" -f $proc.Name) ("{0}  (PID {1})  Signer: {2}  Company: {3}" -f $path, $proc.ProcessId, $sig.Signer, $sig.Company); $count++
        }
        elseif ($risk -eq 'strong') {
            Add-Finding MEDIUM 'Process' ("Process runs from suspicious folder - review: {0}" -f $proc.Name) ("{0}  (PID {1})  signed: {2}  by: {3}" -f $path, $proc.ProcessId, $sig.Status, $sig.Signer); $count++
        }
        elseif ($risk -eq 'weak' -and $unsigned) {
            Add-Finding MEDIUM 'Process' ("Unsigned process - review: {0}" -f $proc.Name) ("{0}  (PID {1})  Company: {2}" -f $path, $proc.ProcessId, $sig.Company); $count++
        }
    }
    if ($count -eq 0) { Write-Host '  Nothing unsigned running from suspicious locations.' -ForegroundColor Green }
}

function Test-NetworkConnections {
    Write-Section 'ACTIVE NETWORK CONNECTIONS (remote-control indicators)'
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    if (-not $conns) { Write-Host '  Could not read TCP connections.' -ForegroundColor DarkGray; return }
    $procMap = @{}
    foreach ($p in $script:Processes) { $procMap[[int]$p.ProcessId] = $p }
    $extIps = New-Object System.Collections.Generic.HashSet[string]
    $hits = 0

    foreach ($c in $conns) {
        $lport = [int]$c.LocalPort
        $rport = [int]$c.RemotePort
        $pr = $procMap[[int]$c.OwningProcess]
        $pname = if ($pr) { $pr.Name } else { "PID $($c.OwningProcess)" }

        if ($c.State -eq 'Listen') {
            if ($RatPorts.ContainsKey($lport)) {
                Add-Finding MEDIUM 'Network' ("Listening on remote-control port {0} ({1})" -f $lport, $RatPorts[$lport]) ("A remote-control server may be running.  Process: {0}  {1}" -f $pname, $(if($pr){$pr.ExecutablePath}else{''})); $hits++
            }
            continue
        }
        if ($c.State -ne 'Established') { continue }
        $remote = "$($c.RemoteAddress)"
        if ($remote -in '127.0.0.1','::1','0.0.0.0','::' -or $remote -like '169.254.*') { continue }
        [void]$extIps.Add($remote)
        $remHit = if ($pr) { Test-Match -Text ("{0} {1}" -f $pr.Name, $pr.ExecutablePath) -Patterns $RemoteToolPatterns } else { $null }
        $spyHit = if ($pr) { Test-Match -Text ("{0} {1}" -f $pr.Name, $pr.ExecutablePath) -Patterns ($SpywarePatterns + $RatMalwarePatterns) } else { $null }
        $portHit = $RatPorts.ContainsKey($rport)
        if ($spyHit)            { Add-Finding HIGH   'Network' ("Spyware/RAT has a live connection: {0}" -f $pname) ("-> {0}:{1}" -f $remote, $rport); $hits++ }
        elseif ($remHit -or $portHit) {
            $lbl = if ($portHit) { " ($($RatPorts[$rport]))" } else { '' }
            Add-Finding MEDIUM 'Network' ("Remote-control connection active: {0}" -f $pname) ("-> {0}:{1}{2}" -f $remote, $rport, $lbl); $hits++
        }
    }
    Add-Finding INFO 'Network' ("{0} distinct external IPs currently connected" -f $extIps.Count) 'Normal for browsers/apps. Only remote-control-specific connections are flagged above.'
    if ($hits -eq 0) { Write-Host '  No remote-control network activity detected.' -ForegroundColor Green }
}

function Test-RemoteConfig {
    Write-Section 'REMOTE ACCESS CONFIGURATION (RDP / Remote Assistance / WinRM)'
    $ts = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    if ($ts -and $ts.PSObject.Properties.Name -contains 'fDenyTSConnections') {
        if ([int]$ts.fDenyTSConnections -eq 0) {
            Add-Finding MEDIUM 'RemoteConfig' 'Remote Desktop (RDP) is ENABLED' 'The PC accepts incoming remote-desktop connections. If nobody enabled this on purpose, it allows remote viewing/control.'
        } else {
            Write-Host '  RDP is disabled (good).' -ForegroundColor Green
        }
    }
    $ra = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
    if ($ra -and $ra.PSObject.Properties.Name -contains 'fAllowToGetHelp' -and [int]$ra.fAllowToGetHelp -eq 1) {
        Add-Finding MEDIUM 'RemoteConfig' 'Remote Assistance is ENABLED' 'Allows someone to connect to "assist". Disable it if not needed.'
    }
    $winrm = $script:Services | Where-Object { $_.Name -eq 'WinRM' }
    if ($winrm -and $winrm.State -eq 'Running') {
        Add-Finding INFO 'RemoteConfig' 'WinRM (Windows Remote Management) service is running' 'Common on managed/work PCs; can be used for remote command execution.'
    }
}

function Test-RecentlyInstalled {
    Write-Section 'RECENTLY INSTALLED SOFTWARE (last 45 days)'
    $cut = (Get-Date).AddDays(-45)
    $any = $false
    foreach ($app in ($script:Installed | Sort-Object InstallDate -Descending)) {
        if ($app.InstallDate -match '^\d{8}$') {
            $d = $null
            try { $d = [datetime]::ParseExact($app.InstallDate, 'yyyyMMdd', $null) } catch {}
            if ($d -and $d -ge $cut) {
                Add-Finding INFO 'Installed' ("Recently installed: {0}" -f $app.DisplayName) ("On {0}  by {1}" -f $d.ToString('yyyy-MM-dd'), $app.Publisher)
                $any = $true
            }
        }
    }
    if (-not $any) { Write-Host '  No software recorded as installed in the last 45 days.' -ForegroundColor DarkGray }
}

function Test-HostsFile {
    Write-Section 'HOSTS FILE'
    $hp = "$env:WINDIR\System32\drivers\etc\hosts"
    if (-not (Test-Path $hp)) { return }
    $lines = Get-Content $hp -ErrorAction SilentlyContinue | Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -match '\S') }
    if (-not $lines) { Write-Host '  Hosts file has no custom entries (good).' -ForegroundColor Green; return }
    foreach ($l in $lines) { Add-Finding MEDIUM 'HostsFile' 'Custom hosts-file entry (can redirect/block sites)' $l.Trim() }
}

function Test-LocalAccounts {
    Write-Section 'LOCAL USER ACCOUNTS'
    try {
        Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled } | ForEach-Object {
            Add-Finding INFO 'Accounts' ("Enabled local account: {0}" -f $_.Name) ("Last logon: {0}" -f $_.LastLogon)
        }
    } catch {
        Write-Host '  Could not enumerate local accounts.' -ForegroundColor DarkGray
    }
}

# ================================================================ REPORT ======

function Write-Report {
    Write-Section 'SUMMARY'
    # de-duplicate identical findings
    $unique = $script:Findings | Sort-Object Severity, Category, Title, Detail -Unique
    $high = @($unique | Where-Object { $_.Severity -eq 'HIGH' })
    $med  = @($unique | Where-Object { $_.Severity -eq 'MEDIUM' })
    $info = @($unique | Where-Object { $_.Severity -eq 'INFO' })
    $sevOrder = @{ 'HIGH' = 0; 'MEDIUM' = 1; 'INFO' = 2 }

    Write-Host ('  HIGH   : {0}' -f $high.Count) -ForegroundColor Red
    Write-Host ('  MEDIUM : {0}' -f $med.Count)  -ForegroundColor Yellow
    Write-Host ('  INFO   : {0}' -f $info.Count) -ForegroundColor Gray
    Write-Host ''
    if ($high.Count -gt 0) {
        Write-Host '  >> HIGH-priority items to look at:' -ForegroundColor Red
        foreach ($f in $high) { Write-Host ('     - {0}' -f $f.Title) -ForegroundColor Red }
    } else {
        Write-Host '  No HIGH-priority indicators were found by this scan.' -ForegroundColor Green
        Write-Host '  (This is reassuring, but not proof of a clean machine - see report notes.)' -ForegroundColor DarkGray
    }

    # ---------------- build HTML ----------------
    function HtmlEnc([string]$s) { if ($null -eq $s) { return '' }; return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<html><head><meta charset='utf-8'><title>Surveillance Scan</title><style>")
    [void]$sb.Append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f1115;color:#e6e6e6}")
    [void]$sb.Append("h1{font-size:22px}h2{font-size:16px;border-bottom:1px solid #333;padding-bottom:4px;margin-top:28px}")
    [void]$sb.Append("table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px}")
    [void]$sb.Append("td,th{border:1px solid #2a2d34;padding:6px 8px;text-align:left;vertical-align:top}")
    [void]$sb.Append("th{background:#1b1e24}.HIGH{color:#ff6b6b;font-weight:bold}.MEDIUM{color:#ffd166}.INFO{color:#9aa0a6}")
    [void]$sb.Append(".box{padding:12px 16px;border-radius:8px;background:#1b1e24;display:inline-block;margin-right:12px}")
    [void]$sb.Append(".live{color:#ff6b6b;font-weight:bold}</style></head><body>")
    [void]$sb.Append("<h1>Surveillance / Spyware Scan Report</h1>")
    [void]$sb.Append("<p>Computer: <b>$(HtmlEnc $env:COMPUTERNAME)</b> &nbsp; User: <b>$(HtmlEnc $env:USERNAME)</b> &nbsp; Generated: <b>$(Get-Date)</b></p>")
    [void]$sb.Append("<div><span class='box HIGH'>HIGH: $($high.Count)</span><span class='box MEDIUM'>MEDIUM: $($med.Count)</span><span class='box INFO'>INFO: $($info.Count)</span></div>")

    $groups = @(
        [PSCustomObject]@{ Name = 'HIGH-priority findings'; Items = $high }
        [PSCustomObject]@{ Name = 'Review (MEDIUM)';        Items = $med  }
        [PSCustomObject]@{ Name = 'Informational';          Items = $info }
    )
    foreach ($grp in $groups) {
        $title = $grp.Name; $items = @($grp.Items)
        if ($items.Count -eq 0) { continue }
        [void]$sb.Append("<h2>$(HtmlEnc $title)</h2><table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Details</th></tr>")
        foreach ($f in $items) {
            [void]$sb.Append("<tr><td class='$($f.Severity)'>$($f.Severity)</td><td>$(HtmlEnc $f.Category)</td><td>$(HtmlEnc $f.Title)</td><td>$(HtmlEnc $f.Detail)</td></tr>")
        }
        [void]$sb.Append("</table>")
    }

    # camera/mic full table
    if ($script:CamMicTable.Count -gt 0) {
        [void]$sb.Append("<h2>Full camera / microphone / location access history</h2>")
        [void]$sb.Append("<table><tr><th>Capability</th><th>Live now</th><th>Last used</th><th>Application</th></tr>")
        foreach ($e in $script:CamMicTable) {
            $live = if ($e.InUseNow) { "<span class='live'>YES</span>" } else { '' }
            $when = if ($e.LastStart) { $e.LastStart.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown' }
            [void]$sb.Append("<tr><td>$(HtmlEnc $e.Capability)</td><td>$live</td><td>$when</td><td>$(HtmlEnc $e.App)</td></tr>")
        }
        [void]$sb.Append("</table>")
    }

    [void]$sb.Append("<h2>Important notes</h2><ul>")
    [void]$sb.Append("<li>This scan is <b>read-only</b> and changed nothing on the PC.</li>")
    [void]$sb.Append("<li><b>MEDIUM</b> items are for human review - many are legitimate.</li>")
    [void]$sb.Append("<li>It cannot guarantee detection of a skilled custom implant, rootkit, firmware/hardware bug, phone tracking, or router-level interception.</li>")
    [void]$sb.Append("<li>If you find something serious: do not immediately delete it. Keep this report, and consider professional help / evidence preservation, especially if a person has physical access to the machine.</li>")
    [void]$sb.Append("</ul></body></html>")

    # ---------------- save ----------------
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseName = "Surveillance_Scan_${env:COMPUTERNAME}_$stamp"
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = $env:TEMP }
    $htmlPath = Join-Path $desktop "$baseName.html"
    $txtPath  = Join-Path $desktop "$baseName.txt"

    try { $sb.ToString() | Out-File -FilePath $htmlPath -Encoding UTF8 } catch { $htmlPath = $null }

    $txt = New-Object System.Text.StringBuilder
    [void]$txt.AppendLine("SURVEILLANCE / SPYWARE SCAN REPORT")
    [void]$txt.AppendLine("Computer: $env:COMPUTERNAME   User: $env:USERNAME   Generated: $(Get-Date)")
    [void]$txt.AppendLine("HIGH: $($high.Count)  MEDIUM: $($med.Count)  INFO: $($info.Count)")
    [void]$txt.AppendLine(('=' * 72))
    foreach ($f in ($unique | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Category)) {
        [void]$txt.AppendLine(("[{0}] {1}: {2}" -f $f.Severity, $f.Category, $f.Title))
        if ($f.Detail) { [void]$txt.AppendLine("        $($f.Detail)") }
    }
    try { $txt.ToString() | Out-File -FilePath $txtPath -Encoding UTF8 } catch { $txtPath = $null }

    Write-Host ''
    Write-Host '  Reports saved:' -ForegroundColor Cyan
    if ($htmlPath) { Write-Host ("    HTML : {0}" -f $htmlPath) -ForegroundColor White }
    if ($txtPath)  { Write-Host ("    Text : {0}" -f $txtPath)  -ForegroundColor White }
    if ($htmlPath) { try { Invoke-Item $htmlPath } catch {} }
}

# ================================================================ MAIN =========

Clear-Host
Write-Host ''
Write-Host '  ############################################################' -ForegroundColor Cyan
Write-Host '  #      SURVEILLANCE / SPYWARE SCANNER  (read-only)         #' -ForegroundColor Cyan
Write-Host '  #      Nothing will be changed, deleted, or sent anywhere. #' -ForegroundColor Cyan
Write-Host '  ############################################################' -ForegroundColor Cyan

$modules = @(
    'Get-SystemInfo', 'Test-CameraMicUsage', 'Test-KnownSpyware', 'Test-RemoteAccessTools',
    'Test-ScreenRecording', 'Test-Autostart', 'Test-ScheduledTasks', 'Test-Services',
    'Test-SuspiciousProcesses', 'Test-NetworkConnections', 'Test-RemoteConfig',
    'Test-RecentlyInstalled', 'Test-HostsFile', 'Test-LocalAccounts'
)
foreach ($m in $modules) {
    try { & $m } catch { Write-Host ("  [!] Module {0} error: {1}" -f $m, $_.Exception.Message) -ForegroundColor DarkYellow }
}

try { Write-Report } catch { Write-Host ("  [!] Report error: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }

Write-Host ''
Write-Host '  Scan complete. Review the HIGH items first, then the saved report.' -ForegroundColor Green
Write-Host '  Press Enter to close...' -ForegroundColor DarkGray
try { [void](Read-Host) } catch {}
