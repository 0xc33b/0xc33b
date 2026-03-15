#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HostSecurityAssessment.ps1 - Host Security Posture & Risk Scoring

.DESCRIPTION
    Evaluates host security configuration, permissions, and controls to produce:
      1. General Posture Score  - % likelihood of compromise based on misconfigs
      2. Threat-Informed Score  - exploitability weighted by MITRE ATT&CK technique
                                  prevalence and mapped to the Cyber Kill Chain

    Outputs findings per check with MITRE technique, Kill Chain phase, severity,
    and the quickest/most effective remediation action.

    Supported OS: Windows (PowerShell 5.1+), Linux / macOS (PowerShell 7+)

.NOTES
    Run as Administrator / root for full coverage.
    Non-admin runs are supported but some checks will be skipped.
#>

[CmdletBinding()]
param(
    [switch]$NoColor,
    [switch]$JsonOutput,
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Default output file: same directory the script was invoked from
$script:RunDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutFile) {
    $ext = if ($JsonOutput) { 'json' } else { 'txt' }
    $OutFile = Join-Path $script:RunDir "host-security-assessment-$($script:Timestamp).$ext"
}

# ---------------------------------------------------------------------------
# REGION: Helpers
# ---------------------------------------------------------------------------
$script:IsWindows = ($PSVersionTable.PSVersion.Major -ge 6) ? $IsWindows : $true
$script:IsLinux   = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsLinux }   else { $false }
$script:IsMacOS   = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsMacOS }   else { $false }

$script:IsAdmin = $false
if ($script:IsWindows) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} else {
    $script:IsAdmin = (id -u) -eq 0
}

function Write-Color {
    param([string]$Text, [string]$Color = 'White', [switch]$NoNewline)
    if ($NoColor -or $JsonOutput) { if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }; return }
    $map = @{ Red='Red'; Yellow='Yellow'; Green='Green'; Cyan='Cyan'; White='White'; Magenta='Magenta'; Gray='DarkGray' }
    $c = if ($map.ContainsKey($Color)) { $map[$Color] } else { 'White' }
    if ($NoNewline) { Write-Host $Text -ForegroundColor $c -NoNewline } else { Write-Host $Text -ForegroundColor $c }
}

# ---------------------------------------------------------------------------
# REGION: Finding Model
# ---------------------------------------------------------------------------
# Severity weights for General Score
$script:SeverityWeight = @{ Critical=10; High=7; Medium=4; Low=2; Info=0 }

# Threat multiplier: how frequently this MITRE technique appears in real-world
# incidents (1.0 = average, 2.0 = twice as common, sourced from MITRE ATT&CK Navigator
# heat maps and Red Canary / Mandiant annual threat reports)
$script:ThreatMultiplier = @{
    'T1078'    = 1.9   # Valid Accounts - extremely common
    'T1003'    = 1.8   # OS Credential Dumping
    'T1003.001'= 1.9
    'T1059'    = 1.8   # Command & Scripting
    'T1059.001'= 1.8
    'T1021'    = 1.7   # Remote Services
    'T1021.001'= 1.7
    'T1021.002'= 1.6
    'T1548'    = 1.5   # Abuse Elevation Control
    'T1548.002'= 1.5
    'T1562'    = 1.6   # Impair Defenses
    'T1562.001'= 1.6
    'T1562.004'= 1.5
    'T1110'    = 1.4   # Brute Force
    'T1135'    = 1.3   # Network Share Discovery
    'T1557'    = 1.4   # Adversary-in-the-Middle
    'T1557.001'= 1.4
    'T1574'    = 1.2   # Hijack Execution Flow
    'T1574.007'= 1.2
    'T1574.009'= 1.2
    'T1091'    = 1.0   # Replication Through Removable Media
    'T1012'    = 1.1   # Query Registry
    'T1005'    = 1.3   # Data from Local System (no encryption)
    'T1190'    = 1.5   # Exploit Public-Facing Application
    'T1484'    = 1.3   # Domain Policy Modification (GPO)
    'T1484.001'= 1.3
    'T1059.005'= 1.2   # Visual Basic
    'T1046'    = 1.1   # Network Service Discovery
}

function New-Finding {
    param(
        [string]$ID,
        [string]$Name,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [ValidateSet('Pass','Fail','Warn','Skip')][string]$Status,
        [string]$Detail,
        [string]$MitreID,
        [string]$MitreName,
        [ValidateSet('Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions')][string]$KillChain,
        [string]$Remediation,
        [string]$Platform = 'All'
    )
    [PSCustomObject]@{
        ID          = $ID
        Name        = $Name
        Severity    = $Severity
        Status      = $Status
        Detail      = $Detail
        MitreID     = $MitreID
        MitreName   = $MitreName
        KillChain   = $KillChain
        Remediation = $Remediation
        Platform    = $Platform
        Weight      = if ($Status -eq 'Fail') { $script:SeverityWeight[$Severity] } else { 0 }
        ThreatMult  = if ($script:ThreatMultiplier.ContainsKey($MitreID)) { $script:ThreatMultiplier[$MitreID] } else { 1.0 }
    }
}

# ---------------------------------------------------------------------------
# REGION: Windows Checks
# ---------------------------------------------------------------------------
function Get-WindowsFindings {
    $findings = @()

    # --- W01: Built-in Administrator account enabled ---
    $adminAcct = Get-LocalUser -Name 'Administrator' 2>$null
    $adminEnabled = $adminAcct -and $adminAcct.Enabled
    $findings += New-Finding -ID 'W01' -Name 'Built-in Administrator account enabled' `
        -Severity 'High' -Status (if ($adminEnabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($adminEnabled) { 'The default Administrator account is active and a known target.' } else { 'Built-in Administrator is disabled.' }) `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Exploitation' `
        -Remediation 'Disable: net user Administrator /active:no  |  Create a renamed local admin with a strong unique password.' `
        -Platform 'Windows'

    # --- W02: Guest account enabled ---
    $guestAcct = Get-LocalUser -Name 'Guest' 2>$null
    $guestEnabled = $guestAcct -and $guestAcct.Enabled
    $findings += New-Finding -ID 'W02' -Name 'Guest account enabled' `
        -Severity 'Medium' -Status (if ($guestEnabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($guestEnabled) { 'Guest account provides unauthenticated or low-privilege access.' } else { 'Guest account disabled.' }) `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Exploitation' `
        -Remediation 'Disable: net user Guest /active:no' `
        -Platform 'Windows'

    # --- W03: Password complexity policy ---
    $passPolicy = net accounts 2>$null
    $minLen = 0
    if ($passPolicy) {
        $lenLine = $passPolicy | Where-Object { $_ -match 'Minimum password length' }
        if ($lenLine -match '(\d+)') { $minLen = [int]$Matches[1] }
    }
    $passWeak = $minLen -lt 12
    $findings += New-Finding -ID 'W03' -Name 'Weak password length policy' `
        -Severity 'High' -Status (if ($passWeak) { 'Fail' } else { 'Pass' }) `
        -Detail "Minimum password length: $minLen chars (recommended: 14+)." `
        -MitreID 'T1110' -MitreName 'Brute Force' -KillChain 'Exploitation' `
        -Remediation 'GPO: Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy. Set min length >= 14, enable complexity.' `
        -Platform 'Windows'

    # --- W04: Account lockout policy ---
    $lockoutLine = $passPolicy | Where-Object { $_ -match 'Lockout threshold' }
    $lockoutThreshold = 0
    if ($lockoutLine -match '(\d+)') { $lockoutThreshold = [int]$Matches[1] }
    $noLockout = $lockoutThreshold -eq 0
    $findings += New-Finding -ID 'W04' -Name 'No account lockout policy' `
        -Severity 'High' -Status (if ($noLockout) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($noLockout) { 'Unlimited login attempts allow brute force attacks.' } else { "Lockout after $lockoutThreshold attempts." }) `
        -MitreID 'T1110' -MitreName 'Brute Force' -KillChain 'Exploitation' `
        -Remediation 'GPO: Account Policies > Account Lockout Policy. Set threshold=5, duration=30min, reset counter=30min.' `
        -Platform 'Windows'

    # --- W05: UAC level ---
    $uacVal = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
    $uacDisabled = $uacVal -eq 0
    $findings += New-Finding -ID 'W05' -Name 'UAC disabled' `
        -Severity 'Critical' -Status (if ($uacDisabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($uacDisabled) { 'UAC is off: any process runs with full admin rights without prompting.' } else { 'UAC is enabled.' }) `
        -MitreID 'T1548.002' -MitreName 'Bypass User Account Control' -KillChain 'Exploitation' `
        -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f  then reboot.' `
        -Platform 'Windows'

    # --- W06: Windows Defender / AV status ---
    $defStatus = Get-MpComputerStatus 2>$null
    $avDisabled = $null -eq $defStatus -or (-not $defStatus.AntivirusEnabled)
    $rtDisabled = $null -eq $defStatus -or (-not $defStatus.RealTimeProtectionEnabled)
    $findings += New-Finding -ID 'W06' -Name 'Windows Defender / AV disabled' `
        -Severity 'Critical' -Status (if ($avDisabled -or $rtDisabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($avDisabled) { 'No active antivirus detected.' } elseif ($rtDisabled) { 'AV present but real-time protection is OFF.' } else { 'Defender active with real-time protection.' }) `
        -MitreID 'T1562.001' -MitreName 'Disable or Modify Tools' -KillChain 'Installation' `
        -Remediation 'Enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false  |  Enforce via GPO: Computer Config > Admin Templates > Windows Defender Antivirus.' `
        -Platform 'Windows'

    # --- W07: Windows Firewall status ---
    $fwProfiles = Get-NetFirewallProfile 2>$null
    $fwDisabled = $fwProfiles | Where-Object { $_.Enabled -eq $false }
    $fwStatus = if ($fwDisabled) { 'Fail' } else { 'Pass' }
    $fwDetail = if ($fwDisabled) {
        "Firewall DISABLED on profiles: $($fwDisabled.Name -join ', ')"
    } else { 'All firewall profiles are enabled.' }
    $findings += New-Finding -ID 'W07' -Name 'Windows Firewall profile disabled' `
        -Severity 'Critical' -Status $fwStatus `
        -Detail $fwDetail `
        -MitreID 'T1562.004' -MitreName 'Disable or Modify System Firewall' -KillChain 'C2' `
        -Remediation 'Set-NetFirewallProfile -All -Enabled True  |  GPO: Computer Config > Windows Settings > Security Settings > Windows Firewall.' `
        -Platform 'Windows'

    # --- W08: SMBv1 enabled ---
    $smb1 = Get-SmbServerConfiguration 2>$null | Select-Object -ExpandProperty EnableSMB1Protocol
    $findings += New-Finding -ID 'W08' -Name 'SMBv1 enabled (EternalBlue / lateral movement vector)' `
        -Severity 'Critical' -Status (if ($smb1) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($smb1) { 'SMBv1 is active. Exploitable for credential relay, lateral movement, and ransomware propagation.' } else { 'SMBv1 is disabled.' }) `
        -MitreID 'T1021.002' -MitreName 'SMB/Windows Admin Shares' -KillChain 'Exploitation' `
        -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force  |  Also disable client: sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi' `
        -Platform 'Windows'

    # --- W09: RDP enabled and NLA status ---
    $rdpEnabled = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
    $nlaEnabled = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthenticationRequired -eq 1
    $rdpStatus = if ($rdpEnabled -and -not $nlaEnabled) { 'Fail' } elseif ($rdpEnabled -and $nlaEnabled) { 'Warn' } else { 'Pass' }
    $rdpDetail = if (-not $rdpEnabled) { 'RDP is disabled.' } elseif ($nlaEnabled) { 'RDP enabled with NLA enforced (acceptable, restrict firewall access further).' } else { 'RDP enabled WITHOUT Network Level Authentication - pre-auth attack surface exposed.' }
    $findings += New-Finding -ID 'W09' -Name 'RDP exposed without NLA' `
        -Severity 'High' -Status $rdpStatus `
        -Detail $rdpDetail `
        -MitreID 'T1021.001' -MitreName 'Remote Desktop Protocol' -KillChain 'Exploitation' `
        -Remediation 'Enable NLA: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthenticationRequired /t REG_DWORD /d 1 /f  |  Restrict RDP to jump hosts via firewall rule.' `
        -Platform 'Windows'

    # --- W10: WDigest plaintext credential caching ---
    $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
    $wdigestOn = $wdigest -eq 1
    $findings += New-Finding -ID 'W10' -Name 'WDigest plaintext credential caching enabled' `
        -Severity 'Critical' -Status (if ($wdigestOn) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($wdigestOn) { 'Plaintext passwords stored in LSASS memory - trivially extracted with Mimikatz.' } else { 'WDigest caching disabled.' }) `
        -MitreID 'T1003.001' -MitreName 'LSASS Memory' -KillChain 'Actions' `
        -Remediation 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f' `
        -Platform 'Windows'

    # --- W11: LSA Protection (RunAsPPL) ---
    $lsaPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
    $lsaWeak = $lsaPPL -ne 1
    $findings += New-Finding -ID 'W11' -Name 'LSA Protection (RunAsPPL) not enabled' `
        -Severity 'High' -Status (if ($lsaWeak) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($lsaWeak) { 'LSASS can be read by non-PPL processes - credential dumping possible.' } else { 'LSA running as Protected Process Light.' }) `
        -MitreID 'T1003.001' -MitreName 'LSASS Memory' -KillChain 'Actions' `
        -Remediation 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f  then reboot. Validate: Process Explorer LSA shows Protected.' `
        -Platform 'Windows'

    # --- W12: Credential Guard ---
    $credGuard = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    $cgEnabled  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LsaCfgFlags
    $cgActive = $cgEnabled -eq 1 -or $cgEnabled -eq 2
    $findings += New-Finding -ID 'W12' -Name 'Credential Guard not enabled' `
        -Severity 'High' -Status (if (-not $cgActive) { 'Fail' } else { 'Pass' }) `
        -Detail (if (-not $cgActive) { 'Credential Guard isolates LSASS in VBS; without it NTLM hashes are extractable.' } else { 'Credential Guard is active.' }) `
        -MitreID 'T1003' -MitreName 'OS Credential Dumping' -KillChain 'Actions' `
        -Remediation 'Enable via Device Guard: GPO > Computer Config > Admin Templates > System > Device Guard. Requires UEFI + Secure Boot + VT-x.' `
        -Platform 'Windows'

    # --- W13: PowerShell Execution Policy ---
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine 2>$null
    $execWeak = $execPolicy -in @('Unrestricted','Bypass','Undefined')
    $findings += New-Finding -ID 'W13' -Name 'PowerShell Execution Policy is permissive' `
        -Severity 'High' -Status (if ($execWeak) { 'Fail' } else { 'Pass' }) `
        -Detail "Execution policy: $execPolicy. Allows unsigned scripts to run without restriction." `
        -MitreID 'T1059.001' -MitreName 'PowerShell' -KillChain 'Exploitation' `
        -Remediation 'Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force  |  Enforce via GPO and enable PowerShell Script Block Logging.' `
        -Platform 'Windows'

    # --- W14: PowerShell v2 available (logging bypass) ---
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root 2>$null
    $ps2Enabled = $ps2 -and $ps2.State -eq 'Enabled'
    $findings += New-Finding -ID 'W14' -Name 'PowerShell v2 enabled (logging bypass)' `
        -Severity 'Medium' -Status (if ($ps2Enabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($ps2Enabled) { 'PSv2 has no ScriptBlock logging or AMSI - attackers downgrade to evade detection.' } else { 'PowerShell v2 is disabled.' }) `
        -MitreID 'T1059.001' -MitreName 'PowerShell' -KillChain 'Exploitation' `
        -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart' `
        -Platform 'Windows'

    # --- W15: BitLocker status ---
    $blStatus = Get-BitLockerVolume -MountPoint 'C:' 2>$null
    $blEnabled = $blStatus -and $blStatus.ProtectionStatus -eq 'On'
    $findings += New-Finding -ID 'W15' -Name 'BitLocker not enabled on system drive' `
        -Severity 'High' -Status (if (-not $blEnabled) { 'Fail' } else { 'Pass' }) `
        -Detail (if (-not $blEnabled) { 'System drive unencrypted - offline attacks can extract data and credentials.' } else { 'BitLocker active on C:.' }) `
        -MitreID 'T1005' -MitreName 'Data from Local System' -KillChain 'Actions' `
        -Remediation 'Enable: manage-bde -on C: -RecoveryPassword  |  Store recovery key in AD or Azure AD. Enforce via GPO > BitLocker Drive Encryption.' `
        -Platform 'Windows'

    # --- W16: Secure Boot ---
    $sb = Confirm-SecureBootUEFI 2>$null
    $findings += New-Finding -ID 'W16' -Name 'Secure Boot disabled or not UEFI' `
        -Severity 'Medium' -Status (if ($sb -ne $true) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($sb -ne $true) { 'Secure Boot not confirmed. Vulnerable to bootkit/rootkit attacks.' } else { 'Secure Boot is enabled.' }) `
        -MitreID 'T1542' -MitreName 'Pre-OS Boot' -KillChain 'Installation' `
        -Remediation 'Enable in UEFI/BIOS firmware settings. Ensure CSM/Legacy mode is off. Pair with TPM 2.0 + BitLocker.' `
        -Platform 'Windows'

    # --- W17: LLMNR / NBT-NS (credential relay) ---
    $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
    $llmnrOn = $llmnr -ne 0
    $findings += New-Finding -ID 'W17' -Name 'LLMNR / NBT-NS enabled (relay attack vector)' `
        -Severity 'High' -Status (if ($llmnrOn) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($llmnrOn) { 'LLMNR/NBT-NS allows Responder-style credential relay attacks on local network.' } else { 'LLMNR disabled via policy.' }) `
        -MitreID 'T1557.001' -MitreName 'LLMNR/NBT-NS Poisoning' -KillChain 'Exploitation' `
        -Remediation 'GPO: Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution = Enabled. Disable NetBIOS via DHCP option 001 or NIC properties.' `
        -Platform 'Windows'

    # --- W18: AutoRun enabled ---
    $autoRun = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    $autoRunWeak = $autoRun -ne 255
    $findings += New-Finding -ID 'W18' -Name 'AutoRun / AutoPlay not fully disabled' `
        -Severity 'Medium' -Status (if ($autoRunWeak) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($autoRunWeak) { "NoDriveTypeAutoRun = $autoRun (255 = disabled all). Enables USB/media-based malware launch." } else { 'AutoRun fully disabled.' }) `
        -MitreID 'T1091' -MitreName 'Replication Through Removable Media' -KillChain 'Delivery' `
        -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f' `
        -Platform 'Windows'

    # --- W19: Remote Registry service ---
    $remReg = Get-Service -Name RemoteRegistry 2>$null
    $remRegOn = $remReg -and $remReg.Status -eq 'Running'
    $findings += New-Finding -ID 'W19' -Name 'Remote Registry service running' `
        -Severity 'Medium' -Status (if ($remRegOn) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($remRegOn) { 'Remote Registry allows remote enumeration and modification of registry - reconnaissance and persistence vector.' } else { 'Remote Registry service is stopped.' }) `
        -MitreID 'T1012' -MitreName 'Query Registry' -KillChain 'Reconnaissance' `
        -Remediation 'Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled' `
        -Platform 'Windows'

    # --- W20: Windows Script Host enabled ---
    $wshKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -ErrorAction SilentlyContinue).Enabled
    $wshEnabled = $wshKey -ne 0   # 0 = disabled; default (key absent) = enabled
    $findings += New-Finding -ID 'W20' -Name 'Windows Script Host (WSH) enabled' `
        -Severity 'Medium' -Status (if ($wshEnabled) { 'Warn' } else { 'Pass' }) `
        -Detail (if ($wshEnabled) { 'WSH allows .vbs/.js/.wsf execution - phishing and dropper delivery mechanism.' } else { 'WSH is disabled.' }) `
        -MitreID 'T1059.005' -MitreName 'Visual Basic / WSH' -KillChain 'Exploitation' `
        -Remediation 'reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f  |  Apply via GPO to all non-developer hosts.' `
        -Platform 'Windows'

    # --- W21: Local Administrator Password Solution (LAPS) ---
    $lapsInstalled = Get-Command 'Get-LapsADPassword' -ErrorAction SilentlyContinue
    $lapsKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue
    $lapsActive = $lapsInstalled -or $lapsKey
    $findings += New-Finding -ID 'W21' -Name 'LAPS (Local Admin Password Solution) not deployed' `
        -Severity 'High' -Status (if (-not $lapsActive) { 'Fail' } else { 'Pass' }) `
        -Detail (if (-not $lapsActive) { 'Shared local admin password across hosts - compromise one, own all (pass-the-hash / pass-the-password).' } else { 'LAPS appears deployed.' }) `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Exploitation' `
        -Remediation 'Deploy Windows LAPS (built-in Win Server 2019+/Win 11 22H2+): Enable-LapsADSchema, Set-LapsADComputerSelfPermission, configure GPO. For legacy use Microsoft LAPS MSI.' `
        -Platform 'Windows'

    # --- W22: Audit Policy - logon events ---
    $auditLogon = auditpol /get /subcategory:"Logon" 2>$null
    $auditWeak = -not ($auditLogon -match 'Success and Failure')
    $findings += New-Finding -ID 'W22' -Name 'Audit policy: logon events not fully logged' `
        -Severity 'Medium' -Status (if ($auditWeak) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($auditWeak) { 'Logon success/failure not fully audited - attacks may go undetected.' } else { 'Logon auditing configured for success and failure.' }) `
        -MitreID 'T1562.002' -MitreName 'Disable Windows Event Logging' -KillChain 'Actions' `
        -Remediation 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable  |  Enforce comprehensive policy via GPO > Advanced Audit Policy.' `
        -Platform 'Windows'

    # --- W23: Open network shares ---
    $shares = Get-SmbShare 2>$null | Where-Object { $_.Name -notin @('IPC$','ADMIN$','C$') -and $_.Name -notmatch '\$$' }
    $hasShares = $shares -and $shares.Count -gt 0
    $findings += New-Finding -ID 'W23' -Name 'Non-default network shares exposed' `
        -Severity 'Medium' -Status (if ($hasShares) { 'Warn' } else { 'Pass' }) `
        -Detail (if ($hasShares) { "Shares found: $($shares.Name -join ', '). Review ACLs for over-permission." } else { 'No non-default shares.' }) `
        -MitreID 'T1135' -MitreName 'Network Share Discovery' -KillChain 'Reconnaissance' `
        -Remediation 'Remove: Remove-SmbShare -Name <share> -Force  |  For required shares: tighten ACLs, disable guest access, enable SMB encryption (Set-SmbServerConfiguration -EncryptData $true).' `
        -Platform 'Windows'

    # --- W24: Unquoted service paths ---
    $unquotedSvcs = @()
    Get-WmiObject Win32_Service 2>$null | Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^[A-Z]:\\Windows' } | ForEach-Object {
        $unquotedSvcs += $_.Name
    }
    $findings += New-Finding -ID 'W24' -Name 'Unquoted service paths detected' `
        -Severity 'Medium' -Status (if ($unquotedSvcs.Count -gt 0) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($unquotedSvcs.Count -gt 0) { "Services with unquoted paths: $($unquotedSvcs -join ', ')" } else { 'No unquoted service paths found.' }) `
        -MitreID 'T1574.009' -MitreName 'Path Interception by Unquoted Path' -KillChain 'Installation' `
        -Remediation 'Wrap service ImagePath values in quotes. Script: Get-WmiObject Win32_Service | Where PathName does not start with quote. Vendor fix if third-party service.' `
        -Platform 'Windows'

    # --- W25: GPO: AppLocker / WDAC status ---
    $applocker = Get-AppLockerPolicy -Effective 2>$null
    $wdacPolicy = Get-CimInstance -ClassName Win32_DeviceGuard 2>$null
    $hasAppControl = ($applocker -and ($applocker.RuleCollections | Measure-Object).Count -gt 0) -or ($wdacPolicy -and $wdacPolicy.CodeIntegrityPolicyEnforcementStatus -ge 1)
    $findings += New-Finding -ID 'W25' -Name 'No application control policy (AppLocker / WDAC)' `
        -Severity 'High' -Status (if (-not $hasAppControl) { 'Fail' } else { 'Pass' }) `
        -Detail (if (-not $hasAppControl) { 'No application whitelisting detected - arbitrary code execution unrestricted.' } else { 'Application control policy found.' }) `
        -MitreID 'T1059' -MitreName 'Command and Scripting Interpreter' -KillChain 'Exploitation' `
        -Remediation 'Deploy WDAC (preferred over AppLocker): Use WDAC Wizard (https://webapp-wdac-wizard.azurewebsites.net) to create audit policy, test, then enforce. Start with "default deny" script rules.' `
        -Platform 'Windows'

    # --- W26: Windows Update / last patch ---
    $wu = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 2>$null
    $patchAge = if ($wu -and $wu.InstalledOn) { ([datetime]::Now - $wu.InstalledOn).Days } else { 999 }
    $patchOld = $patchAge -gt 30
    $findings += New-Finding -ID 'W26' -Name 'System not recently patched (>30 days)' `
        -Severity 'High' -Status (if ($patchOld) { 'Fail' } else { 'Pass' }) `
        -Detail "Last hotfix installed: $(if ($wu) { $wu.InstalledOn.ToString('yyyy-MM-dd') } else { 'unknown' }) ($patchAge days ago)." `
        -MitreID 'T1190' -MitreName 'Exploit Public-Facing Application' -KillChain 'Exploitation' `
        -Remediation 'Immediately: sconfig (Server) / Settings > Windows Update. Enforce: GPO > Computer Config > Admin Templates > Windows Update > Configure Automatic Updates = Auto download and schedule install.' `
        -Platform 'Windows'

    # --- W27: Null session / anonymous access ---
    $restrictNull = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RestrictAnonymous
    $nullAllowed = $restrictNull -ne 2 -and $restrictNull -ne 1
    $findings += New-Finding -ID 'W27' -Name 'Null session / anonymous enumeration not fully restricted' `
        -Severity 'Medium' -Status (if ($nullAllowed) { 'Fail' } else { 'Pass' }) `
        -Detail "RestrictAnonymous = $restrictNull (should be 1 or 2). Anonymous users may enumerate accounts and shares." `
        -MitreID 'T1135' -MitreName 'Network Share Discovery' -KillChain 'Reconnaissance' `
        -Remediation 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f  |  Also set RestrictAnonymousSAM=1.' `
        -Platform 'Windows'

    return $findings
}

# ---------------------------------------------------------------------------
# REGION: Linux/macOS Checks
# ---------------------------------------------------------------------------
function Get-UnixFindings {
    $findings = @()

    # --- U01: Root SSH login allowed ---
    $sshConf = '/etc/ssh/sshd_config'
    $rootLoginAllowed = $false
    if (Test-Path $sshConf) {
        $sshContent = Get-Content $sshConf -ErrorAction SilentlyContinue
        $rootLoginAllowed = $sshContent -match '^\s*PermitRootLogin\s+yes'
    }
    $findings += New-Finding -ID 'U01' -Name 'SSH root login permitted' `
        -Severity 'Critical' -Status (if ($rootLoginAllowed) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($rootLoginAllowed) { 'sshd_config allows direct root login - no audit trail for privileged access.' } else { 'Root SSH login not permitted.' }) `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Exploitation' `
        -Remediation 'sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config && systemctl restart sshd  |  Use sudo for admin tasks.' `
        -Platform 'Unix'

    # --- U02: SSH password authentication enabled ---
    $passwdAuth = $false
    if (Test-Path $sshConf) {
        $sshContent = Get-Content $sshConf -ErrorAction SilentlyContinue
        $passwdAuth = $sshContent -match '^\s*PasswordAuthentication\s+yes' -or (-not ($sshContent -match '^\s*PasswordAuthentication\s+no'))
    }
    $findings += New-Finding -ID 'U02' -Name 'SSH password authentication enabled' `
        -Severity 'High' -Status (if ($passwdAuth) { 'Fail' } else { 'Pass' }) `
        -Detail (if ($passwdAuth) { 'Password auth on SSH allows brute force. Key-based auth is not enforced.' } else { 'SSH password authentication disabled.' }) `
        -MitreID 'T1110' -MitreName 'Brute Force' -KillChain 'Exploitation' `
        -Remediation 'Set PasswordAuthentication no in /etc/ssh/sshd_config. Deploy SSH keys. Restrict access with AllowUsers/AllowGroups. Restart sshd.' `
        -Platform 'Unix'

    # --- U03: World-writable files in /etc ---
    $wwFiles = @()
    if ($script:IsAdmin) {
        $wwOut = bash -c "find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null" 2>$null
        if ($wwOut) { $wwFiles = $wwOut -split "`n" | Where-Object { $_ -ne '' } }
    }
    $findings += New-Finding -ID 'U03' -Name 'World-writable files in /etc' `
        -Severity 'High' -Status (if ($wwFiles.Count -gt 0) { 'Fail' } elseif (-not $script:IsAdmin) { 'Skip' } else { 'Pass' }) `
        -Detail (if ($wwFiles.Count -gt 0) { "World-writable: $($wwFiles[0..2] -join ', ')$(if ($wwFiles.Count -gt 3){' ...'})"}  elseif (-not $script:IsAdmin) { 'Skipped - requires root.' } else { 'No world-writable files in /etc.' }) `
        -MitreID 'T1574.007' -MitreName 'Path Interception by PATH Variable' -KillChain 'Installation' `
        -Remediation 'chmod o-w <file>  |  Audit: find /etc -perm -o+w -type f. Automate permissions hardening with CIS benchmark scripts.' `
        -Platform 'Unix'

    # --- U04: Sudo NOPASSWD entries ---
    $nopasswd = @()
    if ($script:IsAdmin) {
        $sudoOut = bash -c "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'" 2>$null
        if ($sudoOut) { $nopasswd = $sudoOut -split "`n" | Where-Object { $_ -ne '' } }
    }
    $findings += New-Finding -ID 'U04' -Name 'Sudo NOPASSWD entries configured' `
        -Severity 'High' -Status (if ($nopasswd.Count -gt 0) { 'Fail' } elseif (-not $script:IsAdmin) { 'Skip' } else { 'Pass' }) `
        -Detail (if ($nopasswd.Count -gt 0) { "NOPASSWD sudo: $($nopasswd[0..1] -join ' | ')" } elseif (-not $script:IsAdmin) { 'Skipped.' } else { 'No NOPASSWD sudo rules found.' }) `
        -MitreID 'T1548' -MitreName 'Abuse Elevation Control Mechanism' -KillChain 'Exploitation' `
        -Remediation 'Remove NOPASSWD from /etc/sudoers: visudo. Require password for all sudo. Use sudo -l to audit per-user rules.' `
        -Platform 'Unix'

    # --- U05: Firewall (iptables/ufw/firewalld) active ---
    $fwActive = $false
    $ufwOut  = bash -c "ufw status 2>/dev/null | head -1" 2>$null
    $fwdOut  = bash -c "firewall-cmd --state 2>/dev/null" 2>$null
    $iptOut  = bash -c "iptables -L INPUT 2>/dev/null | wc -l" 2>$null
    if ($ufwOut -match 'active') { $fwActive = $true }
    if ($fwdOut -match 'running') { $fwActive = $true }
    if ([int]$iptOut -gt 3) { $fwActive = $true }
    $findings += New-Finding -ID 'U05' -Name 'Host firewall not active' `
        -Severity 'High' -Status (if (-not $fwActive) { 'Fail' } else { 'Pass' }) `
        -Detail (if (-not $fwActive) { 'No active host firewall detected (ufw/firewalld/iptables).' } else { 'Host firewall is active.' }) `
        -MitreID 'T1562.004' -MitreName 'Disable or Modify System Firewall' -KillChain 'C2' `
        -Remediation 'ufw enable && ufw default deny incoming && ufw allow ssh  |  Or: systemctl enable --now firewalld; firewall-cmd --set-default-zone=drop.' `
        -Platform 'Unix'

    # --- U06: Unattended security upgrades configured ---
    $autoUpgrade = Test-Path '/etc/apt/apt.conf.d/20auto-upgrades' -or (bash -c "which yum-cron dnf-automatic 2>/dev/null | head -1" 2>$null) -ne ''
    $findings += New-Finding -ID 'U06' -Name 'Automatic security updates not configured' `
        -Severity 'Medium' -Status (if (-not $autoUpgrade) { 'Warn' } else { 'Pass' }) `
        -Detail (if (-not $autoUpgrade) { 'No unattended-upgrades or yum-cron/dnf-automatic detected. Manual patching is inconsistent.' } else { 'Automatic updates configured.' }) `
        -MitreID 'T1190' -MitreName 'Exploit Public-Facing Application' -KillChain 'Exploitation' `
        -Remediation 'Debian/Ubuntu: apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades. RHEL: dnf install dnf-automatic && systemctl enable --now dnf-automatic.' `
        -Platform 'Unix'

    # --- U07: Core dumps enabled ---
    $corePattern = bash -c "cat /proc/sys/kernel/core_pattern 2>/dev/null" 2>$null
    $coreDumps = $corePattern -ne '|/bin/false' -and $corePattern -ne ''
    $findings += New-Finding -ID 'U07' -Name 'Core dumps may expose sensitive memory' `
        -Severity 'Low' -Status (if ($coreDumps) { 'Warn' } else { 'Pass' }) `
        -Detail "core_pattern: $corePattern. Core dumps can contain passwords, keys, and credentials." `
        -MitreID 'T1003' -MitreName 'OS Credential Dumping' -KillChain 'Actions' `
        -Remediation 'echo "* hard core 0" >> /etc/security/limits.conf && echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf && sysctl -p' `
        -Platform 'Unix'

    return $findings
}

# ---------------------------------------------------------------------------
# REGION: Cross-Platform Checks
# ---------------------------------------------------------------------------
function Get-CommonFindings {
    $findings = @()

    # --- C01: Open listening ports ---
    $listeningPorts = @()
    if ($script:IsWindows) {
        $netstat = netstat -ano 2>$null | Where-Object { $_ -match 'LISTENING' }
        $listeningPorts = $netstat | ForEach-Object { if ($_ -match ':(\d+)\s+0\.0\.0\.0:\*') { $Matches[1] } } | Sort-Object -Unique
    } else {
        $ssOut = bash -c "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null" 2>$null
        $listeningPorts = $ssOut | ForEach-Object { if ($_ -match ':(\d+)\s') { $Matches[1] } } | Sort-Object -Unique
    }
    $riskyPorts = $listeningPorts | Where-Object { $_ -in @('21','23','25','69','110','135','137','138','139','445','512','513','514','1433','1521','3306','5432','5900','5985','5986','6379','8080','27017') }
    $findings += New-Finding -ID 'C01' -Name 'Risky services listening on network' `
        -Severity 'Medium' -Status (if ($riskyPorts.Count -gt 0) { 'Warn' } else { 'Pass' }) `
        -Detail (if ($riskyPorts.Count -gt 0) { "Potentially risky ports open: $($riskyPorts -join ', ')" } else { 'No commonly abused ports detected listening.' }) `
        -MitreID 'T1046' -MitreName 'Network Service Discovery' -KillChain 'Reconnaissance' `
        -Remediation 'Disable unneeded services. Firewall-restrict required services to specific source IPs. Audit: netstat -tlnp (Linux) / netstat -ano (Windows).' `
        -Platform 'All'

    # --- C02: Local admin / privileged users count ---
    $adminCount = 0
    if ($script:IsWindows) {
        $admins = Get-LocalGroupMember -Group 'Administrators' 2>$null
        $adminCount = if ($admins) { ($admins | Measure-Object).Count } else { 0 }
    } else {
        $sudoCount = bash -c "getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | wc -l" 2>$null
        $adminCount = [int]$sudoCount
    }
    $tooManyAdmins = $adminCount -gt 3
    $findings += New-Finding -ID 'C02' -Name 'Excessive local administrator accounts' `
        -Severity 'Medium' -Status (if ($tooManyAdmins) { 'Warn' } else { 'Pass' }) `
        -Detail "$adminCount privileged accounts found. Each is a potential compromise pivot." `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Actions' `
        -Remediation 'Principle of least privilege: remove unnecessary admin rights. Enforce JIT admin (PAM/CyberArk/Azure PIM). Target: max 2 break-glass admin accounts per host.' `
        -Platform 'All'

    # --- C03: Last interactive login age (stale accounts) ---
    # Basic check - are there accounts that haven't logged in but exist?
    $staleFound = $false
    if ($script:IsWindows) {
        $staleUsers = Get-LocalUser 2>$null | Where-Object { $_.Enabled -and ($null -eq $_.LastLogon -or $_.LastLogon -lt (Get-Date).AddDays(-90)) -and $_.Name -notin @('Administrator','DefaultAccount','WDAGUtilityAccount') }
        $staleFound = $staleUsers -and ($staleUsers | Measure-Object).Count -gt 0
    }
    $findings += New-Finding -ID 'C03' -Name 'Stale enabled user accounts (no logon >90 days)' `
        -Severity 'Low' -Status (if ($staleFound) { 'Warn' } else { 'Pass' }) `
        -Detail (if ($staleFound) { "Accounts enabled but inactive >90 days: $($staleUsers.Name -join ', ')" } else { 'No stale accounts detected.' }) `
        -MitreID 'T1078' -MitreName 'Valid Accounts' -KillChain 'Exploitation' `
        -Remediation 'Disable stale accounts: Disable-LocalUser -Name <user>  |  Implement quarterly access reviews. Use AD account expiry for temp staff.' `
        -Platform 'All'

    return $findings
}

# ---------------------------------------------------------------------------
# REGION: Scoring Engine
# ---------------------------------------------------------------------------
function Invoke-Scoring {
    param([array]$Findings)

    $activeFails = $Findings | Where-Object { $_.Status -in @('Fail','Warn') }
    $allChecked  = $Findings | Where-Object { $_.Status -ne 'Skip' }

    # General Score: sum of fail weights / sum of all possible weights
    $totalPossible = ($allChecked | Measure-Object -Property { $script:SeverityWeight[$_.Severity] } -Sum).Sum
    if ($totalPossible -eq 0) { $totalPossible = 1 }
    $totalRisk = ($activeFails | Measure-Object -Property Weight -Sum).Sum
    if ($null -eq $totalRisk) { $totalRisk = 0 }
    $generalScore = [Math]::Round(($totalRisk / $totalPossible) * 100, 1)

    # Threat-Informed Score: weight each fail by threat multiplier, normalize
    $threatRisk = 0
    foreach ($f in $activeFails) {
        $threatRisk += $f.Weight * $f.ThreatMult
    }
    $threatPossible = 0
    foreach ($f in $allChecked) {
        $maxW = $script:SeverityWeight[$f.Severity]
        $tm   = $f.ThreatMult
        $threatPossible += $maxW * $tm
    }
    if ($threatPossible -eq 0) { $threatPossible = 1 }
    $threatScore = [Math]::Round(($threatRisk / $threatPossible) * 100, 1)

    return [PSCustomObject]@{
        GeneralScore  = $generalScore
        ThreatScore   = $threatScore
        TotalFindings = $Findings.Count
        Failures      = ($activeFails | Measure-Object).Count
        Passes        = ($Findings | Where-Object { $_.Status -eq 'Pass' } | Measure-Object).Count
        Skipped       = ($Findings | Where-Object { $_.Status -eq 'Skip' } | Measure-Object).Count
        Critical      = ($activeFails | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
        High          = ($activeFails | Where-Object { $_.Severity -eq 'High' }     | Measure-Object).Count
        Medium        = ($activeFails | Where-Object { $_.Severity -eq 'Medium' }   | Measure-Object).Count
        Low           = ($activeFails | Where-Object { $_.Severity -eq 'Low' }      | Measure-Object).Count
    }
}

# ---------------------------------------------------------------------------
# REGION: Kill Chain Phase Summary
# ---------------------------------------------------------------------------
$script:KillChainOrder = @('Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions')
$script:KillChainLabel = @{
    Reconnaissance = 'Reconnaissance     (Know your target)'
    Weaponization  = 'Weaponization      (Craft the attack)'
    Delivery       = 'Delivery           (Get it to the host)'
    Exploitation   = 'Exploitation       (Execute on the host)'
    Installation   = 'Installation       (Persist on the host)'
    C2             = 'Command & Control  (Communicate out)'
    Actions        = 'Actions on Obj.    (Achieve the goal)'
}

# ---------------------------------------------------------------------------
# REGION: Report Output
# ---------------------------------------------------------------------------
function Write-Report {
    param([array]$Findings, [PSCustomObject]$Scores)

    $line = '=' * 80

    if (-not $JsonOutput) {
        Write-Color $line Cyan
        Write-Color '  HOST SECURITY ASSESSMENT REPORT' Cyan
        Write-Color "  Host    : $($env:COMPUTERNAME)$($env:HOSTNAME)" White
        Write-Color "  OS      : $([System.Environment]::OSVersion.VersionString)" White
        Write-Color "  User    : $([System.Environment]::UserName)" White
        Write-Color "  Elevated: $(if ($script:IsAdmin) { 'YES (full assessment)' } else { 'NO  (some checks skipped)' })" (if ($script:IsAdmin) { 'Green' } else { 'Yellow' })
        Write-Color "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" White
        Write-Color $line Cyan

        # --- Score Banner ---
        $gColor = if ($Scores.GeneralScore -ge 70) { 'Red' } elseif ($Scores.GeneralScore -ge 40) { 'Yellow' } else { 'Green' }
        $tColor = if ($Scores.ThreatScore  -ge 70) { 'Red' } elseif ($Scores.ThreatScore  -ge 40) { 'Yellow' } else { 'Green' }

        Write-Color ''
        Write-Color '  RISK SCORES' White
        Write-Color "  General Posture Score  : " White -NoNewline
        Write-Color "$($Scores.GeneralScore)%" $gColor -NoNewline
        $gLabel = if ($Scores.GeneralScore -ge 70) { ' [HIGH RISK - Immediate action required]' } elseif ($Scores.GeneralScore -ge 40) { ' [MEDIUM RISK - Remediation recommended]' } else { ' [LOW RISK - Good baseline posture]' }
        Write-Color $gLabel $gColor

        Write-Color "  Threat-Informed Score  : " White -NoNewline
        Write-Color "$($Scores.ThreatScore)%" $tColor -NoNewline
        $tLabel = if ($Scores.ThreatScore -ge 70) { ' [EXPLOITABLE by common threat actors]' } elseif ($Scores.ThreatScore -ge 40) { ' [MODERATE exploitability]' } else { ' [LOW exploitability against typical TTPs]' }
        Write-Color $tLabel $tColor

        Write-Color ''
        Write-Color '  Scoring Methodology:' Gray
        Write-Color '  General Score  = weighted severity of all failed checks / total possible weight x 100' Gray
        Write-Color '  Threat Score   = same, but each finding multiplied by MITRE ATT&CK technique' Gray
        Write-Color '                   prevalence (sourced from Red Canary / Mandiant threat reports)' Gray
        Write-Color ''
        Write-Color "  Checks: $($Scores.TotalFindings) total | $($Scores.Failures) failed | $($Scores.Passes) passed | $($Scores.Skipped) skipped" White
        Write-Color "  Failed by severity: Critical=$($Scores.Critical)  High=$($Scores.High)  Medium=$($Scores.Medium)  Low=$($Scores.Low)" (if ($Scores.Critical -gt 0) { 'Red' } elseif ($Scores.High -gt 0) { 'Yellow' } else { 'Green' })
        Write-Color $line Cyan

        # --- Kill Chain Coverage ---
        Write-Color ''
        Write-Color '  CYBER KILL CHAIN - EXPOSURE SUMMARY' White
        $kcGroups = $Findings | Where-Object { $_.Status -in @('Fail','Warn') } | Group-Object -Property KillChain
        foreach ($phase in $script:KillChainOrder) {
            $grp = $kcGroups | Where-Object { $_.Name -eq $phase }
            $count = if ($grp) { $grp.Count } else { 0 }
            $bar = if ($count -gt 0) { '[' + ('!' * [Math]::Min($count,10)) + ']' } else { '[OK]' }
            $label = $script:KillChainLabel[$phase]
            $color = if ($count -ge 3) { 'Red' } elseif ($count -ge 1) { 'Yellow' } else { 'Green' }
            Write-Color "  $bar $label  ($count finding$(if($count -ne 1){'s'}))" $color
        }
        Write-Color $line Cyan

        # --- Findings Detail ---
        Write-Color ''
        Write-Color '  FINDINGS DETAIL' White
        Write-Color ''

        $sevOrder = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
        $sorted = $Findings | Where-Object { $_.Status -in @('Fail','Warn') } | Sort-Object { $sevOrder[$_.Severity] }

        foreach ($f in $sorted) {
            $sevColor = switch ($f.Severity) {
                'Critical' { 'Red' }
                'High'     { 'Magenta' }
                'Medium'   { 'Yellow' }
                'Low'      { 'Gray' }
                default    { 'White' }
            }
            $statusMark = if ($f.Status -eq 'Fail') { '[FAIL]' } else { '[WARN]' }
            Write-Color "  $statusMark [$($f.Severity.ToUpper())] $($f.ID): $($f.Name)" $sevColor
            Write-Color "         Detail     : $($f.Detail)" White
            Write-Color "         MITRE      : $($f.MitreID) - $($f.MitreName)" Cyan
            Write-Color "         Kill Chain : $($f.KillChain)" Cyan
            Write-Color "         Remediation: $($f.Remediation)" Green
            Write-Color ''
        }

        # --- Passed Checks Summary ---
        $passed = $Findings | Where-Object { $_.Status -eq 'Pass' }
        if ($passed.Count -gt 0) {
            Write-Color $line Cyan
            Write-Color '  PASSED CHECKS' White
            foreach ($f in $passed) {
                Write-Color "  [PASS] $($f.ID): $($f.Name)" Green
            }
        }

        # --- Skipped ---
        $skipped = $Findings | Where-Object { $_.Status -eq 'Skip' }
        if ($skipped.Count -gt 0) {
            Write-Color ''
            Write-Color '  SKIPPED (elevation required)' Gray
            foreach ($f in $skipped) {
                Write-Color "  [SKIP] $($f.ID): $($f.Name)" Gray
            }
        }

        Write-Color ''
        Write-Color $line Cyan
        Write-Color '  REMEDIATION PRIORITY (Quick Wins - highest impact, lowest effort)' White
        Write-Color $line Cyan
        $priorities = $Findings | Where-Object { $_.Status -in @('Fail','Warn') -and $_.Severity -in @('Critical','High') } | Sort-Object { $sevOrder[$_.Severity] }
        $rank = 1
        foreach ($f in $priorities) {
            Write-Color "  [$rank] $($f.ID) $($f.Name)" Yellow
            Write-Color "      $($f.Remediation)" Green
            $rank++
        }
        Write-Color ''
        Write-Color $line Cyan
        Write-Color "  Assessment complete. Run as Administrator for full coverage." Gray
        Write-Color $line Cyan
        Write-Color ''
    }
}

# ---------------------------------------------------------------------------
# REGION: Main Execution
# ---------------------------------------------------------------------------
function Invoke-Assessment {
    $allFindings = @()

    # Collect findings per platform
    if ($script:IsWindows) {
        Write-Color '[*] Running Windows checks...' Gray
        $allFindings += Get-WindowsFindings
    } elseif ($script:IsLinux -or $script:IsMacOS) {
        Write-Color '[*] Running Unix checks...' Gray
        $allFindings += Get-UnixFindings
    }

    Write-Color '[*] Running common checks...' Gray
    $allFindings += Get-CommonFindings

    # Score
    $scores = Invoke-Scoring -Findings $allFindings

    if ($JsonOutput) {
        $output = [PSCustomObject]@{
            Host        = "$($env:COMPUTERNAME)$($env:HOSTNAME)"
            Date        = (Get-Date -Format 'o')
            Elevated    = $script:IsAdmin
            Scores      = $scores
            Findings    = $allFindings
        }
        $json = $output | ConvertTo-Json -Depth 5
        $json | Out-File -FilePath $OutFile -Encoding UTF8
        Write-Host "[*] JSON report saved to: $OutFile"
        return
    }

    Write-Report -Findings $allFindings -Scores $scores

    # Always write a plain-text copy alongside the console output
    $script:NoColor = $true
    $capture = & { Write-Report -Findings $allFindings -Scores $scores } 2>&1 | Out-String
    $capture | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Color "[*] Report saved to: $OutFile" Green
}

Invoke-Assessment
