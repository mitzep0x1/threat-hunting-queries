# GoldenSpray Lab
- https://cyberdefenders.org/blueteam-ctf-challenges/goldenspray/
```py
# Review Assets
# TimeFormat:YYYY.MM.DDTHH:mm:ss.SSS

#>>ST-WIN02.SECURETECH.local
#>>ST-WIN01.SECURETECH.local
#>>ST-DC01.SECURETECH.local
#>>ST-FS01.SECURETECH.local

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.LogonGuid,winlog.event_data.Image,winlog.event_data.ParentProcessId,winlog.event_data.ParentImage,winlog.event_data.ProcessId,winlog.event_data.OriginalFileName,winlog.event_data.CommandLine
#>2024.09.09T17:38:44.390>ST-DC01.SECURETECH.local>schtasks  /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\FileCleaner.exe" /sc hourly /ru SYSTEM
#>2024.09.09T17:42:27.907>ST-DC01.SECURETECH.local>SECURETECH\jsmith>C:\Users\Public\BackupRunner.exe:mimikatz.exe

winlog.channel:Security AND winlog.event_data.TargetUserName:*jsmith* AND winlog.event_data.WorkstationName:*
#|winlog.event_data.TargetUserName,winlog.event_data.LogonType
#>2024.09.09T17:34:15.827>ST-DC01.SECURETECH.local>kali>77.91.78.115

winlog.event_data.IpAddress:77.91.78.115
#>2024.09.09T17:00:21.705>ST-WIN02.SECURETECH.local>mwilliams>kali>77.91.78.115





winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:13 AND winlog.event_data.TargetObject.keyword:*CurrentVersion\\\\Run*
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.Image,winlog.event_data.EventType,winlog.event_data.TargetObject

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:11 AND NOT winlog.event_data.TargetFilename.keyword:C\:\\\\Windows\\\\Temp\\\\* 
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.Image,winlog.event_data.TargetFilename







```
