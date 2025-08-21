# BumbleStingLab
- https://cyberdefenders.org/blueteam-ctf-challenges/bumblesting/
```py
# Review Assets

#:winlog.computer_name > visualize
#-winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:3
#-TABLE:winlog.computer_name,winlog.event_data.SourceIp
#>>IT01:10.10.11.110
#>>Support01:10.10.11.217
#>>DC01:10.10.11.156
#>>FILESERVER01:10.10.11.18

# Investigate anormal events

# Network connection detected
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:3
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.Image,winlog.event_data.DestinationIp,winlog.event_data.DestinationPort
#>DC01>C:\Windows\System32\rundll32.exe>dst:3.68.27.19:443

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:11 AND NOT winlog.event_data.TargetFilename:C\:\\\\Windows\\\\Temp\\\\* 
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.Image,winlog.event_data.TargetFilename

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1 AND winlog.computer_name:DC01*
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.LogonGuid,winlog.event_data.Image,winlog.event_data.ParentProcessId,winlog.event_data.ParentImage,winlog.event_data.ProcessId,winlog.event_data.OriginalFileName,winlog.event_data.CommandLine
#>2024.12.01-22:07:21.23>DC01>C:\Windows\system32\cmd.exe /C 7zr.exe x 1.7z
#>2024.12.01-22:07:44.13>DC01>C:\Windows\system32\cmd.exe /C net user sql_admin P@ssw0rd! /add
#>2024.12.01-22:07:54.52>DC01>C:\Windows\system32\cmd.exe /C net localgroup Administrators sql_admin /ADD

# ProcessTampering
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:25
#>2024.12.01-22:04:02.85>DC01>\\10.10.11.156\ADMIN$\0453497.exe
#>2024.12.01-22:50:55.69>DC01>\\10.10.11.18\Shares\patch.exe
#>2024.12.01-22:52:22.59>Support01>\\10.10.11.18\Shares\patch.exe




winlog.event_id:1 AND (winlog.event_data.ParentImage:(*cmd.exe OR *powershell.exe) OR winlog.event_data.Image:(*cmd.exe OR *powershell.exe))

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1 AND winlog.event_data.CommandLine:*/C*
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.LogonGuid,winlog.event_data.Image,winlog.event_data.ParentProcessId,winlog.event_data.ParentImage,winlog.event_data.ProcessId,winlog.event_data.OriginalFileName,winlog.event_data.CommandLine


#>C:\Windows\system32\cmd.exe /C procdump64.exe -accepteula -ma lsass.exe C:\ProgramData\doc1.dmp
#>C:\Windows\system32\cmd.exe /C 7zr.exe a -mx5 C:\ProgramData\doc1.7z c:\ProgramData\doc1.dmp
#>C:\Windows\system32\cmd.exe /C ping -n 1 ad.compliantsecure.store
#>C:\Windows\system32\cmd.exe /C nltest /domain_trusts


```
