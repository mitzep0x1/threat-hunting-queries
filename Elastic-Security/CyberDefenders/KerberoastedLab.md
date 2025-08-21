# Kerberoasted Lab
- https://cyberdefenders.org/blueteam-ctf-challenges/kerberoasted/
```py
# Review Assets
# TimeFormat:YYYY.MM.DDTHH:mm:ss.SSS

#>>DC01

winlog.event_id:4769 AND NOT winlog.event_data.IpAddress:"::1" AND NOT winlog.event_data.ServiceName.keyword:*$
#|winlog.event_data.TargetUserName,winlog.event_data.TicketEncryptionType
#>SQLService,FileShareService

winlog.event_id:(4624 OR 4672) AND winlog.event_data.TargetUserName.keyword:(SQLService OR FileShareService)
#|winlog.event_data.TargetUserName,winlog.event_data.ServiceName 
#>10.0.0.154

winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1
#|winlog.computer_name,winlog.event_data.User,winlog.event_data.LogonGuid,winlog.event_data.Image,winlog.event_data.ParentProcessId,winlog.event_data.ParentImage,winlog.event_data.ProcessId,winlog.event_data.OriginalFileName,winlog.event_data.CommandLine

```
