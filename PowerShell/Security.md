# Hunting With Powershell

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
```powershell
$Date = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=$Date; Id='4624' } | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    [pscustomobject]@{
        TimeCreated     = $_.TimeCreated
        Computer        = $_.MachineName
        SubjectUserName = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        LogonType       = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    }
}
```