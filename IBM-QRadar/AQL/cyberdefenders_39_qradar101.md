# Cyberdefenders
- https://cyberdefenders.org/blueteam-ctf-challenges/39/


```sql
/* Log Source - TOP */
SELECT logsourceid,
    logsourcename(logsourceid) AS logsource,
    COUNT(*)
FROM events
WHERE logsource NOT LIKE '%qradar'
GROUP BY logsourceid, logsource
ORDER BY COUNT(*) DESC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Device Type Name - TOP */
SELECT devicetype,
    LOGSOURCETYPENAME(devicetype) AS devicetypename,
    COUNT(*)
FROM events
WHERE logsourcename(logsourceid) NOT LIKE '%qradar'
GROUP BY devicetype, devicetypename
ORDER BY COUNT(*) ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Category Name - TOP */
SELECT category,
    CATEGORYNAME(category) AS categoryname,
    COUNT(*)
FROM events
WHERE logsourcename(logsourceid) NOT LIKE '%qradar'
GROUP BY category, categoryname
ORDER BY COUNT(*) ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Event Name - TOP */
SELECT qid,
    QIDNAME(qid) AS eventname,
    COUNT(*)
FROM events
WHERE logsourcename(logsourceid) NOT LIKE '%qradar'
GROUP BY qid, eventname
ORDER BY COUNT(*) ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Windows Event ID - TOP */
SELECT EventID,
    CATEGORYNAME(category) AS categoryname,
    QIDNAME(qid) AS eventname,
    COUNT(*)
FROM events
WHERE logsourcename(logsourceid) NOT LIKE '%qradar' AND "EventID" IS NOT NULL
GROUP BY EventID
ORDER BY EventID ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Sysmon(event1) - Image(ProcessName) */
SELECT ImageName, 
    COUNT(*)
FROM events
WHERE EventID = 1
GROUP BY ImageName
ORDER BY COUNT(*) DESC
START '2020-11-08 21:00' STOP '2020-11-10 16:00'

/* Process Details */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    ImageName,
    "Process CommandLine"
FROM events
WHERE EventID IN (46881, 1) AND "Process CommandLine" IS NOT NULL AND ImageName NOT IN ('FaFRuwJIlNvBNaT.exe', 'GoogleUpdate.exe','VMwareResolutionSet.exe')
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* HD-FIN-03 Host Action Details */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    ImageName,
    "Process CommandLine",
    Filename
FROM events
WHERE logsource = 'HD-FIN-03' AND ImageName NOT IN ('FaFRuwJIlNvBNaT.exe', 'GoogleUpdate.exe','VMwareResolutionSet.exe')
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* 192.20.80.25 connection - Suspicious IP detected */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp,
    LOGSOURCENAME(logsourceid) AS logsource,
    CATEGORYNAME(category) AS categoryname,
    sourceip,
    destinationip,
    destinationport
FROM events
WHERE (sourceip='192.20.80.25' OR destinationip='192.20.80.25') AND logsource <> 'Zeek_conn'
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Suricata Rules - TOP */
SELECT "RULE SID",
    "Rule Name",
    COUNT(*)
FROM events
WHERE LOGSOURCENAME(logsourceid) = 'SO-Suricata'
GROUP BY "RULE SID", "Rule Name"
ORDER BY COUNT(*) DESC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* HD-FIN-03 Host - Network Connection */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    ImageName
FROM events
WHERE logsource = 'HD-FIN-03' AND EventID=3
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Identify 192.168.20.20 */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp,
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    sourceip,
    destinationip,
    destinationport,
    PROTOCOLNAME(protocolid),
    "Service Name"
    username
FROM events
WHERE (sourceip='192.168.10.15' and destinationip='192.168.20.20') AND logsource <> 'Zeek_conn'
ORDER BY timestamp ASC
START '2020-11-08 23:00' STOP '2020-11-10 18:00'

/* DC Sysmon Events */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    ImageName,
    "Process CommandLine",
    Filename
FROM events
WHERE logsource = 'DC ' AND UTF8(payload) LIKE '%Source=Microsoft-Windows-Sysmon%' AND ImageName NOT IN ('FaFRuwJIlNvBNaT.exe', 'GoogleUpdate.exe','VMwareResolutionSet.exe', 'svchost.exe')
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Suspicious Pattern */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    ImageName,
    "Process CommandLine",
    Filename
FROM events
WHERE UTF8(payload) LIKE '%\\127.0.0.1\ADMIN$\__%'
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* Sysmon - EventID=13 */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp, 
    LOGSOURCENAME(logsourceid) AS logsource,
    EventID,
    QIDNAME(qid) AS eventname,
    ImageName,
    "Process CommandLine",
    Filename
FROM events
WHERE EventID=13
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* AUX  */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp,
    LOGSOURCENAME(logsourceid) AS logsource,
    CATEGORYNAME(category) AS categoryname,
    sourceip,
    destinationip,
    destinationport
FROM events
WHERE destinationip = '192.168.20.20' and sourceip <> '192.168.20.20' AND logsource <> 'Zeek_conn'
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* from 192.168.10.15 - TOP */
SELECT destinationip,
    COUNT(*)
FROM events
WHERE sourceip='192.168.10.15' AND destinationip <> '192.168.10.15'
GROUP BY destinationip
ORDER BY COUNT(*) DESC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* 192.168.10.15 - TOP */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp,
    LOGSOURCENAME(logsourceid) AS logsource,
    CATEGORYNAME(category) AS categoryname,
    QIDNAME(qid) AS eventname,
    sourceip,
    destinationip,
    destinationport
FROM events
WHERE destinationip='192.168.10.15' AND sourceip <> '192.168.10.15'
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'

/* 192.168.20.20 - TOP */
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd''T''HH:mm:ss') AS timestamp,
    LOGSOURCENAME(logsourceid) AS logsource,
    CATEGORYNAME(category) AS categoryname,
    sourceip,
    destinationip,
    destinationport
FROM events
WHERE destinationip = '192.168.20.20' and sourceip <> '192.168.20.20' AND logsource <> 'Zeek_conn'
ORDER BY timestamp ASC
START '2020-11-08 18:00' STOP '2020-11-10 18:00'
```

# Results

```YAML
[logsource: HD-FIN-03]
omputer=HD-FIN-03.hackdefend.local
OriginatingComputer=192.168.10.15
CommandLine: "C:\Program Files\Microsoft Office\Office15\WINWORD.EXE" /n "C:\Users\nour.HACKDEFEND\Downloads\important_instructions.docx" /o ""

[EventID=22]
UtcTime: 2020-11-08 22:29:12.330
QueryName: sfeur.loki.delve.office.com
ProcessId: 8436
Image: C:\Program Files\Mozilla Firefox\firefox.exe

[EventID=15]
UtcTime: 2020-11-08 22:29:23.012
ProcessGuid: {a72af1fb-7068-5fa8-3001-000000001c00}
ProcessId: 8436
Image: C:\Program Files\Mozilla Firefox\firefox.exe
TargetFilename: C:\Users\nour.HACKDEFEND\Downloads\important_instructions.docx
Hash: MD5=9D08221599FCD9D35D11F9CBD6A0DEA3,SHA256=C7738E24AFDE6DE31DD2E9F8E57305EF3F04164608E6B2CDB93B1BDE0EDA3863,IMPHASH=00000000000000000000000000000000

[EventID=11]
UtcTime: 2020-11-08 22:29:17.711
ProcessId: 8436
Image: C:\Program Files\Mozilla Firefox\firefox.exe
TargetFilename: C:\Users\nour.HACKDEFEND\Downloads\important_instructions.docx

[EventID=1]
UtcTime: 2020-11-08 22:29:50.991
ProcessGuid: {a72af1fb-715e-5fa8-4301-000000001c00}
ProcessId: 9124
Image: C:\Program Files\Microsoft Office\Office15\WINWORD.EXE
CommandLine: "C:\Program Files\Microsoft Office\Office15\WINWORD.EXE" /n "C:\Users\nour.HACKDEFEND\Downloads\important_instructions.docx" /o ""
CurrentDirectory: C:\Users\nour.HACKDEFEND\Download

[EventID=1]
UtcTime: 2020-11-08 22:30:47.515
ProcessGuid: {a72af1fb-7197-5fa8-4701-000000001c00}
ProcessId: 7384
Image: C:\Users\nour.HACKDEFEND\FSETPBEUsIek.exe
CommandLine: FSETPBEUsIek.exe
LogonGuid: {a72af1fb-412d-5fa8-d537-090000000000}
CurrentDirectory: C:\Users\nour.HACKDEFEND\
User: HACKDEFEND\nour
Hashes: MD5=6F37EB2B7F6720B48588FB2B84ED17C8,SHA256=B88A1534B65F09CC7B7AF7D76

[EventID=3]
UtcTime: 2020-11-08 22:30:46.619
ProcessGuid: {a72af1fb-7197-5fa8-4701-000000001c00}
ProcessId: 7384
Image: C:\Users\nour.HACKDEFEND\FSETPBEUsIek.exe
User: HACKDEFEND\nour
Protocol: tcp
DestinationIp: 192.20.80.25 > "Suspicious IP"
DestinationHostname: nothing.attdns.com
DestinationPort: 449

[EventID=22]
UtcTime: 2020-11-08 22:30:49.110
ProcessGuid: {a72af1fb-7068-5fa8-3001-000000001c00}
ProcessId: 8436
Image: C:\Program Files\Mozilla Firefox\firefox.exe
QueryName: github.com

[EventID=1]
UtcTime: 2020-11-08 22:32:37.223
ProcessGuid: {a72af1fb-7205-5fa8-4b01-000000001c00}
ProcessId: 5952
Image: C:\Windows\SysWOW64\cmd.exe
CommandLine: C:\Windows\system32\cmd.exe
User: HACKDEFEND\nour

[EventID=11]
UtcTime: 2020-11-08 22:35:03.769
Image: C:\Users\nour.HACKDEFEND\FSETPBEUsIek.exe
TargetFilename: C:\Users\NOUR~1.HAC\AppData\Local\Temp\uCOadJlMb.vbs

[EventID=1]
UtcTime: 2020-11-08 22:35:04.063
ProcessGuid: {a72af1fb-7298-5fa8-5201-000000001c00}
ProcessId: 4120
Image: C:\Windows\SysWOW64\cscript.exe
CommandLine: cscript "C:\Users\NOUR~1.HAC\AppData\Local\Temp\uCOadJlMb.vbs"
CurrentDirectory: C:\Users\nour.HACKDEFEND\
User: HACKDEFEND\nour

[EventID=11]
UtcTime: 2020-11-08 22:35:36.654
ProcessGuid: {a72af1fb-7298-5fa8-5201-000000001c00}
ProcessId: 4120
Image: C:\Windows\SysWOW64\cscript.exe
TargetFilename: C:\Users\NOUR~1.HAC\AppData\Local\Temp\radD54BD.tmp\FaFRuwJIlNvBNaT.exe

[EventID=8]
UtcTime: 2020-11-08 22:35:37.718
SourceProcessId: 7384
SourceImage: C:\Users\nour.HACKDEFEND\FSETPBEUsIek.exe
TargetProcessId: 3828
TargetImage: C:\Windows\SysWOW64\notepad.exe
NewThreadId: 3852


[EventID=1]
UtcTime: 2020-11-08 22:38:07.173
ProcessGuid: {a72af1fb-734f-5fa8-6301-000000001c00}
ProcessId: 8112
Image: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe CommandLine: powershell
CurrentDirectory: C:\Users\nour.HACKDEFEND\
User: HACKDEFEND\nour
LogonGuid: {a72af1fb-412d-5fa8-d537-090000000000}

[EventID=11]
UtcTime: 2020-11-08 22:38:12.965
ProcessGuid: {a72af1fb-734f-5fa8-6301-000000001c00}
ProcessId: 8112
Image: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: "C:\Users\nour.HACKDEFEND\AppData\Local\Temp\__PSScriptPolicyTest_1cnlmp23.xlc.ps1"

[EventID=800]
TimeGenerated=1604875141 > "Sun Nov 08 2020 22:39:01 GMT+0000"
command line: Get-ChildItem -Path C:\Users\nour.HACKDEFEND -Filter project48-transactions.xlsx -Recurse -ErrorAction SilentlyContinue -Force
UserId=HACKDEFEND\nour

[EventID=800]
TimeGenerated=1604875184 > "Sun Nov 08 2020 22:39:44 GMT+0000"
command line: Get-ChildItem -Path C:\Users\nour.HACKDEFEND -Filter project48 -Recurse -ErrorAction SilentlyContinue -Force
UserId=HACKDEFEND\nour

[EventID=800]
TimeGenerated=1604876097 > "Sun Nov 08 2020 22:54:57 GMT+0000"
command line: Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
UserId=HACKDEFEND\nour

[EventID=800]
TimeGenerated=1604876130 > "Sun Nov 08 2020 22:55:30 GMT+0000"
command line: Get-Process | Where-Object { $_.ProcessName -eq "Sysmon64" }
UserId=HACKDEFEND\nour

[EventID=800]
TimeGenerated=1604876585 > "Sun Nov 08 2020 23:03:05 GMT+0000"
command line: 1..30 | % {"192.168.10.$($_): $(Test-Connection -count 1 -comp 192.168.10.$($_) -quiet)"}
UserId=HACKDEFEND\nour

[EventID=800]
TimeGenerated=1604876723 > "Sun Nov 08 2020 23:05:23 GMT+0000"
UserId=HACKDEFEND\nour
command line: 1..30 | % {"192.168.20.$($_): $(Test-Connection -count 1 -comp 192.168.20.$($_) -quiet)"}

[EventID=3]
UtcTime: 2020-11-08 23:14:02.276 > "SIEM TIME: 11:14:10"
ProcessGuid: {a72af1fb-72b9-5fa8-5601-000000001c00}
ProcessId: 3828
Image: C:\Windows\SysWOW64\notepad.exe
User: HACKDEFEND\nour
SourceIp: 192.168.10.15
DestinationIp: 192.168.20.20 > "Movement Lateral <---------------"
DestinationPort: 389
DestinationPortName: ldap

[NIDS Alert]
"timestamp": "2020-11-08T19:39:54.261057+0000"
"signature": "ET MALWARE Possible Metasploit Payload Common Construct Bind_API (from server)"
"category": "A Network Trojan was detected"
"src_ip": "192.20.80.25"
"dest_ip": "192.168.10.15"
"dest_port": 50026


[logsource: DC ]
Computer=DC.hackdefend.local
OriginatingComputer=192.168.20.20
Source Network Address: 192.168.10.15

[EventID=1]
UtcTime: 2020-11-09 09:24:36.935
ProcessId: 4764
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1604913874.5822518 2>&1
CurrentDirectory: C:\ User: HACKDEFEND\Administrator
```

# References

- https://www.ibm.com/docs/no/qradar-on-cloud?topic=searches-advanced-search-options
- https://www.ibm.com/docs/en/qradar-on-cloud?topic=aql-query-structure
- https://www.ibm.com/docs/en/qradar-on-cloud?topic=language-time-criteria-in-aql-queries
- https://www.ibm.com/docs/en/qradar-on-cloud?topic=language-event-flow-simarc-fields-aql-queries
