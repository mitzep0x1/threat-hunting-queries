# Boss Of The SOC v1 Lab
- https://tryhackme.com/r/room/splunk201
- https://cyberdefenders.org/blueteam-ctf-challenges/15
- https://medium.com/@mitzepx01/boss-of-the-soc-v1-lab-cyberdefenders-threat-hunting-6a20490a7c1a

```spl
`comment("index - top -> Query to display the available indexes")`
| eventcount summarize=false index=*

`comment("sourcetype - top")`
index=botsv1
| stats count by sourcetype
| sort -count

`comment("summary - source")`
index=botsv1
| stats count by host, source, sourcetype
| sort -count


index=botsv1 "imreallynotbatman.com"
| top sourcetype

`comment("IIS Server Logs")`
index=botsv1 sourcetype=iis "imreallynotbatman.com"

`comment("stream - HTTP Logs")`
index=botsv1 sourcetype="stream:http" "imreallynotbatman.com"

`comment("suricata Alerts")`
index=botsv1 sourcetype="suricata" "imreallynotbatman.com"

`comment("FortiGate UTM Logs")`
index=botsv1 sourcetype="fgt_utm" "imreallynotbatman.com"


index=botsv1 sourcetype="iis" "imreallynotbatman.com" NOT cs_User_Agent="Mozilla*"
| stats count by c_ip, cs_User_Agent, cs_method, cs_uri_stem, sc_status
| sort -count


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" NOT http_user_agent="Mozilla*"
| stats count by c_ip, http_user_agent 
| sort -count


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" http_user_agent="Python-urllib/2.7" http_method=POST
| stats count by _time, src_content, status 
| sort _time


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" earliest="08/10/2016:21:48:05" latest="08/10/2016:21:58:05" cookie="7598a3465c906161e060ac551a9e0276=9qfk2654t4rmhltilkfhe7ua23" http_method=POST
| sort _time


index=botsv1 sourcetype="suricata" "imreallynotbatman.com"
| stats count by event_type 
| sort -count


index=botsv1 sourcetype="suricata" "imreallynotbatman.com" event_type=alert
| stats count by src_ip, signature, url
| sort -count


index=botsv1 sourcetype="fgt_utm" src="192.168.250.70"
| stats count by dstip, url
| sort -count


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" http_user_agent="Python-urllib/2.7" http_method=POST
| rex field="src_content" "passwd=(?<pass>.+?(?=&|$))"
| eval passwdlen=len(pass) 
| search passwdlen=6
| lookup coldplay.csv song as pass output song
| search song=*
| table pass


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" http_user_agent="Python-urllib/2.7" http_method=POST
| rex field="src_content" "passwd=(?<pass>.+?(?=&|$))"
| eval passwd_len = len(pass)
| stats avg(passwd_len) as avg_passwd_len
| eval avg_passwd_len = round(avg_passwd_len,2)


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" http_method=POST
| rex field="src_content" "passwd=(?<pass>.+?(?=&|$))"
| search pass="batman"
| sort _time
| streamstats current=f window=1 last(_time) as prev_time
| eval diff_seconds=round(_time - prev_time, 2)
| table _time prev_time diff_seconds http_user_agent c_ip src_content


index=botsv1 sourcetype="stream:http" "imreallynotbatman.com" http_method=POST
| rex field="src_content" "passwd=(?<pass>.+?(?=&|$))"
| stats dc(pass) as "unique"


index=botsv1 "cerberhhyed5frqa"
| sort _time


index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 "WScript" 
| eval cmdl=len(cmdline)
| table _time EventID ParentProcessId parent_process_name  ProcessId process_name cmdline cmdl
| sort _time


index=botsv1 earliest="08/24/2016:16:43:21" latest="08/24/2016:16:53:21" "192.168.250.100" sourcetype="fgt_utm" subtype=webfilter 
| table _time site vendor_url
| sort _time


index=botsv1 EventCode=5145 ".pdf" WriteData


index=botsv1 "osk.exe" file_path="*bob.smith.WAYNECORPINC*" ".txt" 
```