# Valid Accounts (T1078)
- https://attack.mitre.org/techniques/T1078/

## Valid Accounts: Cloud Accounts
- https://attack.mitre.org/techniques/T1078/004/

### Microsoft 365 Portal Login from Multiple Countries
- Description: Detects accounts that successfully sign in from more than one country within a configurable time window. 
- Kibana Query Language: `event.action: "UserLoggedIn" AND NOT o365.audit.UserId: "Not Available" AND source.geo.country_name:*`
- Elasticsearch Query Language:
```sql
FROM .ds-logs-o365.audit-*
| WHERE event.action == "UserLoggedIn" AND NOT o365.audit.UserId == "Not Available" AND source.geo.country_name IS NOT NULL
| STATS _xc = COUNT(), _xcard = COUNT_DISTINCT(source.geo.country_name), _xcardv = VALUES(source.geo.country_name) BY o365.audit.UserId
| EVAL _xcardv = MV_CONCAT(_xcardv, ", ")
| EVAL _xmsg = CONCAT(o365.audit.UserId, " M365 Portal Login from ", _xcardv)
| WHERE _xcard > 1
| LIMIT 10
```
- Notes: Review user agent and ASN of the source IP.
- False Positive: Legitimate user travel, corporate VPNs or proxies routing traffic through multiple countries.
- References: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/o365/initial_access_microsoft_365_portal_login_from_rare_location
