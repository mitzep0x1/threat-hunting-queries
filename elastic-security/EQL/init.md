```sql
// This query detects the creation and subsequent deletion of a user account within 1 hour
sequence by winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName with maxspan=1h
[iam where event.code == "4720"]
[iam where event.code == "4726"]
```