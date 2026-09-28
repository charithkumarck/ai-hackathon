"""
A realistic starter rule set for the bulk-coverage demo.

Deliberately lopsided the way a real SIEM is: heavy on identity and Windows
endpoint because that is where teams start, thin on network, almost nothing in
cloud. That imbalance is the point -- it is what the coverage screen exposes.
"""
from __future__ import annotations

SEED_RULES: list[dict[str, str]] = [
    # ---------------- Identity (well covered) ----------------
    {"name": "Brute force - failed logon burst", "language": "SPL", "query":
     'index=authentication action=failure\n| stats count by src_ip, user\n| where count > 20'},
    {"name": "Password spraying across accounts", "language": "KQL", "query":
     'SigninLogs\n| where ResultType != 0\n| summarize accounts=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)\n| where accounts > 15'},
    {"name": "Disabled account logon attempt", "language": "KQL", "query":
     'SigninLogs\n| where ResultType == 50057\n| summarize count() by UserPrincipalName, IPAddress'},
    {"name": "Legacy auth protocol usage", "language": "KQL", "query":
     'SigninLogs\n| where ClientAppUsed in ("IMAP4","POP3","SMTP")\n| where ResultType == 0\n| project TimeGenerated, UserPrincipalName, IPAddress'},
    {"name": "Impossible travel", "language": "SPL", "query":
     'index=authentication action=success\n| stats values(country) as countries dc(country) as n by user, _time span=1h\n| where n > 1'},
    {"name": "Account lockout storm", "language": "SPL", "query":
     'index=wineventlog EventCode=4740\n| stats count by user\n| where count > 3'},
    {"name": "Guest account sign-in", "language": "KQL", "query":
     'SigninLogs\n| where UserType == "Guest" and ResultType == 0\n| summarize count() by UserPrincipalName'},
    {"name": "Service account interactive logon", "language": "SPL", "query":
     'index=wineventlog EventCode=4624 Logon_Type=2 user=svc_*\n| table _time, user, src_ip'},

    # ---------------- Endpoint (moderate) ----------------
    {"name": "Encoded PowerShell execution", "language": "KQL", "query":
     'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine'},
    {"name": "LSASS memory access", "language": "KQL", "query":
     'DeviceEvents\n| where ActionType == "OpenProcessApiCall"\n| where FileName =~ "lsass.exe"\n| where InitiatingProcessFileName !in ("MsMpEng.exe","csrss.exe")'},
    {"name": "Suspicious scheduled task creation", "language": "SPL", "query":
     'index=wineventlog EventCode=4698\n| search Task_Name!="\\\\Microsoft\\\\*"\n| table _time, host, user, Task_Name'},
    {"name": "Registry run key persistence", "language": "SPL", "query":
     'index=sysmon EventCode=13 TargetObject="*\\\\CurrentVersion\\\\Run\\\\*"\n| table _time, host, Image, TargetObject, Details'},
    {"name": "Office spawning a script host", "language": "KQL", "query":
     'DeviceProcessEvents\n| where InitiatingProcessFileName in ("winword.exe","excel.exe","outlook.exe")\n| where FileName in ("wscript.exe","cscript.exe","powershell.exe","cmd.exe")'},
    {"name": "Shadow copy deletion", "language": "SPL", "query":
     'index=sysmon EventCode=1 (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wbadmin*delete*catalog*")\n| table _time, host, user, CommandLine'},
    {"name": "Security tooling service stopped", "language": "SPL", "query":
     'index=wineventlog EventCode=7036 Service_Name IN ("Windows Defender","CrowdStrike Falcon","SentinelOne")\n| search Message="*stopped*"'},
    {"name": "New local admin account", "language": "SPL", "query":
     'index=wineventlog EventCode=4720\n| join user [search index=wineventlog EventCode=4732 Group_Name=Administrators]\n| table _time, host, user'},
    {"name": "Rundll32 with network connection", "language": "KQL", "query":
     'DeviceNetworkEvents\n| where InitiatingProcessFileName =~ "rundll32.exe"\n| where RemoteIPType == "Public"'},
    {"name": "Mass file encryption behaviour", "language": "KQL", "query":
     'DeviceFileEvents\n| summarize modified=count() by DeviceId, InitiatingProcessFileName, bin(Timestamp, 5m)\n| where modified > 500'},

    # ---------------- Network (thin) ----------------
    {"name": "Beaconing to rare external domain", "language": "SPL", "query":
     'index=proxy\n| stats count avg(bytes_out) as avg_out by dest_domain, src_ip\n| where count > 100 AND avg_out < 1000'},
    {"name": "DNS tunnelling - long query names", "language": "SPL", "query":
     'index=dns\n| eval qlen=len(query)\n| where qlen > 100\n| stats count by src_ip, query'},
    {"name": "SMB lateral movement burst", "language": "KQL", "query":
     'DeviceNetworkEvents\n| where RemotePort == 445\n| summarize hosts=dcount(RemoteIP) by DeviceName, bin(Timestamp, 10m)\n| where hosts > 10'},

    # ---------------- Cloud (almost nothing) ----------------
    {"name": "S3 bucket made public", "language": "SPL", "query":
     'index=cloudtrail eventName=PutBucketAcl\n| search requestParameters.x-amz-acl="public-read"\n| table _time, userIdentity.arn, requestParameters.bucketName'},

    # ---------------- A few more, mixed ----------------
    {"name": "Kerberoasting - RC4 ticket requests", "language": "SPL", "query":
     'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17\n| stats dc(Service_Name) as services by user\n| where services > 5'},
    {"name": "Golden ticket anomaly", "language": "SPL", "query":
     'index=wineventlog EventCode=4768\n| search Account_Domain!="CORP"\n| table _time, user, src_ip'},
    {"name": "Credential file access", "language": "KQL", "query":
     'DeviceFileEvents\n| where FileName in~ ("unattend.xml","credentials","id_rsa",".aws/credentials")\n| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath'},
    {"name": "Domain account enumeration", "language": "SPL", "query":
     'index=sysmon EventCode=1 (CommandLine="*net group*domain admins*" OR CommandLine="*net user*/domain*")\n| table _time, host, user, CommandLine'},
    {"name": "Archive utility on file share", "language": "KQL", "query":
     'DeviceProcessEvents\n| where FileName in~ ("7z.exe","rar.exe","winrar.exe")\n| where ProcessCommandLine has "\\\\\\\\"'},
    {"name": "Windows event log cleared", "language": "SPL", "query":
     'index=wineventlog EventCode=1102\n| table _time, host, user'},
    {"name": "MFA fatigue - repeated push denials", "language": "KQL", "query":
     'SigninLogs\n| where ResultType == 500121\n| summarize denials=count() by UserPrincipalName, bin(TimeGenerated, 15m)\n| where denials > 5'},
    {"name": "Inbox forwarding rule created", "language": "KQL", "query":
     'OfficeActivity\n| where Operation in ("New-InboxRule","Set-InboxRule")\n| where Parameters has_any ("ForwardTo","RedirectTo")'},
]


def seed_queries() -> list[dict[str, str]]:
    return SEED_RULES
