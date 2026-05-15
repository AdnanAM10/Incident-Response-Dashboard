# Sentinel IR — a learning-focused incident response platform

Sentinel IR is a small but realistic web application that simulates the
day-to-day workflow of a Security Operations Center (SOC) analyst /
incident responder. It is intended as a learning sandbox: you can click
through real-style detections, triage them, open tickets, drive them
through the full IR lifecycle, attach evidence and IOCs, and close them
out — without needing access to a real corporate environment.

It is modelled on the concepts and workflows of real-world tools:

| Real-world tool | What it does | What Sentinel IR borrows |
|---|---|---|
| **TheHive Project** | Open-source IR case management | Cases, tasks, observables (IOCs), TLP markings, alert → case promotion |
| **Splunk SOAR (Phantom)** | Security orchestration & playbooks | Playbook concept tied to incident category |
| **IBM Resilient (QRadar SOAR)** | IR workflow & ticketing | Ticket lifecycle, classifications, MTTR |
| **ServiceNow Security Operations** | Enterprise SIR ticketing | Ticket IDs, priorities, severity, assignment |
| **Splunk Enterprise Security / Sentinel / QRadar** | SIEM detection content | The "Alert Queue" with raw events from EDR, IDS, cloud, etc. |
| **PagerDuty / Opsgenie** | On-call & escalation | Severity/priority pairing, status workflow |

It is **NOT** a real SOC tool — it is a teaching tool. There is no real
detection engine, no integration with EDR, no automation, no auth, no
encryption. Treat the database as throw-away.

---

## 1. Quick start

### Requirements
- Python 3.10+
- pip

### Install & run

```bash
# from the project folder
python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell:  .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# populate the database with sample SOC data
python seed.py

# start the web app
python app.py
```

Open http://127.0.0.1:5000 in your browser.

To reset the data at any time, just re-run `python seed.py` — it drops
and recreates everything.

---

## 2. What's in the box

You are dropped into a fictional company's SOC with 5 staff members
and roughly 30 freshly-arrived alerts spanning multiple detection
sources:

- **CrowdStrike Falcon / SentinelOne / Microsoft Defender** — EDR (endpoint detection & response)
- **Splunk / Wazuh** — SIEM (security information & event management)
- **Suricata / Zeek** — Network IDS / NSM
- **Palo Alto NGFW / Cloudflare / AWS WAF** — Network perimeter
- **Proofpoint** — Email security gateway
- **Okta / Azure AD** — Identity & SSO
- **AWS GuardDuty / CloudTrail / GitHub** — Cloud & SaaS
- **Symantec DLP / Microsoft Purview** — Data loss prevention
- **Tenable / Auditd** — Vulnerability & host audit

The alerts cover scenarios you'll see in any real SOC: phishing,
ransomware, credential-stuffing, beacons to known C2, DNS exfiltration,
LSASS access (Mimikatz-style), insider data theft to USB, OAuth
consent grants, public S3 buckets, leaked AWS keys, and so on.

You will also find **6 response playbooks** covering phishing,
ransomware, credential compromise, malware, data exfiltration, and DDoS.

---

## 3. The roles you can play

The top-right "Acting as:" dropdown lets you switch between personas to
simulate handoffs.

| User | Role | Use them for |
|---|---|---|
| Ana Martinez | IR lead | Final triage, status changes, closing |
| Jamal Chen | Analyst | First-line triage, note-taking |
| Riya Kapoor | Analyst | Forensic tasks, IOC enrichment |
| Tunde Okafor | Analyst | Hunting / scoping work |
| Sofia Oliveira | Manager | Read-only stakeholder, sign-off |

Roles are cosmetic in this demo — every persona can do everything. In a
real tool, role-based access control would gate destructive actions.

---

## 4. The core concepts (read this first)

### 4.1 Alert vs. Incident

A **detection** is what a tool tells you it saw. In Sentinel IR these
are **Alerts**.

An **incident** is an analyst's confirmed (or strongly suspected)
problem worth investigating and responding to. It is a *case file*, a
*ticket*, a *workflow object* with a status, tasks, evidence, IOCs, a
timeline of who did what when, and ultimately a closure outcome.

Most alerts never become incidents (they are false positives or benign).
A single incident may bundle many related alerts.

### 4.2 The NIST IR lifecycle (SP 800-61r2)

Sentinel IR's incident statuses follow the canonical phases:

```
   Preparation       (offline — runbooks, training, tooling)
       ↓
   Detection & Analysis
       new  →  triage  →  investigating
       ↓
   Containment, Eradication & Recovery
       contained  →  eradicated  →  recovered
       ↓
   Post-Incident Activity
       closed   (with a classification: true_positive, false_positive,
                 benign, duplicate)
```

You are not forced to move strictly forward. Real incidents bounce —
you might go *investigating* → *contained* and then re-open
*investigating* if you discover the attacker is still active.

### 4.3 Severity vs. Priority

These are different and analysts mix them up. In Sentinel IR:

- **Severity** = how bad would this be if true? (`info`/`low`/`medium`/`high`/`critical`)
  Driven by data sensitivity, blast radius, attacker capability.
- **Priority** = how urgently should we work on it? (`P1`–`P5`)
  Driven by severity + business context + how much attacker dwell time
  matters. A P1 might be a *high* severity incident where the attacker
  is actively pivoting *right now*.

### 4.4 Classification (at closure)

When you close an incident you tag it with one of:

- **true_positive** — real incident, confirmed
- **false_positive** — the detection fired but it wasn't real
- **benign** — real activity, but harmless / authorized (e.g. red-team)
- **duplicate** — same as another incident

This is how the SOC measures detection quality over time.

### 4.5 TLP (Traffic Light Protocol)

When you add IOCs, you tag them with a TLP level. This dictates how
widely you can share that indicator outside your team.

| TLP | Meaning |
|---|---|
| WHITE | unlimited sharing |
| GREEN | community / peer orgs |
| AMBER | your organization only |
| RED | named recipients only (very sensitive) |

### 4.6 MITRE ATT&CK

Alerts and (good) incident write-ups reference the ATT&CK framework —
e.g. `T1110.001 Password Guessing` or `T1486 Data Encrypted for Impact`.
This is the industry-standard vocabulary for adversary behavior. When you
see one in an alert, you can look it up at https://attack.mitre.org.

---

## 5. Walkthrough: handle your first incident

Let's walk through a realistic end-to-end response. Time required: ~15 min.

### Step 1 — survey the queue

Go to **Alert Queue**. Sort/scan by severity. You should see something
like:

> `critical` · CrowdStrike Falcon · *Office spawning PowerShell with encoded payload on FIN-WS-014*

That's a textbook macro-borne malware execution attempt. Click it.

### Step 2 — read the raw event

In the detail view:

- The **Description** gives you the analyst-readable summary.
- **Raw event** shows you what the tool actually saw — process tree,
  command-line, decoded payload, the destination IP.
- **Indicators** lists the IOCs the platform parsed out for you.
- **MITRE** tells you this maps to `T1059.001 PowerShell`.

This is the moment of "is this a real problem?" Decisions a human makes
here:

- Is `WINWORD.EXE → cmd.exe → powershell.exe -enc` ever legitimate? **No.**
- Did EDR block it? Yes — Falcon prevention engaged. Good news, but
  doesn't mean the threat is over (other endpoints may not have had the
  same luck).

### Step 3 — promote to incident

Scroll to "Promote to incident". Pick:
- Category: **malware**
- Priority: **P2** (high severity, contained on one host, but warrants
  immediate investigation of scope)

Click **Create incident**. Sentinel IR will:
- Mint a ticket ID (`INC-2026-NNNN`)
- Carry over source IP, destination IP, host and user from the alert as
  starting IOCs
- Add a timeline entry
- Move the alert's status to `escalated`
- Drop you into the incident detail view

### Step 4 — open the right playbook

In the right column, the platform shows you the playbooks that match
the incident category. Click **"Malware on Endpoint"** in a new tab —
this is your checklist.

### Step 5 — build the response

Working from the playbook, add **Response tasks** on the incident:

1. *Verify hash on VirusTotal — winword.exe and any dropped payload*
2. *Isolate FIN-WS-014 via CrowdStrike network containment*
3. *Pull email logs — was there an inbound message that delivered this doc?*
4. *Hunt: search Falcon for any other host with WINWORD → powershell -enc in last 7d*
5. *Check user kpatel's other devices and recent sign-ins*
6. *Decide: clean or reimage FIN-WS-014?*

Assign tasks to teammates (switch persona with the top-right dropdown
to "do" the work as different analysts).

### Step 6 — record evidence and findings

As you "do" each task, add **timeline entries** at the bottom of the
incident page:

- *Note*: "VT shows 47/72 detection for sha256 d7e1f3b5… — confirmed Qakbot loader."
- *Evidence*: "Memory image of FIN-WS-014 captured to evidence locker E-2026-0014."
- *Note*: "Fleet hunt — no other endpoints show this process chain in last 30 days."

### Step 7 — track new IOCs

While investigating, you'll find new indicators. Add them under
**Observables / IOCs**:

| Type | Value | TLP | Notes |
|---|---|---|---|
| `domain` | `cs-beacon.xyz` | AMBER | Cobalt Strike C2 paired with this campaign |
| `hash_sha256` | `9c3e7b2c...` | AMBER | HTML smuggling attachment dropped IOC |
| `email` | `billing@docusgn-secure.com` | GREEN | spoofed sender from related Proofpoint alert |

### Step 8 — move through the lifecycle

In the right-hand panel, change the status as your response progresses:

- `triage` → `investigating` (once you've scoped it)
- `investigating` → `contained` (host isolated, IOCs blocked at the
  perimeter)
- `contained` → `eradicated` (host reimaged, persistence removed)
- `eradicated` → `recovered` (host returned to production, monitoring
  in place)
- `recovered` → `closed`, classification: `true_positive`

Each status change writes to the timeline automatically — you'll have a
defensible, auditable record by the time you close.

### Step 9 — close out

When closing, set classification to `true_positive`. The dashboard's
MTTR (mean time to closure) metric updates.

🎉 You just ran a real IR workflow.

---

## 6. Scenarios to practice

The seed data is intentionally varied. Try these:

1. **The ransomware drill (critical, time-pressured)**
   Find the *"Mass file rename pattern on SRV-FS-02"* alert. Promote
   under category `ransomware`, priority `P1`. Open the **Ransomware
   Containment** playbook. The clock is your enemy.

2. **The insider threat (HR-sensitive)**
   Find *"312 customer records copied to USB by user lpark"*. This is
   not a malware case. Open under category `insider_threat`. Note the
   playbook reminds you NOT to alert the subject before HR/legal weigh
   in.

3. **The phishing campaign (multi-alert, scope-driven)**
   Find both the HTML smuggling attachment alert AND the O365
   credential phish alert. They look like the same campaign — link
   them under one incident. Use the **Phishing Response** playbook.

4. **The false positive (practice closure discipline)**
   Find the EICAR test file alert. It's a known-benign test, but
   protocol says you still triage it. Promote to an incident, run
   through a minimal lifecycle, close as `false_positive`.

5. **The cloud incident (no endpoint to image)**
   Find *"Root account API call from unusual ASN"*. Pivot through the
   **Compromised Credentials** playbook. The response is entirely
   identity / IAM oriented.

6. **The detection engineering moment**
   Find *"Internal port scan: 10.42.9.21 → /24"* — done by user
   `jchen`. Open the alert; you'll see jchen *also* triggered an
   impossible-travel alert earlier. Could the port scan be follow-on
   activity from a compromised account, not legitimate IT? Practice
   the analytical pivot.

---

## 7. Concept cheat-sheet

**SOC** — Security Operations Center. The team / function that does
detection and response.

**SIEM** — Security Information & Event Management. Centralizes logs,
runs detection rules. Examples: Splunk ES, Microsoft Sentinel, Elastic
SIEM, IBM QRadar.

**EDR** — Endpoint Detection & Response. Agent on each device that
sees process activity, file changes, network calls. Examples:
CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint.

**SOAR** — Security Orchestration, Automation & Response. Glues tools
together with playbooks and automation. Examples: Splunk SOAR,
Tines, Torq, XSOAR.

**IDS / NSM** — Intrusion Detection System / Network Security
Monitoring. Watches traffic. Examples: Suricata, Zeek, Snort.

**IOC** — Indicator of Compromise. A specific artifact tied to bad
activity: IP, domain, URL, file hash, email address, mutex name. In
TheHive these are called "observables."

**TTP** — Tactics, Techniques, Procedures. Behavioral patterns
attackers use. The MITRE ATT&CK framework catalogs these.

**MTTR** — Mean Time To Resolution (or Respond). How long, on
average, it takes you to close incidents. The dashboard tracks this.

**MTTD** — Mean Time To Detect. How long between attacker activity
and your alert. (Not tracked in this demo — requires ground-truth
attacker start time.)

**Dwell time** — How long an attacker was in your environment before
you discovered them. The metric Mandiant publishes every year.

**Chain of custody** — Documentation that proves forensic evidence
wasn't tampered with. Critical for cases that go legal.

**Containment vs. eradication vs. recovery** — Three distinct steps
people commonly conflate.
- *Contained*: attacker can no longer act (host isolated, account
  disabled, network blocked).
- *Eradicated*: the threat is removed (malware deleted, persistence
  gone, vulnerability patched).
- *Recovered*: business is back to normal (systems restored, users
  back online, monitoring in place to detect recurrence).

---

## 8. What this demo does NOT do (and why that's fine)

- **No real authentication** — you switch personas with a dropdown.
  Real platforms use SSO with MFA.
- **No real detection engine** — alerts are static seed data. Real
  SIEMs run continuous correlation rules.
- **No integrations** — clicking "isolate host" in a real EDR actually
  isolates. Here we just type "I isolated the host" in a note.
- **No automation** — real SOAR platforms execute playbook steps for
  you. Here playbooks are reference text.
- **No threat-intel feeds** — real tools auto-enrich an IP/hash with
  reputation data from VT, MISP, AbuseIPDB, etc.
- **No reporting** — real platforms generate PDF incident reports for
  legal, regulators, executives.
- **No SLA tracking, no on-call rotations, no shift handoff, no audit
  log, no metrics export.**

The goal is to make the *workflow* concrete enough that you understand
what those production capabilities are for and what they would feel
like if you had them.

---

## 9. Where to go next (real-world)

If you want to keep learning:

- **TheHive** (free, self-hosted) — install it and use it for a couple
  of weeks. The concept model is almost identical to this demo.
- **The DFIR Report** (https://thedfirreport.com) — free, deep
  case studies of real intrusions. Read 3 of them; you'll
  understand the genre.
- **MITRE ATT&CK** — read through one tactic (e.g. Initial Access)
  and the techniques under it.
- **SANS reading room / NIST SP 800-61r2** — canonical IR documents.
- **Set up a home SOC**: Wazuh + Suricata + a few VMs and you can
  generate your own alerts.

Good hunting.
