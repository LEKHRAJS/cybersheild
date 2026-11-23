"""
VulnShield Standalone — Single-file Windows EVTX analyzer + web UI.
Requirements:
    pip install flask flask-cors python-evtx pandas openpyxl xlsxwriter
Run:
    python vulnshield_web.py
Open:
    http://localhost:5000
"""

import os
import io
import re
import sys
import json
import uuid
import time
import threading
import traceback
import platform
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from xml.etree import ElementTree as ET

# ---------- optional imports (checked at runtime) ----------
try:
    from evtx import PyEvtxParser
except Exception:
    PyEvtxParser = None

try:
    import pandas as pd
except Exception:
    pd = None

from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS

# ===========================================================================
# CONFIG
# ===========================================================================
BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

JOBS = {}  # job_id -> state dict

app = Flask(__name__)
CORS(app)

# ===========================================================================
# EVENT DEFINITIONS — the "brain" of the analyzer
# ===========================================================================
# Each rule: (rule_name, severity, domain, description)
SECURITY_RULES = {
    # Logon / Auth
    4624: ("Successful Logon", "Informational", "Authentication", "A logon was successful."),
    4625: ("Failed Logon", "Medium", "Authentication", "A logon attempt failed."),
    4634: ("Logoff", "Informational", "Authentication", "An account was logged off."),
    4647: ("User Initiated Logoff", "Informational", "Authentication", "User initiated logoff."),
    4648: ("Explicit Credential Logon", "High", "Authentication", "Logon attempted using explicit credentials (possible lateral movement)."),
    4672: ("Special Privileges Assigned", "Medium", "Privilege", "Special privileges assigned to new logon (admin/System)."),
    4776: ("NTLM Authentication", "Informational", "Authentication", "NTLM credential validation."),
    4771: ("Kerberos Pre-Auth Failed", "Medium", "Authentication", "Kerberos pre-authentication failed."),

    # Account management
    4720: ("User Account Created", "High", "Account Management", "A user account was created."),
    4722: ("User Account Enabled", "Medium", "Account Management", "A user account was enabled."),
    4723: ("Password Change Attempt", "Low", "Account Management", "Attempt to change account password."),
    4724: ("Password Reset", "High", "Account Management", "An attempt was made to reset an account's password."),
    4725: ("User Account Disabled", "Medium", "Account Management", "A user account was disabled."),
    4726: ("User Account Deleted", "High", "Account Management", "A user account was deleted."),
    4728: ("Member Added to Global Group", "High", "Account Management", "A member was added to a security-enabled global group."),
    4732: ("Member Added to Local Group", "High", "Account Management", "A member was added to a security-enabled local group."),
    4756: ("Member Added to Universal Group", "High", "Account Management", "Member added to universal security group."),

    # Process
    4688: ("Process Created", "Informational", "Process", "A new process has been created."),
    4689: ("Process Exited", "Informational", "Process", "A process has exited."),

    # Services
    4697: ("Service Installed", "High", "Persistence", "A service was installed in the system."),
    7045: ("Service Installed (System)", "High", "Persistence", "A new service was installed."),
    7040: ("Service Start Type Changed", "Medium", "Persistence", "Service start type changed."),

    # Scheduled tasks
    4698: ("Scheduled Task Created", "High", "Persistence", "A scheduled task was created."),
    4699: ("Scheduled Task Deleted", "Medium", "Persistence", "A scheduled task was deleted."),
    4702: ("Scheduled Task Updated", "Medium", "Persistence", "A scheduled task was updated."),

    # Audit log
    1102: ("Audit Log Cleared", "High", "Anti-Forensics", "The audit log was cleared — strong indicator of anti-forensics."),
    104:  ("Log Cleared", "High", "Anti-Forensics", "Event log was cleared."),

    # Object access / privilege
    4663: ("Object Access Attempt", "Low", "Object Access", "An attempt was made to access an object."),
    4670: ("Permissions Changed", "Medium", "Object Access", "Permissions on an object were changed."),
    4657: ("Registry Value Modified", "Medium", "Registry", "A registry value was modified."),

    # Firewall / network
    4946: ("Firewall Rule Added", "Medium", "Network", "A Windows Firewall rule was added."),
    4947: ("Firewall Rule Modified", "Low", "Network", "A Windows Firewall rule was modified."),
    4948: ("Firewall Rule Deleted", "Medium", "Network", "A Windows Firewall rule was deleted."),

    # Shares
    5140: ("Network Share Accessed", "Low", "Lateral Movement", "A network share object was accessed."),
    5145: ("Network Share Detailed", "Low", "Lateral Movement", "Detailed network share access."),

    # RDP session
    4778: ("Session Reconnected", "Low", "RDP", "A session was reconnected."),
    4779: ("Session Disconnected", "Low", "RDP", "A session was disconnected."),
    1149: ("RDP Auth (TerminalServices)", "Medium", "RDP", "RDP authentication succeeded (TerminalServices)."),

    # Credential access
    5379: ("Credential Manager Read", "Medium", "Credential Access", "Credentials were read from Credential Manager."),

    # WMI
    5861: ("WMI Persistence Registered", "High", "Persistence", "New WMI permanent event subscription."),

    # PowerShell classic
    400:  ("PowerShell Engine Started", "Informational", "PowerShell", "PowerShell engine started."),
    403:  ("PowerShell Engine Stopped", "Informational", "PowerShell", "PowerShell engine stopped."),
    600:  ("PowerShell Provider Started", "Informational", "PowerShell", "PowerShell provider started."),

    # PowerShell Operational
    4103: ("PowerShell Module Logging", "Informational", "PowerShell", "PowerShell module logging event."),
    4104: ("PowerShell Script Block", "Medium", "PowerShell", "PowerShell script block was logged (inspect for malicious content)."),
    4105: ("PowerShell Command Started", "Informational", "PowerShell", "PowerShell command started."),
    4106: ("PowerShell Command Completed", "Informational", "PowerShell", "PowerShell command completed."),
    40961:("PowerShell Console Startup", "Informational", "PowerShell", "PowerShell console starting."),
    40962:("PowerShell Console Ready", "Informational", "PowerShell", "PowerShell console ready for user input."),

    # Sysmon
    1:   ("Sysmon Process Create", "Informational", "Sysmon", "Sysmon: process creation."),
    2:   ("Sysmon File Time Changed", "High", "Sysmon", "Sysmon: file creation time changed (timestomping)."),
    3:   ("Sysmon Network Connect", "Low", "Sysmon", "Sysmon: network connection detected."),
    4:   ("Sysmon Service State Changed", "Informational", "Sysmon", "Sysmon: service state change."),
    5:   ("Sysmon Process Terminated", "Informational", "Sysmon", "Sysmon: process terminated."),
    6:   ("Sysmon Driver Loaded", "Medium", "Sysmon", "Sysmon: driver loaded."),
    7:   ("Sysmon Image Loaded", "Low", "Sysmon", "Sysmon: image loaded."),
    8:   ("Sysmon CreateRemoteThread", "High", "Sysmon", "Sysmon: CreateRemoteThread (possible injection)."),
    9:   ("Sysmon RawAccessRead", "Medium", "Sysmon", "Sysmon: raw access to disk."),
    10:  ("Sysmon Process Access", "Medium", "Sysmon", "Sysmon: process opened (possible credential dumping)."),
    11:  ("Sysmon File Create", "Low", "Sysmon", "Sysmon: file created."),
    12:  ("Sysmon Registry Add/Delete", "Low", "Sysmon", "Sysmon: registry key created/deleted."),
    13:  ("Sysmon Registry Set", "Medium", "Sysmon", "Sysmon: registry value set."),
    14:  ("Sysmon Registry Rename", "Low", "Sysmon", "Sysmon: registry key renamed."),
    15:  ("Sysmon FileCreateStreamHash", "High", "Sysmon", "Sysmon: alternate data stream created (possible malware)."),
    17:  ("Sysmon Pipe Created", "Low", "Sysmon", "Sysmon: named pipe created."),
    18:  ("Sysmon Pipe Connected", "Low", "Sysmon", "Sysmon: named pipe connected."),
    19:  ("Sysmon WMI Filter", "High", "Sysmon", "Sysmon: WMI event filter registered."),
    20:  ("Sysmon WMI Consumer", "High", "Sysmon", "Sysmon: WMI event consumer registered."),
    21:  ("Sysmon WMI Consumer-to-Filter", "High", "Sysmon", "Sysmon: WMI binding registered."),
    22:  ("Sysmon DNS Query", "Low", "Sysmon", "Sysmon: DNS query."),
    23:  ("Sysmon File Delete", "Medium", "Sysmon", "Sysmon: file deleted (archived)."),
    24:  ("Sysmon Clipboard Change", "Low", "Sysmon", "Sysmon: clipboard changed."),
    25:  ("Sysmon Process Tampering", "High", "Sysmon", "Sysmon: process tampering (hollowing)."),
    26:  ("Sysmon File Delete Detected", "Medium", "Sysmon", "Sysmon: file delete detected."),

    # Defender
    1116: ("Defender Malware Detected", "High", "Defender", "Windows Defender detected malware."),
    1117: ("Defender Action Taken", "High", "Defender", "Defender took action against malware."),
    1118: ("Defender Scan Failed", "Medium", "Defender", "Defender remediation failed."),
    1119: ("Defender Remediation Failed", "High", "Defender", "Defender critical failure."),
    1006: ("Defender Malware (alt)", "High", "Defender", "Defender detected malware (alternate ID)."),
    1007: ("Defender Action (alt)", "High", "Defender", "Defender took action (alternate ID)."),
    1008: ("Defender Action Failed", "High", "Defender", "Defender action failed."),
    1015: ("Defender Suspicious Behavior", "High", "Defender", "Defender detected suspicious behavior."),

    # System
    1074: ("System Shutdown/Restart", "Informational", "System", "System was shut down or restarted."),
    6005: ("Event Log Service Started", "Informational", "System", "Event Log service started (boot)."),
    6006: ("Event Log Service Stopped", "Informational", "System", "Event Log service stopped (shutdown)."),
    6008: ("Unexpected Shutdown", "Medium", "System", "Previous system shutdown was unexpected."),
    6013: ("System Uptime Report", "Informational", "System", "System uptime report."),
    7034: ("Service Crashed", "Medium", "System", "A service terminated unexpectedly."),
    7036: ("Service State Change", "Informational", "System", "A service entered running/stopped state."),

    # SMB Client
    31001:("SMB Client Connected", "Low", "Lateral Movement", "SMB client connected to share."),

    # SMB Server Operational
    551:  ("SMB Server Session", "Low", "Lateral Movement", "SMB session established."),

    # Group Policy
    8004: ("Group Policy Applied", "Informational", "Group Policy", "Group Policy applied."),
    8005: ("Group Policy Processed", "Informational", "Group Policy", "Group Policy processed."),
    8006: ("Group Policy Extension", "Informational", "Group Policy", "Group Policy extension processed."),
    8007: ("Group Policy Failed", "Medium", "Group Policy", "Group Policy processing failed."),

    # TerminalServices LocalSessionManager
    21:   ("RDP Session Logon", "Medium", "RDP", "Remote Desktop Services: session logon succeeded."),
    22:   ("RDP Shell Start", "Low", "RDP", "Remote Desktop Services: shell start notification."),
    23:   ("RDP Session Logoff", "Low", "RDP", "Remote Desktop Services: session logoff."),
    24:   ("RDP Session Disconnected", "Low", "RDP", "Remote Desktop Services: session disconnected."),
    25:   ("RDP Session Reconnected", "Low", "RDP", "Remote Desktop Services: session reconnected."),
    39:   ("RDP Session Disconnected", "Low", "RDP", "RDP session disconnected (alt)."),
    40:   ("RDP Session Disconnected (Reason)", "Low", "RDP", "RDP session disconnected with reason."),

    # RDP Client
    1024: ("RDP Client Connection", "Low", "RDP", "RDP client initiated connection."),
    1025: ("RDP Client Disconnection", "Low", "RDP", "RDP client disconnected."),
    1102: ("RDP Client Reconnected", "Low", "RDP", "RDP client reconnected."),

    # WinRM
    6:    ("WinRM Session Created", "Medium", "WinRM", "WinRM session created."),
    7:    ("WinRM Session Closed", "Low", "WinRM", "WinRM session closed."),
    91:   ("WinRM Request", "Low", "WinRM", "WinRM request handled."),
    142:  ("WinRM Plugin Loaded", "Low", "WinRM", "WinRM plugin loaded."),

    # User Profile Service
    1511: ("User Profile Loaded", "Informational", "User Profile", "User profile loaded."),
    1512: ("User Profile Unloaded", "Informational", "User Profile", "User profile unloaded."),
    1518: ("User Profile Created", "Low", "User Profile", "User profile created."),
}

CHANNEL_MAP = {
    "security": "Security",
    "system": "System",
    "windows powershell": "PowerShell",
    "microsoft-windows-powershell/operational": "PowerShell/Operational",
    "microsoft-windows-powershell": "PowerShell/Operational",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "TerminalServices",
    "microsoft-windows-terminalservices-rdpclient/operational": "RDPClient",
    "microsoft-windows-taskscheduler/operational": "ScheduledTask",
    "microsoft-windows-windows defender/operational": "Defender",
    "microsoft-windows-winrm/operational": "WinRM",
    "microsoft-windows-sysmon/operational": "Sysmon",
    "microsoft-windows-groupPolicy/operational": "GroupPolicy",
    "microsoft-windows-smbserver/operational": "SMBServer",
    "microsoft-windows-smbclient/security": "SMBClient",
    "microsoft-windows-user profile service/operational": "UserProfile",
}

SUSPICIOUS_PROCESS_NAMES = re.compile(
    r"(mimikatz|psexec|procdump|wce\.exe|pwdump|netcat|ncat|cobaltstrike|beacon"
    r"|meterpreter|nc\.exe|rundll32\.exe.*javascript|regsvr32\.exe.*scrobj"
    r"|mshta\.exe.*http|wmic\.exe.*process call create"
    r"|powershell\.exe.*-enc|powershell\.exe.*-nop|powershell\.exe.*downloadstring"
    r"|certutil\.exe.*-urlcache|bitsadmin\.exe.*\/transfer|schtasks\.exe.*\/create"
    r"|vssadmin\.exe.*delete|wbadmin\.exe.*delete|bcdedit\.exe.*recoveryenabled no)",
    re.IGNORECASE,
)

SUSPICIOUS_COMMAND_PATTERNS = re.compile(
    r"(Invoke-Mimikatz|Invoke-Expression|IEX\s*\(|DownloadString|DownloadFile"
    r"|FromBase64String|-EncodedCommand|New-Object Net\.WebClient"
    r"|Add-MpPreference.*ExclusionPath|Set-MpPreference.*Disable"
    r"|Wevtutil\s+cl|Clear-EventLog|Remove-EventLog"
    r"|netsh\s+advfirewall\s+set\s+.*state\s+off"
    r"|schtasks\s+\/create|reg\s+add.*Run"
    r"|vssadmin\s+delete\s+shadows|cipher\s+\/w)",
    re.IGNORECASE,
)


# ===========================================================================
# UTILITIES
# ===========================================================================
def log_to(job_id, msg):
    if job_id in JOBS:
        JOBS[job_id]["log"].append(msg)
        if len(JOBS[job_id]["log"]) > 2000:
            JOBS[job_id]["log"] = JOBS[job_id]["log"][-1500:]


def set_progress(job_id, pct):
    if job_id in JOBS:
        JOBS[job_id]["progress"] = min(99, max(0, pct))


# ===========================================================================
# EVTX PARSING
# ===========================================================================
def parse_evtx_file(path):
    """Yield dicts {event_id, channel, computer, time, record_id, raw_xml, data}."""
    parser = PyEvtxParser(str(path))
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    for record in parser.records():
        try:
            root = ET.fromstring(record["data"])
        except ET.ParseError:
            continue
        sys_el = root.find("e:System", ns)
        if sys_el is None:
            continue

        def _text(el):
            return el.text if el is not None and el.text else ""

        event_id = None
        eid_el = sys_el.find("e:EventID", ns)
        if eid_el is not None and eid_el.text:
            event_id = int(eid_el.text)

        channel = _text(sys_el.find("e:Channel", ns))
        computer = _text(sys_el.find("e:Computer", ns))
        time_el = sys_el.find("e:TimeCreated", ns)
        time_created = time_el.get("SystemTime") if time_el is not None else ""
        record_id = _text(sys_el.find("e:EventRecordID", ns))

        # Extract <EventData><Data Name="X">value</Data>
        data = {}
        ed = root.find("e:EventData", ns)
        if ed is not None:
            for d in ed.findall("e:Data", ns):
                name = d.get("Name") or f"_{len(data)}"
                data[name] = (d.text or "").strip()

        yield {
            "event_id": event_id,
            "channel": channel,
            "computer": computer,
            "time_created": time_created,
            "record_id": record_id,
            "raw_xml": record["data"],
            "data": data,
        }


def parse_timestamp(ts):
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


# ===========================================================================
# EVENT → ANALYSIS
# ===========================================================================
def analyze_event(ev):
    """Return a normalized finding dict or None if event not interesting."""
    eid = ev["event_id"]
    channel = (ev["channel"] or "").strip()
    data = ev["data"]

    rule = SECURITY_RULES.get(eid)
    if not rule:
        # Only include informational events from Security/Sysmon/PowerShell
        if channel.lower() not in (
            "security", "microsoft-windows-sysmon/operational",
            "microsoft-windows-powershell/operational",
            "microsoft-windows-windows defender/operational",
        ):
            return None
        rule = (f"EventID {eid}", "Informational", channel or "Unknown", f"Event ID {eid} on {channel}.")

    name, severity, domain, description = rule

    # --- Additional heuristic scoring ---
    haystack = " ".join(f"{k}={v}" for k, v in data.items())

    # Process-related suspicious commands
    if eid in (1, 4688) and data:
        img = (data.get("Image") or data.get("NewProcessName") or "").lower()
        cmd = data.get("CommandLine") or data.get("ProcessCommandLine") or ""
        if SUSPICIOUS_PROCESS_NAMES.search(img) or SUSPICIOUS_COMMAND_PATTERNS.search(cmd):
            severity = "High"
            name = "Suspicious Process Execution"
            description = f"Suspicious process/command: {img or cmd[:120]}"

    # Script block logging
    if eid == 4104 and data:
        script = data.get("ScriptBlockText", "")
        if SUSPICIOUS_COMMAND_PATTERNS.search(script):
            severity = "High"
            name = "Suspicious PowerShell Script Block"
            description = "PowerShell script block contains suspicious patterns."

    # Log cleared
    if eid in (1102, 104):
        severity = "High"

    # Build the finding
    dt = parse_timestamp(ev["time_created"])
    return {
        "timestamp": dt.timestamp() if dt else None,
        "datetime": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
        "event_id": eid,
        "channel": channel,
        "computer": ev["computer"],
        "record_id": ev["record_id"],
        "rule": name,
        "severity": severity,
        "domain": domain,
        "description": description,
        "data": data,
        "raw_xml": ev["raw_xml"][:4000],  # cap size
    }


def channel_to_bucket(channel):
    c = (channel or "").lower().strip()
    for key, bucket in CHANNEL_MAP.items():
        if key in c:
            return bucket
    return channel or "Other"


# ===========================================================================
# ANALYSIS PIPELINE
# ===========================================================================
def analyze_folder(job_id, folder):
    folder = Path(folder)
    evtx_files = list(folder.rglob("*.[eE][vV][tT][xX]"))
    log_to(job_id, f"[*] Found {len(evtx_files)} .evtx file(s) in {folder}")

    findings = []
    per_channel = defaultdict(list)
    event_id_counter = Counter()
    severity_counter = Counter()
    rule_counter = Counter()
    user_counter = Counter()
    ip_counter = Counter()
    proc_counter = Counter()
    host_counter = Counter()
    timesketch_rows = []

    total_records = 0

    for idx, f in enumerate(evtx_files):
        base_pct = int((idx / max(1, len(evtx_files))) * 90)
        set_progress(job_id, base_pct)
        log_to(job_id, f"[{idx+1}/{len(evtx_files)}] Analyzing {f.name} ...")
        try:
            count_this = 0
            for ev in parse_evtx_file(f):
                total_records += 1
                count_this += 1
                finding = analyze_event(ev)
                if finding is None:
                    continue

                findings.append(finding)
                bucket = channel_to_bucket(ev["channel"])
                per_channel[bucket].append(finding)
                event_id_counter[finding["event_id"]] += 1
                severity_counter[finding["severity"]] += 1
                rule_counter[finding["rule"]] += 1
                if finding["computer"]:
                    host_counter[finding["computer"]] += 1

                d = finding["data"]
                for key in ("TargetUserName", "SubjectUserName", "User", "UserID", "AccountName"):
                    if d.get(key) and not d[key].endswith("$"):
                        user_counter[d[key]] += 1
                        break
                for key in ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress", "DestinationIp"):
                    val = d.get(key)
                    if val and val not in ("-", "::1", "127.0.0.1"):
                        ip_counter[val] += 1
                        break
                img = d.get("Image") or d.get("NewProcessName") or d.get("ProcessName")
                if img:
                    proc_counter[Path(img).name] += 1

                timesketch_rows.append({
                    "message": finding["rule"],
                    "timestamp": finding["timestamp"],
                    "datetime": finding["datetime"],
                    "timestamp_desc": "Event Time",
                    "Event ID": finding["event_id"],
                    "Channel": finding["channel"],
                    "Computer": finding["computer"],
                    "Severity": finding["severity"],
                    "Domain": finding["domain"],
                    "Description": finding["description"],
                })
            log_to(job_id, f"    → {count_this} records parsed")
        except Exception as e:
            log_to(job_id, f"    [!] Error on {f.name}: {e}")
            traceback.print_exc()

    set_progress(job_id, 92)
    log_to(job_id, f"[*] Total events parsed: {total_records}")
    log_to(job_id, f"[*] Total findings: {len(findings)}")

    # ---------- Build summaries ----------
    def topn(counter, n=15):
        return [{"name": k, "count": v} for k, v in counter.most_common(n)]

    severity_order = ["High", "Medium", "Low", "Informational"]
    sev_summary = [{"severity": s, "count": severity_counter.get(s, 0)} for s in severity_order]

    # Logon summary (4624/4625)
    logon_ok = defaultdict(int)
    logon_fail = defaultdict(int)
    for f in findings:
        if f["event_id"] == 4624:
            u = f["data"].get("TargetUserName", "?")
            if not u.endswith("$"):
                logon_ok[u] += 1
        elif f["event_id"] == 4625:
            u = f["data"].get("TargetUserName", "?")
            logon_fail[u] += 1

    logon_table = []
    all_users = set(logon_ok) | set(logon_fail)
    for u in sorted(all_users):
        logon_table.append({
            "user": u,
            "successful": logon_ok.get(u, 0),
            "failed": logon_fail.get(u, 0),
        })
    logon_table.sort(key=lambda r: r["successful"] + r["failed"], reverse=True)

    # Executed processes
    process_table = topn(proc_counter, 25)

    # Per-channel counts
    channel_summary = [{"channel": k, "count": len(v)} for k, v in
                       sorted(per_channel.items(), key=lambda kv: len(kv[1]), reverse=True)]

    # Timesketch chronological order
    timesketch_rows.sort(key=lambda r: r["timestamp"] or 0)

    summary = {
        "total_events": total_records,
        "total_findings": len(findings),
        "severity": sev_summary,
        "top_rules": topn(rule_counter, 15),
        "top_event_ids": topn(event_id_counter, 15),
        "top_users": topn(user_counter, 15),
        "top_ips": topn(ip_counter, 15),
        "top_hosts": topn(host_counter, 15),
        "top_processes": process_table,
        "channels": channel_summary,
        "logons": logon_table,
    }

    # ---------- Write output files ----------
    out_dir = OUTPUT_DIR / f"report_{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON (structured results — powers the UI)
    json_path = out_dir / "results.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "findings": findings}, fh, default=str)

    # Timesketch CSV
    ts_path = out_dir / "timesketch.csv"
    with open(ts_path, "w", encoding="utf-8", newline="") as fh:
        fh.write("message,timestamp,datetime,timestamp_desc,Event ID,Channel,Computer,Severity,Domain,Description\n")
        for r in timesketch_rows:
            def esc(x):
                s = str(x).replace('"', '""')
                return f'"{s}"' if any(c in s for c in ',"\n') else s
            fh.write(",".join([
                esc(r["message"]), esc(r["timestamp"]), esc(r["datetime"]),
                esc(r["timestamp_desc"]), esc(r["Event ID"]), esc(r["Channel"]),
                esc(r["Computer"]), esc(r["Severity"]), esc(r["Domain"]), esc(r["Description"]),
            ]) + "\n")

    # Excel report (if pandas available)
    xlsx_path = out_dir / "VulnShield_Report.xlsx"
    if pd is not None:
        try:
            with pd.ExcelWriter(xlsx_path, engine="xlsxwriter") as writer:
                wb = writer.book

                # --- Summary sheet ---
                ws = wb.add_worksheet("Summary")
                writer.sheets["Summary"] = ws
                row = 0
                ws.write(row, 0, "VulnShield Analysis Summary"); ws.write(row, 1, "")
                row += 2
                ws.write(row, 0, "Total Events Parsed"); ws.write(row, 1, total_records); row += 1
                ws.write(row, 0, "Total Findings"); ws.write(row, 1, len(findings)); row += 1
                ws.write(row, 0, "Analysis Time (UTC)"); ws.write(row, 1, datetime.utcnow().isoformat()); row += 2

                ws.write(row, 0, "Severity"); ws.write(row, 1, "Count"); row += 1
                for s in sev_summary:
                    ws.write(row, 0, s["severity"]); ws.write(row, 1, s["count"]); row += 1

                row += 2
                ws.write(row, 0, "Top Detection Rules"); ws.write(row, 1, "Count"); row += 1
                for r in summary["top_rules"]:
                    ws.write(row, 0, r["name"]); ws.write(row, 1, r["count"]); row += 1

                row += 2
                ws.write(row, 0, "Top Users"); ws.write(row, 1, "Count"); row += 1
                for r in summary["top_users"]:
                    ws.write(row, 0, r["name"]); ws.write(row, 1, r["count"]); row += 1

                row += 2
                ws.write(row, 0, "Top Source IPs"); ws.write(row, 1, "Count"); row += 1
                for r in summary["top_ips"]:
                    ws.write(row, 0, r["name"]); ws.write(row, 1, r["count"]); row += 1

                # --- Findings sheet ---
                findings_pd = pd.DataFrame([{
                    "DateTime": f["datetime"],
                    "EventID": f["event_id"],
                    "Severity": f["severity"],
                    "Domain": f["domain"],
                    "Rule": f["rule"],
                    "Channel": f["channel"],
                    "Computer": f["computer"],
                    "Description": f["description"],
                } for f in findings])
                if not findings_pd.empty:
                    findings_pd.to_excel(writer, sheet_name="Findings", index=False)

                # --- Per-channel sheets ---
                for bucket, items in per_channel.items():
                    if not items:
                        continue
                    df = pd.DataFrame([{
                        "DateTime": f["datetime"],
                        "EventID": f["event_id"],
                        "Severity": f["severity"],
                        "Rule": f["rule"],
                        "Domain": f["domain"],
                        "Description": f["description"],
                        "Computer": f["computer"],
                    } for f in items])
                    sheet = re.sub(r"[\[\]\*?/\\:]", "_", bucket)[:31] or "Channel"
                    df.to_excel(writer, sheet_name=sheet, index=False)

                # --- Logon Summary sheet ---
                if logon_table:
                    pd.DataFrame(logon_table).to_excel(writer, sheet_name="Logon Summary", index=False)

                # --- Process Summary sheet ---
                if process_table:
                    pd.DataFrame(process_table).to_excel(writer, sheet_name="Process Summary", index=False)

                # --- Event ID Frequency ---
                pd.DataFrame([{"EventID": k, "Count": v} for k, v in event_id_counter.most_common()]
                             ).to_excel(writer, sheet_name="EventID Frequency", index=False)

                wb.close()
            log_to(job_id, f"[✓] Excel report written: {xlsx_path}")
        except Exception as e:
            log_to(job_id, f"[!] Excel write failed: {e}")
            xlsx_path = None
    else:
        xlsx_path = None
        log_to(job_id, "[!] pandas not installed — skipping Excel output")

    set_progress(job_id, 100)
    log_to(job_id, f"[✓] JSON results: {json_path}")
    log_to(job_id, f"[✓] Timesketch CSV: {ts_path}")
    log_to(job_id, "[✓] Analysis complete")

    return {
        "out_dir": str(out_dir),
        "json": str(json_path),
        "timesketch": str(ts_path),
        "xlsx": str(xlsx_path) if xlsx_path else None,
        "summary": summary,
    }


# ===========================================================================
# BACKGROUND JOB RUNNER
# ===========================================================================
def run_job(job_id, folder):
    JOBS[job_id]["status"] = "running"
    try:
        result = analyze_folder(job_id, folder)
        JOBS[job_id]["result"] = result
        JOBS[job_id]["status"] = "done"
    except Exception as e:
        JOBS[job_id]["status"] = "error"
        log_to(job_id, f"[!] Fatal: {e}")
        log_to(job_id, traceback.format_exc())
    finally:
        JOBS[job_id]["progress"] = 100


# ===========================================================================
# API
# ===========================================================================
@app.route("/api/upload", methods=["POST"])
def api_upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "no files"}), 400
    job_id = str(uuid.uuid4())[:8]
    target = UPLOAD_DIR / job_id
    target.mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        if f.filename and f.filename.lower().endswith((".evtx", ".csv")):
            f.save(target / f.filename)
            saved.append(f.filename)
    return jsonify({"job_id": job_id, "path": str(target), "files": saved})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json() or {}
    job_id = data.get("job_id")
    path = data.get("path")
    if not job_id or not path:
        return jsonify({"error": "job_id and path required"}), 400
    JOBS[job_id] = {
        "status": "queued",
        "progress": 0,
        "log": [],
        "result": None,
        "started": time.time(),
    }
    threading.Thread(target=run_job, args=(job_id, path), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def api_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"status": "unknown"})
    return jsonify({
        "status": job["status"],
        "progress": job["progress"],
        "log": job["log"][-500:],
    })


@app.route("/api/results/<job_id>")
def api_results(job_id):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        return jsonify({"error": "not ready"}), 404
    result = job["result"]
    with open(result["json"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # return top N findings only (UI has detail download)
    data["findings"] = data["findings"][:500]
    return jsonify(data)


@app.route("/api/download/<job_id>/<kind>")
def api_download(job_id, kind):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        return "Not ready", 404
    result = job["result"]
    mapping = {
        "xlsx": result["xlsx"],
        "timesketch": result["timesketch"],
        "json": result["json"],
    }
    path = mapping.get(kind)
    if not path or not Path(path).exists():
        return f"{kind} not available", 404
    return send_file(path, as_attachment=True, download_name=Path(path).name)


# ===========================================================================
# FRONTEND
# ===========================================================================
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>VulnShield — Windows EVTX Analyzer</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0e1a;--card:rgba(20,27,45,.75);--border:rgba(120,160,255,.15);
  --primary:#4f8cff;--primary-2:#7c5cff;--accent:#22d3ee;
  --text:#e6edf7;--muted:#8b9ab8;--danger:#ff5470;--warn:#ffb547;--ok:#22c55e;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);
  min-height:100vh;overflow-x:hidden;position:relative}
.bg-grid{position:fixed;inset:0;
  background-image:linear-gradient(rgba(79,140,255,.06) 1px,transparent 1px),
    linear-gradient(90deg,rgba(79,140,255,.06) 1px,transparent 1px);
  background-size:44px 44px;
  -webkit-mask-image:radial-gradient(ellipse at 50% 0%,#000 40%,transparent 80%);
  mask-image:radial-gradient(ellipse at 50% 0%,#000 40%,transparent 80%);
  z-index:-2}
.bg-glow{position:fixed;top:-300px;left:50%;transform:translateX(-50%);
  width:900px;height:900px;
  background:radial-gradient(circle,rgba(124,92,255,.35),transparent 60%);
  filter:blur(80px);z-index:-1;animation:float 12s ease-in-out infinite alternate}
@keyframes float{from{transform:translateX(-50%) translateY(0)}
  to{transform:translateX(-50%) translateY(40px)}}
.topbar{display:flex;justify-content:space-between;align-items:center;
  padding:22px 40px;border-bottom:1px solid var(--border);
  backdrop-filter:blur(12px);position:sticky;top:0;z-index:50;
  background:rgba(10,14,26,.75)}
.brand{display:flex;gap:14px;align-items:center}
.shield{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--primary),var(--primary-2));
  box-shadow:0 8px 24px rgba(79,140,255,.4);color:white}
.shield svg{width:26px;height:26px}
.brand h1{font-size:1.2rem;font-weight:700;letter-spacing:-.02em}
.brand p{font-size:.75rem;color:var(--muted)}
.status-pill{display:flex;align-items:center;gap:8px;padding:8px 14px;
  border-radius:999px;background:rgba(255,255,255,.04);
  border:1px solid var(--border);font-size:.8rem;color:var(--muted)}
.status-pill .dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.status-pill.running .dot{background:var(--warn);animation:pulse 1.4s infinite}
.status-pill.done .dot{background:var(--ok)}
.status-pill.error .dot{background:var(--danger)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,181,71,.6)}
  100%{box-shadow:0 0 0 12px rgba(255,181,71,0)}}
.container{max-width:1200px;margin:40px auto;padding:0 24px;
  display:flex;flex-direction:column;gap:28px}
.card{position:relative;background:var(--card);border:1px solid var(--border);
  border-radius:16px;padding:32px;backdrop-filter:blur(20px);
  transition:all .35s ease;animation:rise .5s ease both}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.card.locked{opacity:.4;pointer-events:none}
.step-badge{position:absolute;top:-14px;left:24px;
  background:linear-gradient(135deg,var(--primary),var(--primary-2));
  color:white;font-size:.75rem;font-weight:700;padding:6px 12px;
  border-radius:999px;letter-spacing:.06em;box-shadow:0 6px 20px rgba(79,140,255,.4)}
.card h2{font-size:1.35rem;margin-bottom:6px;letter-spacing:-.02em}
.sub{color:var(--muted);font-size:.9rem;margin-bottom:22px}
code{font-family:'JetBrains Mono',monospace;background:rgba(79,140,255,.12);
  padding:2px 6px;border-radius:6px;font-size:.8rem;color:var(--accent)}
.dropzone{border:2px dashed rgba(120,160,255,.3);border-radius:14px;
  padding:42px 24px;text-align:center;cursor:pointer;
  transition:all .25s ease;background:rgba(79,140,255,.03)}
.dropzone:hover,.dropzone.drag{border-color:var(--primary);
  background:rgba(79,140,255,.08);transform:translateY(-2px)}
.dz-icon{width:46px;height:46px;color:var(--primary);margin-bottom:12px}
.dropzone .hint{font-size:.78rem;color:var(--muted)}
.file-list{list-style:none;margin-top:18px;display:flex;flex-direction:column;gap:8px}
.file-list li{display:flex;justify-content:space-between;align-items:center;
  padding:10px 14px;border-radius:10px;background:rgba(255,255,255,.03);
  border:1px solid var(--border);font-size:.85rem;
  font-family:'JetBrains Mono',monospace}
.file-list li span{color:var(--muted);font-size:.75rem}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn{padding:12px 22px;border-radius:10px;border:none;font-family:inherit;
  font-size:.9rem;font-weight:600;cursor:pointer;transition:all .2s ease;
  text-decoration:none;display:inline-flex;align-items:center;gap:8px}
.btn.primary{background:linear-gradient(135deg,var(--primary),var(--primary-2));
  color:white;box-shadow:0 8px 22px rgba(79,140,255,.35)}
.btn.primary:hover:not(:disabled){transform:translateY(-2px);
  box-shadow:0 12px 30px rgba(79,140,255,.5)}
.btn.ghost{background:rgba(255,255,255,.05);color:var(--text);
  border:1px solid var(--border)}
.btn.ghost:hover{background:rgba(255,255,255,.1)}
.btn:disabled{opacity:.4;cursor:not-allowed;box-shadow:none}
.progress-wrap{display:flex;align-items:center;gap:16px;margin-bottom:18px}
.progress{flex:1;height:10px;border-radius:999px;background:rgba(255,255,255,.06);
  overflow:hidden}
.progress-fill{height:100%;width:0%;
  background:linear-gradient(90deg,var(--primary),var(--accent));
  border-radius:999px;transition:width .4s ease;position:relative;overflow:hidden}
.progress-fill::after{content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);
  animation:shimmer 1.4s infinite}
@keyframes shimmer{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
#progressPct{font-family:'JetBrains Mono',monospace;color:var(--accent);
  font-size:.9rem;min-width:46px}
.console{background:#05080f;border:1px solid var(--border);border-radius:10px;
  padding:16px;font-family:'JetBrains Mono',monospace;font-size:.78rem;
  color:#9fe8b0;max-height:340px;overflow-y:auto;line-height:1.6;
  white-space:pre-wrap;word-break:break-word}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-bottom:24px}
.stat{padding:18px;border-radius:12px;background:rgba(255,255,255,.03);
  border:1px solid var(--border);transition:all .25s}
.stat:hover{transform:translateY(-3px);border-color:var(--primary)}
.stat .label{font-size:.72rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;margin-bottom:8px}
.stat .value{font-size:1.9rem;font-weight:700;letter-spacing:-.02em}
.stat.high .value{color:var(--danger)}
.stat.medium .value{color:var(--warn)}
.stat.low .value{color:var(--accent)}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:12px}
@media(max-width:780px){.charts{grid-template-columns:1fr}}
.chart-card{padding:20px;border-radius:12px;background:rgba(255,255,255,.03);
  border:1px solid var(--border)}
.chart-card h3{font-size:.9rem;margin-bottom:16px;color:var(--muted);font-weight:500}
.bars{display:flex;flex-direction:column;gap:10px}
.bar-row{display:grid;grid-template-columns:150px 1fr 46px;align-items:center;
  gap:10px;font-size:.8rem}
.bar-track{height:8px;border-radius:999px;background:rgba(255,255,255,.06);
  overflow:hidden}
.bar-fill{height:100%;border-radius:999px;
  transition:width .6s cubic-bezier(.2,.9,.3,1)}
.bar-count{font-family:'JetBrains Mono',monospace;color:var(--muted);text-align:right}
.bar-row .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.tab{padding:8px 14px;border-radius:8px;font-size:.82rem;cursor:pointer;
  border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--muted);
  transition:all .2s}
.tab:hover{color:var(--text);border-color:var(--primary)}
.tab.active{background:linear-gradient(135deg,var(--primary),var(--primary-2));
  color:white;border-color:transparent}
.tab-content{display:none}.tab-content.active{display:block}
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead th{text-align:left;padding:10px;color:var(--muted);font-weight:600;
  border-bottom:1px solid var(--border);position:sticky;top:0;background:#0d1424}
tbody td{padding:10px;border-bottom:1px solid rgba(120,160,255,.06);
  font-family:'JetBrains Mono',monospace;word-break:break-word}
tbody tr:hover{background:rgba(79,140,255,.06)}
.table-wrap{max-height:520px;overflow:auto;border:1px solid var(--border);
  border-radius:10px}
.badge{padding:3px 9px;border-radius:999px;font-size:.7rem;font-weight:700;
  letter-spacing:.03em}
.badge.High{background:rgba(255,84,112,.15);color:#ff8a9c;border:1px solid rgba(255,84,112,.3)}
.badge.Medium{background:rgba(255,181,71,.15);color:#ffc988;border:1px solid rgba(255,181,71,.3)}
.badge.Low{background:rgba(34,211,238,.15);color:#7ee6f5;border:1px solid rgba(34,211,238,.3)}
.badge.Informational{background:rgba(139,154,184,.15);color:#aab7cc;border:1px solid rgba(139,154,184,.3)}
.downloads{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}
footer{text-align:center;padding:40px 20px;color:var(--muted);font-size:.8rem}
</style>
</head>
<body>
<div class="bg-grid"></div><div class="bg-glow"></div>

<header class="topbar">
  <div class="brand">
    <div class="shield">
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5v6c0 5 3.5 9.5 8 11 4.5-1.5 8-6 8-11V5l-8-3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <div><h1>VulnShield</h1><p>Windows EVTX Threat Analyzer</p></div>
  </div>
  <div class="status-pill" id="statusPill"><span class="dot"></span><span id="statusText">Idle</span></div>
</header>

<main class="container">
  <section class="card" id="step-upload">
    <div class="step-badge">01</div>
    <h2>Upload Windows Event Logs</h2>
    <p class="sub">Drop your <code>.evtx</code> files. Security, System, PowerShell, Sysmon, Defender, RDP, SMB, Tasks &amp; more are auto-detected.</p>
    <div class="dropzone" id="dropzone">
      <input type="file" id="fileInput" multiple accept=".evtx" hidden />
      <svg class="dz-icon" viewBox="0 0 24 24" fill="none"><path d="M12 16V4m0 0l-4 4m4-4l4 4M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <p><strong>Click to browse</strong> or drag .evtx files here</p>
      <span class="hint">Multi-file supported · all processing is local</span>
    </div>
    <ul class="file-list" id="fileList"></ul>
    <div class="actions">
      <button class="btn ghost" id="clearBtn">Clear</button>
      <button class="btn primary" id="uploadBtn" disabled>Upload &amp; Analyze →</button>
    </div>
  </section>

  <section class="card locked" id="step-progress">
    <div class="step-badge">02</div>
    <h2>Analysis in Progress</h2>
    <div class="progress-wrap">
      <div class="progress"><div class="progress-fill" id="progressFill"></div></div>
      <span id="progressPct">0%</span>
    </div>
    <pre class="console" id="console"></pre>
  </section>

  <section class="card locked" id="step-results">
    <div class="step-badge">03</div>
    <h2>Detection Summary</h2>
    <div class="stats" id="stats"></div>

    <div class="charts">
      <div class="chart-card"><h3>Incidents by Severity</h3><div class="bars" id="sevBars"></div></div>
      <div class="chart-card"><h3>Top Detection Rules</h3><div class="bars" id="ruleBars"></div></div>
      <div class="chart-card"><h3>Top Users</h3><div class="bars" id="userBars"></div></div>
      <div class="chart-card"><h3>Top Source IPs</h3><div class="bars" id="ipBars"></div></div>
    </div>

    <h2 style="margin-top:30px;font-size:1.1rem">Detailed Findings</h2>
    <div class="tabs" id="tabs"></div>
    <div id="tabContents"></div>

    <div class="downloads">
      <a class="btn primary" id="dlXlsx" download>⬇ Download Excel Report (.xlsx)</a>
      <a class="btn ghost" id="dlTs" download>⬇ Download Timesketch CSV</a>
      <a class="btn ghost" id="dlJson" download>⬇ Download JSON</a>
    </div>
  </section>
</main>

<footer>VulnShield · 100% local analysis · No data leaves your machine</footer>

<script>
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const fileList = document.getElementById("fileList");
const uploadBtn = document.getElementById("uploadBtn");
const clearBtn = document.getElementById("clearBtn");
const statusPill = document.getElementById("statusPill");
const statusText = document.getElementById("statusText");
const consoleEl = document.getElementById("console");
const progressFill = document.getElementById("progressFill");
const progressPct = document.getElementById("progressPct");

let files = [];
let jobId = null;

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("dragover", e => { e.preventDefault(); dropzone.classList.add("drag"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", e => {
  e.preventDefault(); dropzone.classList.remove("drag");
  addFiles([...e.dataTransfer.files]);
});
fileInput.addEventListener("change", () => addFiles([...fileInput.files]));

function addFiles(list){
  const valid = list.filter(f => /\.evtx$/i.test(f.name));
  files.push(...valid);
  renderFiles();
}
function renderFiles(){
  fileList.innerHTML = files.map(f =>
    `<li><span>📄 ${f.name}</span><span>${(f.size/1024/1024).toFixed(2)} MB</span></li>`).join("");
  uploadBtn.disabled = files.length === 0;
}
clearBtn.addEventListener("click", () => { files = []; renderFiles(); });

function unlock(id){ document.getElementById(id).classList.remove("locked"); }
function setStatus(cls, text){
  statusPill.className = "status-pill " + cls;
  statusText.textContent = text;
}

uploadBtn.addEventListener("click", async () => {
  const fd = new FormData();
  files.forEach(f => fd.append("files", f));
  uploadBtn.textContent = "Uploading...";
  try{
    const res = await fetch("/api/upload", { method:"POST", body: fd });
    const data = await res.json();
    if(!res.ok) throw new Error(data.error || "upload failed");
    jobId = data.job_id;
    uploadBtn.textContent = "Uploaded ✓";
    unlock("step-progress"); unlock("step-results");
    setStatus("running","Analyzing");
    await fetch("/api/analyze", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ job_id: jobId, path: data.path }),
    });
    pollStatus();
  }catch(e){
    uploadBtn.textContent = "Upload Failed — Retry";
    alert("Upload failed: " + e.message);
  }
});

async function pollStatus(){
  try{
    const res = await fetch("/api/status/" + jobId);
    const s = await res.json();
    progressFill.style.width = (s.progress||0) + "%";
    progressPct.textContent = (s.progress||0) + "%";
    consoleEl.textContent = (s.log||[]).join("\n");
    consoleEl.scrollTop = consoleEl.scrollHeight;

    if(s.status === "done"){
      setStatus("done","Complete");
      progressFill.style.width = "100%";
      progressPct.textContent = "100%";
      await loadResults();
      return;
    }
    if(s.status === "error"){
      setStatus("error","Error"); return;
    }
    setTimeout(pollStatus, 1200);
  }catch(e){ setTimeout(pollStatus, 2000); }
}

async function loadResults(){
  const res = await fetch("/api/results/" + jobId);
  const data = await res.json();
  renderSummary(data.summary, data.findings);
  document.getElementById("dlXlsx").href = `/api/download/${jobId}/xlsx`;
  document.getElementById("dlTs").href = `/api/download/${jobId}/timesketch`;
  document.getElementById("dlJson").href = `/api/download/${jobId}/json`;
}

function barList(el, rows, color){
  const max = Math.max(1, ...rows.map(r=>r.count));
  el.innerHTML = rows.map(r => `
    <div class="bar-row">
      <span class="name" title="${r.name}">${r.name}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(r.count/max*100).toFixed(0)}%;background:${color}"></div></div>
      <span class="bar-count">${r.count}</span>
    </div>`).join("") || `<div style="color:var(--muted);font-size:.85rem">No data</div>`;
}

function renderSummary(summary, findings){
  const sevMap = Object.fromEntries(summary.severity.map(s=>[s.severity,s.count]));
  const total = summary.total_findings || 1;
  document.getElementById("stats").innerHTML = `
    <div class="stat"><div class="label">Total Events</div><div class="value">${summary.total_events}</div></div>
    <div class="stat"><div class="label">Total Findings</div><div class="value">${summary.total_findings}</div></div>
    <div class="stat high"><div class="label">High</div><div class="value">${sevMap.High||0}</div></div>
    <div class="stat medium"><div class="label">Medium</div><div class="value">${sevMap.Medium||0}</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value">${sevMap.Low||0}</div></div>
    <div class="stat"><div class="label">Informational</div><div class="value">${sevMap.Informational||0}</div></div>
  `;

  const sevColors = {High:"#ff5470",Medium:"#ffb547",Low:"#22d3ee",Informational:"#8b9ab8"};
  barList(document.getElementById("sevBars"),
    summary.severity.map(s=>({name:s.severity,count:s.count})),
    "#4f8cff");
  // apply per-row colors manually:
  document.querySelectorAll("#sevBars .bar-row").forEach((row,i)=>{
    const s = summary.severity[i];
    const fill = row.querySelector(".bar-fill");
    if(fill) fill.style.background = sevColors[s.severity] || "#4f8cff";
  });

  barList(document.getElementById("ruleBars"),
    summary.top_rules.map(r=>({name:r.name,count:r.count})),
    "linear-gradient(90deg,#4f8cff,#7c5cff)");
  barList(document.getElementById("userBars"),
    summary.top_users.map(r=>({name:r.name,count:r.count})),
    "linear-gradient(90deg,#22d3ee,#4f8cff)");
  barList(document.getElementById("ipBars"),
    summary.top_ips.map(r=>({name:r.name,count:r.count})),
    "linear-gradient(90deg,#ffb547,#ff5470)");

  // Tabs
  const tabs = ["All", "High", "Medium", "Low", "Informational"];
  const tabsEl = document.getElementById("tabs");
  const contentsEl = document.getElementById("tabContents");
  tabsEl.innerHTML = tabs.map((t,i)=>`<div class="tab ${i===0?'active':''}" data-t="${t}">${t}</div>`).join("");
  contentsEl.innerHTML = tabs.map((t,i)=>`
    <div class="tab-content ${i===0?'active':''}" data-t="${t}">
      <div class="table-wrap"><table>
        <thead><tr>
          <th style="width:150px">Time</th><th style="width:70px">EID</th>
          <th style="width:110px">Severity</th><th>Rule</th>
          <th style="width:110px">Domain</th><th>Computer</th><th>Description</th>
        </tr></thead>
        <tbody id="tbody-${t}"></tbody>
      </table></div>
    </div>`).join("");

  const filtered = t => t === "All" ? findings : findings.filter(f=>f.severity===t);
  tabs.forEach(t=>{
    const rows = filtered(t).slice(0, 500).map(f=>`
      <tr>
        <td>${f.datetime}</td>
        <td>${f.event_id ?? ""}</td>
        <td><span class="badge ${f.severity}">${f.severity}</span></td>
        <td>${f.rule}</td>
        <td>${f.domain}</td>
        <td>${f.computer||""}</td>
        <td>${f.description}</td>
      </tr>`).join("");
    document.getElementById("tbody-"+t).innerHTML = rows || `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No findings</td></tr>`;
  });

  tabsEl.addEventListener("click", e=>{
    const tab = e.target.closest(".tab"); if(!tab) return;
    document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(x=>x.classList.remove("active"));
    tab.classList.add("active");
    document.querySelector(`.tab-content[data-t="${tab.dataset.t}"]`).classList.add("active");
  });
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ===========================================================================
# MAIN
# ===========================================================================
if __name__ == "__main__":
    if platform.system().lower() == "windows":
        import multiprocessing
        multiprocessing.freeze_support()

    print("=" * 66)
    print("  VulnShield Standalone")
    print("  Uploads :", UPLOAD_DIR)
    print("  Reports :", OUTPUT_DIR)
    print("  Open    : http://localhost:5000")
    print("=" * 66)

    missing = []
    if PyEvtxParser is None: missing.append("python-evtx")
    if pd is None: missing.append("pandas openpyxl xlsxwriter")
    if missing:
        print("[!] Missing packages:")
        for m in missing: print("     pip install", m)
        print()

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)