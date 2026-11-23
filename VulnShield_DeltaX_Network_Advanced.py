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
import csv
import math
import uuid
import time
import threading
import subprocess
import traceback
import platform
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from xml.etree import ElementTree as ET

# ---------- EVTX parser: use python-evtx only ----------
# Do not install the separate PyPI package "evtx" in this Windows venv:
# its lowercase import directory collides with python-evtx's "Evtx" directory.
try:
    from Evtx.Evtx import Evtx as _PythonEvtx
except Exception:
    _PythonEvtx = None

class _PythonEvtxParserCompat:
    def __init__(self, filename):
        self.filename = str(filename)

    def records(self):
        if _PythonEvtx is None:
            raise RuntimeError(
                "python-evtx is not installed. Run: python -m pip install python-evtx"
            )
        with _PythonEvtx(self.filename) as log:
            for rec in log.records():
                try:
                    xml_text = rec.xml()
                except Exception:
                    continue
                try:
                    root = ET.fromstring(xml_text)
                except ET.ParseError:
                    continue
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                system = root.find("e:System", ns)
                time_node = system.find("e:TimeCreated", ns) if system is not None else None
                timestamp = time_node.get("SystemTime", "") if time_node is not None else ""
                yield {"data": xml_text, "timestamp": timestamp}

PyEvtxParser = _PythonEvtxParserCompat if _PythonEvtx is not None else None

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
INTEL_IMPORTED = {"filename": "", "records": [], "kind": ""}
INTEL_IMPORT_LOCK = threading.RLock()


# ===========================================================================
# LIVE WINDOWS EVENT MONITOR
# ===========================================================================
LIVE_STATE = {
    "running": False,
    "events": [],
    "findings": [],
    "last_error": "",
    "started_at": None,
    "thread": None,
}
LIVE_LOCK = threading.Lock()
LIVE_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
]
LIVE_MAX_EVENTS = 10000
LIVE_POLL_SECONDS = 2


def _wevtutil_xml(channel, query, count=100):
    """Read event XML from a Windows event channel using built-in wevtutil."""
    command = [
        "wevtutil.exe", "qe", channel, "/q:" + query,
        "/f:xml", "/rd:false", "/c:" + str(count)
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip()
        if "No events were found" in message:
            return []
        raise RuntimeError(message or f"wevtutil failed for {channel}")

    raw = completed.stdout.strip()
    if not raw:
        return []

    # Some Windows builds return one Event, others return an Events wrapper,
    # and some return adjacent Event elements. Handle all three formats.
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw).strip()
    try:
        root = ET.fromstring(raw)
        if root.tag.endswith("Event"):
            return [root]
        if root.tag.endswith("Events"):
            return [el for el in list(root) if el.tag.endswith("Event")]
    except ET.ParseError:
        pass

    # Fallback for adjacent Event elements without a common root.
    fragments = re.findall(
        r"(<(?:[A-Za-z0-9_]+:)?Event\b.*?</(?:[A-Za-z0-9_]+:)?Event>)",
        raw, flags=re.DOTALL
    )
    parsed = []
    for fragment in fragments:
        try:
            parsed.append(ET.fromstring(fragment))
        except ET.ParseError:
            continue
    if parsed:
        return parsed

    raise RuntimeError(f"Could not parse XML returned for Windows channel '{channel}'.")


def _live_event_dict(root):
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None:
        return None
    def txt(node):
        return node.text.strip() if node is not None and node.text else ""
    eid = txt(system.find("e:EventID", ns))
    if not eid:
        return None
    tc = system.find("e:TimeCreated", ns)
    data = {}
    event_data = root.find("e:EventData", ns)
    if event_data is not None:
        for item in event_data.findall("e:Data", ns):
            key = item.get("Name") or f"_{len(data)}"
            data[key] = (item.text or "").strip()
    # Some providers use UserData instead of EventData; preserve its text.
    if not data:
        user_data = root.find("e:UserData", ns)
        if user_data is not None:
            data["UserData"] = " ".join(t.strip() for t in user_data.itertext() if t.strip())
    raw = ET.tostring(root, encoding="unicode")
    return {
        "event_id": int(eid),
        "channel": txt(system.find("e:Channel", ns)),
        "computer": txt(system.find("e:Computer", ns)),
        "time_created": tc.get("SystemTime", "") if tc is not None else "",
        "record_id": txt(system.find("e:EventRecordID", ns)),
        "raw_xml": raw,
        "data": data,
    }


def _available_live_channels():
    """Return only configured channels present on this Windows installation."""
    configured = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
    ]
    completed = subprocess.run(
        ["wevtutil.exe", "el"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if completed.returncode != 0:
        # Let the normal collector report access or service errors.
        return configured
    installed = {line.strip().casefold() for line in completed.stdout.splitlines() if line.strip()}
    return [name for name in configured if name.casefold() in installed]


def _latest_record_id(channel):
    # Start from the newest existing record so monitoring captures new activity,
    # rather than replaying the entire historical event log on startup.
    command = ["wevtutil.exe", "qe", channel, "/q:*", "/f:xml", "/rd:true", "/c:1"]
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return 0
    raw = re.sub(r"<\?xml[^>]*\?>", "", completed.stdout.strip()).strip()
    try:
        root = ET.fromstring(raw)
        ev = _live_event_dict(root)
        return int(ev["record_id"]) if ev else 0
    except (ET.ParseError, TypeError, ValueError, KeyError):
        return 0


def _live_monitor_loop():
    cursors = {}
    failed_logons = defaultdict(list)
    try:
        available_channels = _available_live_channels()
        missing_channels = [name for name in LIVE_CHANNELS if name not in available_channels]
        for channel in missing_channels:
            if channel.casefold() == "microsoft-windows-sysmon/operational".casefold():
                with LIVE_LOCK:
                    LIVE_STATE["last_error"] = (
                        "Optional Sysmon channel is not installed; continuing without Sysmon. "
                        "Install Sysmon only if you want Sysmon-specific process telemetry."
                    )
        if not available_channels:
            with LIVE_LOCK:
                LIVE_STATE["last_error"] = (
                    "No configured Windows Event Log channels were found. "
                    "Check Windows Event Log service and run the application with appropriate permissions."
                )
            return
        for channel in available_channels:
            try:
                cursors[channel] = _latest_record_id(channel)
            except Exception as exc:
                with LIVE_LOCK:
                    LIVE_STATE["last_error"] = f"{channel}: {exc}"
                cursors[channel] = 0

        while True:
            with LIVE_LOCK:
                if not LIVE_STATE["running"]:
                    break
            for channel in available_channels:
                with LIVE_LOCK:
                    if not LIVE_STATE["running"]:
                        break
                try:
                    query = f"*[System[(EventRecordID > {cursors.get(channel, 0)})]]"
                    xml_events = _wevtutil_xml(channel, query, count=100)
                    for root in xml_events:
                        ev = _live_event_dict(root)
                        if not ev:
                            continue
                        try:
                            rid = int(ev["record_id"])
                            cursors[channel] = max(cursors.get(channel, 0), rid)
                        except (TypeError, ValueError):
                            pass
                        failed_count = 1
                        if ev["event_id"] == 4625:
                            event_data = ev.get("data") or {}
                            account = (
                                event_data.get("TargetUserName")
                                or event_data.get("AccountName")
                                or event_data.get("SubjectUserName")
                                or "unknown-account"
                            )
                            source_ip = event_data.get("IpAddress") or event_data.get("SourceNetworkAddress") or "unknown-source"
                            key = f"{account.casefold()}|{source_ip.casefold()}"
                            now_ts = time.time()
                            failed_logons[key] = [t for t in failed_logons[key] if now_ts - t <= 300]
                            failed_logons[key].append(now_ts)
                            failed_count = len(failed_logons[key])

                        finding = analyze_event(ev, failed_login_count=failed_count)
                        record = {
                            "time": finding["datetime"] if finding else ev["time_created"],
                            "event_id": ev["event_id"],
                            "channel": ev["channel"] or channel,
                            "computer": ev["computer"],
                            "record_id": ev["record_id"],
                            "severity": finding["severity"] if finding else "Unclassified",
                            "rule": finding["rule"] if finding else "No matching detection rule",
                            "analysis_status": finding["analysis_status"] if finding else "Captured - not classified",
                            "description": finding["description"] if finding else (
                                f"Event ID {ev['event_id']} was captured, but no VulnShield rule is configured for this event."
                            ),
                            "data": ev["data"],
                        }
                        with LIVE_LOCK:
                            LIVE_STATE["events"].append(record)
                            LIVE_STATE["events"] = LIVE_STATE["events"][-LIVE_MAX_EVENTS:]
                            if finding:
                                LIVE_STATE["findings"].append(record)
                                LIVE_STATE["findings"] = LIVE_STATE["findings"][-LIVE_MAX_EVENTS:]
                except Exception as exc:
                    with LIVE_LOCK:
                        LIVE_STATE["last_error"] = f"{channel}: {exc}"
            time.sleep(LIVE_POLL_SECONDS)
    finally:
        with LIVE_LOCK:
            LIVE_STATE["running"] = False


def _start_live_monitor():
    if platform.system().lower() != "windows":
        raise RuntimeError("Live Windows Event Log collection is available only on Windows.")
    with LIVE_LOCK:
        if LIVE_STATE["running"]:
            return
        LIVE_STATE.update({
            "running": True, "events": [], "findings": [],
            "last_error": "", "started_at": datetime.now().isoformat(),
        })
        worker = threading.Thread(target=_live_monitor_loop, daemon=True, name="VulnShieldLiveMonitor")
        LIVE_STATE["thread"] = worker
        worker.start()


def _stop_live_monitor():
    with LIVE_LOCK:
        LIVE_STATE["running"] = False


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
    if PyEvtxParser is None:
        raise RuntimeError(
            "No working EVTX parser is available. Activate the project venv and run: "
            "python -m pip install python-evtx"
        )
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
def analyze_event(ev, failed_login_count=1):
    """
    Classify a live Windows event using the event-ID rule base plus
    lightweight contextual heuristics. Returns None only when no rule applies.
    """
    try:
        eid = int(ev.get("event_id", 0))
    except (TypeError, ValueError):
        return None

    channel = (ev.get("channel") or "").strip()
    channel_lower = channel.casefold()
    data = ev.get("data") or {}
    # Normalize keys so differences in provider casing do not bypass rules.
    normalized = {str(k).casefold(): str(v) for k, v in data.items()}

    rule = SECURITY_RULES.get(eid)
    if not rule:
        # A captured event without a matching rule must remain explicitly
        # unclassified; do not label it as a threat or silently call it low risk.
        return None

    name, severity, domain, description = rule
    evidence = []

    # Repeated failed logons: one failure is medium; a burst is high.
    if eid == 4625:
        if failed_login_count >= 5:
            severity = "High"
            name = "Repeated Failed Logon Attempts"
            description = (
                f"{failed_login_count} failed logon attempts were observed "
                "for the same account/source within the monitoring window."
            )
            evidence.append(f"Failed logon count in 5-minute window: {failed_login_count}")
        else:
            evidence.append(f"Failed logon attempt; observed count: {failed_login_count}")

    # Process creation: inspect process image and command line from both
    # Sysmon (Event 1) and Security auditing (Event 4688).
    if eid in (1, 4688):
        image = (
            normalized.get("image")
            or normalized.get("newprocessname")
            or normalized.get("processname")
            or ""
        )
        command = (
            normalized.get("commandline")
            or normalized.get("processcommandline")
            or normalized.get("process_command_line")
            or ""
        )
        combined = f"{image} {command}".strip()
        if combined and (
            SUSPICIOUS_PROCESS_NAMES.search(combined)
            or SUSPICIOUS_COMMAND_PATTERNS.search(combined)
        ):
            severity = "High"
            name = "Suspicious Process Execution"
            description = "Process creation matched a suspicious executable or command-line pattern."
            evidence.append(combined[:500])

    # PowerShell script block: examine all available event-data values because
    # providers sometimes use different field names.
    if eid == 4104:
        script_text = " ".join(normalized.values())
        if SUSPICIOUS_COMMAND_PATTERNS.search(script_text):
            severity = "High"
            name = "Suspicious PowerShell Script Block"
            description = "PowerShell script block matched a suspicious command pattern."
            evidence.append(script_text[:500])

    # High-impact audit and persistence actions.
    if eid in (1102, 104):
        severity = "Critical"
        evidence.append("Windows event log clearing event.")
    elif eid in (4720, 4728, 4732, 4756, 4697, 7045, 4698, 5861):
        severity = "High"
        evidence.append("Sensitive account, group, service, task, or persistence change.")

    dt = parse_timestamp(ev.get("time_created", ""))
    return {
        "timestamp": dt.timestamp() if dt else None,
        "datetime": dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "",
        "event_id": eid,
        "channel": channel,
        "computer": ev.get("computer", ""),
        "record_id": ev.get("record_id", ""),
        "rule": name,
        "severity": severity,
        "domain": domain,
        "description": description,
        "evidence": evidence,
        "analysis_status": "Rule matched",
        "data": data,
        "raw_xml": (ev.get("raw_xml") or "")[:4000],
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
    # Track every parsed event independently from detection findings. This is
    # essential: an event without a matching rule must still appear in event
    # frequency/channel reports so missing rule coverage can be diagnosed.
    event_id_counter = Counter()
    all_channel_counter = Counter()
    unmatched_event_counter = Counter()
    event_inventory = []
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
                eid = ev.get("event_id")
                channel_name = (ev.get("channel") or "Unknown").strip() or "Unknown"
                if eid is not None:
                    event_id_counter[int(eid)] += 1
                all_channel_counter[channel_name] += 1
                event_inventory.append({
                    "timestamp": ev.get("time_created", ""),
                    "event_id": eid,
                    "channel": channel_name,
                    "computer": ev.get("computer", ""),
                    "record_id": ev.get("record_id", ""),
                    "data": ev.get("data", {}),
                })

                finding = analyze_event(ev)
                if finding is None:
                    unmatched_event_counter[(int(eid) if eid is not None else "Unknown", channel_name)] += 1
                    continue

                findings.append(finding)
                bucket = channel_to_bucket(ev["channel"])
                per_channel[bucket].append(finding)
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
    channel_summary = [{"channel": k, "count": v} for k, v in
                       all_channel_counter.most_common()]

    # Timesketch chronological order
    timesketch_rows.sort(key=lambda r: r["timestamp"] or 0)

    summary = {
        "total_events": total_records,
        "total_findings": len(findings),
        "severity": sev_summary,
        "top_rules": topn(rule_counter, 15),
        "top_event_ids": topn(event_id_counter, 30),
        "unmatched_event_ids": [
            {"event_id": k[0], "channel": k[1], "count": v}
            for k, v in unmatched_event_counter.most_common(100)
        ],
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
        json.dump({"summary": summary, "findings": findings,
                   "all_events": event_inventory}, fh, default=str)

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

                # --- All parsed events (including events with no matching rule) ---
                all_events_pd = pd.DataFrame([{
                    "DateTime": e["timestamp"],
                    "EventID": e["event_id"],
                    "Channel": e["channel"],
                    "Computer": e["computer"],
                    "RecordID": e["record_id"],
                    "EventData": json.dumps(e["data"], ensure_ascii=False, default=str),
                } for e in event_inventory])
                all_events_pd.to_excel(writer, sheet_name="All Events", index=False)

                # --- Event ID Frequency: all parsed events, not only findings ---
                pd.DataFrame([{"EventID": k, "Count": v} for k, v in event_id_counter.most_common()]
                             ).to_excel(writer, sheet_name="EventID Frequency", index=False)

                # --- Events not covered by a detection rule ---
                pd.DataFrame([{"EventID": k[0], "Channel": k[1], "Count": v}
                              for k, v in unmatched_event_counter.most_common()]
                             ).to_excel(writer, sheet_name="Unmatched Event IDs", index=False)

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

@app.route("/api/live/start", methods=["POST"])
def api_live_start():
    try:
        _start_live_monitor()
        return jsonify({"status": "running", "message": "Live monitoring started."})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    _stop_live_monitor()
    return jsonify({"status": "stopping", "message": "Live monitoring stop requested."})


@app.route("/api/live/status")
def api_live_status():
    with LIVE_LOCK:
        return jsonify({
            "running": LIVE_STATE["running"],
            "started_at": LIVE_STATE["started_at"],
            "last_error": LIVE_STATE["last_error"],
            "total_events": len(LIVE_STATE["events"]),
            "total_findings": len(LIVE_STATE["findings"]),
            "events": list(reversed(LIVE_STATE["events"][-100:])),
            "findings": list(reversed(LIVE_STATE["findings"][-100:])),
        })


@app.route("/api/live/events")
def api_live_events():
    with LIVE_LOCK: return jsonify({"running":LIVE_STATE["running"],"events":list(LIVE_STATE["events"])})


@app.route("/api/live/report.xlsx")
def api_live_excel_report():
    """Export the current live-monitoring session as a multi-sheet Excel workbook."""
    if pd is None:
        return jsonify({"error": "Excel export requires pandas and openpyxl. Install them with: pip install pandas openpyxl"}), 500
    with LIVE_LOCK:
        events = [dict(item) for item in LIVE_STATE["events"]]
        findings = [dict(item) for item in LIVE_STATE["findings"]]
        started_at = LIVE_STATE["started_at"]
        running = LIVE_STATE["running"]
    if not events:
        return jsonify({"error": "No live events have been collected yet. Start monitoring and try again."}), 400

    def flatten(record):
        row = {k: v for k, v in record.items() if k != "data"}
        event_data = record.get("data") or {}
        for key, value in event_data.items():
            row[f"Data_{key}"] = value
        return row

    all_df = pd.DataFrame([flatten(x) for x in events])
    findings_df = pd.DataFrame([flatten(x) for x in findings])
    event_freq = all_df.groupby("event_id", dropna=False).size().reset_index(name="Count").sort_values("Count", ascending=False)
    severity_df = all_df.groupby("severity", dropna=False).size().reset_index(name="Count").sort_values("Count", ascending=False)
    channel_df = all_df.groupby("channel", dropna=False).size().reset_index(name="Count").sort_values("Count", ascending=False)
    summary_df = pd.DataFrame([
        {"Metric": "Monitoring Started", "Value": started_at or ""},
        {"Metric": "Report Generated", "Value": datetime.now().isoformat(timespec="seconds")},
        {"Metric": "Monitoring Running At Export", "Value": running},
        {"Metric": "Total Events Captured", "Value": len(events)},
        {"Metric": "Detected Findings", "Value": len(findings)},
        {"Metric": "Captured Event Channels", "Value": all_df["channel"].nunique() if "channel" in all_df else 0},
    ])
    output = io.BytesIO()
    try:
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            summary_df.to_excel(writer, sheet_name="Summary", index=False)
            all_df.to_excel(writer, sheet_name="All Live Events", index=False)
            findings_df.to_excel(writer, sheet_name="Detected Findings", index=False)
            event_freq.to_excel(writer, sheet_name="Event ID Frequency", index=False)
            severity_df.to_excel(writer, sheet_name="Severity Summary", index=False)
            channel_df.to_excel(writer, sheet_name="Channel Summary", index=False)
            for ws in writer.book.worksheets:
                ws.freeze_panes = "A2"
                ws.auto_filter.ref = ws.dimensions
                for column_cells in ws.columns:
                    max_len = min(max(len(str(cell.value or "")) for cell in column_cells) + 2, 55)
                    ws.column_dimensions[column_cells[0].column_letter].width = max(12, max_len)
        output.seek(0)
    except Exception as exc:
        return jsonify({"error": f"Could not generate Excel report: {exc}"}), 500
    filename = f"VulnShield_Live_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output, as_attachment=True, download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


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

# ===========================================================================
# ADVANCED ATTACK PATTERN RECOGNITION / ATTACK DNA
# ===========================================================================
def _norm_event_record(row):
    """Normalize VulnShield EVTX/live/report rows into a common evidence record."""
    row = row or {}
    data = row.get("data") if isinstance(row.get("data"), dict) else {}
    # Also accept flattened CSV/Excel report columns.
    merged = {str(k).casefold(): v for k, v in row.items()}
    merged_data = {str(k).casefold(): v for k, v in data.items()}
    def pick(*names):
        for name in names:
            key = name.casefold()
            value = merged_data.get(key)
            if value in (None, ""):
                value = merged.get(key)
            if value not in (None, ""):
                return str(value)
        return ""
    try:
        eid = int(float(pick("event_id", "event id", "eventid", "event code")))
    except Exception:
        eid = None
    ts = pick("time_created", "timestamp", "date and time", "datetime", "time")
    host = pick("computer", "computer name", "hostname", "host", "machine")
    channel = pick("channel", "log name", "source")
    user = pick("targetusername", "subjectusername", "accountname", "user", "username", "user name")
    ip = pick("ipaddress", "sourceip", "source ip", "sourceaddress", "clientaddress", "source network address")
    image = pick("image", "newprocessname", "processname", "process image")
    cmd = pick("commandline", "processcommandline", "process command line", "command")
    desc = pick("description", "event description", "rule", "detection rule")
    raw = pick("raw_xml", "original event log", "eventdata")
    try:
        parsed = parse_timestamp(ts)
        sort_ts = parsed.timestamp() if parsed else 0
    except Exception:
        sort_ts = 0
    return {
        "event_id": eid, "timestamp": ts, "sort_ts": sort_ts, "computer": host or "Unknown host",
        "channel": channel, "user": user or "Unknown user", "source_ip": ip or "Unknown source",
        "image": image, "command": cmd, "description": desc, "raw": raw[:1800],
        "data": data, "record_id": pick("record_id", "record id")
    }


def analyze_attack_dna(records):
    """Rule/sequence-based explainable attack hypotheses; deliberately conservative."""
    events = [_norm_event_record(x) for x in (records or [])]
    events = [e for e in events if e["event_id"] is not None]
    events.sort(key=lambda x: x["sort_ts"])
    ids = [e["event_id"] for e in events]
    by_id = defaultdict(list)
    for e in events:
        by_id[e["event_id"]].append(e)
    candidates = []

    def add(name, confidence, severity, evs, explanation, category, required=""):
        evs = sorted(evs, key=lambda x: x["sort_ts"])
        unique = []
        seen = set()
        for e in evs:
            key = (e["event_id"], e["timestamp"], e["computer"], e["record_id"])
            if key not in seen:
                seen.add(key); unique.append(e)
        if not unique:
            return
        hosts = sorted({e["computer"] for e in unique})
        users = sorted({e["user"] for e in unique if e["user"] != "Unknown user"})
        ips = sorted({e["source_ip"] for e in unique if e["source_ip"] != "Unknown source"})
        candidates.append({
            "attack": name, "category": category, "confidence": int(max(10, min(98, confidence))),
            "severity": severity, "host": ", ".join(hosts[:3]), "users": users[:5], "source_ips": ips[:5],
            "event_ids": sorted({e["event_id"] for e in unique}), "evidence_count": len(unique),
            "first_seen": unique[0]["timestamp"], "last_seen": unique[-1]["timestamp"],
            "explanation": explanation, "required_telemetry": required,
            "evidence": [{"event_id": e["event_id"], "timestamp": e["timestamp"], "host": e["computer"],
                          "user": e["user"], "source_ip": e["source_ip"], "channel": e["channel"],
                          "description": e["description"] or e["raw"][:250]} for e in unique[:20]]
        })

    # Brute force and password spraying use 4625, with a time-window/source/account heuristic.
    failures = by_id.get(4625, [])
    groups = defaultdict(list)
    for e in failures:
        groups[(e["user"], e["source_ip"], e["computer"])].append(e)
    for (user, ip, host), group in groups.items():
        if len(group) >= 5:
            add("Brute-force login attempt", min(96, 58 + len(group)*3), "High", group,
                f"{len(group)} failed logons for the same account/source/host were observed. Confirm time window, logon type and source attribution.",
                "Credential Access")
    spray_groups = defaultdict(list)
    for e in failures:
        spray_groups[(e["source_ip"], e["computer"])].append(e)
    for (ip, host), group in spray_groups.items():
        users = {e["user"] for e in group if e["user"] != "Unknown user"}
        if len(users) >= 5:
            add("Possible password spraying", min(94, 60 + len(users)*4), "High", group,
                f"Failed logons affected {len(users)} distinct accounts from one source/host. This pattern may also arise from shared infrastructure or misconfiguration.",
                "Credential Access")
    # Failure followed by successful logon for same account and source (where available).
    successes = by_id.get(4624, [])
    for fail in failures:
        matches = [ok for ok in successes if ok["user"] == fail["user"] and
                   (fail["source_ip"] == "Unknown source" or ok["source_ip"] == fail["source_ip"]) and
                   (not fail["sort_ts"] or not ok["sort_ts"] or 0 <= ok["sort_ts"]-fail["sort_ts"] <= 1800)]
        if matches:
            add("Possible account compromise / successful logon after failures", 72, "High", [fail, matches[0]],
                "A successful logon followed failed logon activity for the same account (and matching source where available). Validate logon type, workstation and MFA context.",
                "Credential Access")

    # Privilege and account manipulation.
    privilege = by_id.get(4672, [])
    group_add = sum((by_id.get(x, []) for x in (4728, 4732, 4756)), [])
    account_changes = sum((by_id.get(x, []) for x in (4720, 4722, 4724, 4726)), [])
    if privilege and group_add:
        add("Possible privilege escalation / privileged group modification", 82, "High", privilege + group_add,
            "Special privileges and security-group membership changes were observed. Verify the initiating account and approved change ticket.",
            "Privilege Escalation")
    elif group_add:
        add("Sensitive security-group membership change", 70, "High", group_add,
            "A member was added to a privileged or security-enabled group. Event ID alone does not establish malicious intent.",
            "Account Manipulation")
    if account_changes:
        add("Account manipulation", 65, "Medium", account_changes,
            "User creation, enablement, password reset or deletion activity was observed. Correlate actor, target and change approval.",
            "Account Manipulation")

    # Persistence.
    persistence = sum((by_id.get(x, []) for x in (4697, 7045, 4698, 4699, 4702, 5861)), [])
    if persistence:
        add("Possible persistence establishment or modification", 76, "High", persistence,
            "Service installation, scheduled-task changes or WMI subscription activity was observed. Inspect service/task command, path, signer and creator.",
            "Persistence")

    # Defence evasion / log manipulation.
    evasion = sum((by_id.get(x, []) for x in (1102, 104, 4719)), [])
    if evasion:
        add("Security log clearing / audit policy modification", 94, "Critical", evasion,
            "A log-clearing or audit-policy-change event was recorded. Preserve evidence and verify whether this was an authorised administrative action.",
            "Defense Evasion")
    # PowerShell / suspicious process execution.
    suspicious_exec = []
    for e in events:
        text_blob = (e["image"] + " " + e["command"] + " " + e["description"] + " " + e["raw"]).lower()
        if e["event_id"] in (1, 4688, 4104) and (
            SUSPICIOUS_PROCESS_NAMES.search(text_blob) or SUSPICIOUS_COMMAND_PATTERNS.search(text_blob)
        ):
            suspicious_exec.append(e)
    if suspicious_exec:
        add("Suspicious process / PowerShell execution", 84, "High", suspicious_exec,
            "Process or script telemetry matched configured suspicious command patterns. Review full command line, parent process, signer and execution context.",
            "Execution")

    # Credential access and lateral movement.
    cred = by_id.get(5379, []) + by_id.get(10, [])
    if cred:
        add("Possible credential access / process credential inspection", 72, "High", cred,
            "Credential Manager access or Sysmon process-access telemetry was observed. These events require process and target context to confirm abuse.",
            "Credential Access")
    lateral = sum((by_id.get(x, []) for x in (4648, 5140, 5145, 1149, 21, 31001, 551)), [])
    if lateral:
        add("Possible lateral movement / remote access activity", 68, "Medium", lateral,
            "Explicit credentials, RDP authentication/session or SMB share activity was observed. Correlate source host, target host, account and process.",
            "Lateral Movement")

    # Malware / Defender evidence.
    defender = sum((by_id.get(x, []) for x in (1116, 1117, 1118, 1119, 1006, 1007, 1008, 1015)), [])
    if defender:
        add("Windows Defender malware or suspicious-behaviour alert", 91, "Critical" if any(e["event_id"] in (1116, 1119, 1015) for e in defender) else "High",
            defender, "Windows Defender reported malware, suspicious behaviour or remediation activity. Review detection name and remediation status.",
            "Malware")

    # Ransomware-like behaviour is only a heuristic when destructive file activity and shadow-copy commands co-occur.
    destructive = [e for e in events if e["event_id"] in (23, 26) or
                   re.search(r"vssadmin.*delete|wbadmin.*delete|shadow", e["command"] + " " + e["raw"], re.I)]
    if len(destructive) >= 5:
        add("Possible ransomware / destructive file activity", 70, "High", destructive,
            "Multiple file-deletion or recovery-inhibition indicators were observed. This is a heuristic; confirm file-change volume, ransom notes and endpoint protection telemetry.",
            "Impact")

    # Event-ID-only endpoint logs cannot prove network DoS/DDoS, phishing, exfiltration, DNS tunnelling or web attacks.
    catalogue = [
        {"attack":"Brute force", "evidence":"4625 repeated failures; optionally 4771/4776", "limitation":"Requires grouping by account/source/time; a single failure is not brute force."},
        {"attack":"Password spraying", "evidence":"4625 across many accounts from one source", "limitation":"Needs source IP and distinct-account context."},
        {"attack":"Account compromise", "evidence":"4625 followed by 4624; 4672 may add context", "limitation":"A sequence is a suspicion, not proof; correlate MFA, logon type and device."},
        {"attack":"Privilege escalation", "evidence":"4672, 4728, 4732, 4756, 4720", "limitation":"Legitimate admin changes are common; actor and change context matter."},
        {"attack":"Persistence", "evidence":"4697, 7045, 4698, 4702, 5861", "limitation":"Inspect service/task command, creator, signer and approval."},
        {"attack":"Defense evasion / log tampering", "evidence":"1102, 104, 4719; related service events", "limitation":"Distinguish attacker activity from authorised maintenance."},
        {"attack":"PowerShell / script execution", "evidence":"4104, 4103, 4688, Sysmon 1", "limitation":"Script content and process ancestry are needed."},
        {"attack":"Credential access", "evidence":"5379, Sysmon 10, suspicious process evidence", "limitation":"Requires process/target context; IDs alone do not prove dumping."},
        {"attack":"Lateral movement", "evidence":"4648, 5140, 5145, RDP 1149/21, Sysmon 3", "limitation":"Correlate source and destination systems and account."},
        {"attack":"Malware activity", "evidence":"Defender 1116/1117/1015; Sysmon process/file events", "limitation":"Use Defender detection details and remediation outcome."},
        {"attack":"Ransomware-like activity", "evidence":"Sysmon file deletion events 23/26 plus recovery-inhibition commands", "limitation":"Requires file activity telemetry, process lineage and endpoint context."},
        {"attack":"DoS / DDoS", "evidence":"Windows endpoint Event IDs are insufficient on their own", "limitation":"Requires firewall, router, NetFlow/IPFIX, packet or network telemetry; high event volume alone is not proof."},
        {"attack":"Data exfiltration", "evidence":"Possible process/network events, file access", "limitation":"Requires proxy, firewall, DNS, DLP or network-flow byte counts."},
        {"attack":"Phishing", "evidence":"Endpoint execution may appear later in 4688/4104/Defender events", "limitation":"Email gateway/mailbox telemetry is required to identify the phishing message."},
        {"attack":"DNS tunnelling", "evidence":"Sysmon 22 DNS queries", "limitation":"Requires DNS query content, frequency and entropy analysis; event ID alone is insufficient."},
        {"attack":"Web application attacks", "evidence":"Not reliably represented by generic Windows Security IDs", "limitation":"Requires IIS/reverse-proxy/WAF/application logs."}
    ]
    categories = Counter(c["category"] for c in candidates)
    confidence_bins = Counter("High (80–100)" if c["confidence"] >= 80 else "Medium (60–79)" if c["confidence"] >= 60 else "Low (<60)" for c in candidates)
    hosts = {e["computer"] for e in events}
    story = [{"time":e["timestamp"], "event_id":e["event_id"], "host":e["computer"], "user":e["user"],
              "source_ip":e["source_ip"], "channel":e["channel"], "description":e["description"] or f"Windows Event ID {e['event_id']}"} for e in events[-100:]]
    candidates.sort(key=lambda c: (c["confidence"], c["evidence_count"]), reverse=True)
    return {"total_events":len(events), "host_count":len(hosts), "hypothesis_count":len(candidates),
            "high_confidence":sum(c["confidence"] >= 80 for c in candidates),
            "category_counts":dict(categories), "confidence_counts":dict(confidence_bins),
            "candidates":candidates, "story":story, "catalogue":catalogue,
            "limitations":["Attack names are hypotheses derived from observed telemetry, not confirmed incidents.",
                           "DoS/DDoS, phishing, exfiltration and web attacks require additional network, email or application telemetry.",
                           "Confidence values are heuristic prioritisation scores, not calibrated probabilities."]}


def _flatten_report_record(row):
    """Normalize report rows from VulnShield exports and common SIEM CSV/XLSX files."""
    out = dict(row or {})
    # Preserve original keys while adding canonical aliases used by both engines.
    aliases = {
        "event_id": ("Event ID", "EventID", "eventid", "Id", "id"),
        "timestamp": ("Date and Time", "TimeCreated", "Time Created", "TimeCreated SystemTime", "Timestamp", "time"),
        "computer": ("Computer Name", "Computer", "Hostname", "Host", "DeviceName"),
        "channel": ("Channel", "Log Name", "Provider"),
        "user": ("User", "Account Name", "TargetUserName", "SubjectUserName", "Username"),
        "source_ip": ("Source IP", "IpAddress", "Source Network Address", "SourceAddress", "src_ip", "ClientIP"),
        "destination_ip": ("Destination IP", "DestAddress", "DestinationAddress", "dst_ip", "LocalAddress"),
        "description": ("Event Description", "Description", "Detection Rule", "Rule", "Message"),
        "severity": ("Severity", "Risk", "Level"),
        "raw": ("Original Event Log", "Raw Event", "raw_xml", "Message"),
    }
    low={str(k).strip().lower():v for k,v in out.items()}
    for canonical, keys in aliases.items():
        if out.get(canonical) not in (None, ""):
            continue
        for key in keys:
            value=low.get(key.lower())
            if value not in (None, ""):
                out[canonical]=value; break
    # Flatten nested EventData fields into the row for network/identity extraction.
    data=out.get("data") or out.get("EventData") or {}
    if isinstance(data, dict):
        for k,v in data.items(): out.setdefault(str(k),v)
    return out

def _network_flows_from_events(records):
    """Extract only events with actual connection/firewall telemetry; no synthetic inference."""
    flows=[]
    for raw in records or []:
        if not isinstance(raw,dict): continue
        e=_flatten_report_record(raw)
        try: eid=int(float(str(e.get('event_id','')).strip()))
        except Exception: eid=-1
        data=e.get('data') if isinstance(e.get('data'),dict) else {}
        merged={**e,**data}
        def pick(*keys):
            low={str(k).lower().replace(' ','').replace('_',''):v for k,v in merged.items()}
            for k in keys:
                v=low.get(k.lower().replace(' ','').replace('_',''))
                if v not in (None,'','-'): return v
            return ''
        # Sysmon 3 and Windows Filtering Platform 5156 provide connection metadata.
        if eid not in (3,5156,5157,5152,5154,5155,5158): continue
        src=pick('SourceIp','SourceAddress','RemoteAddress','src_ip','SourceIP')
        dst=pick('DestinationIp','DestAddress','LocalAddress','dst_ip','DestinationIP')
        if not src and not dst: continue
        proto=pick('Protocol','ProtocolName') or 'TCP'
        if str(proto).isdigit(): proto={'6':'TCP','17':'UDP','1':'ICMP'}.get(str(proto),'UNKNOWN')
        port=pick('DestinationPort','DestPort','RemotePort','LocalPort')
        flows.append({'timestamp':e.get('timestamp') or e.get('TimeCreated') or '', 'source_ip':str(src),
                      'destination_ip':str(dst), 'protocol':str(proto), 'destination_port':str(port),
                      'tcp_flags':pick('TcpFlags','Flags'), 'packets':1, 'bytes':0,
                      'event_id':eid, 'computer':e.get('computer','')})
    return flows

@app.route('/api/intelligence/import', methods=['POST'])
def api_intelligence_import():
    f=request.files.get('file')
    if not f: return jsonify({'error':'Choose an event or network report file.'}),400
    name=Path(f.filename or 'report').name
    ext=Path(name).suffix.lower()
    raw=f.stream.read(25*1024*1024+1)
    if len(raw)>25*1024*1024: return jsonify({'error':'Report exceeds the 25 MB upload limit.'}),413
    try:
        if ext=='.csv':
            records=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig',errors='replace'))))
        elif ext=='.json':
            obj=json.loads(raw.decode('utf-8-sig'))
            if isinstance(obj,list): records=obj
            elif isinstance(obj,dict):
                records=obj.get('all_events') or obj.get('events') or obj.get('records') or obj.get('results') or []
                if isinstance(records,dict): records=records.get('events') or records.get('records') or []
        elif ext in ('.xlsx','.xls'):
            if pd is None: raise ValueError('Excel import requires pandas and openpyxl. Install both packages.')
            book=pd.read_excel(io.BytesIO(raw),sheet_name=None)
            # Prefer the complete event inventory sheet when present; otherwise combine sheets.
            selected=next((v for k,v in book.items() if k.strip().lower() in ('all events','all live events','event inventory','events')),None)
            frame=selected if selected is not None else pd.concat(list(book.values()),ignore_index=True) if book else pd.DataFrame()
            records=frame.where(pd.notna(frame),None).to_dict(orient='records')
        else:
            raise ValueError('Supported report formats: CSV, JSON, XLSX and XLS.')
        if not isinstance(records,list) or not records: raise ValueError('No event records found in the selected report.')
        records=[_flatten_report_record(x) for x in records if isinstance(x,dict)]
        if not records: raise ValueError('The report contains no usable tabular records.')
        with INTEL_IMPORT_LOCK:
            INTEL_IMPORTED.update({'filename':name,'records':records[:100000],'kind':'events'})
        flows=_network_flows_from_events(records)
        return jsonify({'status':'loaded','filename':name,'records':len(records),'network_flows':len(flows),
                        'event_ids':len({str(x.get('event_id','')) for x in records}),
                        'message':f'Imported {len(records):,} report records. {len(flows):,} contain supported network connection telemetry.'})
    except Exception as exc:
        return jsonify({'error':f'Could not import report: {exc}'}),400

@app.route('/api/intelligence/import/data')
def api_intelligence_import_data():
    with INTEL_IMPORT_LOCK: return jsonify({'records':INTEL_IMPORTED['records'],'filename':INTEL_IMPORTED['filename']})

@app.route('/api/intelligence/import/status')
def api_intelligence_import_status():
    with INTEL_IMPORT_LOCK:
        return jsonify({'filename':INTEL_IMPORTED['filename'],'records':len(INTEL_IMPORTED['records']),'kind':INTEL_IMPORTED['kind']})

@app.route('/api/intelligence/network-source', methods=['POST'])
def api_intelligence_network_source():
    payload=request.get_json(silent=True) or {}; source=payload.get('source','report')
    if source=='live':
        with LIVE_LOCK: records=[dict(x) for x in LIVE_STATE['events']]
        label='Live Windows Event Tracker'
    else:
        with INTEL_IMPORT_LOCK: records=list(INTEL_IMPORTED['records']); label=INTEL_IMPORTED['filename'] or 'Imported report'
        if not records:
            # Fall back to the currently analysed dashboard report inventory.
            for job in reversed(list(JOBS.values())):
                result=job.get('result') or {}
                if result.get('all_events'):
                    records=result['all_events']; label='Current VulnShield analysis report'; break
    flows=_network_flows_from_events(records)
    if not flows:
        return jsonify({'error':f'{label} contains no supported network connection records. Network analysis needs Sysmon Event ID 3 or Windows Filtering Platform events 5156/5157/5152 with source/destination addresses. Import a NetFlow/IPFIX CSV for broader traffic analysis.','records':len(records),'network_flows':0}),400
    try:
        result=analyze_network_flows(flows)
        result['input_filename']=label; result['source_mode']=source; result['source_event_records']=len(records)
        return jsonify(result)
    except Exception as exc: return jsonify({'error':str(exc)}),400

@app.route("/api/attack-analysis", methods=["POST"])
def api_attack_analysis():
    payload = request.get_json(silent=True) or {}
    records = payload.get("events") or []
    if not isinstance(records, list):
        return jsonify({"error":"events must be a list"}), 400
    if len(records) > 50000:
        return jsonify({"error":"Please analyse at most 50,000 records per request."}), 413
    try:
        return jsonify(analyze_attack_dna(records))
    except Exception as exc:
        return jsonify({"error":f"Attack analysis failed: {exc}"}), 500


@app.route("/api/notify", methods=["POST"])
def api_notify():
    """Send a user-requested incident summary through SMTP and/or HTTPS webhook."""
    payload = request.get_json(silent=True) or {}
    alert = payload.get("alert") or {}
    subject = str(payload.get("subject") or "VulnShield Security Alert")[:180]
    body = str(payload.get("body") or json.dumps(alert, indent=2, default=str))[:20000]
    results = []
    email_cfg = payload.get("email") or {}
    if email_cfg.get("host") and email_cfg.get("to") and email_cfg.get("from"):
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = email_cfg["from"]
        msg["To"] = email_cfg["to"]
        msg.set_content(body)
        port = int(email_cfg.get("port") or 587)
        with smtplib.SMTP(str(email_cfg["host"]), port, timeout=15) as server:
            server.ehlo()
            if port == 465:
                raise ValueError("Use SMTP port 587 with STARTTLS; implicit SSL is not enabled in this build.")
            server.starttls()
            server.ehlo()
            if email_cfg.get("username"):
                server.login(str(email_cfg["username"]), str(email_cfg.get("password") or ""))
            server.send_message(msg)
        results.append("Email sent")
    webhook = str(payload.get("webhook") or "").strip()
    if webhook:
        from urllib.request import Request, urlopen
        from urllib.parse import urlparse
        parsed = urlparse(webhook)
        if parsed.scheme != "https" or not parsed.netloc:
            return jsonify({"error":"Webhook must be a valid HTTPS URL."}), 400
        data = json.dumps({"text":subject + "\n" + body, "vulnshield":alert}, default=str).encode("utf-8")
        req = Request(webhook, data=data, headers={"Content-Type":"application/json"}, method="POST")
        with urlopen(req, timeout=12) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"Webhook returned HTTP {response.status}")
        results.append("Webhook delivered")
    if not results:
        return jsonify({"error":"Configure an SMTP recipient or HTTPS webhook."}), 400
    return jsonify({"status":"sent", "results":results})


# ===========================================================================
# NETWORK THREAT INTELLIGENCE — DoS / DDoS TELEMETRY ANALYSIS
# ===========================================================================
NETWORK_LAST_ANALYSIS = {}

def _net_pick(row, *names, default=""):
    lookup = {str(k).strip().lower().replace(" ", "_").replace("-", "_"): v for k, v in row.items()}
    for name in names:
        key = name.lower().replace(" ", "_").replace("-", "_")
        if key in lookup and lookup[key] not in (None, ""):
            return lookup[key]
    return default

def _net_num(value, default=0.0):
    try:
        return max(0.0, float(str(value).replace(",", "").strip()))
    except Exception:
        return default

def analyze_network_flows(rows, window_seconds=10):
    """Analyze flow summaries; this is not packet inspection or a mitigation engine."""
    if not isinstance(rows, list) or not rows:
        raise ValueError("No network flow rows were supplied.")
    if len(rows) > 100000:
        raise ValueError("Please analyse at most 100,000 flow rows per request.")
    normalized=[]
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        ts=str(_net_pick(raw,"timestamp","time","start_time","date_time","datetime"))
        src=str(_net_pick(raw,"source_ip","src_ip","src","client_ip","remote_address"))
        dst=str(_net_pick(raw,"destination_ip","dest_ip","dst_ip","dst","server_ip","local_address"))
        proto=str(_net_pick(raw,"protocol","proto",default="UNKNOWN")).upper()
        flags=str(_net_pick(raw,"tcp_flags","flags","tcp_flag")).upper()
        packets=_net_num(_net_pick(raw,"packets","packet_count","pkts","total_packets",default=1),1)
        byte_count=_net_num(_net_pick(raw,"bytes","byte_count","octets","total_bytes",default=0))
        port=str(_net_pick(raw,"destination_port","dst_port","dest_port","server_port"))
        status=str(_net_pick(raw,"http_status","status_code","status"))
        requests=_net_num(_net_pick(raw,"requests","request_count","http_requests",default=1),1)
        # Accept ISO timestamps. Unparseable rows remain in totals but are not assigned to time bins.
        epoch=None
        try:
            dt=datetime.fromisoformat(ts.replace('Z','+00:00'))
            if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
            epoch=dt.timestamp()
        except Exception:
            pass
        normalized.append({"timestamp":ts,"epoch":epoch,"source_ip":src,"destination_ip":dst,"protocol":proto,
            "tcp_flags":flags,"packets":packets,"bytes":byte_count,"destination_port":port,
            "http_status":status,"requests":requests})
    if not normalized:
        raise ValueError("No usable flow records found. Check the CSV column headers.")
    timed=[r for r in normalized if r['epoch'] is not None]
    bins=defaultdict(lambda:{"packets":0.0,"bytes":0.0,"sources":set(),"destinations":set(),"syn":0.0,"ack":0.0,"requests":0.0,"errors":0.0,"flows":0})
    sources=Counter(); destinations=Counter(); protocols=Counter(); ports=Counter(); src_dst=Counter()
    syn_total=ack_total=0.0; http_requests=http_errors=0.0
    for r in normalized:
        if r['source_ip']: sources[r['source_ip']]+=1
        if r['destination_ip']: destinations[r['destination_ip']]+=r['packets']
        protocols[r['protocol']]+=r['packets']
        if r['destination_port']: ports[r['destination_port']]+=r['packets']
        if r['source_ip'] and r['destination_ip']: src_dst[(r['source_ip'],r['destination_ip'])]+=r['packets']
        flags=r['tcp_flags'].replace(',',' ').replace('|',' ').split()
        is_syn=('S' in flags or 'SYN' in flags or '0X02' in flags or '2' in flags)
        is_ack=('A' in flags or 'ACK' in flags or '0X10' in flags or '16' in flags)
        if is_syn: syn_total+=r['packets']
        if is_ack: ack_total+=r['packets']
        if r['http_status']:
            http_requests+=r['requests']
            try:
                if int(float(r['http_status']))>=400: http_errors+=r['requests']
            except Exception: pass
        if r['epoch'] is not None:
            b=int(r['epoch']//window_seconds)*window_seconds; x=bins[b]
            x['packets']+=r['packets'];x['bytes']+=r['bytes'];x['flows']+=1
            if r['source_ip']:x['sources'].add(r['source_ip'])
            if r['destination_ip']:x['destinations'].add(r['destination_ip'])
            if is_syn:x['syn']+=r['packets']
            if is_ack:x['ack']+=r['packets']
            x['requests']+=r['requests'] if r['http_status'] else 0
            try:
                if int(float(r['http_status']))>=400:x['errors']+=r['requests']
            except Exception: pass
    timeline=[]
    for stamp,x in sorted(bins.items()):
        timeline.append({"time":datetime.fromtimestamp(stamp,timezone.utc).isoformat(),"packets_per_sec":round(x['packets']/window_seconds,2),
            "mbps":round(x['bytes']*8/window_seconds/1_000_000,4),"unique_sources":len(x['sources']),
            "unique_destinations":len(x['destinations']),"syn_packets":round(x['syn'],2),"ack_packets":round(x['ack'],2),
            "http_requests_per_sec":round(x['requests']/window_seconds,2),"http_errors":round(x['errors'],2),"flows":x['flows']})
    pps=[x['packets_per_sec'] for x in timeline]
    median=sorted(pps)[len(pps)//2] if pps else 0
    deviations=sorted(abs(v-median) for v in pps); mad=deviations[len(deviations)//2] if deviations else 0
    peak=max(pps or [0]); peak_bin=max(timeline,key=lambda x:x['packets_per_sec']) if timeline else {}
    unique_sources=len(sources); unique_targets=len(destinations)
    total_packets=sum(r['packets'] for r in normalized); total_bytes=sum(r['bytes'] for r in normalized)
    entropy=0.0
    if sources:
        n=sum(sources.values())
        entropy=-sum((v/n)*math.log2(v/n) for v in sources.values() if v)
    syn_ratio=syn_total/max(1.0,ack_total)
    http_error_rate=http_errors/max(1.0,http_requests)*100 if http_requests else 0.0
    # Relative anomaly evidence. With fewer than 3 time buckets, the rate-baseline signal is intentionally weak.
    robust_limit=max(median+6*mad, median*3, 1.0)
    rate_anomaly=bool(len(pps)>=3 and peak>robust_limit)
    many_sources=unique_sources>=20
    concentrated_target=bool(destinations and max(destinations.values())/max(1,total_packets)>=0.45)
    syn_signal=syn_ratio>=3.0 and syn_total>=100
    http_signal=http_requests>=100 and http_error_rate>=10
    score=0; reasons=[]
    if rate_anomaly: score+=35;reasons.append(f"Peak packet rate {peak:.2f} pps exceeded the robust baseline threshold {robust_limit:.2f} pps")
    if many_sources: score+=20;reasons.append(f"Traffic observed from {unique_sources} distinct source IPs")
    if concentrated_target: score+=10;reasons.append("A large share of observed packets targeted one destination")
    if syn_signal: score+=25;reasons.append(f"SYN-to-ACK packet ratio was {syn_ratio:.2f}")
    if http_signal: score+=20;reasons.append(f"HTTP error ratio was {http_error_rate:.1f}% across supplied status-coded requests")
    if not timed: reasons.append("No parseable timestamps: time-rate and baseline analysis are unavailable")
    score=min(100,score)
    if score>=65 and many_sources: classification="Possible DDoS"
    elif score>=55: classification="Possible DoS / service-flood anomaly"
    elif score>=30: classification="Network traffic anomaly — investigate"
    else: classification="No strong DoS/DDoS pattern in supplied telemetry"
    severity="Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=30 else "Informational"
    result={"summary":{"records":len(normalized),"total_packets":round(total_packets),"total_bytes":round(total_bytes),
        "unique_sources":unique_sources,"unique_destinations":unique_targets,"peak_pps":round(peak,2),
        "peak_mbps":round(max([x['mbps'] for x in timeline] or [0]),4),"syn_ack_ratio":round(syn_ratio,2),
        "http_error_rate":round(http_error_rate,2),"source_entropy":round(entropy,3),"time_buckets":len(timeline),
        "baseline_median_pps":round(median,2),"baseline_mad_pps":round(mad,2)},
        "assessment":{"classification":classification,"severity":severity,"score":score,"reasons":reasons or ["No strong indicator was observed in the supplied flow summaries."],
        "confidence_note":"Heuristic evidence score, not a calibrated probability or confirmation of an attack."},
        "timeline":timeline,"top_sources":[{"ip":k,"flows":v} for k,v in sources.most_common(10)],
        "top_destinations":[{"ip":k,"packets":round(v)} for k,v in Counter({k:v for k,v in destinations.items()}).most_common(10)],
        "protocols":[{"protocol":k,"packets":round(v)} for k,v in protocols.most_common()],
        "top_ports":[{"port":k,"packets":round(v)} for k,v in ports.most_common(10)],
        "limitations":["Flow summaries do not provide full packet payloads or prove malicious intent.",
        "SYN/ACK analysis is only meaningful when the input includes reliable TCP flag or connection-state data.",
        "HTTP flood analysis requires request-level or status-coded application telemetry.",
        "A host-side sensor cannot see traffic discarded upstream before it reaches the host; use router, firewall, CDN or ISP flow telemetry for link-saturation attacks.",
        "The baseline is estimated from the supplied time buckets. Use separate known-benign baseline data and hold-out attack data for research evaluation."]}
    NETWORK_LAST_ANALYSIS.clear();NETWORK_LAST_ANALYSIS.update(result)
    return result

@app.route("/api/network/analyze", methods=["POST"])
def api_network_analyze():
    payload=request.get_json(silent=True) or {}
    rows=payload.get("flows") or []
    try:
        return jsonify(analyze_network_flows(rows, int(payload.get("window_seconds") or 10)))
    except Exception as exc:
        return jsonify({"error":str(exc)}),400

@app.route("/api/network/upload", methods=["POST"])
def api_network_upload():
    f=request.files.get("file")
    if not f: return jsonify({"error":"Choose a CSV flow-summary file."}),400
    if not f.filename.lower().endswith('.csv'): return jsonify({"error":"Only CSV flow-summary files are supported."}),400
    try:
        raw=f.stream.read(15*1024*1024+1)
        if len(raw)>15*1024*1024: return jsonify({"error":"CSV exceeds the 15 MB upload limit."}),413
        import io as _io
        decoded=raw.decode('utf-8-sig',errors='replace')
        rows=list(csv.DictReader(_io.StringIO(decoded)))
        result=analyze_network_flows(rows)
        result['input_filename']=Path(f.filename).name
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error":f"Could not analyse CSV: {exc}"}),400

@app.route("/api/network/demo", methods=["POST"])
def api_network_demo():
    # Synthetic demonstration only; never represents live or real attack traffic.
    now=int(time.time())
    rows=[]
    for i in range(12):
        for j in range(4):
            rows.append({"timestamp":datetime.fromtimestamp(now-120+i*10,timezone.utc).isoformat(),"source_ip":f"192.0.2.{10+j}",
                "destination_ip":"198.51.100.20","protocol":"TCP","tcp_flags":"ACK","packets":18+j*3,"bytes":12000})
    for j in range(160):
        rows.append({"timestamp":datetime.fromtimestamp(now-10+(j%8),timezone.utc).isoformat(),"source_ip":f"203.0.113.{(j%220)+1}",
            "destination_ip":"198.51.100.20","protocol":"TCP","tcp_flags":"SYN","destination_port":"443","packets":90,"bytes":54000})
    try:
        result=analyze_network_flows(rows,10);result['demo_mode']=True
        return jsonify(result)
    except Exception as exc: return jsonify({"error":str(exc)}),500


# FRONTEND
# ===========================================================================
INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnShield | Windows Security Analytics</title>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--panel2:#17223a;--line:#263450;--text:#eaf0ff;--muted:#91a1bf;--blue:#72a7ff;--cyan:#56d6d0;--red:#ff6f7d;--orange:#ffbf69;--green:#68dba2;--purple:#b49aff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top left,#17284b 0%,var(--bg) 42%);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif}
.wrap{max-width:1500px;margin:auto;padding:26px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:13px}.logo{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,#6da4ff,#61e0d0);display:grid;place-items:center;color:#071124;font-weight:900;font-size:21px;box-shadow:0 8px 25px #4b8dff30}
h1{font-size:24px;margin:0;letter-spacing:-.5px}.sub{color:var(--muted);margin-top:3px}.pill{border:1px solid #344563;background:#16213a;border-radius:999px;padding:8px 12px;color:#b9c8e5;font-size:12px}
.banner{border:1px solid #69552e;background:#2a241a;color:#ffe0a8;border-radius:12px;padding:12px 15px;margin:0 0 18px;display:none}
.filters{display:flex;flex-wrap:wrap;gap:10px;background:#10182b;border:1px solid var(--line);border-radius:15px;padding:14px;margin-bottom:17px}
input,select,button{font:inherit;color:var(--text);background:#0c1427;border:1px solid #30415f;border-radius:9px;padding:10px 12px;outline:none}
input:focus,select:focus{border-color:var(--blue)}input[type=search]{min-width:230px;flex:1}select{min-width:150px}button{cursor:pointer;background:#1a2b4a}button:hover{background:#263d64}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:13px;margin-bottom:17px}.card{background:linear-gradient(145deg,#151f35,#10182a);border:1px solid var(--line);border-radius:15px;padding:16px;min-width:0;box-shadow:0 10px 30px #00000012}.klabel{color:var(--muted);font-size:12px}.kvalue{font-size:28px;font-weight:750;letter-spacing:-.7px;margin:7px 0 2px}.hint{font-size:11px;color:#8da0c2}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;margin-bottom:15px}.span-4{grid-column:span 4}.span-5{grid-column:span 5}.span-6{grid-column:span 6}.span-7{grid-column:span 7}.span-8{grid-column:span 8}.span-12{grid-column:span 12}
.card h2{font-size:14px;margin:0 0 4px;font-weight:700}.desc{color:var(--muted);font-size:11px;margin-bottom:12px}.chart{height:235px;position:relative}.chart canvas{width:100%;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:10px;color:var(--muted);font-size:11px;margin-top:8px}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.barlist{display:flex;flex-direction:column;gap:11px}.barrow{display:grid;grid-template-columns:minmax(80px,1.2fr) 2fr 38px;gap:10px;align-items:center;font-size:11px}.barlabel{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c5d2e9}.track{height:9px;background:#26334c;border-radius:99px;overflow:hidden}.fill{height:100%;border-radius:99px;background:linear-gradient(90deg,#689dff,#58d7cf)}.barcount{text-align:right;color:#e6edfc;font-variant-numeric:tabular-nums}
.tablehead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}.tablewrap{overflow:auto;max-height:520px;border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:12px;white-space:nowrap}th{position:sticky;top:0;background:#1a2741;color:#b9c9e5;text-align:left;font-weight:650;z-index:1}td,th{padding:10px 12px;border-bottom:1px solid #24324b}tbody tr{cursor:pointer}tbody tr:hover{background:#1a2944}td.descell{max-width:330px;overflow:hidden;text-overflow:ellipsis}
.sev{display:inline-block;padding:3px 8px;border-radius:99px;font-size:10px;font-weight:750}.sev-Critical{color:#ffabb3;background:#53242e}.sev-High{color:#ffd19a;background:#4b3522}.sev-Medium{color:#c6d8ff;background:#263a62}.sev-Low{color:#9ce9c2;background:#173f36}
.empty{padding:30px;text-align:center;color:var(--muted)}.footer{color:#7485a4;font-size:11px;margin:18px 2px}.modal{position:fixed;inset:0;background:#020611c9;display:none;align-items:center;justify-content:center;padding:20px;z-index:10}.modal.open{display:flex}.modalbox{background:#101a2e;border:1px solid #354766;border-radius:16px;width:min(900px,100%);max-height:88vh;overflow:auto;padding:20px}.modalhead{display:flex;justify-content:space-between;align-items:center;gap:10px}.modal h2{margin:0 0 12px}.details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.detail{background:#17233a;border-radius:8px;padding:10px;overflow-wrap:anywhere}.detail label{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}.detail span{white-space:pre-wrap;overflow-wrap:anywhere}.raw{white-space:pre-wrap;overflow-wrap:anywhere;max-height:220px;overflow:auto;background:#080e1c;border-radius:8px;padding:12px;font-size:11px;color:#c6d3eb}
.page-nav{display:flex;gap:7px;flex-wrap:wrap;padding:9px;background:#0d1729;border:1px solid var(--line);border-radius:14px;margin:0 0 18px;position:sticky;top:8px;z-index:5;backdrop-filter:blur(12px)}.nav-btn{background:transparent;border-color:transparent;color:#aebdd8;padding:10px 13px;font-size:12px}.nav-btn:hover{background:#1a2944}.nav-btn.active{background:linear-gradient(135deg,#294875,#1d4653);border-color:#456b91;color:#fff}.page-intro{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:0 0 16px;padding:2px 3px 10px;border-bottom:1px solid #263450}.page-intro h2{font-size:20px;margin:2px 0 3px}.page-intro p{color:var(--muted);font-size:12px;margin:0}.page-kicker{font-size:9px;letter-spacing:1.6px;color:var(--cyan);font-weight:800}.page-hidden{display:none!important}.page-nav button{white-space:nowrap}@media(max-width:700px){.page-nav{position:static}.nav-btn{flex:1 1 42%;}.page-intro{align-items:flex-start}.page-intro .pill{display:none}}
@media(max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.span-4,.span-5,.span-6,.span-7,.span-8{grid-column:span 12}.wrap{padding:14px}.chart{height:220px}}@media(max-width:480px){.kpis{grid-template-columns:1fr 1fr}.kvalue{font-size:23px}.details{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<header class="top"><div class="brand"><div class="logo">V</div><div><h1>VulnShield <span style="color:#7daeff">/</span> Security Analytics</h1><div class="sub">Windows Event Log Management &amp; Threat Analysis · Report Explorer</div></div></div><div class="pill">LOCAL REPORT VIEWER · INTERACTIVE</div></header>
<nav class="page-nav" aria-label="Dashboard pages">
<button class="nav-btn active" data-target="overview">Overview</button>
<button class="nav-btn" data-target="monitoring">Monitoring &amp; Reports</button>
<button class="nav-btn" data-target="charts">Graphical Analysis</button>
<button class="nav-btn" data-target="investigation">Event Intelligence</button>
<button class="nav-btn" data-target="validation">Analyst Validation</button>
<button class="nav-btn" data-target="performance">Performance Evaluation</button>
<button class="nav-btn" data-target="attack">Attack Intelligence</button>
<button class="nav-btn" data-target="xdr">XDR Alert Center</button>
<button class="nav-btn" data-target="network">Network Threat Intelligence</button>
</nav>
<div class="page-intro"><div><div class="page-kicker">VULNSHIELD WORKSPACE</div><h2 id="pageTitle">Overview</h2><p id="pageDescription">A consolidated view of detected events, severity and monitored endpoints.</p></div><span class="pill" id="pageCounter">PAGE 1 / 6</span></div>
<section class="card" style="margin-bottom:17px;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap">
<div><h2 style="margin:0 0 4px">Load a new VulnShield report</h2><div class="desc" style="margin:0">Choose a new Excel report (.xlsx/.xls) or CSV to refresh the dashboard without changing the existing views.</div></div>
<div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap"><input id="reportUpload" type="file" accept=".xlsx,.xls,.csv" aria-label="Upload new report file" style="max-width:290px"><span class="pill" id="uploadStatus">Current report loaded</span></div>
</section>
<div class="banner" id="mismatch"></div>

<section class="card" id="evtxAnalyzer" style="margin:0 0 16px">
  <div class="tablehead">
    <div><h2>EVTX Upload &amp; Threat Analysis</h2>
      <div class="desc">Upload one or more Windows .evtx files, run VulnShield detection, inspect parsed events and download reports.</div>
    </div>
    <span class="pill" id="evtxStatus">Ready for upload</span>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <input id="evtxFiles" type="file" accept=".evtx,.csv" multiple style="max-width:420px">
    <button id="evtxAnalyzeBtn">Upload &amp; Analyze EVTX</button>
    <progress id="evtxProgress" value="0" max="100" style="width:180px;height:12px"></progress>
    <span id="evtxProgressText" class="hint">0%</span>
  </div>
  <pre id="evtxLog" class="raw" style="margin-top:12px;max-height:150px">Choose EVTX files to begin.</pre>
  <div id="evtxDownloads" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px"></div>
</section>

<section class="card" id="liveMonitor" style="margin:0 0 16px">
  <div class="tablehead">
    <div><h2>Live Windows Event Log Tracker &amp; Analyzer</h2>
      <div class="desc">Collect new events from installed Windows event channels and classify matching events in near real time.</div>
    </div>
    <span class="pill" id="liveState">Not monitoring</span>
  </div>
  <div style="display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-bottom:12px">
    <button id="liveStart">▶ Start Live Monitoring</button>
    <button id="liveStop" disabled>■ Stop Monitoring</button>
    <a class="pill" href="/api/live/report.xlsx" style="text-decoration:none">Download Live Excel Report</a>
    <span class="hint" id="liveStarted"></span>
  </div>
  <div class="kpis" style="grid-template-columns:repeat(4,minmax(120px,1fr));margin-bottom:12px">
    <div class="card"><div class="klabel">Captured events</div><div class="kvalue" id="liveTotal">0</div></div>
    <div class="card"><div class="klabel">Detected findings</div><div class="kvalue" id="liveFindings" style="color:var(--red)">0</div></div>
    <div class="card"><div class="klabel">Unique Event IDs</div><div class="kvalue" id="liveUnique">0</div></div>
    <div class="card"><div class="klabel">Channels observed</div><div class="kvalue" id="liveChannels">0</div></div>
  </div>
  <div class="desc" id="liveError" style="color:var(--orange);white-space:pre-wrap"></div>
  <div class="grid" style="margin-bottom:8px">
    <div class="span-6 card" style="box-shadow:none"><h2>Live Event ID Frequency</h2><div id="liveEventIdBars" class="barlist"></div></div>
    <div class="span-6 card" style="box-shadow:none"><h2>Live Severity Distribution</h2><div id="liveSeverityBars" class="barlist"></div></div>
  </div>
  <div class="tablehead"><h2>Live Event Stream</h2><span class="pill" id="liveRowsCount">0 recent records</span></div>
  <div class="tablewrap" style="max-height:340px"><table><thead><tr><th>Time</th><th>Event ID</th><th>Severity</th><th>Detection rule</th><th>Channel</th><th>Computer</th><th>Description</th></tr></thead><tbody id="liveRows"><tr><td colspan="7" class="empty">Start monitoring to collect events.</td></tr></tbody></table></div>
</section>


<section class="card" id="analystValidation" data-page="validation" style="margin:0 0 16px">
  <div class="tablehead">
    <div>
      <h2>Analyst Validation Workbench</h2>
      <div class="desc">Select an event to inspect its metadata and original log payload. Record an analyst assessment for the current review.</div>
    </div>
    <span class="pill" id="validationCount">0 events available</span>
  </div>
  <div class="filters" style="margin:12px 0">
    <input id="validationSearch" type="search" placeholder="Search events by ID, rule, user, host or description…">
    <select id="validationSeverity"><option value="">All severities</option></select>
    <select id="validationVerdict">
      <option value="">All review states</option>
      <option value="Unreviewed">Unreviewed</option>
      <option value="True Positive">True Positive</option>
      <option value="False Positive">False Positive</option>
      <option value="Needs Investigation">Needs Investigation</option>
    </select>
  </div>
  <div class="tablewrap" style="max-height:330px">
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Event ID</th><th>Detection Rule</th><th>Computer</th><th>Review State</th></tr></thead>
      <tbody id="validationRows"><tr><td colspan="6" class="empty">Load a report or run an EVTX analysis to begin validation.</td></tr></tbody>
    </table>
  </div>
  <div class="grid" style="margin-top:14px">
    <div class="span-5 card" style="box-shadow:none">
      <h2>Analyst Assessment</h2>
      <div class="desc" id="validationPrompt">Select an event from the table to inspect it.</div>
      <label style="display:block;margin:12px 0 6px;color:var(--muted);font-size:11px">Assessment</label>
      <select id="validationAssessment" style="width:100%" disabled>
        <option value="Unreviewed">Unreviewed</option>
        <option value="True Positive">True Positive</option>
        <option value="False Positive">False Positive</option>
        <option value="Needs Investigation">Needs Investigation</option>
      </select>
      <label style="display:block;margin:12px 0 6px;color:var(--muted);font-size:11px">Analyst notes</label>
      <textarea id="validationNotes" rows="5" placeholder="Record why this event is considered genuine, benign, or requires further investigation…" style="width:100%;resize:vertical" disabled></textarea>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
        <button id="saveValidation" type="button" disabled>Save assessment</button>
        <button id="downloadAssessments" type="button">Download analyst assessments (CSV)</button>
      </div>
      <div class="hint" id="validationSaveStatus" style="margin-top:8px">Saved assessments persist in this browser and can be exported as CSV.</div>
    </div>
    <div class="span-7 card" style="box-shadow:none">
      <h2>Selected Event Details</h2>
      <div id="validationDetails" class="details"><div class="empty">No event selected.</div></div>
      <h3 style="font-size:13px;margin-top:16px">Original Event Log / Payload</h3>
      <pre id="validationRaw" class="raw">Select an event to view its original event-log payload.</pre>
    </div>
  </div>
</section>

<section class="filters">
<input id="search" type="search" placeholder="Search rule, event description, computer, user, IP…">
<select id="severity"><option value="">All severities</option></select>
<select id="domain"><option value="">All domains</option></select>
<select id="sheet"><option value="">All event categories</option></select>
<select id="eventid"><option value="">All event IDs</option></select>
<select id="eventSort" title="Sort event records"><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="severity">Severity: Critical to Low</option><option value="eventid">Event ID: low to high</option><option value="eventid_desc">Event ID: high to low</option><option value="frequency">Most frequent Event IDs</option></select>
<button id="reset">Reset filters</button><button id="export">Export filtered CSV</button>
</section>
<section class="kpis">
<div class="card"><div class="klabel">Filtered event records</div><div class="kvalue" id="kTotal">—</div><div class="hint">From populated event sheets</div></div>
<div class="card"><div class="klabel">Critical severity</div><div class="kvalue" id="kCritical" style="color:var(--red)">—</div><div class="hint" id="pCritical">Share of filtered records</div></div>
<div class="card"><div class="klabel">High severity</div><div class="kvalue" id="kHigh" style="color:var(--orange)">—</div><div class="hint">Requires context review</div></div>
<div class="card"><div class="klabel">Detection rules</div><div class="kvalue" id="kRules">—</div><div class="hint">Distinct rule labels</div></div>
<div class="card"><div class="klabel">Computers observed</div><div class="kvalue" id="kComputers">—</div><div class="hint">Distinct host names in records</div></div>
</section>
<section class="grid">
<div class="card span-5"><h2>Severity distribution</h2><div class="desc">Counts in the currently filtered records</div><div class="chart"><canvas id="severityChart"></canvas></div><div class="legend" id="severityLegend"></div></div>
<div class="card span-7"><h2>Events over time</h2><div class="desc">Monthly event volume based on the report timestamps</div><div class="chart"><canvas id="timelineChart"></canvas></div></div>
<div class="card span-6"><h2>Detection domains</h2><div class="desc">Distribution across recorded detection domains</div><div id="domainBars" class="barlist"></div></div>
<div class="card span-6"><h2>Top detection rules</h2><div class="desc">Most frequent rule labels in the filtered records</div><div id="ruleBars" class="barlist"></div></div>
<div class="card span-6"><h2>Top Windows Event IDs</h2><div class="desc">Most frequent event IDs in the filtered records</div><div id="eventBars" class="barlist"></div></div>
<div class="card span-6"><h2>Event categories / sheets</h2><div class="desc">Rows contributed by each populated event category</div><div id="sheetBars" class="barlist"></div></div>
<div class="card span-12"><div class="tablehead"><div><h2>Event explorer</h2><div class="desc" style="margin:4px 0 0">Select any row to inspect fields and the original event-log payload.</div></div><div class="pill" id="tableCount">0 records</div></div>
<div class="tablewrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Detection rule</th><th>Event ID</th><th>Domain</th><th>Computer</th><th>Description</th></tr></thead><tbody id="eventRows"></tbody></table><div id="empty" class="empty" style="display:none">No records match these filters.</div></div><div class="desc" id="pageInfo" style="margin-top:10px"></div><div style="display:flex;gap:8px;margin-top:8px"><button id="prev">Previous</button><button id="next">Next</button></div>
</div></section>
<section class="card" id="performanceMatrix" style="margin:0 0 15px">
<h2>Performance Matrix</h2>
<div class="desc">Enter results from a labelled test run to calculate the agreed detection and performance metrics. These values are kept separate from the report's alert counts.</div>
<div class="card" style="box-shadow:none;margin:12px 0">
  <h2>Automated Ground-Truth Evaluation</h2>
  <div class="desc">Upload a labelled ground-truth file and the corresponding VulnShield expected-results/output file. The evaluator matches records using a shared Test Case ID / Record ID when available; otherwise it uses Event ID + Computer Name + timestamp. A ground-truth event missing from the results file is treated as not detected.</div>
  <div class="perf-inputs" style="margin-top:12px">
    <label>Ground-truth file (.csv / .xlsx / .xls)<input id="groundTruthFile" type="file" accept=".csv,.xlsx,.xls"></label>
    <label>Expected results file (.csv / .xlsx / .xls)<input id="expectedResultsFile" type="file" accept=".csv,.xlsx,.xls"></label>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
    <button id="calculateFromFiles" type="button">Calculate from uploaded files</button>
    <button id="downloadEvaluation" type="button" disabled>Download evaluation details (CSV)</button>
  </div>
  <div class="hint" id="fileEvaluationStatus" style="margin-top:9px">Required columns: a shared event identifier and a label. Ground-truth labels should identify Malicious/Attack or Benign/Normal; expected results should identify Detected/Malicious or Not Detected/Benign.</div>
</div>
<div class="grid" style="margin:0 0 12px">
<div class="span-6 card" style="box-shadow:none"><h2>Detection evaluation inputs</h2><div class="desc">Confusion-matrix counts from known test cases</div>
<div class="perf-inputs">
<label>True Positives (TP)<input id="perfTP" type="number" min="0" step="1" value="0"></label>
<label>False Positives (FP)<input id="perfFP" type="number" min="0" step="1" value="0"></label>
<label>False Negatives (FN)<input id="perfFN" type="number" min="0" step="1" value="0"></label>
<label>True Negatives (TN)<input id="perfTN" type="number" min="0" step="1" value="0"></label>
</div></div>
<div class="span-6 card" style="box-shadow:none"><h2>Processing performance inputs</h2><div class="desc">Enter measured values from the same test run</div>
<div class="perf-inputs">
<label>Records processed<input id="perfRecords" type="number" min="0" step="1" value="0"></label>
<label>Elapsed time (seconds)<input id="perfSeconds" type="number" min="0" step="any" value="0"></label>
<label>Records parsed successfully<input id="perfParsed" type="number" min="0" step="1" value="0"></label>
<label>CPU usage (%)<input id="perfCPU" type="number" min="0" max="100" step="any" placeholder="Optional"></label>
<label>Memory usage (MB)<input id="perfMemory" type="number" min="0" step="any" placeholder="Optional"></label>
</div></div></div>
<div class="tablewrap"><table><thead><tr><th>Metric</th><th>Formula / basis</th><th>Calculated result</th><th>Interpretation</th></tr></thead><tbody id="performanceRows"></tbody></table></div>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px"><button id="resetPerformance" type="button">Reset performance inputs</button><button id="exportPerformance" type="button">Export performance matrix CSV</button></div>
<div class="desc" style="margin:12px 0 0">Precision = TP/(TP+FP) · Recall = TP/(TP+FN) · F1 = 2×Precision×Recall/(Precision+Recall) · FPR = FP/(FP+TN) · FNR = FN/(FN+TP). Metrics requiring a zero denominator show N/A. Accuracy = (TP+TN)/(TP+FP+FN+TN). Throughput and parsing success are calculated from your measured inputs. CPU and memory are manually entered measurements.</div>
</section>
<style>
.perf-inputs{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.perf-inputs label{display:flex;flex-direction:column;gap:5px;color:var(--muted);font-size:11px}.perf-inputs input{width:100%;min-width:0}.perf-good{color:var(--green);font-weight:700}.perf-warn{color:var(--orange);font-weight:700}
@media(max-width:600px){.perf-inputs{grid-template-columns:1fr}}
</style>

<section class="card" id="attackIntelligencePage" data-page="attack" style="margin:0 0 16px">
 <div class="tablehead"><div><h2>Advanced Attack Pattern Recognition &amp; Attack DNA</h2>
 <div class="desc">Correlates observed Event IDs, account, host, source IP, timestamps and event details into explainable attack hypotheses. Results are indicators, not proof of compromise.</div></div><span class="pill">EVIDENCE-AWARE ANALYSIS</span></div>
 <div class="filters" style="margin:12px 0">
  <select id="attackSource"><option value="report">Imported report / current analysis</option><option value="live">Live monitoring tracker</option></select>
  <label>Import event report<input id="attackImportFile" type="file" accept=".csv,.json,.xlsx,.xls"></label><button id="attackImportBtn" class="secondary">Import report</button>
  <button id="runAttackAnalysis">Run Attack DNA Analysis</button>
  <label style="display:flex;align-items:center;gap:7px;color:var(--muted)"><input id="attackAutoLive" type="checkbox"> Auto-refresh live analysis (10 sec)</label>
  <span class="hint" id="attackStatus">Import a report or start the live Windows event tracker. Imported records are shared with Network Threat Intelligence.</span>
 </div>
 <div class="kpis" style="grid-template-columns:repeat(4,minmax(130px,1fr));margin-bottom:14px">
  <div class="card"><div class="klabel">Events analysed</div><div class="kvalue" id="dnaEvents">0</div></div>
  <div class="card"><div class="klabel">Attack hypotheses</div><div class="kvalue" id="dnaHypotheses">0</div></div>
  <div class="card"><div class="klabel">High-confidence patterns</div><div class="kvalue" id="dnaHigh">0</div></div>
  <div class="card"><div class="klabel">Hosts observed</div><div class="kvalue" id="dnaHosts">0</div></div>
 </div>
 <div class="grid" style="margin-bottom:14px">
  <div class="span-6 card" style="box-shadow:none"><h2>Possible Attack Categories</h2><div id="attackCategoryBars" class="barlist"></div></div>
  <div class="span-6 card" style="box-shadow:none"><h2>Evidence / Confidence Distribution</h2><div id="attackConfidenceBars" class="barlist"></div></div>
 </div>
 <div class="card" style="box-shadow:none;margin-bottom:14px">
  <h2>Attack DNA – Reconstructed Incident Story</h2>
  <div class="desc">A chronological view of observed events grouped into a possible attack progression. Missing stages are not treated as proof that an action did not occur.</div>
  <div id="attackStory" class="timeline" style="margin-top:12px"><div class="empty">Run Attack DNA analysis to build the incident story.</div></div>
 </div>
 <div class="tablehead"><h2>Detected Attack Hypotheses</h2><span class="pill" id="attackResultCount">0 candidates</span></div>
 <div class="tablewrap"><table><thead><tr><th>Possible attack</th><th>Confidence</th><th>Severity</th><th>Host</th><th>Evidence</th><th>Event IDs</th><th>Interpretation</th></tr></thead><tbody id="attackRows"><tr><td colspan="7" class="empty">No analysis performed.</td></tr></tbody></table></div>
 <div class="card" style="box-shadow:none;margin-top:14px">
  <h2>Attack catalogue and telemetry requirements</h2>
  <div class="desc">Some attacks cannot be reliably identified from Windows Event IDs alone. VulnShield marks the additional telemetry required rather than inventing a detection.</div>
  <div class="tablewrap"><table><thead><tr><th>Attack category</th><th>Possible Windows evidence</th><th>Additional telemetry / limitation</th></tr></thead><tbody id="attackCatalogue"></tbody></table></div>
 </div>
</section>

<section class="card" id="xdrAlertPage" data-page="xdr" style="margin:0 0 16px">
 <div class="tablehead"><div><h2>Extended Detection &amp; Response (XDR) Alert Center</h2>
 <div class="desc">Send selected VulnShield attack-analysis findings to an email recipient and/or HTTPS webhook. Credentials are used for this request only and are not saved by the application.</div></div><span class="pill">OPTIONAL NOTIFICATIONS</span></div>
 <div class="grid">
  <div class="span-6 card" style="box-shadow:none">
   <h2>Email notification (SMTP)</h2>
   <div class="perf-inputs">
    <label>SMTP host<input id="smtpHost" placeholder="smtp.example.com"></label>
    <label>SMTP port<input id="smtpPort" type="number" value="587"></label>
    <label>SMTP username<input id="smtpUser" autocomplete="off"></label>
    <label>SMTP password / app password<input id="smtpPass" type="password" autocomplete="new-password"></label>
    <label>From email<input id="smtpFrom" type="email" placeholder="alerts@example.com"></label>
    <label>Recipient email<input id="smtpTo" type="email" placeholder="analyst@example.com"></label>
   </div>
  </div>
  <div class="span-6 card" style="box-shadow:none">
   <h2>Webhook / messaging integration</h2>
   <label style="display:flex;flex-direction:column;gap:6px;color:var(--muted)">HTTPS webhook URL
    <input id="webhookUrl" type="url" placeholder="https://your-approved-endpoint.example/alerts">
   </label>
   <div class="desc" style="margin-top:10px">Use an endpoint you control, such as an approved Teams/Slack workflow or an internal notification gateway. The endpoint must accept JSON POST requests. Do not paste private tokens into a shared screenshot.</div>
   <label style="display:flex;align-items:center;gap:8px;margin-top:14px"><input id="notifyHighOnly" type="checkbox" checked> Send only High / Critical attack hypotheses</label>
  </div>
 </div>
 <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px">
  <button id="sendAttackAlerts">Send Current Attack Findings</button>
  <span class="hint" id="notifyStatus">Run Attack Intelligence before sending notifications.</span>
 </div>
 <div class="desc" style="margin-top:14px">Safety note: Notifications are advisory. VulnShield does not automatically block users, terminate processes or modify endpoints. Verify the incident before response actions.</div>
</section>


<section class="card" id="networkThreatPage" data-page="network" style="margin:0 0 16px">
 <div class="tablehead"><div><h2>Network Threat Intelligence — DoS / DDoS Detection</h2>
 <div class="desc">Analyse NetFlow/IPFIX, firewall, packet-capture-derived or application flow summaries. The engine identifies traffic anomalies and explains the evidence; it does not block traffic.</div></div><span class="pill">NETWORK BEHAVIOUR ENGINE</span></div>
 <div class="card" style="box-shadow:none;margin:12px 0">
  <div class="filters" style="align-items:center">
   <label style="display:flex;flex-direction:column;gap:5px;color:var(--muted)">Import network flow CSV<input id="networkFile" type="file" accept=".csv"></label>
   <button id="networkUploadBtn">Analyse flow CSV</button>
   <label style="display:flex;flex-direction:column;gap:5px;color:var(--muted)">Import event report<input id="networkEventFile" type="file" accept=".csv,.json,.xlsx,.xls"></label><button id="networkEventImportBtn" class="secondary">Import event report</button><select id="networkSource"><option value="report">Imported event report</option><option value="live">Live Windows event tracker</option></select><button id="networkSourceBtn" class="secondary">Analyse selected source</button><button id="networkDemoBtn" class="secondary">Load synthetic demo</button>
   <span id="networkStatus" class="hint">Import a report or flow CSV, start live monitoring, or load synthetic demo data.</span>
  </div>
  <div class="desc" style="margin-top:10px">Flow CSV columns: timestamp, source_ip, destination_ip, protocol, packets, bytes, destination_port, tcp_flags, http_status, requests. You can also analyse an imported event report or the live tracker, but only supported network connection events (Sysmon 3 / Windows Filtering Platform 5156 etc.) are converted into flow evidence.</div>
  <div class="desc" style="margin-top:5px">Privacy: IP addresses and traffic metadata are processed by this local Flask application. Avoid importing payloads or sensitive data you do not have permission to analyse.</div>
 </div>
 <div class="kpis" style="grid-template-columns:repeat(4,minmax(130px,1fr));margin-bottom:14px">
  <div class="card"><div class="klabel">Flow records</div><div class="kvalue" id="netRecords">—</div></div>
  <div class="card"><div class="klabel">Unique source IPs</div><div class="kvalue" id="netSources">—</div></div>
  <div class="card"><div class="klabel">Peak packet rate</div><div class="kvalue" id="netPeak">—</div><div class="klabel">packets / second</div></div>
  <div class="card"><div class="klabel">Traffic assessment</div><div class="kvalue" id="netAssessment" style="font-size:17px">Awaiting data</div><div class="klabel" id="netSeverity">No assessment</div></div>
 </div>
 <div class="grid" style="margin-bottom:14px">
  <div class="span-8 card" style="box-shadow:none"><h2>Traffic Rate Over Time</h2><canvas id="networkTimeline" height="230" style="width:100%;height:230px"></canvas><div class="desc">Packets per second by time bucket. Baseline is estimated from the supplied sample; use a separate benign baseline for rigorous experiments.</div></div>
  <div class="span-4 card" style="box-shadow:none"><h2>Evidence Score</h2><div class="kvalue" id="netScore" style="font-size:42px">—</div><div class="track" style="height:12px;margin:12px 0"><div class="fill" id="netScoreBar" style="width:0%"></div></div><div class="desc" id="netScoreNote">Heuristic prioritisation score, not a probability.</div></div>
 </div>
 <div class="grid" style="margin-bottom:14px">
  <div class="span-6 card" style="box-shadow:none"><h2>Top Source IPs</h2><div id="networkSourceBars" class="barlist"></div></div>
  <div class="span-6 card" style="box-shadow:none"><h2>Protocol Distribution</h2><div id="networkProtocolBars" class="barlist"></div></div>
 </div>
 <div class="card" style="box-shadow:none;margin-bottom:14px"><h2>Why VulnShield Flagged This Traffic</h2><ul id="networkReasons" class="desc"><li>Waiting for network telemetry.</li></ul></div>
 <div class="grid" style="margin-bottom:14px">
  <div class="span-6 card" style="box-shadow:none"><h2>Traffic Indicators</h2><div class="tablewrap"><table><tbody id="networkMetrics"><tr><td class="empty">No analysis available.</td></tr></tbody></table></div></div>
  <div class="span-6 card" style="box-shadow:none"><h2>Top Destination Ports</h2><div id="networkPortBars" class="barlist"></div><h2 style="margin-top:16px">Top Destinations</h2><div id="networkDestinationBars" class="barlist"></div></div>
 </div>
 <div class="tablehead"><h2>Detection Logic &amp; Telemetry Coverage</h2><button id="networkExportBtn" disabled>Export analysis JSON</button></div>
 <div class="tablewrap"><table><thead><tr><th>Detection signal</th><th>Evidence used</th><th>What it can indicate</th><th>Important limitation</th></tr></thead><tbody>
 <tr><td>Volumetric anomaly</td><td>Packets/sec and Mbps versus robust sample baseline</td><td>Traffic surge or resource pressure</td><td>High legitimate traffic can also produce surges</td></tr>
 <tr><td>Distributed source pattern</td><td>Unique source IP count and source entropy</td><td>Possible distributed flood</td><td>NAT, spoofing and shared clients can distort source diversity</td></tr>
 <tr><td>TCP SYN pressure</td><td>SYN-to-ACK packet ratio when flags are present</td><td>Possible SYN flood / incomplete handshakes</td><td>Flow summaries may not include handshake state</td></tr>
 <tr><td>HTTP service pressure</td><td>Request rate and HTTP 4xx/5xx response ratio</td><td>Possible HTTP flood or service distress</td><td>Requires request-level web/app logs; error codes alone are not proof</td></tr>
 </tbody></table></div>
 <div class="desc" id="networkLimitations" style="margin-top:12px">DoS/DDoS classification requires appropriate network telemetry. Windows Event IDs alone cannot confirm these attacks.</div>
</section>

<div class="footer">Generated from the uploaded Excel report. This dashboard visualizes detections recorded in the report; an alert is not proof of a confirmed attack. Review event context and validate detections before taking action.</div>
</div>
<div class="modal" id="modal"><div class="modalbox"><div class="modalhead"><h2>Event details</h2><button id="closeModal">Close ✕</button></div><div id="detailGrid" class="details"></div><h3 style="font-size:13px;margin-top:18px">Original Event Log</h3><pre id="rawLog" class="raw"></pre></div></div>
<script>
let DATA=[];
let SUMMARY=[];
/* original summary cleared */
let UNUSED_SUMMARY=[];
const $=id=>document.getElementById(id);
// Multi-page workspace: keep the existing analysis features, but show one focused workspace at a time.
const pageMeta={
 overview:['Overview','A consolidated view of report totals, severity and the current event snapshot.'],
 monitoring:['Monitoring & Reports','Upload reports, analyze EVTX files, and collect new Windows events live.'],
 charts:['Graphical Analysis','Explore severity, event timelines, detection domains, rules and event-ID patterns.'],
 investigation:['Event Intelligence','Filter and search the analyzed event inventory by severity, domain, category and Event ID.'],
 validation:['Analyst Validation','Inspect individual event records and review the original event-log payload before confirming an alert.'],
 performance:['Performance Evaluation','Evaluate detection quality and processing performance using labelled test results.'],
 attack:['Attack Intelligence','Correlate Windows events into possible attack patterns, attack DNA and an evidence-backed incident story.'],
 xdr:['XDR Alert Center','Configure optional email and webhook notifications for high-confidence VulnShield findings.'],
 network:['Network Threat Intelligence','Analyse network flow behaviour for possible DoS, DDoS, SYN flood and HTTP flood patterns.']
};
function setupPages(){
 const bySel=(sel,page)=>document.querySelectorAll(sel).forEach(el=>el.dataset.page=page);
 bySel('#mismatch','overview');
 const mainKpis=document.querySelector('.wrap > section.kpis');if(mainKpis)mainKpis.dataset.page='overview';
 const reportUploadCard=document.querySelector('#reportUpload')?.closest('section');if(reportUploadCard)reportUploadCard.dataset.page='monitoring';
 bySel('#evtxAnalyzer','monitoring');bySel('#liveMonitor','monitoring');
 const mainFilters=document.querySelector('.wrap > section.filters');if(mainFilters)mainFilters.dataset.page='investigation';
 bySel('#performanceMatrix','performance');
 const chartGrid=document.querySelector('section.grid');
 if(chartGrid){
   [...chartGrid.children].forEach(el=>{
     // The event explorer belongs on Event Intelligence, not on the charts page.
     if(el.querySelector('#eventRows')) el.dataset.page='investigation';
     else el.dataset.page='charts';
   });
 }
 document.querySelectorAll('[data-page]').forEach(el=>el.classList.add('page-hidden'));
 document.querySelectorAll('.nav-btn').forEach(btn=>btn.addEventListener('click',()=>showPage(btn.dataset.target)));
 showPage('overview');
}
function showPage(page){
 document.querySelectorAll('[data-page]').forEach(el=>el.classList.toggle('page-hidden',el.dataset.page!==page));
 document.querySelectorAll('.nav-btn').forEach(btn=>btn.classList.toggle('active',btn.dataset.target===page));
 const meta=pageMeta[page]||pageMeta.overview;$('pageTitle').textContent=meta[0];$('pageDescription').textContent=meta[1];
 const index=Object.keys(pageMeta).indexOf(page)+1;$('pageCounter').textContent=`PAGE ${index} / ${Object.keys(pageMeta).length}`;
 if(page==='charts')requestAnimationFrame(()=>render());
 if(page==='investigation')requestAnimationFrame(()=>renderTable());
 if(page==='validation')requestAnimationFrame(()=>renderValidation());
 window.scrollTo({top:0,behavior:'smooth'});
}

const colors={Critical:'#ff6f7d',High:'#ffbf69',Medium:'#72a7ff',Low:'#68dba2',Unknown:'#71809e'};
const uniq=a=>[...new Set(a.filter(v=>v!==null&&v!==undefined&&String(v).trim()!=='' ).map(String))].sort((a,b)=>a.localeCompare(b));
const val=(r,k)=>r[k]===null||r[k]===undefined?'':String(r[k]);
const severityOrder=['Critical','High','Medium','Low'];
let filtered=DATA.slice(),page=0,pageSize=50;
function populate(id,values){const el=$(id);uniq(values).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;el.appendChild(o)})}
populate('severity',DATA.map(r=>r.Severity));populate('domain',DATA.map(r=>r['Detection Domain']));populate('sheet',DATA.map(r=>r._sheet));populate('eventid',DATA.map(r=>r['Event ID']));setSelectOptions('validationSeverity',DATA.map(r=>r.Severity),'All severities');
function matches(r,q){if(!q)return true;const s=[r['Detection Rule'],r['Event Description'],r['Computer Name'],r['User'],r['UserID'],r['Source IP'],r['Event ID'],r['Channel'],r['Original Event Log'],r._sheet].map(val).join(' ').toLowerCase();return s.includes(q.toLowerCase())}
function applyFilters(){const q=$('search').value.trim();const sev=$('severity').value,dom=$('domain').value,sh=$('sheet').value,eid=$('eventid').value;filtered=DATA.filter(r=>(!sev||val(r,'Severity')===sev)&&(!dom||val(r,'Detection Domain')===dom)&&(!sh||r._sheet===sh)&&(!eid||val(r,'Event ID')===eid)&&matches(r,q));
 const rank={Critical:4,High:3,Medium:2,Low:1,Unclassified:0,Unknown:0};const mode=$('eventSort')?.value||'newest';
 filtered.sort((a,b)=>{const ta=Date.parse(val(a,'Date and Time'))||0,tb=Date.parse(val(b,'Date and Time'))||0;const ia=Number(val(a,'Event ID'))||0,ib=Number(val(b,'Event ID'))||0; if(mode==='oldest')return ta-tb;if(mode==='severity')return (rank[val(b,'Severity')]||0)-(rank[val(a,'Severity')]||0)||tb-ta;if(mode==='eventid')return ia-ib;if(mode==='eventid_desc')return ib-ia;if(mode==='frequency'){const freq={};DATA.forEach(x=>{const k=val(x,'Event ID');freq[k]=(freq[k]||0)+1});return (freq[val(b,'Event ID')]||0)-(freq[val(a,'Event ID')]||0)||ia-ib;}return tb-ta;});page=0;render()}
['search','severity','domain','sheet','eventid'].forEach(id=>$(id).addEventListener(id==='search'?'input':'change',applyFilters));$('eventSort').addEventListener('change',applyFilters);
$('reset').onclick=()=>{['search','severity','domain','sheet','eventid'].forEach(id=>$(id).value='');$('eventSort').value='newest';applyFilters()};
function counts(key){const c={};filtered.forEach(r=>{const k=val(r,key)||'Unknown';c[k]=(c[k]||0)+1});return c}
function topCounts(key,n=8){return Object.entries(counts(key)).sort((a,b)=>b[1]-a[1]).slice(0,n)}
function setKpis(){const sev=counts('Severity');$('kTotal').textContent=filtered.length.toLocaleString();$('kCritical').textContent=(sev.Critical||0).toLocaleString();$('kHigh').textContent=(sev.High||0).toLocaleString();$('pCritical').textContent=(filtered.length?((sev.Critical||0)/filtered.length*100).toFixed(1):'0.0')+'% of filtered records';$('kRules').textContent=uniq(filtered.map(r=>r['Detection Rule'])).length;$('kComputers').textContent=uniq(filtered.map(r=>r['Computer Name'])).length}
function drawDonut(canvasId,legendId,dataMap){const c=$(canvasId),ctx=c.getContext('2d'),rect=c.getBoundingClientRect(),dpr=window.devicePixelRatio||1;c.width=Math.max(1,rect.width*dpr);c.height=Math.max(1,rect.height*dpr);ctx.scale(dpr,dpr);const w=rect.width,h=rect.height;ctx.clearRect(0,0,w,h);const entries=Object.entries(dataMap).sort((a,b)=>severityOrder.indexOf(a[0])-severityOrder.indexOf(b[0]));const total=entries.reduce((s,e)=>s+e[1],0);const radius=Math.min(w*.29,h*.39),cx=w*.32,cy=h*.5;let start=-Math.PI/2;entries.forEach(([name,n])=>{const angle=total?n/total*Math.PI*2:0;ctx.beginPath();ctx.arc(cx,cy,radius,start,start+angle);ctx.strokeStyle=colors[name]||colors.Unknown;ctx.lineWidth=22;ctx.stroke();start+=angle});ctx.textAlign='center';ctx.fillStyle='#edf3ff';ctx.font='700 22px Segoe UI,Arial';ctx.fillText(total.toLocaleString(),cx,cy+3);ctx.fillStyle='#91a1bf';ctx.font='11px Segoe UI,Arial';ctx.fillText('events',cx,cy+21);const lg=$(legendId);lg.innerHTML='';entries.forEach(([name,n])=>{const s=document.createElement('span');s.innerHTML=`<i class="dot" style="background:${colors[name]||colors.Unknown}"></i>${esc(name)} <b style="color:#eaf0ff">${n}</b>`;lg.appendChild(s)})}
function drawTimeline(){const c=$('timelineChart'),ctx=c.getContext('2d'),rect=c.getBoundingClientRect(),dpr=window.devicePixelRatio||1;c.width=Math.max(1,rect.width*dpr);c.height=Math.max(1,rect.height*dpr);ctx.scale(dpr,dpr);const w=rect.width,h=rect.height;ctx.clearRect(0,0,w,h);const buckets={};filtered.forEach(r=>{const t=Date.parse(val(r,'Date and Time'));if(!Number.isFinite(t))return;const d=new Date(t),k=d.getUTCFullYear()+'-'+String(d.getUTCMonth()+1).padStart(2,'0');buckets[k]=(buckets[k]||0)+1});const keys=Object.keys(buckets).sort();if(!keys.length){ctx.fillStyle='#91a1bf';ctx.fillText('No timestamp data',12,25);return}const pad={l:34,r:10,t:12,b:36},cw=w-pad.l-pad.r,ch=h-pad.t-pad.b,max=Math.max(...keys.map(k=>buckets[k]),1);ctx.strokeStyle='#293750';ctx.fillStyle='#8192b1';ctx.font='10px Segoe UI,Arial';for(let i=0;i<=4;i++){const y=pad.t+ch*i/4;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();ctx.fillText(Math.round(max*(1-i/4)),2,y+3)}const step=cw/keys.length,bw=Math.max(2,Math.min(22,step*.66));keys.forEach((k,i)=>{const bh=buckets[k]/max*ch,x=pad.l+i*step+(step-bw)/2,y=pad.t+ch-bh;const grad=ctx.createLinearGradient(0,y,0,y+bh);grad.addColorStop(0,'#68a1ff');grad.addColorStop(1,'#52d6cf');ctx.fillStyle=grad;ctx.beginPath();ctx.roundRect?ctx.roundRect(x,y,bw,bh,3):ctx.rect(x,y,bw,bh);ctx.fill();if(keys.length<15||i%Math.ceil(keys.length/12)===0){ctx.save();ctx.translate(x+bw/2,h-8);ctx.rotate(-.45);ctx.textAlign='right';ctx.fillStyle='#91a1bf';ctx.fillText(k,0,0);ctx.restore()}})}
function renderBars(id,items){const el=$(id);el.innerHTML='';if(!items.length){el.textContent='No data for current filters';return}const max=Math.max(...items.map(x=>x[1]),1);items.forEach(([name,n])=>{const row=document.createElement('div');row.className='barrow';const label=document.createElement('div');label.className='barlabel';label.title=name;label.textContent=name;const track=document.createElement('div');track.className='track';const fill=document.createElement('div');fill.className='fill';fill.style.width=(n/max*100)+'%';track.appendChild(fill);const count=document.createElement('div');count.className='barcount';count.textContent=n;row.append(label,track,count);el.appendChild(row)})}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function renderTable(){const tbody=$('eventRows');tbody.innerHTML='';const start=page*pageSize,rows=filtered.slice(start,start+pageSize);rows.forEach(r=>{const tr=document.createElement('tr');const cols=[val(r,'Date and Time'),val(r,'Severity'),r._sheet,val(r,'Detection Rule'),val(r,'Event ID'),val(r,'Detection Domain'),val(r,'Computer Name'),val(r,'Event Description')];cols.forEach((v,i)=>{const td=document.createElement('td');if(i===1){const span=document.createElement('span');span.className='sev sev-'+(v||'Unknown');span.textContent=v||'Unknown';td.appendChild(span)}else{td.textContent=v; if(i===7)td.className='descell'}tr.appendChild(td)});tr.onclick=()=>showDetails(r);tbody.appendChild(tr)});$('empty').style.display=rows.length?'none':'block';if(!rows.length)$('empty').textContent=DATA.length?'No records match these filters.':'No event data loaded yet. Upload a VulnShield Excel/CSV report in Monitoring & Reports, or run an EVTX analysis.';$('tableCount').textContent=filtered.length.toLocaleString()+' records';$('pageInfo').textContent=filtered.length?`Showing ${start+1}–${Math.min(start+pageSize,filtered.length)} of ${filtered.length.toLocaleString()} filtered records`:'0 records';$('prev').disabled=page===0;$('next').disabled=(page+1)*pageSize>=filtered.length}
function showDetails(r){const grid=$('detailGrid');grid.innerHTML='';Object.entries(r).filter(([k,v])=>k!=='Original Event Log'&&v!==null&&v!==''&&k!=='timestamp').forEach(([k,v])=>{const d=document.createElement('div');d.className='detail';const l=document.createElement('label');l.textContent=k;const s=document.createElement('span');s.textContent=String(v);d.append(l,s);grid.appendChild(d)});$('rawLog').textContent=val(r,'Original Event Log')||'No original event-log payload is present for this row.';$('modal').classList.add('open')}

// Analyst Validation page: independent event queue and selected-event detail view.
const ANALYST_REVIEW_STORAGE_KEY='vulnshield_analyst_reviews_v1';
const analystReviews = new Map();
try {
  const savedReviews=JSON.parse(localStorage.getItem(ANALYST_REVIEW_STORAGE_KEY)||'{}');
  Object.entries(savedReviews).forEach(([k,v])=>analystReviews.set(k,v));
} catch(err) { console.warn('Could not restore saved analyst reviews:',err); }
let selectedValidationKey = null;
let validationVisibleRows = [];
function validationKey(r, index){
  return [val(r,'Event ID'),val(r,'Date and Time'),val(r,'Computer Name'),val(r,'Detection Rule'),String(index)].join('|');
}
function reviewFor(key){return analystReviews.get(key)||{assessment:'Unreviewed',notes:''};}
function renderValidation(){
  const body=$('validationRows');
  if(!body)return;
  const q=$('validationSearch').value.trim().toLowerCase();
  const sev=$('validationSeverity').value;
  const verdict=$('validationVerdict').value;
  body.innerHTML='';
  validationVisibleRows=[];
  DATA.forEach((r,index)=>{
    const key=validationKey(r,index), review=reviewFor(key);
    const hay=[val(r,'Event ID'),val(r,'Detection Rule'),val(r,'Event Description'),val(r,'Computer Name'),val(r,'User'),val(r,'Source IP'),val(r,'Channel')].join(' ').toLowerCase();
    if(q&&!hay.includes(q))return;
    if(sev&&val(r,'Severity')!==sev)return;
    if(verdict&&review.assessment!==verdict)return;
    validationVisibleRows.push({r,key,index});
  });
  $('validationCount').textContent=`${validationVisibleRows.length.toLocaleString()} of ${DATA.length.toLocaleString()} events`;
  if(!validationVisibleRows.length){
    const tr=document.createElement('tr'),td=document.createElement('td');
    td.colSpan=6;td.className='empty';
    td.textContent=DATA.length?'No events match the selected validation filters.':'No event data loaded yet. Upload a report or run an EVTX analysis under Monitoring & Reports.';
    tr.appendChild(td);body.appendChild(tr);
  } else {
    validationVisibleRows.forEach(({r,key})=>{
      const review=reviewFor(key),tr=document.createElement('tr');
      if(key===selectedValidationKey)tr.style.background='#203653';
      [val(r,'Date and Time'),val(r,'Severity')||'Unknown',val(r,'Event ID'),val(r,'Detection Rule')||'No matching detection rule',val(r,'Computer Name')||'—',review.assessment].forEach((v,i)=>{
        const td=document.createElement('td');
        if(i===1){const badge=document.createElement('span');badge.className='sev sev-'+(v||'Unknown');badge.textContent=v;td.appendChild(badge)}
        else td.textContent=v;
        tr.appendChild(td);
      });
      tr.addEventListener('click',()=>selectValidationEvent(r,key));
      body.appendChild(tr);
    });
  }
  if(selectedValidationKey && !validationVisibleRows.some(x=>x.key===selectedValidationKey)){
    selectedValidationKey=null;
    clearValidationSelection();
  }
}
function clearValidationSelection(){
  $('validationPrompt').textContent='Select an event from the table to inspect it.';
  $('validationDetails').innerHTML='<div class="empty">No event selected.</div>';
  $('validationRaw').textContent='Select an event to view its original event-log payload.';
  $('validationAssessment').value='Unreviewed';
  $('validationAssessment').disabled=true;
  $('validationNotes').value='';
  $('validationNotes').disabled=true;
  $('saveValidation').disabled=true;
}
function selectValidationEvent(r,key){
  selectedValidationKey=key;
  const review=reviewFor(key);
  $('validationPrompt').textContent=`Event ID ${val(r,'Event ID')||'Unknown'} · ${val(r,'Detection Rule')||'No matching detection rule'}`;
  const grid=$('validationDetails');grid.innerHTML='';
  Object.entries(r).filter(([k,v])=>k!=='Original Event Log'&&k!=='timestamp'&&v!==null&&v!=='').forEach(([k,v])=>{
    const d=document.createElement('div');d.className='detail';
    const label=document.createElement('label');label.textContent=k;
    const value=document.createElement('span');value.textContent=String(v);
    d.append(label,value);grid.appendChild(d);
  });
  $('validationRaw').textContent=val(r,'Original Event Log')||'No original event-log payload is present for this row.';
  $('validationAssessment').value=review.assessment;
  $('validationAssessment').disabled=false;
  $('validationNotes').value=review.notes;
  $('validationNotes').disabled=false;
  $('saveValidation').disabled=false;
  $('validationSaveStatus').textContent='Review the event context and save your assessment.';
  renderValidation();
}
function saveValidationAssessment(){
  if(!selectedValidationKey)return;
  analystReviews.set(selectedValidationKey,{
    assessment:$('validationAssessment').value,
    notes:$('validationNotes').value.trim(),
    savedAt:new Date().toISOString()
  });
  try {
    localStorage.setItem(ANALYST_REVIEW_STORAGE_KEY,JSON.stringify(Object.fromEntries(analystReviews)));
    $('validationSaveStatus').textContent='Assessment saved in this browser. Use Download analyst assessments to export your review records.';
  } catch(err) {
    $('validationSaveStatus').textContent='Assessment saved for this session, but browser storage was unavailable. Export the CSV before closing the page.';
  }
  renderValidation();
}
$('validationSearch').addEventListener('input',renderValidation);
$('validationSeverity').addEventListener('change',renderValidation);
$('validationVerdict').addEventListener('change',renderValidation);
$('saveValidation').addEventListener('click',saveValidationAssessment);

function csvCell(value){return '"'+String(value??'').replace(/"/g,'""').replace(/\r?\n/g,' ')+'"';}
function downloadCsv(filename, rows){
  if(!rows.length){alert('There are no records to export.');return;}
  const cols=[...new Set(rows.flatMap(row=>Object.keys(row)))];
  const csv=[cols.map(csvCell).join(','),...rows.map(row=>cols.map(k=>csvCell(row[k])).join(','))].join('\r\n');
  const blob=new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8;'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
}
$('downloadAssessments').addEventListener('click',()=>{
  const rows=DATA.map((r,index)=>{
    const review=reviewFor(validationKey(r,index));
    return {...r,'Analyst Assessment':review.assessment,'Analyst Notes':review.notes,'Assessment Saved At':review.savedAt||''};
  }).filter(r=>r['Analyst Assessment']!=='Unreviewed'||r['Analyst Notes']);
  if(!rows.length){alert('No analyst assessments have been saved yet.');return;}
  downloadCsv('VulnShield_Analyst_Assessments.csv',rows);
});


function render(){setKpis();drawDonut('severityChart','severityLegend',counts('Severity'));drawTimeline();renderBars('domainBars',topCounts('Detection Domain',10));renderBars('ruleBars',topCounts('Detection Rule',8));renderBars('eventBars',topCounts('Event ID',8));renderBars('sheetBars',topCounts('_sheet',10));renderTable()}
$('prev').onclick=()=>{if(page>0){page--;renderTable()}};$('next').onclick=()=>{if((page+1)*pageSize<filtered.length){page++;renderTable()}};
$('closeModal').onclick=()=>$('modal').classList.remove('open');$('modal').onclick=e=>{if(e.target===$('modal'))$('modal').classList.remove('open')};
$('export').onclick=()=>{const cols=[...new Set(filtered.flatMap(r=>Object.keys(r)))];const csv=[cols.map(x=>'"'+x.replace(/"/g,'""')+'"').join(','),...filtered.map(r=>cols.map(k=>'"'+val(r,k).replace(/"/g,'""').replace(/\r?\n/g,' ')+'"').join(','))].join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));a.download='vulnshield_filtered_events.csv';a.click();URL.revokeObjectURL(a.href)};
$('prev').disabled=true;
const reportTotal=SUMMARY.reduce((s,r)=>s+(Number(r.Counts)||0),0);
if(reportTotal!==DATA.length){$('mismatch').style.display='block';$('mismatch').textContent=`Report consistency note: the “Result Summary” sheet totals ${reportTotal.toLocaleString()} records, while the populated event-category sheets contain ${DATA.length.toLocaleString()} rows. This dashboard charts the event-category rows; reconcile the summary sheet before treating these totals as identical.`}

// Additional features: load a newer report and calculate the VulnShield performance matrix.
function setSelectOptions(id, values, firstLabel){const el=$(id),old=el.value;el.innerHTML='';const first=document.createElement('option');first.value='';first.textContent=firstLabel;el.appendChild(first);uniq(values).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;el.appendChild(o)});if([...el.options].some(o=>o.value===old))el.value=old;}
function updateMismatch(){const reportTotal=(SUMMARY||[]).reduce((sum,r)=>sum+(Number(r.Counts)||0),0);const banner=$('mismatch');if(reportTotal && reportTotal!==DATA.length){banner.style.display='block';banner.textContent=`Report consistency note: the “Result Summary” sheet totals ${reportTotal.toLocaleString()} records, while the populated event-category sheets contain ${DATA.length.toLocaleString()} rows. This dashboard charts the event-category rows; reconcile the summary sheet before treating these totals as identical.`}else if(!DATA.length){banner.style.display='block';banner.textContent='No event rows were found in the selected report. Check that the workbook contains populated event-category sheets.'}else{banner.style.display='none';banner.textContent=''}}
function reloadDashboardData(rows, summary, filename){DATA=rows;SUMMARY=summary||[];setSelectOptions('validationSeverity',DATA.map(r=>r.Severity),'All severities');setSelectOptions('severity',DATA.map(r=>r.Severity),'All severities');setSelectOptions('domain',DATA.map(r=>r['Detection Domain']),'All domains');setSelectOptions('sheet',DATA.map(r=>r._sheet),'All event categories');setSelectOptions('eventid',DATA.map(r=>r['Event ID']),'All event IDs');['search','severity','domain','sheet','eventid'].forEach(id=>$(id).value='');if($('eventSort'))$('eventSort').value='newest';filtered=DATA.slice().sort((a,b)=>(Date.parse(val(b,'Date and Time'))||0)-(Date.parse(val(a,'Date and Time'))||0));page=0;updateMismatch();render();renderValidation();$('uploadStatus').textContent=`Loaded ${filename} · ${DATA.length.toLocaleString()} rows`;}
function loadScript(src){return new Promise((resolve,reject)=>{const existing=document.querySelector('script[data-sheetjs]');if(existing&&window.XLSX){resolve();return}const sc=document.createElement('script');sc.src=src;sc.dataset.sheetjs='1';sc.onload=resolve;sc.onerror=()=>reject(new Error('Could not load the Excel reader. Check your internet connection and try again.'));document.head.appendChild(sc);});}
$('reportUpload').addEventListener('change',async e=>{const file=e.target.files&&e.target.files[0];if(!file)return;$('uploadStatus').textContent='Reading report…';try{let rows=[],summary=[];const lower=file.name.toLowerCase();if(lower.endsWith('.csv')){const text=await file.text();const lines=text.replace(/^\uFEFF/,'').split(/\r?\n/).filter(x=>x.trim());if(!lines.length)throw new Error('The CSV file is empty.');const parseLine=line=>{const out=[];let cur='',q=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'&&q&&line[i+1]==='"'){cur+='"';i++}else if(c==='"')q=!q;else if(c===','&&!q){out.push(cur);cur=''}else cur+=c}out.push(cur);return out};const headers=parseLine(lines[0]);rows=lines.slice(1).map(line=>{const vals=parseLine(line),o={};headers.forEach((h,i)=>o[h]=vals[i]??'');o._sheet='Uploaded CSV';return o}).filter(r=>Object.values(r).some(v=>String(v??'').trim()));}else{if(!window.XLSX)await loadScript('https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js');const buffer=await file.arrayBuffer();const wb=XLSX.read(buffer,{type:'array',cellDates:true});for(const name of wb.SheetNames){const sheet=wb.Sheets[name];const json=XLSX.utils.sheet_to_json(sheet,{defval:null,raw:false});if(name.toLowerCase()==='result summary'){summary=json;continue}if(!json.length)continue;const hasEventCols=json.some(r=>Object.keys(r).some(k=>/date and time|detection rule|severity|event id|event description/i.test(k)));if(!hasEventCols)continue;json.forEach(r=>{r._sheet=name;rows.push(r)})}}
if(!rows.length)throw new Error('No event records found. Excel reports should contain event-category sheets with columns such as Date and Time, Severity, Detection Rule, or Event ID.');reloadDashboardData(rows,summary,file.name);
}catch(err){$('uploadStatus').textContent='Upload failed';alert('Unable to load report: '+err.message)}finally{e.target.value=''}});
function nval(id){const v=Number($(id).value);return Number.isFinite(v)&&v>=0?v:0}function pct(v){return v===null?'N/A':(v*100).toFixed(2)+'%'}function num(v,d=2){return v===null||!Number.isFinite(v)?'N/A':v.toLocaleString(undefined,{maximumFractionDigits:d})}
function renderPerformance(){const tp=nval('perfTP'),fp=nval('perfFP'),fn=nval('perfFN'),tn=nval('perfTN'),records=nval('perfRecords'),seconds=nval('perfSeconds'),parsed=nval('perfParsed'),cpu=$('perfCPU').value.trim()===''?null:nval('perfCPU'),mem=$('perfMemory').value.trim()===''?null:nval('perfMemory');const ratio=(a,b)=>b>0?a/b:null;const precision=ratio(tp,tp+fp),recall=ratio(tp,tp+fn),f1=(precision!==null&&recall!==null&&precision+recall>0)?2*precision*recall/(precision+recall):null;const total=tp+fp+fn+tn;const metrics=[['Precision','TP / (TP + FP)',pct(precision),'Of the alerts classified as positive, the proportion that were true positives.'],['Recall / Detection rate','TP / (TP + FN)',pct(recall),'Of the known positive cases, the proportion detected.'],['F1-score','2 × Precision × Recall / (Precision + Recall)',pct(f1),'Harmonic mean of precision and recall.'],['Accuracy','(TP + TN) / (TP + FP + FN + TN)',pct(ratio(tp+tn,total)),'Overall correctness on labelled test cases.'],['False-positive rate','FP / (FP + TN)',pct(ratio(fp,fp+tn)),'Proportion of known negative cases incorrectly flagged.'],['False-negative rate','FN / (FN + TP)',pct(ratio(fn,fn+tp)),'Proportion of known positive cases missed.'],['Throughput','Records processed / elapsed seconds',seconds>0?num(records/seconds)+' records/sec':'N/A','Calculated from the entered workload and elapsed time.'],['Parsing success rate','Successfully parsed / records processed',records>0?pct(Math.min(1,parsed/records)):'N/A','Based on the entered parsing counts; capped at 100% for display.'],['CPU usage','Measured during test run',cpu===null?'Not entered':num(cpu)+'%','Manually entered measurement; not inferred from the report.'],['Memory usage','Measured during test run',mem===null?'Not entered':num(mem)+' MB','Manually entered measurement; not inferred from the report.']];const tbody=$('performanceRows');tbody.innerHTML='';metrics.forEach(([name,formula,result,desc])=>{const tr=document.createElement('tr');[name,formula,result,desc].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===2)td.className=result==='N/A'?'perf-warn':'perf-good';tr.appendChild(td)});tbody.appendChild(tr)});}
['perfTP','perfFP','perfFN','perfTN','perfRecords','perfSeconds','perfParsed','perfCPU','perfMemory'].forEach(id=>$(id).addEventListener('input',renderPerformance));$('resetPerformance').onclick=()=>{[['perfTP',0],['perfFP',0],['perfFN',0],['perfTN',0],['perfRecords',0],['perfSeconds',0],['perfParsed',0],['perfCPU',''],['perfMemory','']].forEach(([id,v])=>$(id).value=v);renderPerformance()};$('exportPerformance').onclick=()=>{const rows=[...$('performanceRows').rows].map(r=>[...r.cells].map(c=>c.textContent));const csv=[['Metric','Formula / basis','Calculated result','Interpretation'],...rows].map(row=>row.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));a.download='vulnshield_performance_matrix.csv';a.click();URL.revokeObjectURL(a.href)};
renderPerformance();updateMismatch();render();setupPages();window.addEventListener('resize',()=>render());

// ---------- Ground truth vs expected-results evaluation ----------
let fileEvaluationRows=[];
function normHeader(v){return String(v??'').toLowerCase().replace(/[^a-z0-9]/g,'');}
function findField(row,aliases){
  const map=new Map(Object.keys(row).map(k=>[normHeader(k),k]));
  for(const alias of aliases){const key=map.get(normHeader(alias));if(key!==undefined)return row[key];}
  return '';
}
function normalizeLabel(v){
  const s=String(v??'').trim().toLowerCase();
  if(['1','true','yes','malicious','attack','attacker','positive','detected','alert','threat','anomaly'].includes(s))return 'malicious';
  if(['0','false','no','benign','normal','negative','not detected','not_detected','no alert','clean','safe'].includes(s))return 'benign';
  return '';
}
function getTruthLabel(row){
  return normalizeLabel(findField(row,['Ground Truth','GroundTruth','Actual Label','Actual','Label','Class','Is Malicious','Malicious','Expected Label','Truth']));
}
function getPredictionLabel(row){
  const explicit=findField(row,['Predicted Label','Prediction','Predicted','Detection Result','Expected Result','Result','Is Detected','Detected','Alert','Classification','Is Malicious']);
  const normalized=normalizeLabel(explicit);
  if(normalized)return normalized;
  const rule=findField(row,['Detection Rule','Rule','Alert Name']);
  const severity=findField(row,['Severity','Risk Level']);
  if(String(rule??'').trim() && !/no matching|no detection|none|not detected/i.test(String(rule)))return 'malicious';
  if(/critical|high|medium/i.test(String(severity??'')))return 'malicious';
  if(/low|informational|none|benign/i.test(String(severity??'')))return 'benign';
  return '';
}
function rowMatchKey(row){
  const id=findField(row,['Test Case ID','TestCaseID','Record ID','RecordID','Unique ID','Event Record ID']);
  if(String(id??'').trim())return 'id:'+String(id).trim().toLowerCase();
  const event=findField(row,['Event ID','EventID','Event Code']);
  const host=findField(row,['Computer Name','Computer','Hostname','Host','Machine']);
  const time=findField(row,['Date and Time','Timestamp','Time Created','Time','Event Time']);
  if(!String(event??'').trim())return '';
  return 'evt:'+String(event).trim().toLowerCase()+'|'+String(host??'').trim().toLowerCase()+'|'+String(time??'').trim().toLowerCase();
}
async function readEvaluationFile(file){
  if(!file)throw new Error('Please select both the ground-truth and expected-results files.');
  if(!window.XLSX)await loadScript('https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js');
  const buffer=await file.arrayBuffer();
  const wb=XLSX.read(buffer,{type:'array',cellDates:false});
  let combined=[];
  wb.SheetNames.forEach(name=>{
    const rows=XLSX.utils.sheet_to_json(wb.Sheets[name],{defval:'',raw:false});
    if(rows.length)combined=combined.concat(rows);
  });
  if(!combined.length)throw new Error(file.name+' contains no data rows.');
  return combined;
}
function setMetricInput(id,value){$(id).value=String(value);}
function calculateFileEvaluation(groundRows,resultRows){
  const resultMap=new Map(), duplicatePredictions=[];
  resultRows.forEach((r,i)=>{
    const key=rowMatchKey(r);if(!key)return;
    if(resultMap.has(key))duplicatePredictions.push(key);
    else resultMap.set(key,r);
  });
  let TP=0,FP=0,FN=0,TN=0,unlabelled=0,unmatchedTruth=0;
  const detail=[];
  groundRows.forEach((truth,i)=>{
    const key=rowMatchKey(truth);
    if(!key){unlabelled++;detail.push({'Match Key':'','Ground Truth':getTruthLabel(truth)||'Unknown','Prediction':'Unknown','Outcome':'Excluded','Reason':'No usable shared identifier'});return;}
    const actual=getTruthLabel(truth);
    if(!actual){unlabelled++;detail.push({'Match Key':key,'Ground Truth':'Unknown','Prediction':'Unknown','Outcome':'Excluded','Reason':'Ground-truth label missing or unsupported'});return;}
    const predRow=resultMap.get(key);
    if(!predRow)unmatchedTruth++;
    const predicted=predRow?getPredictionLabel(predRow):'benign';
    if(predRow&&!predicted){unlabelled++;detail.push({'Match Key':key,'Ground Truth':actual,'Prediction':'Unknown','Outcome':'Excluded','Reason':'Expected-results row has no recognized prediction label'});return;}
    let outcome='';
    if(actual==='malicious'&&predicted==='malicious'){TP++;outcome='TP';}
    else if(actual==='benign'&&predicted==='malicious'){FP++;outcome='FP';}
    else if(actual==='malicious'&&predicted==='benign'){FN++;outcome='FN';}
    else {TN++;outcome='TN';}
    detail.push({'Match Key':key,'Ground Truth':actual,'Prediction':predicted,'Outcome':outcome,'Reason':predRow?'Matched expected-results record': 'No matching output record; treated as not detected'});
  });
  const predictedKeys=new Set(groundRows.map(rowMatchKey).filter(Boolean));
  const extraPredictions=[...resultMap.keys()].filter(k=>!predictedKeys.has(k)).length;
  if(TP+FP+FN+TN===0)throw new Error('No comparable labelled records found. Check the shared ID columns and label values.');
  return {TP,FP,FN,TN,unlabelled,unmatchedTruth,extraPredictions,duplicatePredictions:duplicatePredictions.length,detail};
}
$('calculateFromFiles').addEventListener('click',async()=>{
  const status=$('fileEvaluationStatus'),btn=$('calculateFromFiles');
  btn.disabled=true;status.textContent='Reading files and matching records…';
  try{
    const truthRows=await readEvaluationFile($('groundTruthFile').files[0]);
    const resultRows=await readEvaluationFile($('expectedResultsFile').files[0]);
    const metrics=calculateFileEvaluation(truthRows,resultRows);
    setMetricInput('perfTP',metrics.TP);setMetricInput('perfFP',metrics.FP);
    setMetricInput('perfFN',metrics.FN);setMetricInput('perfTN',metrics.TN);
    renderPerformance();fileEvaluationRows=metrics.detail;$('downloadEvaluation').disabled=false;
    status.textContent=`Evaluation complete: ${metrics.TP+metrics.FP+metrics.FN+metrics.TN} matched labelled cases · TP ${metrics.TP}, FP ${metrics.FP}, FN ${metrics.FN}, TN ${metrics.TN}. Unlabelled/excluded: ${metrics.unlabelled}; missing output rows: ${metrics.unmatchedTruth}; extra output rows: ${metrics.extraPredictions}; duplicate output keys: ${metrics.duplicatePredictions}.`;
  }catch(err){status.textContent='Evaluation failed: '+err.message;fileEvaluationRows=[];$('downloadEvaluation').disabled=true;}
  finally{btn.disabled=false;}
});
$('downloadEvaluation').addEventListener('click',()=>{
  if(!fileEvaluationRows.length){alert('Run the file evaluation first.');return;}
  downloadCsv('VulnShield_GroundTruth_Evaluation.csv',fileEvaluationRows);
});


// ---------- VulnShield backend integration: EVTX upload + live monitoring ----------
let activeAnalysisJob = null;
let livePollHandle = null;
const byId = id => document.getElementById(id);
function safeText(v){return String(v ?? '');}
function toDashboardRow(e, finding){
  const d = e.data || {};
  const f = finding || {};
  const eventId = e.event_id ?? f.event_id ?? '';
  const channel = e.channel || f.channel || 'Unknown';
  const dataText = Object.entries(d).map(([k,v])=>`${k}: ${v}`).join(' | ');
  const desc = f.description || (eventId ? `Event ID ${eventId} captured; no matching detection rule.` : 'Parsed event');
  return {
    'Date and Time': e.timestamp || f.datetime || e.time_created || '',
    'timestamp': f.timestamp ?? '',
    'Detection Rule': f.rule || 'No matching detection rule',
    'Severity': f.severity || 'Unclassified',
    'Detection Domain': f.domain || channel,
    'Event Description': desc + (dataText ? ` — ${dataText.slice(0,500)}` : ''),
    'Event ID': String(eventId),
    'Computer Name': e.computer || f.computer || '',
    'User': d.TargetUserName || d.SubjectUserName || d.AccountName || d.User || d.Username || e.user || f.user || '',
    'Source IP': d.IpAddress || d.SourceIp || d.SourceNetworkAddress || d.ClientAddress || e.source_ip || f.source_ip || '',
    'Channel': channel,
    'Original Event Log': e.raw_xml || f.raw_xml || JSON.stringify(d),
    '_sheet': channel
  };
}
function showDownloads(job){
  const box=byId('evtxDownloads');
  box.innerHTML='';
  [['xlsx','Excel report'],['json','JSON results'],['timesketch','Timesketch CSV']].forEach(([kind,label])=>{
    const a=document.createElement('a');a.className='pill';a.href=`/api/download/${job}/${kind}`;a.textContent='⬇ '+label;a.style.textDecoration='none';box.appendChild(a);
  });
}
async function runEvtxAnalysis(){
  const files=byId('evtxFiles').files;
  if(!files.length){alert('Choose at least one .evtx or .csv file.');return;}
  const btn=byId('evtxAnalyzeBtn'), log=byId('evtxLog');
  btn.disabled=true;btn.textContent='Uploading…';byId('evtxStatus').textContent='Uploading files';
  byId('evtxProgress').value=0;byId('evtxProgressText').textContent='0%';byId('evtxDownloads').innerHTML='';
  try{
    const fd=new FormData();[...files].forEach(f=>fd.append('files',f));
    const up=await fetch('/api/upload',{method:'POST',body:fd});const uploaded=await up.json();
    if(!up.ok)throw new Error(uploaded.error||'Upload failed');
    const start=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:uploaded.job_id,path:uploaded.path})});
    const started=await start.json();if(!start.ok)throw new Error(started.error||'Could not start analysis');
    activeAnalysisJob=uploaded.job_id;btn.textContent='Analyzing…';byId('evtxStatus').textContent='Analysis running';
    await pollEvtxJob(uploaded.job_id);
  }catch(err){byId('evtxStatus').textContent='Analysis failed';log.textContent=err.message;btn.disabled=false;btn.textContent='Upload & Analyze EVTX';}
}
async function pollEvtxJob(job){
  const log=byId('evtxLog');
  try{
    const r=await fetch('/api/status/'+job);const s=await r.json();
    byId('evtxProgress').value=s.progress||0;byId('evtxProgressText').textContent=(s.progress||0)+'%';
    log.textContent=(s.log||[]).join('\n');
    log.scrollTop=log.scrollHeight;
    if(s.status==='done'){
      const rr=await fetch('/api/results/'+job);const data=await rr.json();if(!rr.ok)throw new Error(data.error||'Could not load results');
      const findings=data.findings||[], all=data.all_events||[];
      const fMap=new Map(findings.map(f=>[`${f.event_id}|${f.channel}|${f.record_id}`,f]));
      const rows=all.map(e=>toDashboardRow(e,fMap.get(`${e.event_id}|${e.channel}|${e.record_id}`)));
      reloadDashboardData(rows,[],`EVTX analysis ${job}`);
      byId('evtxStatus').textContent=`Complete · ${all.length.toLocaleString()} events · ${findings.length.toLocaleString()} findings`;
      showDownloads(job);
      byId('evtxAnalyzeBtn').disabled=false;byId('evtxAnalyzeBtn').textContent='Upload & Analyze EVTX';
      return;
    }
    if(s.status==='error'){byId('evtxStatus').textContent='Analysis error';byId('evtxAnalyzeBtn').disabled=false;byId('evtxAnalyzeBtn').textContent='Upload & Analyze EVTX';return;}
    setTimeout(()=>pollEvtxJob(job),1000);
  }catch(err){byId('evtxStatus').textContent='Error';log.textContent += '\n'+err.message;byId('evtxAnalyzeBtn').disabled=false;byId('evtxAnalyzeBtn').textContent='Upload & Analyze EVTX';}
}
byId('evtxAnalyzeBtn').addEventListener('click',runEvtxAnalysis);

function renderMiniBars(id, pairs){
  const el=byId(id);el.innerHTML='';
  if(!pairs.length){el.textContent='No live data yet';return;}
  const max=Math.max(...pairs.map(x=>x[1]),1);
  pairs.forEach(([label,count])=>{
    const row=document.createElement('div');row.className='barrow';
    const name=document.createElement('div');name.className='barlabel';name.textContent=label;
    const track=document.createElement('div');track.className='track';
    const fill=document.createElement('div');fill.className='fill';fill.style.width=(count/max*100)+'%';track.appendChild(fill);
    const n=document.createElement('div');n.className='barcount';n.textContent=count;
    row.append(name,track,n);el.appendChild(row);
  });
}
function renderLive(data){
  const events=data.events||[], findings=data.findings||[];
  byId('liveTotal').textContent=(data.total_events||0).toLocaleString();
  byId('liveFindings').textContent=(data.total_findings||0).toLocaleString();
  byId('liveUnique').textContent=new Set(events.map(e=>e.event_id)).size;
  byId('liveChannels').textContent=new Set(events.map(e=>e.channel)).size;
  byId('liveState').textContent=data.running?'Monitoring':'Stopped';
  byId('liveStarted').textContent=data.started_at?`Started: ${data.started_at}`:'';
  byId('liveError').textContent=data.last_error||'';
  byId('liveStop').disabled=!data.running;byId('liveStart').disabled=!!data.running;
  const ids={},sevs={};events.forEach(e=>ids[e.event_id]=(ids[e.event_id]||0)+1);events.forEach(e=>sevs[e.severity]=(sevs[e.severity]||0)+1);
  renderMiniBars('liveEventIdBars',Object.entries(ids).sort((a,b)=>b[1]-a[1]).slice(0,10));
  renderMiniBars('liveSeverityBars',Object.entries(sevs).sort((a,b)=>b[1]-a[1]));
  const tbody=byId('liveRows');tbody.innerHTML='';
  events.slice(0,100).forEach(e=>{
    const tr=document.createElement('tr');
    [e.time,e.event_id,e.severity,e.rule,e.channel,e.computer,e.description].forEach((v,i)=>{
      const td=document.createElement('td');td.textContent=safeText(v);if(i===2){const badge=document.createElement('span');badge.className='sev sev-'+(v||'Low');badge.textContent=safeText(v);td.textContent='';td.appendChild(badge);}tr.appendChild(td);
    });tbody.appendChild(tr);
  });
  if(!events.length){tbody.innerHTML='<tr><td colspan="7" class="empty">No events collected yet. New events appear while monitoring is running.</td></tr>';}
  byId('liveRowsCount').textContent=`${events.length} recent records`;
}
async function pollLive(){
  try{const r=await fetch('/api/live/status');const data=await r.json();renderLive(data);if(data.running)livePollHandle=setTimeout(pollLive,1500);}
  catch(err){byId('liveError').textContent=err.message;livePollHandle=setTimeout(pollLive,3000);}
}
byId('liveStart').addEventListener('click',async()=>{
  byId('liveStart').disabled=true;
  try{const r=await fetch('/api/live/start',{method:'POST'});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not start monitor');byId('liveState').textContent='Starting…';pollLive();}
  catch(err){byId('liveError').textContent=err.message;byId('liveStart').disabled=false;}
});
byId('liveStop').addEventListener('click',async()=>{
  try{await fetch('/api/live/stop',{method:'POST'});}catch(err){byId('liveError').textContent=err.message;}
  if(livePollHandle)clearTimeout(livePollHandle);pollLive();
});
pollLive();


// ---------------------------------------------------------------------------
// Attack Intelligence: report/live event normalization and rendering
// ---------------------------------------------------------------------------
let latestAttackAnalysis = null;
function attackRecordsFromDashboard(){
  // Current report viewer uses a normalized DATA array.
  return (DATA || []).map(r => ({
    "event_id": r["Event ID"], "timestamp": r["Date and Time"], "computer": r["Computer Name"],
    "channel": r["Channel"] || r._sheet, "user": r["User"] || r["UserID"] || r["TargetUserName"] || r["Account Name"] || "",
    "source_ip": r["Source IP"] || r["IpAddress"] || r["Source Network Address"] || "", "description": r["Event Description"],
    "rule": r["Detection Rule"], "severity": r["Severity"], "raw_xml": r["Original Event Log"]
  }));
}
function renderAttackAnalysis(result){
  latestAttackAnalysis = result;
  $('dnaEvents').textContent=(result.total_events||0).toLocaleString();
  $('dnaHypotheses').textContent=(result.hypothesis_count||0).toLocaleString();
  $('dnaHigh').textContent=(result.high_confidence||0).toLocaleString();
  $('dnaHosts').textContent=(result.host_count||0).toLocaleString();
  renderMiniBars('attackCategoryBars',Object.entries(result.category_counts||{}).sort((a,b)=>b[1]-a[1]));
  renderMiniBars('attackConfidenceBars',Object.entries(result.confidence_counts||{}));
  const rows=$('attackRows');rows.innerHTML='';
  (result.candidates||[]).forEach(c=>{
    const tr=document.createElement('tr');
    [c.attack,c.confidence+'%',c.severity,c.host,(c.evidence_count+' evidence records'),(c.event_ids||[]).join(', '),c.explanation].forEach((v,i)=>{
      const td=document.createElement('td');td.textContent=String(v??'');if(i===1||i===2){const b=document.createElement('span');b.className='sev sev-'+(i===2?c.severity:'Medium');b.textContent=String(v);td.textContent='';td.appendChild(b);}tr.appendChild(td);
    });rows.appendChild(tr);
  });
  if(!(result.candidates||[]).length)rows.innerHTML='<tr><td colspan="7" class="empty">No supported attack pattern was identified in this dataset. This does not prove the system is free of threats.</td></tr>';
  $('attackResultCount').textContent=(result.candidates||[]).length+' candidates';
  const story=$('attackStory');story.innerHTML='';
  (result.story||[]).slice(-60).forEach(e=>{
    const item=document.createElement('div');item.className='detail';item.style.marginBottom='8px';
    const title=document.createElement('b');title.textContent=`${e.time||'Unknown time'} · Event ID ${e.event_id}`;
    const desc=document.createElement('div');desc.className='desc';desc.textContent=`${e.description} · ${e.host} · ${e.user} · ${e.source_ip}`;
    item.append(title,desc);story.appendChild(item);
  });
  if(!(result.story||[]).length)story.innerHTML='<div class="empty">No event timeline available.</div>';
  const cat=$('attackCatalogue');cat.innerHTML='';
  (result.catalogue||[]).forEach(c=>{const tr=document.createElement('tr');[c.attack,c.evidence,c.limitation].forEach(v=>{const td=document.createElement('td');td.textContent=v;tr.appendChild(td)});cat.appendChild(tr)});
  $('attackStatus').textContent='Analysis complete · '+(result.limitations||[]).join(' ');
}
async function runAttackAnalysis(){
  const source=$('attackSource').value;
  $('attackStatus').textContent='Analysing event evidence…';
  try{
    let events=[];
    if(source==='live'){
      const live=await fetch('/api/live/events').then(r=>r.json());
      events=(live.events||[]).map(e=>({...e,event_id:e.event_id??e.eventId??e.id,timestamp:e.timestamp||e.time_created||e.time||e.datetime,computer:e.computer||e.hostname||e.host,user:e.user||e.username||e.account,source_ip:e.source_ip||e.ip_address||e.ipAddress,description:e.description||e.rule,raw_xml:e.raw_xml||e.raw||''}));
    } else {
      events=[];
      const imported=await fetch('/api/intelligence/import/status').then(r=>r.json());
      if(imported.records){const ir=await fetch('/api/intelligence/import/data').then(r=>r.json()).catch(()=>({records:[]}));events=ir.records||[];}
      if(!events.length)events=attackRecordsFromDashboard();
      if(!events.length && activeAnalysisJob){
        const report=await fetch('/api/results/'+activeAnalysisJob).then(r=>r.json());
        events=report.all_events||[];
      }
    }
    if(!events.length){$('attackStatus').textContent='No records found. Upload a report or run EVTX analysis / live monitoring first.';return;}
    const response=await fetch('/api/attack-analysis',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({events})});
    const result=await response.json();if(!response.ok)throw new Error(result.error||'Analysis failed');
    renderAttackAnalysis(result);
  }catch(err){$('attackStatus').textContent='Attack analysis failed: '+err.message;}
}
$('attackImportBtn').addEventListener('click',async()=>{
  const f=$('attackImportFile').files[0];if(!f){$('attackStatus').textContent='Choose a CSV, JSON or Excel event report first.';return;}
  const fd=new FormData();fd.append('file',f);$('attackStatus').textContent='Importing report…';
  try{const r=await fetch('/api/intelligence/import',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error||'Import failed');$('attackSource').value='report';$('attackStatus').textContent=d.message+' This report is now available to both intelligence pages.';}
  catch(e){$('attackStatus').textContent='Import failed: '+e.message;}
});
$('runAttackAnalysis').addEventListener('click',runAttackAnalysis);
let attackAutoTimer = null;
$('attackAutoLive').addEventListener('change',()=>{
  if(attackAutoTimer){clearInterval(attackAutoTimer);attackAutoTimer=null;}
  if($('attackAutoLive').checked){
    $('attackSource').value='live';
    $('attackStatus').textContent='Live attack analysis auto-refresh enabled (10 seconds).';
    runAttackAnalysis();
    attackAutoTimer=setInterval(()=>{
      if($('attackAutoLive').checked && $('attackSource').value==='live') runAttackAnalysis();
    },10000);
  }
});

// XDR notification workflow. No credentials are written to disk or localStorage.
$('sendAttackAlerts').addEventListener('click',async()=>{
  const result=latestAttackAnalysis;
  if(!result){$('notifyStatus').textContent='Run Attack Intelligence first.';return;}
  const onlyHigh=$('notifyHighOnly').checked;
  const selected=(result.candidates||[]).filter(c=>!onlyHigh||['High','Critical'].includes(c.severity));
  if(!selected.length){$('notifyStatus').textContent='No matching findings to notify.';return;}
  const email={host:$('smtpHost').value.trim(),port:$('smtpPort').value,username:$('smtpUser').value,
    password:$('smtpPass').value,from:$('smtpFrom').value.trim(),to:$('smtpTo').value.trim()};
  const webhook=$('webhookUrl').value.trim();
  const body=selected.map(c=>`${c.attack} | ${c.severity} | confidence score ${c.confidence}%\nHost: ${c.host}\nEvent IDs: ${c.event_ids.join(', ')}\nEvidence: ${c.evidence_count}\n${c.explanation}`).join('\n\n---\n\n');
  $('notifyStatus').textContent='Sending notifications…';
  try{
    const r=await fetch('/api/notify',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({subject:`VulnShield: ${selected.length} attack hypothesis(es)`,body,
        alert:{count:selected.length,candidates:selected},email,webhook})});
    const d=await r.json();if(!r.ok)throw new Error(d.error||'Notification failed');
    $('notifyStatus').textContent=(d.results||[]).join(' · ');
  }catch(err){$('notifyStatus').textContent='Notification failed: '+err.message;}
});


// Network Threat Intelligence dashboard
let NETWORK_RESULT=null;
function networkBars(id,items,labelKey,valueKey){const el=$(id);if(!el)return;el.innerHTML='';if(!items||!items.length){el.innerHTML='<div class="empty">No telemetry available.</div>';return}const max=Math.max(...items.map(x=>Number(x[valueKey])||0),1);items.forEach(x=>{const row=document.createElement('div');row.className='barrow';const label=document.createElement('div');label.className='barlabel';label.textContent=x[labelKey];label.title=x[labelKey];const track=document.createElement('div');track.className='track';const fill=document.createElement('div');fill.className='fill';fill.style.width=(Number(x[valueKey])||0)/max*100+'%';track.appendChild(fill);const count=document.createElement('div');count.className='barcount';count.textContent=Number(x[valueKey]).toLocaleString();row.append(label,track,count);el.appendChild(row)})}
function drawNetworkTimeline(points){const c=$('networkTimeline');if(!c)return;const ctx=c.getContext('2d'),rect=c.getBoundingClientRect(),dpr=window.devicePixelRatio||1;c.width=Math.max(1,rect.width*dpr);c.height=230*dpr;ctx.scale(dpr,dpr);const w=rect.width,h=230;ctx.clearRect(0,0,w,h);if(!points||!points.length){ctx.fillStyle='#91a1bf';ctx.fillText('No timestamped flow data',14,24);return}const vals=points.map(p=>p.packets_per_sec),max=Math.max(...vals,1),pad={l:42,r:12,t:16,b:32},cw=w-pad.l-pad.r,ch=h-pad.t-pad.b;ctx.strokeStyle='#293750';ctx.fillStyle='#91a1bf';ctx.font='10px Segoe UI,Arial';for(let i=0;i<=4;i++){let y=pad.t+ch*i/4;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();ctx.fillText((max*(1-i/4)).toFixed(0),4,y+3)}ctx.beginPath();points.forEach((p,i)=>{const x=pad.l+(points.length===1?cw/2:i*cw/(points.length-1)),y=pad.t+ch-(p.packets_per_sec/max*ch);if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y)});ctx.strokeStyle='#56d6d0';ctx.lineWidth=2.5;ctx.stroke();points.forEach((p,i)=>{const x=pad.l+(points.length===1?cw/2:i*cw/(points.length-1)),y=pad.t+ch-(p.packets_per_sec/max*ch);ctx.fillStyle='#72a7ff';ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fill()});ctx.fillStyle='#91a1bf';ctx.fillText('Time buckets ('+points.length+')',pad.l,h-7)}
function renderNetworkResult(d){NETWORK_RESULT=d;const s=d.summary||{},a=d.assessment||{};$('netRecords').textContent=(s.records||0).toLocaleString();$('netSources').textContent=(s.unique_sources||0).toLocaleString();$('netPeak').textContent=Number(s.peak_pps||0).toLocaleString();$('netAssessment').textContent=a.classification||'Unknown';$('netSeverity').textContent=a.severity||'';$('netScore').textContent=(a.score??0)+'/100';$('netScoreBar').style.width=(a.score??0)+'%';$('netScoreNote').textContent=a.confidence_note||'Heuristic evidence score.';drawNetworkTimeline(d.timeline||[]);networkBars('networkSourceBars',(d.top_sources||[]).map(x=>({label:x.ip,value:x.flows})),'label','value');networkBars('networkProtocolBars',(d.protocols||[]).map(x=>({label:x.protocol,value:x.packets})),'label','value');networkBars('networkPortBars',(d.top_ports||[]).map(x=>({label:'Port '+x.port,value:x.packets})),'label','value');networkBars('networkDestinationBars',(d.top_destinations||[]).map(x=>({label:x.ip,value:x.packets})),'label','value');$('networkReasons').innerHTML='';(a.reasons||[]).forEach(r=>{const li=document.createElement('li');li.textContent=r;$('networkReasons').appendChild(li)});const metrics=[['Total packets',s.total_packets],['Total bytes',s.total_bytes],['Unique destinations',s.unique_destinations],['Peak throughput (Mbps)',s.peak_mbps],['SYN / ACK ratio',s.syn_ack_ratio],['HTTP error ratio (%)',s.http_error_rate],['Source IP entropy (bits)',s.source_entropy],['Baseline median (pps)',s.baseline_median_pps],['Baseline MAD (pps)',s.baseline_mad_pps]];$('networkMetrics').innerHTML=metrics.map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v===undefined?'N/A':esc(Number(v).toLocaleString())}</td></tr>`).join('');$('networkLimitations').textContent=(d.limitations||[]).join(' ');$('networkExportBtn').disabled=false;$('networkStatus').textContent=(d.input_filename?'Analysed '+d.input_filename:d.demo_mode?'Synthetic demo loaded':'Network analysis completed')+' · '+s.records+' records';}
async function networkRequest(url,options={}){$('networkStatus').textContent='Analysing network telemetry…';$('networkUploadBtn').disabled=true;$('networkDemoBtn').disabled=true;try{const r=await fetch(url,options);let d={};try{d=await r.json()}catch(_){throw new Error('Server returned a non-JSON response. Check the Flask terminal for an exception.')}if(!r.ok)throw new Error(d.error||('HTTP '+r.status+' · network analysis failed'));if(!d.summary||!d.assessment)throw new Error('The server response is missing summary or assessment data. Restart the updated VulnShield application.');renderNetworkResult(d)}catch(e){$('networkStatus').textContent='Analysis failed: '+e.message;console.error('VulnShield network analysis:',e)}finally{$('networkUploadBtn').disabled=false;$('networkDemoBtn').disabled=false}}
$('networkUploadBtn').addEventListener('click',()=>{const f=$('networkFile').files[0];if(!f){$('networkStatus').textContent='Choose a CSV file first.';return}const fd=new FormData();fd.append('file',f);networkRequest('/api/network/upload',{method:'POST',body:fd})});
$('networkDemoBtn').addEventListener('click',()=>networkRequest('/api/network/demo',{method:'POST'}));
$('networkSourceBtn').addEventListener('click',()=>networkRequest('/api/intelligence/network-source',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:$('networkSource').value})}));
$('networkEventImportBtn').addEventListener('click',async()=>{
  const f=$('networkEventFile').files[0];if(!f){$('networkStatus').textContent='Choose an event report (CSV, JSON or Excel) first.';return;}
  const fd=new FormData();fd.append('file',f);$('networkStatus').textContent='Importing event report…';
  try{const r=await fetch('/api/intelligence/import',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.error||'Import failed');$('networkSource').value='report';$('networkStatus').textContent=d.message+' Select Analyse selected source to run network analysis.';}
  catch(e){$('networkStatus').textContent='Import failed: '+e.message;}
});


$('networkExportBtn').addEventListener('click',()=>{if(!NETWORK_RESULT)return;const blob=new Blob([JSON.stringify(NETWORK_RESULT,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='VulnShield_Network_Threat_Analysis.json';a.click();URL.revokeObjectURL(a.href)});
window.addEventListener('resize',()=>{if(NETWORK_RESULT&&$('networkThreatPage')&&!$('networkThreatPage').classList.contains('page-hidden'))drawNetworkTimeline(NETWORK_RESULT.timeline||[])});

</script></body></html>"""

# Serve the dashboard at the root URL.
@app.route("/", methods=["GET"])
def dashboard_home():
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