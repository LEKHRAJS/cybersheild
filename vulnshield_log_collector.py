"""
VulnShield - Automatic Windows Event Log Collector
Python 3.10+ | Windows 10/11

Exports selected Windows Event Log channels directly into one output folder.
Uses Windows' built-in wevtutil.exe; no PowerShell and no pip packages required.

Run once:
    python vulnshield_log_collector.py

Run continuously every 5 minutes:
    python vulnshield_log_collector.py --watch --interval 5

Include optional channels:
    python vulnshield_log_collector.py --all-channels

Choose output directory:
    python vulnshield_log_collector.py --output "D:\\VulnShield\\CollectedLogs"
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

CORE_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-Sysmon/Operational",
]

OPTIONAL_CHANNELS = [
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-GroupPolicy/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-SMBClient/Connectivity",
    "Microsoft-Windows-SMBServer/Operational",
]

DEFAULT_OUTPUT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "VulnShield" / "CollectedLogs"


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_wevtutil(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["wevtutil.exe", *args],
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=180,
    )


def get_available_channels() -> set[str]:
    result = run_wevtutil("el")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not list Windows Event Log channels.")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def safe_filename(channel: str) -> str:
    return "".join("_" if c in '\\/:*?"<>| ' else c for c in channel) + ".evtx"


def export_channel(channel: str, folder: Path) -> dict:
    target = folder / safe_filename(channel)
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        result = run_wevtutil("epl", channel, str(target), "/ow:true")
        if result.returncode == 0 and target.exists():
            return {
                "channel": channel,
                "status": "Success",
                "file": str(target),
                "size_bytes": target.stat().st_size,
                "started_at": started,
                "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "message": "",
            }
        message = (result.stderr or result.stdout or f"wevtutil exit code {result.returncode}").strip()
        return {
            "channel": channel, "status": "Failed", "file": str(target),
            "size_bytes": 0, "started_at": started,
            "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "message": message,
        }
    except Exception as exc:
        return {
            "channel": channel, "status": "Failed", "file": str(target),
            "size_bytes": 0, "started_at": started,
            "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "message": str(exc),
        }


def collect(output_root: Path, include_optional: bool = False) -> Path:
    if not is_windows():
        raise OSError("This collector runs on Windows only.")
    if shutil.which("wevtutil.exe") is None:
        raise RuntimeError("wevtutil.exe was not found. Run this script on Windows 10/11.")

    output_root.mkdir(parents=True, exist_ok=True)
    # Save each channel directly in the chosen output folder. In watch mode,
    # /ow:true replaces the previous snapshot for that channel on each cycle.
    folder = output_root

    requested = CORE_CHANNELS + (OPTIONAL_CHANNELS if include_optional else [])
    available = get_available_channels()
    results = []

    print(f"\n[VulnShield] Collection started: {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}")
    print(f"[VulnShield] Destination folder: {folder}")
    print("[VulnShield] Existing channel snapshots will be overwritten on each collection cycle.")
    if not is_admin():
        print("[Warning] Not elevated. Some protected channels, especially Security, may fail.")

    for channel in requested:
        if channel not in available:
            print(f"[NOT INSTALLED] {channel}")
            results.append({
                "channel": channel, "status": "NotInstalled", "file": "",
                "size_bytes": 0, "started_at": "", "completed_at": "",
                "message": "Channel is not present on this Windows installation.",
            })
            continue

        print(f"[EXPORTING] {channel}")
        row = export_channel(channel, folder)
        results.append(row)
        print(f"  [{row['status'].upper()}] {row['message']}" if row["message"] else f"  [SAVED] {row['file']}")

    manifest = folder / "collection_manifest.csv"
    columns = ["channel", "status", "file", "size_bytes", "started_at", "completed_at", "message"]
    with manifest.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)

    summary = {
        "computer_name": os.environ.get("COMPUTERNAME", "unknown"),
        "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "output_folder": str(folder),
        "requested_channels": len(requested),
        "successful": sum(r["status"] == "Success" for r in results),
        "failed": sum(r["status"] == "Failed" for r in results),
        "not_installed": sum(r["status"] == "NotInstalled" for r in results),
        "manifest": str(manifest),
    }
    (folder / "collection_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print("\n[VulnShield] Collection finished.")
    print(f"  Success: {summary['successful']} | Failed: {summary['failed']} | Not installed: {summary['not_installed']}")
    print(f"  Manifest: {manifest}")
    return folder


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatically export VulnShield Windows Event Log channels.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output root folder.")
    parser.add_argument("--all-channels", action="store_true", help="Also attempt optional project-related channels.")
    parser.add_argument("--watch", action="store_true", help="Repeat collection at a fixed interval.")
    parser.add_argument("--interval", type=int, default=5, help="Minutes between collections when --watch is used (default: 5).")
    args = parser.parse_args()

    if args.interval < 1:
        parser.error("--interval must be at least 1 minute.")
    if not is_windows():
        print("Error: this program must run on Windows 10/11.", file=sys.stderr)
        return 2

    try:
        if not args.watch:
            collect(args.output, args.all_channels)
            return 0

        print(f"[VulnShield] Continuous collection enabled. Interval: {args.interval} minute(s).")
        print("[VulnShield] Press Ctrl+C to stop.")
        while True:
            try:
                collect(args.output, args.all_channels)
            except Exception as exc:
                print(f"[ERROR] Collection cycle failed: {exc}", file=sys.stderr)
            time.sleep(args.interval * 60)

    except KeyboardInterrupt:
        print("\n[VulnShield] Collector stopped by user.")
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
