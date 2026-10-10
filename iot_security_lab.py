#!/usr/bin/env python3
"""Basic helper for an authorized IoT security testing lab."""

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")


def save_report(filename, data):
    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / filename
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("Report saved to:", path)


def inventory(csv_file):
    with open(csv_file, newline="", encoding="utf-8") as file:
        devices = list(csv.DictReader(file))

    report = {
        "project": "IoT Device Penetration Testing Lab",
        "created": datetime.utcnow().isoformat() + "Z",
        "type": "Device Inventory",
        "devices": devices,
    }
    save_report("device_inventory.json", report)

    print("\nIoT Device Inventory")
    for device in devices:
        print(
            device.get("device_name", "Unknown"),
            "|", device.get("device_type", "Unknown"),
            "|", device.get("ip_address", "Unknown"),
            "| Firmware:", device.get("firmware_version", "Unknown")
        )


def firmware(file_path):
    path = Path(file_path)
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")
    strings = sorted(set(re.findall(r"[ -~]{4,}", text)))
    urls = sorted(set(re.findall(r"https?://[^\s\"']+", text)))
    sha256 = hashlib.sha256(data).hexdigest()

    report = {
        "project": "IoT Device Penetration Testing Lab",
        "created": datetime.utcnow().isoformat() + "Z",
        "type": "Firmware Inspection",
        "file": path.name,
        "size_bytes": len(data),
        "sha256": sha256,
        "printable_strings": strings[:100],
        "urls_found": urls[:50],
        "note": "These are indicators for manual review, not proof of a vulnerability."
    }
    save_report("firmware_analysis.json", report)

    print("\nFirmware Analysis")
    print("File:", path.name)
    print("Size:", len(data), "bytes")
    print("SHA-256:", sha256)
    print("Printable strings:", len(strings))
    print("URLs found:", len(urls))


def network(csv_file):
    with open(csv_file, newline="", encoding="utf-8") as file:
        observations = list(csv.DictReader(file))

    findings = []
    for row in observations:
        protocol = row.get("protocol", "").upper()
        port = row.get("port", "")
        if protocol == "HTTP" or port == "80":
            findings.append({
                "type": "Clear-text HTTP review",
                "source": row.get("source"),
                "destination": row.get("destination"),
                "port": port,
                "recommendation": "Check whether sensitive information is sent without encryption."
            })

    report = {
        "project": "IoT Device Penetration Testing Lab",
        "created": datetime.utcnow().isoformat() + "Z",
        "type": "Network Observation Review",
        "observations": len(observations),
        "findings": findings,
    }
    save_report("network_review.json", report)

    print("\nNetwork Observation Review")
    print("Observations:", len(observations))
    print("Items requiring review:", len(findings))


def main():
    parser = argparse.ArgumentParser(description="IoT security lab helper")
    sub = parser.add_subparsers(dest="command")

    p1 = sub.add_parser("inventory")
    p1.add_argument("csv_file")

    p2 = sub.add_parser("firmware")
    p2.add_argument("file")

    p3 = sub.add_parser("network")
    p3.add_argument("csv_file")

    args = parser.parse_args()

    if args.command == "inventory":
        inventory(args.csv_file)
    elif args.command == "firmware":
        firmware(args.file)
    elif args.command == "network":
        network(args.csv_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
