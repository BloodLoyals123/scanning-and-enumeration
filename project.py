

import subprocess
import socket
import sys
import os
import json
import logging
from datetime import datetime

SCAN_PROFILES = {
    "basic": ["-sS", "-T4"],
    "service": ["-sS", "-sV", "-T4"],
    "full": ["-sS", "-sV", "-O", "-A", "-T4"],
    "vuln": ["-sS", "-sV", "--script=vuln", "-T4"]
}

REPORT_DIR = "reports"
LOG_FILE = "pentest.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)



def check_privileges():
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Run as root for SYN/OS scans.")
        sys.exit(1)


def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def run_nmap(target, profile):
    args = SCAN_PROFILES[profile]
    command = ["nmap"] + args + [target]

    logging.info(f"Running scan: {' '.join(command)}")

    print(f"\n[+] Target : {target}")
    print(f"[+] Profile: {profile}")
    print(f"[+] Started: {datetime.now()}\n")

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.stderr:
        logging.error(result.stderr)

    return result.stdout


def parse_output(output):
    ports = []
    os_info = []
    vulns = []

    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            ports.append(line.strip())

        if line.startswith("Running:") or line.startswith("OS details"):
            os_info.append(line.strip())

        if "VULNERABLE" in line or "CVE-" in line:
            vulns.append(line.strip())

    return {
        "ports": ports,
        "os": os_info,
        "vulnerabilities": vulns
    }


def save_report(target, profile, parsed, raw):
    os.makedirs(REPORT_DIR, exist_ok=True)

    report = {
        "target": target,
        "profile": profile,
        "scan_time": str(datetime.now()),
        "results": parsed
    }

    json_path = f"{REPORT_DIR}/{target}_{profile}.json"
    txt_path = f"{REPORT_DIR}/{target}_{profile}.txt"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=4)

    with open(txt_path, "w") as f:
        f.write(raw)

    print(f"[+] Reports saved:")
    print(f"    {json_path}")
    print(f"    {txt_path}")


def main():
 

    check_privileges()

    target = input("Target IP: ").strip()
    if not validate_ip(target):
        print("[!] Invalid IP")
        sys.exit(1)

    print("\nScan Profiles:")
    for p in SCAN_PROFILES:
        print(f" - {p}")

    profile = input("\nChoose profile: ").strip().lower()
    if profile not in SCAN_PROFILES:
        print("[!] Invalid profile")
        sys.exit(1)

    raw = run_nmap(target, profile)
    parsed = parse_output(raw)

    print("\n===== SCAN SUMMARY =====")
    print(f"Open Ports: {len(parsed['ports'])}")
    print(f"OS Info   : {'Yes' if parsed['os'] else 'No'}")
    print(f"Vulns     : {len(parsed['vulnerabilities'])}")

    save_report(target, profile, parsed, raw)


if __name__ == "__main__":
    main()
