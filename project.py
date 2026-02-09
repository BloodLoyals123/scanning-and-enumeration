

import subprocess
import socket
import sys
from datetime import datetime



NMAP_ARGS = [
    "-sS",      
    "-sV",      
    "-O",       
    "-T4"       
]



def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def run_nmap_scan(target_ip: str) -> str:
 
    command = ["nmap"] + NMAP_ARGS + [target_ip]

    print(f"\n[+] Target      : {target_ip}")
    print(f"[+] Scan started: {datetime.now()}")
    print(f"[+] Command     : {' '.join(command)}\n")

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.stderr:
        print("[!] Nmap Errors:")
        print(result.stderr)

    return result.stdout


def parse_nmap_output(output: str):
    
    open_ports = []
    os_guesses = []

    for line in output.splitlines():
        
        if "/tcp" in line and "open" in line:
            open_ports.append(line.strip())

        
        if line.startswith("OS details") or line.startswith("Running:"):
            os_guesses.append(line.strip())

    return open_ports, os_guesses


def generate_report(target_ip: str, raw_output: str):
    open_ports, os_guesses = parse_nmap_output(raw_output)

    print("\n" + "=" * 65)
    print("            LEGIT NMAP SECURITY SCAN REPORT")
    print("=" * 65)

    print(f"Target IP : {target_ip}")
    print(f"Scan Time : {datetime.now()}")
    print("-" * 65)

    if os_guesses:
        print("OS Detection:")
        for os in os_guesses:
            print(f"  {os}")
    else:
        print("OS Detection: Not available")

    print("-" * 65)

    if not open_ports:
        print("No open TCP ports detected.")
    else:
        print("Open Ports & Services:")
        for port in open_ports:
            print(f"  {port}")

    print("-" * 65)
    print("Security Recommendations:")
    print("- Close unused ports")
    print("- Remove legacy services (FTP/Telnet)")
    print("- Patch exposed services")
    print("- Restrict access via firewall")
    print("- Monitor with IDS/IPS")

    print("=" * 65)


def main():
    print("  Authorized use only. Scanning without permission is illegal.\n")

    target_ip = input("Enter target IP : ").strip()

    if not validate_ip(target_ip):
        print("[!] Invalid IP address.")
        sys.exit(1)

    raw_output = run_nmap_scan(target_ip)
    generate_report(target_ip, raw_output)


if __name__ == "__main__":
    main()
