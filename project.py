

import socket
import sys
from datetime import datetime



PORT_START = 20
PORT_END = 1024
TIMEOUT = 1

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS"
}



def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False



def detect_os(target_ip: str) -> str:
  
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target_ip, 80))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()

        if ttl <= 64:
            return "Linux / Unix (Likely)"
        elif ttl <= 128:
            return "Windows (Likely)"
        else:
            return "Network Device / Unknown"

    except:
        return "OS Detection Failed"



def scan_ports(target_ip: str) -> list:
    open_ports = []

    print(f"\n[+] Target: {target_ip}")
    print(f"[+] Scan started: {datetime.now()}\n")

    for port in range(PORT_START, PORT_END + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    open_ports.append(port)

        except:
            continue

    return open_ports



def grab_banner(target_ip: str, port: int) -> str:
    try:
        with socket.socket() as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((target_ip, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else "No banner"
    except:
        return "Banner not available"



def identify_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "Unknown")

def assess_risk(port: int) -> str:
    if port in (21, 23):
        return "High Risk"
    elif port in (22, 80):
        return "Medium Risk"
    else:
        return "Low Risk"



def generate_report(target_ip: str, open_ports: list):
    print("\n" + "=" * 55)
    print("        DEEP SECURITY SCAN REPORT")
    print("=" * 55)

    os_guess = detect_os(target_ip)
    print(f"Target OS Guess : {os_guess}")
    print("-" * 55)

    if not open_ports:
        print("No open ports detected.")
        return

    for port in open_ports:
        service = identify_service(port)
        risk = assess_risk(port)
        banner = grab_banner(target_ip, port)

        print(f"Port: {port}")
        print(f"  Service : {service}")
        print(f"  Risk    : {risk}")
        print(f"  Banner  : {banner}")
        print("-" * 55)

    print("\nSecurity Recommendations:")
    print("- Close unused ports")
    print("- Disable FTP/Telnet")
    print("- Patch outdated services")
    print("- Use firewall & IDS")



def main():
    target_ip = input("Enter target IP : ").strip()

    if not validate_ip(target_ip):
        print("[!] Invalid IP address.")
        sys.exit(1)

    open_ports = scan_ports(target_ip)
    generate_report(target_ip, open_ports)

if __name__ == "__main__":
    main()
