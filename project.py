import socket
from datetime import datetime


services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS"
}

def scan_ports(target):
    open_ports = []
    print("\nScanning target:", target)
    print("Scan started at:", datetime.now())

    for port in range(20, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports

def detect_service(port):
    return services.get(port, "Unknown Service")

def risk_level(port):
    if port in [21, 23]:
        return "High Risk"
    elif port in [22, 80]:
        return "Medium Risk"
    else:
        return "Low Risk"

def generate_report(open_ports):
    print("\n------ Security Assessment Report ------")
    if not open_ports:
        print("No open ports found.")
        return

    for port in open_ports:
        print(f"Port {port} | Service: {detect_service(port)} | Risk: {risk_level(port)}")

    print("\nRecommendations:")
    print("- Close unused ports")
    print("- Disable insecure services like FTP and Telnet")
    print("- Use firewall and strong passwords")


target_ip = input("Enter target IP : ")
ports_found = scan_ports(target_ip)
generate_report(ports_found)