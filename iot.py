import socket

# List of common ports to scan
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-ALT'
}

# Vulnerable service versions (simplified example)
VULNERABLE_VERSIONS = {
    'OpenSSH': ['7.2p2', '7.6p1'],  # Example versions
    'Apache': ['2.4.18', '2.4.29'],
    'MySQL': ['5.5.35']
}

# Function to scan open ports on the target IP
def scan_ports(ip):
    open_ports = []
    print(f"Scanning {ip} for open ports...")
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# Function to detect services running on open ports
def detect_services(open_ports):
    detected_services = {}
    for port in open_ports:
        service = COMMON_PORTS.get(port, 'Unknown')
        detected_services[port] = service
    return detected_services

# Function to check if services are vulnerable
def check_vulnerabilities(services):
    vulnerable_services = []
    for port, service in services.items():
        if service in VULNERABLE_VERSIONS:
            vulnerable_services.append((port, service, VULNERABLE_VERSIONS[service]))
    return vulnerable_services

# Main function to perform the scan
def main():
    ip = input("Enter the IP address of the system to scan: ")
    
    # Scan for open ports
    open_ports = scan_ports(ip)
    
    # Detect services on open ports
    services = detect_services(open_ports)
    
    # Check for vulnerabilities in detected services
    vulnerabilities = check_vulnerabilities(services)
    
    print("\n--- Scan Results ---")
    
    if open_ports:
        print(f"Open ports found: {open_ports}")
        print("Detected services:")
        for port, service in services.items():
            print(f" - Port {port}: {service}")
    else:
        print("No open ports found.")
    
    if vulnerabilities:
        print("\nVulnerabilities in services:")
        for port, service, versions in vulnerabilities:
            print(f" - Port {port}: {service} (Vulnerable versions: {versions})")
    else:
        print("No vulnerabilities detected in services.")
    
    if not open_ports and not vulnerabilities:
        print("\nNo issues detected on the system.")

if __name__ == "__main__":
    main()
