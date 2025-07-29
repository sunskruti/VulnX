import socket

def scan_ports(host, port_range=(1, 1024)):
    print(f"[*] Scanning ports on {host}")
    open_ports = []

    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))

            if result == 0:
                open_ports.append(port)

            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port} on {host}: {e}")
            continue

    return open_ports

