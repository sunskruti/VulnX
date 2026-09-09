import socket

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8000, 8080, 8443, 8888]

def scan_ports(host: str, ports: list = None, timeout: float = 0.8) -> list:
    """
    Scans common TCP ports on the target host.
    """
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
        except (socket.gaierror, socket.timeout, socket.error):
            pass
        finally:
            sock.close()

    return open_ports
