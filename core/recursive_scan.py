from scanner.ports import scan_ports
from core.headers import check_headers
from core.cve_checker import check_cves
from core.subdomains import enumerate_subdomains

def recursive_subdomain_scan(domain: str, depth: int, scanned: set = None) -> dict:
    """
    Recursively discovers subdomains and scans each discovered host up to the specified depth.
    """
    if depth <= 0:
        return {}

    if scanned is None:
        scanned = set()

    if domain in scanned:
        return {}

    scanned.add(domain)
    print(f"\n[+] Recursive Scan: {domain} (Depth remaining: {depth})")

    result = {domain: {}}

    # Port Scan
    try:
        open_ports = scan_ports(domain)
        print(f"[+] Open ports on {domain}: {open_ports}")
        result[domain]["ports"] = open_ports
    except Exception as e:
        print(f"[!] Port scan failed on {domain}: {e}")
        result[domain]["ports"] = []

    # Headers
    try:
        headers = check_headers(domain)
        result[domain]["headers"] = headers
    except Exception as e:
        print(f"[!] Header check failed on {domain}: {e}")
        headers = {}
        result[domain]["headers"] = {}

    # CVEs / Security Advisories
    try:
        cve_results = check_cves(headers)
        result[domain]["cves"] = cve_results
        if cve_results:
            print(f"[!] Security Advisories on {domain}: {len(cve_results)} findings")
    except Exception as e:
        print(f"[!] CVE check failed on {domain}: {e}")
        result[domain]["cves"] = []

    # Enumerate nested subdomains if depth allows
    result[domain]["subdomains"] = {}
    if depth > 1:
        subdomains = enumerate_subdomains(domain)
        for sub in subdomains:
            if sub not in scanned:
                sub_result = recursive_subdomain_scan(sub, depth - 1, scanned)
                result[domain]["subdomains"].update(sub_result)

    return result
