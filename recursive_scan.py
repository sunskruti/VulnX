from scanners.ports import scan_ports
from scanners.headers import check_headers
from scanners.cve_checker import check_cves
from core.recon import perform_recon
from core.fingerprint import detect_tech_stack
from core.dns_lookup import get_dns_records
from main import enumerate_subdomains  # or refactor into a shared utils file

def recursive_subdomain_scan(domain, depth):
    result = {}

    def scan_recursive(domain, level):
        if level == 0:
            return

        subdomains = enumerate_subdomains(domain)
        for sub in subdomains:
            print(f"\n[*] Recursively scanning {sub} at depth {depth - level + 1}")
            result[sub] = {}

            try:
                open_ports = scan_ports(sub)
                print(f"[+] Open ports on {sub}: {open_ports}")
                result[sub]["ports"] = open_ports
            except Exception as e:
                print(f"[!] Port scan failed on {sub}: {e}")

            try:
                headers = check_headers(sub)
                print(f"[+] Headers for {sub}: {headers}")
                result[sub]["headers"] = headers
            except Exception as e:
                print(f"[!] Header check failed on {sub}: {e}")
                headers = {}

            try:
                cve_results = check_cves(headers)
                print(f"[+] CVE Matches on {sub}: {cve_results}")
                result[sub]["cves"] = cve_results
            except Exception as e:
                print(f"[!] CVE check failed on {sub}: {e}")

            # Recursive call on this subdomain
            scan_recursive(sub, level - 1)

    scan_recursive(domain, depth)
    return result
