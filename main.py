### main.py

import argparse
from scanners.subdomains import enumerate_subdomains
from scanners.ports import scan_ports
from scanners.headers import check_headers
from scanners.cve_checker import check_cves


def main():
    parser = argparse.ArgumentParser(description="VulnX - Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain to scan")
    args = parser.parse_args()

    target = args.target
    print(f"[*] Starting scan on: {target}\n")

    subdomains = enumerate_subdomains(target)
    print("[+] Subdomains found:", subdomains)

    for sub in subdomains:
        open_ports = scan_ports(sub)
        print(f"[+] Open ports on {sub}: {open_ports}")

        headers = check_headers(sub)
        print(f"[+] Headers for {sub}: {headers}")

        cve_results = check_cves(headers)
        print(f"[+] CVE Matches: {cve_results}\n")


if __name__ == "__main__":
    main()
