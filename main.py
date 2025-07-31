import argparse

from scanners.headers import check_headers
from scanners.cve_checker import check_cves
from scanners.ports import scan_ports
from core.recon import perform_recon
from core.fingerprint import detect_tech_stack
from core.dns_lookup import get_dns_records
from sublist3r import main as sublist3r_main


def enumerate_subdomains(domain):
    try:
        subdomains = sublist3r_main(
            domain,
            40,
            None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )
        return subdomains
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="VulnX - Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain to scan")
    args = parser.parse_args()
    target = args.target
    print(f"[*] Starting scan on: {target}\n")

    # 1. Recon
    recon_info = {}
    try:
        recon_info = perform_recon(target)
    except Exception as e:
        print(f"[!] Recon failed: {e}")

    try:
        dns_info = get_dns_records(target)
        recon_info['dns_records'] = dns_info
    except Exception as e:
        print(f"[!] DNS Lookup failed: {e}")
        recon_info['dns_records'] = "Error fetching DNS records"

    print("[+] Recon Info:", recon_info)

    # 2. Tech Stack
    try:
        tech_stack = detect_tech_stack(target)
        print("[+] Tech Stack:", tech_stack)
    except Exception as e:
        print(f"[!] Tech stack detection failed: {e}")

    # 3. Subdomain Enumeration
    subdomains = enumerate_subdomains(target)
    print("[+] Subdomains found:", subdomains)

    # 4. Scan each subdomain
    for sub in subdomains:
        print(f"\n[*] Scanning subdomain: {sub}")
        try:
            open_ports = scan_ports(sub)
            print(f"[+] Open ports on {sub}: {open_ports}")
        except Exception as e:
            print(f"[!] Port scan failed: {e}")

        try:
            headers = check_headers(sub)
            print(f"[+] Headers for {sub}: {headers}")
        except Exception as e:
            print(f"[!] Header check failed: {e}")
            headers = {}

        try:
            cve_results = check_cves(headers)
            print(f"[+] CVE Matches: {cve_results}")
        except Exception as e:
            print(f"[!] CVE check failed: {e}")


if __name__ == "__main__":
    main()
