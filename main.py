import argparse
import os
import json
from datetime import datetime
from scanners.headers import check_headers
from scanners.cve_checker import check_cves
from scanners.ports import scan_ports
from core.recon import perform_recon
from core.fingerprint import detect_tech_stack
from core.dns_lookup import get_dns_records
from sublist3r import main as sublist3r_main


def export_results(scan_data, domain):
    try:
        folder = os.path.join("exports", domain)
        os.makedirs(folder, exist_ok=True)

        filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".json"
        path = os.path.join(folder, filename)

        with open(path, "w") as f:
            json.dump(scan_data, f, indent=4)

        print(f"[+] Exported to: {path}")
        return path
    except Exception as e:
        print(f"[!] Export failed: {e}")
        return None

def recursive_subdomain_scan(domain, depth, scanned=None):
    if depth <= 0:
        return {}

    if scanned is None:
        scanned = set()

    if domain in scanned:
        return {}

    print(f"[🔁] Recursive scan: {domain} (depth={depth})")
    scanned.add(domain)

    result = {domain: {}}

    try:
        open_ports = scan_ports(domain)
        headers = check_headers(domain)
        cves = check_cves(headers)
    except Exception as e:
        print(f"[!] Error scanning {domain}: {e}")
        open_ports, headers, cves = [], {}, []

    result[domain]["ports"] = open_ports
    result[domain]["headers"] = headers
    result[domain]["cves"] = cves

    subdomains = enumerate_subdomains(domain)
    result[domain]["subdomains"] = {}

    for sub in subdomains:
        if sub not in scanned:
            sub_result = recursive_subdomain_scan(sub, depth - 1, scanned)
            result[domain]["subdomains"].update(sub_result)

    return result


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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Target domain to scan")
    group.add_argument("--resume", help="Path to JSON file to resume scan from")
    parser.add_argument("--recursive",type=int,default=0,help="Recursive subdomain scan depth (default: 0)"
    )
    args = parser.parse_args()

    if args.resume:
        # Load previous data
        try:
            with open(args.resume, "r") as f:
                saved_data = json.load(f)
            target = saved_data["metadata"]["target"]
            print(f"[⏳] Resuming scan on: {target}\n")
            # Add resume logic here if needed later
        except Exception as e:
            print(f"[!] Resume failed: {e}")
            return
    else:
        target = args.target
        print(f"[*] Starting scan on: {target}\n")

        scan_data = {"metadata": {"target": target, "time": datetime.now().isoformat()}}

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
        scan_data["recon"] = recon_info

        # 2. Tech Stack
        try:
            tech_stack = detect_tech_stack(target)
            print("[+] Tech Stack:", tech_stack)
            scan_data["tech_stack"] = tech_stack
        except Exception as e:
            print(f"[!] Tech stack detection failed: {e}")
            scan_data["tech_stack"] = "Failed"

        # 3. Subdomain Enumeration
        from core.recursive_scan import recursive_subdomain_scan  # make sure this import is added

        # 3. Subdomain Enumeration with optional recursive scan
        scan_data["subdomains"] = {}

        if args.recursive > 0:
            print(f"[*] Running recursive scan with depth {args.recursive}")
            recursive_result = recursive_subdomain_scan(target, args.recursive)
            scan_data["subdomains"] = recursive_result
        else:
            subdomains = enumerate_subdomains(target)
            print("[+] Subdomains found:", subdomains)

            for sub in subdomains:
                print(f"\n[*] Scanning subdomain: {sub}")
                scan_data["subdomains"][sub] = {}

                try:
                    open_ports = scan_ports(sub)
                    print(f"[+] Open ports on {sub}: {open_ports}")
                    scan_data["subdomains"][sub]["ports"] = open_ports
                except Exception as e:
                    print(f"[!] Port scan failed: {e}")

                try:
                    headers = check_headers(sub)
                    print(f"[+] Headers for {sub}: {headers}")
                    scan_data["subdomains"][sub]["headers"] = headers
                except Exception as e:
                    print(f"[!] Header check failed: {e}")
                    headers = {}

                try:
                    cve_results = check_cves(headers)
                    print(f"[+] CVE Matches: {cve_results}")
                    scan_data["subdomains"][sub]["cves"] = cve_results
                except Exception as e:
                    print(f"[!] CVE check failed: {e}")

        # 5. Export results
        export_path = export_results(scan_data, target)
        if export_path:
            print(f"\n[💡] Resume later with:\npython main.py --resume {export_path}")

if __name__ == "__main__":
    main()
