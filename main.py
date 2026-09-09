import argparse
import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from scanner.ports import scan_ports
from core.headers import check_headers
from core.cve_checker import check_cves
from core.recon import perform_recon
from core.fingerprint import detect_tech_stack
from core.dns_lookup import get_dns_records
from core.subdomains import enumerate_subdomains
from core.recursive_scan import recursive_subdomain_scan
from utils import clean_url


def export_results(scan_data, domain):
    """
    Exports scan findings to JSON and HTML formats inside the exports/<domain>/ directory.
    """
    try:
        folder = os.path.join("exports", domain)
        os.makedirs(folder, exist_ok=True)

        timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # 1. Export JSON
        json_filename = f"{timestamp_str}.json"
        json_path = os.path.join(folder, json_filename)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4)
        print(f"[+] Exported JSON report to: {json_path}")

        # 2. Export HTML
        html_path = export_html_report(scan_data, domain, folder, timestamp_str)

        return json_path, html_path
    except Exception as e:
        print(f"[!] Export failed: {e}")
        return None, None


def export_html_report(scan_data, domain, folder, timestamp_str):
    """
    Renders report_template.html using Jinja2 and writes to an HTML file.
    """
    try:
        template_dir = os.path.dirname(os.path.abspath(__file__))
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")

        rendered_html = template.render(
            target=domain,
            scan_time=scan_data.get("metadata", {}).get("time", datetime.now().isoformat()),
            recon=scan_data.get("recon", {}),
            tech_stack=scan_data.get("tech_stack", []),
            dns_records=scan_data.get("recon", {}).get("dns_records", {}),
            subdomains=scan_data.get("subdomains", {})
        )

        html_filename = f"{timestamp_str}.html"
        html_path = os.path.join(folder, html_filename)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        print(f"[+] Exported HTML report to: {html_path}")
        return html_path
    except Exception as e:
        print(f"[!] HTML report generation failed: {e}")
        return None


def scan_single_host(host):
    """
    Scans ports, checks headers, and evaluates security advisories for a single host.
    """
    result = {"ports": [], "headers": {}, "cves": []}

    try:
        open_ports = scan_ports(host)
        print(f"[+] Open ports on {host}: {open_ports if open_ports else 'None detected'}")
        result["ports"] = open_ports
    except Exception as e:
        print(f"[!] Port scan failed for {host}: {e}")

    try:
        headers = check_headers(host)
        result["headers"] = headers
    except Exception as e:
        print(f"[!] Header check failed for {host}: {e}")

    try:
        cve_results = check_cves(result["headers"])
        if cve_results:
            print(f"[!] Security Advisories on {host}: {len(cve_results)} findings")
            for finding in cve_results:
                print(f"    - {finding}")
        result["cves"] = cve_results
    except Exception as e:
        print(f"[!] CVE check failed for {host}: {e}")

    return result


def display_banner():
    banner = r"""
 __      __   _       _  __
 \ \    / /  | |     | |/ /
  \ \  / /_ _| |_ __ | ' / 
   \ \/ / _` | | '_ \|  <  
    \  / (_| | | | | | . \ 
     \/ \__,_|_|_| |_|_|\_\
  VulnX - Recon & Vulnerability Scanner
"""
    print(banner)


def main():
    display_banner()
    parser = argparse.ArgumentParser(description="VulnX - Recon & Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Target domain/URL to scan (e.g., example.com)")
    group.add_argument("--resume", help="Path to JSON file to resume/inspect scan from")
    parser.add_argument(
        "--recursive",
        type=int,
        default=0,
        help="Recursive subdomain scan depth (default: 0)"
    )
    args = parser.parse_args()

    if args.resume:
        # Load and display previous scan data
        try:
            with open(args.resume, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            target = saved_data.get("metadata", {}).get("target", "Unknown")
            scan_time = saved_data.get("metadata", {}).get("time", "Unknown")
            print(f"[+] Loaded previous scan for: {target} (Scan Time: {scan_time})\n")

            subdomains_count = len(saved_data.get("subdomains", {}))
            print(f"[*] Total hosts in scan data: {subdomains_count}")
            
            # Re-generate HTML report from resumed data
            folder = os.path.dirname(args.resume)
            timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_resumed"
            export_html_report(saved_data, target, folder, timestamp_str)
            print("[+] Scan review and HTML re-export completed.")
            return
        except Exception as e:
            print(f"[!] Resume failed: {e}")
            return

    # Sanitize target input
    raw_target = args.target
    target = clean_url(raw_target)
    if not target:
        print(f"[!] Invalid target specified: {raw_target}")
        return

    print(f"[*] Starting security audit on target: {target}\n")

    scan_data = {
        "metadata": {
            "target": target,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }

    # 1. Reconnaissance (WHOIS + DNS)
    print("=" * 60)
    print("[1] Running Reconnaissance & DNS Records...")
    print("=" * 60)
    recon_info = {}
    try:
        recon_info = perform_recon(target)
    except Exception as e:
        print(f"[!] Recon failed: {e}")
        recon_info["error"] = str(e)

    try:
        dns_info = get_dns_records(target)
        recon_info['dns_records'] = dns_info
    except Exception as e:
        print(f"[!] Detailed DNS Lookup failed: {e}")
        recon_info['dns_records'] = f"Error: {e}"

    print(f"[+] WHOIS Status: {'Success' if 'error' not in recon_info.get('whois', {}) else 'Partial/Unavailable'}")
    scan_data["recon"] = recon_info

    # 2. Tech Stack Fingerprinting
    print("\n" + "=" * 60)
    print("[2] Tech Stack Fingerprinting...")
    print("=" * 60)
    try:
        tech_stack = detect_tech_stack(target)
        print("[+] Tech Stack detected:", tech_stack)
        scan_data["tech_stack"] = tech_stack
    except Exception as e:
        print(f"[!] Tech stack detection failed: {e}")
        scan_data["tech_stack"] = ["Detection failed"]

    # 3. Target Host & Subdomain Scanning
    print("\n" + "=" * 60)
    print("[3] Subdomain Enumeration & Host Scanning...")
    print("=" * 60)
    scan_data["subdomains"] = {}

    # Always scan the main target first
    print(f"\n[*] Scanning primary target host: {target}")
    scan_data["subdomains"][target] = scan_single_host(target)

    if args.recursive > 0:
        print(f"\n[*] Running recursive subdomain scan with depth {args.recursive}...")
        recursive_result = recursive_subdomain_scan(target, args.recursive)
        scan_data["subdomains"].update(recursive_result)
    else:
        subdomains = enumerate_subdomains(target)
        print(f"[+] Subdomains discovered: {len(subdomains)}")

        for sub in subdomains:
            if sub != target and sub not in scan_data["subdomains"]:
                print(f"\n[*] Scanning discovered host: {sub}")
                scan_data["subdomains"][sub] = scan_single_host(sub)

    # 4. Export results
    print("\n" + "=" * 60)
    print("[4] Generating Reports & Summary...")
    print("=" * 60)
    json_path, html_path = export_results(scan_data, target)
    if json_path:
        print(f"\n[i] You can review or re-render this scan later with:")
        print(f"python main.py --resume \"{json_path}\"")


if __name__ == "__main__":
    main()
