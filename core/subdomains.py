import requests

def enumerate_subdomains(domain: str) -> list:
    """
    Enumerates subdomains using crt.sh Certificate Transparency logs.
    """
    print(f"[*] Enumerating subdomains for: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnX-Scanner/1.0"
    }
    
    subdomains = set()
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value')
                    if name_value:
                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            # Strip wildcards
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and domain in sub and not sub.startswith("."):
                                subdomains.add(sub)
            except Exception as e:
                print(f"[!] Warning: Could not parse crt.sh JSON response: {e}")
        else:
            print(f"[!] crt.sh returned HTTP {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Subdomain enumeration network error: {e}")
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")

    # Always ensure the root domain is not the only thing unless no subdomains found
    found = sorted(subdomains)
    print(f"[+] Found {len(found)} subdomains.")
    return found
