# scanners/subdomains.py

import requests

def enumerate_subdomains(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        subdomains = set()
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    for sub in name_value.split('\n'):
                        if domain in sub:
                            subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
        return []
