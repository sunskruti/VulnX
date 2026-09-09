import requests
import urllib3

# Suppress insecure HTTPS warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(host: str) -> dict:
    """
    Inspects security headers for a given host (trying HTTPS first, then HTTP).
    """
    print(f"[*] Checking security headers for {host}")
    report = {}
    response = None
    
    # Try HTTPS first, then fallback to HTTP
    for proto in ["https", "http"]:
        try:
            url = f"{proto}://{host}"
            response = requests.get(url, timeout=6, verify=False, allow_redirects=True, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnX-Scanner/1.0"
            })
            break
        except Exception:
            continue

    if response is None:
        print(f"[!] Could not connect to {host} over HTTP/HTTPS.")
        for header in SECURITY_HEADERS:
            report[header] = "Unreachable"
        return report

    # Check security headers
    for header in SECURITY_HEADERS:
        val = response.headers.get(header)
        if val:
            report[header] = f"Present ({val[:80]}...)" if len(val) > 80 else f"Present ({val})"
        else:
            report[header] = "Missing"

    # Capture Server or X-Powered-By if present
    if "Server" in response.headers:
        report["Server-Header"] = response.headers["Server"]
    if "X-Powered-By" in response.headers:
        report["X-Powered-By-Header"] = response.headers["X-Powered-By"]

    return report
