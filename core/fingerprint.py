import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def detect_tech_stack(domain: str) -> list:
    """
    Fingerprints technologies, server software, frameworks, and reverse proxies.
    """
    stack = []
    res = None
    
    for proto in ["https", "http"]:
        try:
            res = requests.get(
                f"{proto}://{domain}",
                timeout=6,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnX-Scanner/1.0"}
            )
            break
        except Exception:
            continue

    if res is None:
        return ["Host unreachable on HTTP/HTTPS"]

    headers = res.headers

    # Server banner
    server = headers.get('Server')
    if server:
        stack.append(f"Server: {server}")

    # X-Powered-By
    powered_by = headers.get('X-Powered-By')
    if powered_by:
        stack.append(f"Framework: {powered_by}")

    # Cloudflare / WAF
    if 'cf-ray' in headers or 'cloudflare' in str(headers.get('Server', '')).lower():
        stack.append("CDN/WAF: Cloudflare")
    if 'x-amz-cf-id' in headers:
        stack.append("CDN: AWS CloudFront")
    if 'x-akamai-transformed' in headers:
        stack.append("CDN: Akamai")

    # Common cookies
    cookies = res.cookies.get_dict()
    if 'PHPSESSID' in cookies:
        stack.append("Backend: PHP")
    if 'JSESSIONID' in cookies:
        stack.append("Backend: Java / Tomcat")
    if 'csrftoken' in cookies:
        stack.append("Backend: Python (Django/Flask)")
    if 'laravel_session' in cookies:
        stack.append("Framework: Laravel (PHP)")

    if not stack:
        stack.append("Generic Web Server (No explicit technology banner disclosed)")

    return stack
