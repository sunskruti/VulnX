import requests

def check_headers(host):
    print(f"[*] Checking security headers for {host}")
    headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options"
    ]
    report = {}
    try:
        response = requests.get(f"http://{host}", timeout=5)
        for header in headers_to_check:
            if header in response.headers:
                report[header] = "Present"
            else:
                report[header] = "Missing"
    except Exception as e:
        print(f"[!] Failed to fetch headers: {e}")
    return report
