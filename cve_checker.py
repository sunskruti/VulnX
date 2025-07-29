def check_cves(headers):
    print("[*] Simulating CVE check from headers (demo)")
    # Fake CVE match based on missing headers
    cves = []
    if headers.get("Content-Security-Policy") == "Missing":
        cves.append("CVE-2021-XYZ1 - Missing CSP policy")
    if headers.get("Strict-Transport-Security") == "Missing":
        cves.append("CVE-2020-XYZ2 - Missing HSTS")
    return cves
