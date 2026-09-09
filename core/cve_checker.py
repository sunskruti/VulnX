def check_cves(headers: dict) -> list:
    """
    Evaluates vulnerability advisories and security weaknesses based on header analysis and server fingerprinting.
    """
    findings = []
    
    if not isinstance(headers, dict) or not headers:
        return findings

    # 1. Missing Critical Security Headers
    if headers.get("Content-Security-Policy") == "Missing":
        findings.append("VULN-CSP-01: Content-Security-Policy header is missing (Prone to XSS/Data Injection).")
    
    if headers.get("Strict-Transport-Security") == "Missing":
        findings.append("VULN-HSTS-01: HTTP Strict Transport Security (HSTS) is missing (Susceptible to SSL stripping/MitM).")

    if headers.get("X-Frame-Options") == "Missing":
        findings.append("VULN-CLICKJACK-01: X-Frame-Options header is missing (Prone to Clickjacking).")

    if headers.get("X-Content-Type-Options") == "Missing":
        findings.append("VULN-MIME-01: X-Content-Type-Options header is missing (MIME sniffing risks).")

    # 2. Server Banner Information Disclosure
    server = headers.get("Server-Header") or headers.get("Server")
    if server:
        findings.append(f"INFO-LEAK-01: Server banner disclosure detected ({server}).")

    powered_by = headers.get("X-Powered-By-Header") or headers.get("X-Powered-By")
    if powered_by:
        findings.append(f"INFO-LEAK-02: X-Powered-By banner disclosure detected ({powered_by}).")

    return findings
