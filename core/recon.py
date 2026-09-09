import whois
import dns.resolver

def perform_recon(domain: str) -> dict:
    """
    Performs initial reconnaissance including WHOIS lookup and basic DNS records.
    """
    result = {}
    
    # 1. WHOIS Lookup
    try:
        w = whois.whois(domain)
        # Convert datetime or list objects to string for clean serialization
        result['whois'] = {
            'domain_name': str(w.domain_name) if w.domain_name else domain,
            'registrar': str(w.registrar) if w.registrar else "Unknown",
            'creation_date': str(w.creation_date) if w.creation_date else "Unknown",
            'expiration_date': str(w.expiration_date) if w.expiration_date else "Unknown",
            'emails': str(w.emails) if w.emails else "Hidden / Protected",
            'country': str(w.country) if w.country else "Unknown",
        }
    except Exception as e:
        result['whois'] = {"error": f"WHOIS lookup failed or timed out: {e}"}

    # 2. DNS Resolution
    try:
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0
        for record_type in ['A', 'MX', 'TXT', 'NS']:
            try:
                answers = resolver.resolve(domain, record_type)
                records[record_type] = [r.to_text() for r in answers]
            except Exception:
                records[record_type] = []
        result['dns_records'] = records
    except Exception as e:
        result['dns_records'] = {"error": f"DNS lookup failed: {e}"}

    return result
