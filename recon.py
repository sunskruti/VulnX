import whois
import dns.resolver
import requests

def perform_recon(domain):
    result = {}
    try:
        w = whois.whois(domain)
        result['whois'] = {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date),
        }
    except Exception as e:
        result['whois'] = f"WHOIS lookup failed: {e}"

    try:
        records = {}
        for record_type in ['A', 'MX', 'TXT']:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
        result['dns_records'] = records
    except Exception as e:
        result['dns_records'] = f"DNS lookup failed: {e}"

    return result
