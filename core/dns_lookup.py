import dns.resolver

def get_dns_records(domain: str) -> dict:
    """
    Performs comprehensive DNS record lookups for common record types.
    """
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = "Non-existent domain (NXDOMAIN)"
        except Exception as e:
            records[rtype] = f"Lookup error: {e}"

    return records
