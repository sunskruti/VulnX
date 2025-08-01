import dns.resolver

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except Exception as e:
            records[rtype] = f"Error: {e}"

    return records
