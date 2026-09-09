import re
from urllib.parse import urlparse

def clean_url(url: str) -> str:
    """
    Cleans and extracts a valid domain/hostname from a raw URL or input string.
    Removes protocols (http/https), path fragments, query parameters, and port numbers.
    """
    if not url:
        return ""
    
    url = url.strip()
    
    # Prepend http:// if no protocol present so urlparse handles netloc properly
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
        
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]
        
    # Strip trailing slash or path remainders
    domain = domain.strip("/").strip()
    return domain.lower()
