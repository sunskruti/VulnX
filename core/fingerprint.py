import requests

def detect_tech_stack(domain):
    stack = []
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers
        server = headers.get('Server')
        powered_by = headers.get('X-Powered-By')
        if server:
            stack.append(f"Server: {server}")
        if powered_by:
            stack.append(f"X-Powered-By: {powered_by}")
    except Exception as e:
        stack.append(f"Tech detection failed: {e}")
    return stack
