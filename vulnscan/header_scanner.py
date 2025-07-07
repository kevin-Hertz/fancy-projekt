import os

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Cache-Control",
    "Pragma",
    "Expires"
]


def scan_headers(path):
    headers_path = os.path.join(path, "headers.conf")
    missing = []
    if not os.path.isfile(headers_path):
        print(f"[!] headers.conf not found at {headers_path}")
        return missing

    with open(headers_path, "r") as f:
        content = f.read().lower()

    for header in REQUIRED_HEADERS:
        if header.lower() not in content:
            missing.append(header)

    return missing