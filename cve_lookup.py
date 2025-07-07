import requests

def real_cve_lookup(package, version):
    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {
                    "name": package,
                    "ecosystem": "PyPI"
                },
                "version": version
            },
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        vulnerabilities = []

        for vuln in data.get("vulns", []):
            vulnerabilities.append({
                "id": vuln.get("id"),
                "description": vuln.get("details", "").strip().replace("\n", " ")
            })

        return vulnerabilities

    except Exception as e:
        print(f"[!] Error looking up {package}=={version}: {e}")
        return []

def fake_cve_lookup(package, version):
    if package.lower() == "requests" and version == "2.18.0":
        return [
            {
                "id": "CVE-2018-18074",
                "description": "Requests 2.18.0 has an open redirect vulnerability."
            }
        ]
    return []