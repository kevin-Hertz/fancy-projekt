import os
import sys
import argparse

from cve_lookup import fake_cve_lookup, real_cve_lookup
from header_scanner import scan_headers
from report_generator import generate_markdown_report, generate_html_report

print("CWD:", os.getcwd())
print("sys.path:", sys.path)

USE_REAL_API = False
lookup = real_cve_lookup if USE_REAL_API else fake_cve_lookup

def parse_requirements(path):
    deps = []
    req_path = os.path.join(path, "requirements.txt")

    if not os.path.isfile(req_path):
        print(f"requirements.txt not found at {req_path}")
        return deps

    with open(req_path, 'r') as f:
        for line in f:
            line = line.strip()
            if '==' in line:
                package, version = line.split('==')
                deps.append((package.strip(), version.strip()))

    return deps

def scan_dependencies(path, lookup):
    deps = parse_requirements(path)
    findings = []

    for pkg, ver in deps:
        cves = lookup(pkg, ver)
        if cves:
            findings.append({
                "package": pkg,
                "version": ver,
                "cves": cves
            })

    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("--real", action="store_true", help="Use real CVE API lookup")
    args = parser.parse_args()

    lookup = real_cve_lookup if args.real else fake_cve_lookup

    results = scan_dependencies(".", lookup)
    print("\n[+] Vulnerabilities Found:")
    for item in results:
        print(f"- {item['package']}=={item['version']}")
        for cve in item["cves"]:
            print(f"  • {cve['id']}: {cve['description']}")

    missing_headers = scan_headers(".")
    if missing_headers:
        print("\n[!] Missing security headers:")
        for h in missing_headers:
            print(f" - {h}")
    else:
        print("\n[+] All security headers present.")

    md_report = generate_markdown_report(results)
    with open("scan_report.md", "w") as f:
        f.write(md_report)
    print("\n[+] Markdown report saved as scan_report.md")

    html_report = generate_html_report(results)
    with open("scan_report.html", "w") as f:
        f.write(html_report)
    print("[+] HTML report saved as scan_report.html")
