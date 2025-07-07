def generate_markdown_report(findings):
    lines = ["# Vulnerability Report\n"]
    if not findings:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines)
    
    for item in findings:
        lines.append(f"## {item['package']}=={item['version']}\n")
        if item["cves"]:
            for cve in item["cves"]:
                lines.append(f"- **{cve['id']}**: {cve['description']}")
        else:
            lines.append("- No known vulnerabilities.")

    return "\n".join(lines)

def generate_html_report(findings):
    if not findings:
        return "<h1>Vulnerability Scan Report</h1><p>No vulnerabilities found.</p>"

    html = ["<h1>Vulnerability Scan Report</h1>"]
    for item in findings:
        html.append(f"<h2>Package: {item['package']}=={item['version']}</h2><ul>")
        for cve in item["cves"]:
            html.append(f"<li><strong>{cve['id']}</strong>: {cve['description']}</li>")
        html.append("</ul>")
    return "\n".join(html)