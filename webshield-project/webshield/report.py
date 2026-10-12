import json
from jinja2 import Template

def to_json(findings, path):
    data = [f.__dict__ for f in findings]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def to_html(findings, path):
    template = Template("""
    <html><head><title>WebShield Report</title></head><body>
    <h1>WebShield Report</h1>
    <table border="1">
    <tr><th>Name</th><th>Severity</th><th>URL</th><th>Remediation</th></tr>
    {% for f in findings %}
    <tr>
        <td>{{ f.name }}</td>
        <td>{{ f.severity }}</td>
        <td>{{ f.url }}</td>
        <td>{{ f.remediation }}</td>
    </tr>
    {% endfor %}
    </table>
    </body></html>
    """)
    with open(path, "w") as f:
        f.write(template.render(findings=findings))
