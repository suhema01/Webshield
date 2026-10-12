class FlaskFixer:
    def __init__(self, app_path="vulnerable_app/app.py"):
        self.app_path = app_path

    def apply(self, target, findings):
        patch = '''
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
'''
        with open("reports/security_headers.patch", "w") as f:
            f.write(patch)
        print("[+] Patch written to reports/security_headers.patch")
        print("[!] Review and apply manually, or use the bundled fixed app.")
