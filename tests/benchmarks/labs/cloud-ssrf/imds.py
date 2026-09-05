"""Fake EC2 Instance Metadata Service (IMDS) for HEAVEN's cloud SSRF lab.

Serves the real IMDSv1 path layout on 169.254.169.254:80 with INERT placeholder
credentials (an obviously-fake AKIA... example key, never a real secret). It
exists only so a server-side-request-forgery in the sibling web app can reach
"instance metadata" the way it would in a real cloud VM — proving HEAVEN's
metadata-SSRF detection end to end. Read-only; nothing here grants any access.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE = "heaven-lab-role"
_DIR = "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nsecurity-groups\n"
_CREDS = (
    '{\n'
    '  "Code": "Success",\n'
    '  "Type": "AWS-HMAC",\n'
    '  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",\n'
    '  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
    '  "Token": "IQoJb3JpZ2luX2VjEXAMPLEINERTTOKEN"\n'
    '}\n'
)


class IMDS(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        p = self.path
        if p.rstrip("/") == "/latest/meta-data":
            body = _DIR
        elif p.rstrip("/") == "/latest/meta-data/iam/security-credentials":
            body = ROLE + "\n"
        elif p.rstrip("/").endswith(f"/security-credentials/{ROLE}"):
            body = _CREDS
        elif p.startswith("/latest/meta-data"):
            # Any other metadata key: echo the directory so an SSRF that reaches
            # us always sees recognisable instance-metadata indicators.
            body = _DIR
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 80), IMDS).serve_forever()
