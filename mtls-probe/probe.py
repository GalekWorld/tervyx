"""Minimal HTTPS client-certificate probe for staging validation."""

from __future__ import annotations

import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class ProbeHandler(BaseHTTPRequestHandler):
    server_version = "TervyxMTLSProbe/1.0"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path not in {"/health", "/internal/mtls-probe"}:
            self.send_error(404)
            return
        body = json.dumps({"status": "ok", "mtls": "client_certificate_verified"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Keep diagnostics useful without echoing headers or certificate data.
        print(f"mtls-probe: {self.address_string()} - {format % args}", flush=True)


def _required_file(variable: str) -> str:
    value = os.environ.get(variable, "")
    if not value:
        raise RuntimeError(f"{variable} must point to a mounted secret file")
    path = Path(value)
    if not path.is_file() or not os.access(path, os.R_OK):
        raise RuntimeError(f"{variable} is not a readable file")
    return str(path)


def main() -> None:
    ca_file = _required_file("MTLS_PROBE_CA_FILE")
    cert_file = _required_file("MTLS_PROBE_SERVER_CERT_FILE")
    key_file = _required_file("MTLS_PROBE_SERVER_KEY_FILE")
    port = int(os.environ.get("MTLS_PROBE_PORT", "8443"))
    if not 1 <= port <= 65535:
        raise RuntimeError("MTLS_PROBE_PORT must be between 1 and 65535")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # Container ingress is controlled by the platform network policy.
    server = ThreadingHTTPServer(("0.0.0.0", port), ProbeHandler)  # noqa: S104
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"mtls-probe listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
