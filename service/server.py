"""A small read-only health endpoint used as the CI scan target."""

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info("received request with %d headers", len(self.headers))
        healthy = self.path == "/health"
        body = json.dumps({"status": "ok"} if healthy else {"error": "unknown path"}).encode()
        self.send_response(200 if healthy else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):
        logging.info("completed request with status %s", code)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    with ThreadingHTTPServer(("0.0.0.0", 8080), HealthHandler) as server:
        server.serve_forever()
