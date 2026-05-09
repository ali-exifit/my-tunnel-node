#!/usr/bin/env python3
"""
exit_node_server.py — Python equivalent of the TypeScript exit node.

Runs a threaded HTTP server on localhost:8181 that relays requests to
arbitrary https:// or http:// URLs.  Authentication is via a pre‑shared
key (PSK) given in the environment variable EXIT_NODE_PSK.

Usage:
  export EXIT_NODE_PSK="your-strong-secret"
  python vps_exit_node.py

The server only accepts POST requests with a JSON payload:
  { "k": "<PSK>", "u": "<target URL>", "m": "<method>", "h": {...},
    "b": "<base64 body>" }

It replies with a JSON envelope:
  { "s": <status>, "h": { ... }, "b": "<base64 response body>" }

A GET request to / returns a basic health check.
"""

import argparse
import base64
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("exit-node")

# ---------------------------------------------------------------------------
# Constants (matching the TypeScript STRIP_HEADERS exactly)
# ---------------------------------------------------------------------------
_STRIP_HEADERS = frozenset({
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "proxy-connection",
    "proxy-authorization",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "via",
})

# Maximum sizes to avoid memory exhaustion
_MAX_REQUEST_BODY = 32 * 1024 * 1024
_MAX_RESPONSE_BODY = 64 * 1024 * 1024
_OUTBOUND_TIMEOUT = 30

# Pre‑shared key loaded at startup
_PSK: str = ""

# ---------------------------------------------------------------------------
# HTTP client – no-redirect opener (matching redirect: "manual")
# ---------------------------------------------------------------------------
_NO_REDIRECT_OPENER = urllib.request.OpenerDirector()
for handler in (
    urllib.request.UnknownHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
):
    _NO_REDIRECT_OPENER.add_handler(handler)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_headers(raw: object) -> dict[str, str]:
    """Return a clean header dict, removing hop‑by‑hop and proxy headers."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not k or not isinstance(k, str):
            continue
        if k.lower() in _STRIP_HEADERS:
            continue
        out[k] = str(v) if v is not None else ""
    return out

def _is_loop(own_host: str, target_url: str) -> bool:
    """Return True if target_url points at the same host that received this request."""
    try:
        own = urlparse(f"//{own_host}")
        dst = urlparse(target_url)
        return own.hostname == dst.hostname
    except Exception:
        return False

def _collect_headers(raw_headers) -> dict:
    """Collect HTTP response headers, preserving all values for duplicate names."""
    out: dict = {}
    key_map: dict[str, str] = {}
    for k, v in raw_headers.items():
        kl = k.lower()
        if kl not in key_map:
            key_map[kl] = k
            out[k] = v
        else:
            canonical = key_map[kl]
            cur = out[canonical]
            if isinstance(cur, list):
                cur.append(v)
            else:
                out[canonical] = [cur, v]
    return out

def _relay_request(url: str, method: str, headers: dict[str, str], body: bytes) -> dict:
    """Perform the outbound request and return a relay‑JSON dict."""
    request = urllib.request.Request(url, method=method, headers=headers)
    if body:
        request.data = body

    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=_OUTBOUND_TIMEOUT) as resp:
            data = resp.read(_MAX_RESPONSE_BODY)
            return {
                "s": resp.status,
                "h": _collect_headers(resp.headers),
                "b": base64.b64encode(data).decode(),
            }
    except urllib.error.HTTPError as exc:
        data = exc.read(_MAX_RESPONSE_BODY) if exc.fp else b""
        return {
            "s": exc.code,
            "h": _collect_headers(exc.headers) if exc.headers else {},
            "b": base64.b64encode(data).decode(),
        }

# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _ExitNodeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(
            200,
            {
                "ok": True,
                "status": "healthy",
                "message": "VPS exit node is running (Python).",
                "usage": "Send POST with relay payload for actual proxy requests.",
            },
        )

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length") or 0)
        if content_length <= 0:
            self._send_json(400, {"e": "empty_body"})
            return
        if content_length > _MAX_REQUEST_BODY:
            self._send_json(413, {"e": "request_too_large"})
            return

        raw = self.rfile.read(content_length)
        try:
            body = json.loads(raw)
        except Exception:
            self._send_json(400, {"e": "bad_json"})
            return

        if not isinstance(body, dict):
            self._send_json(400, {"e": "bad_json"})
            return

        k = str(body.get("k") or "")
        u = str(body.get("u") or "")
        m = str(body.get("m") or "GET").upper()
        h = _sanitize_headers(body.get("h"))
        b64 = body.get("b")

        if not _PSK:
            self._send_json(500, {"e": "server_psk_missing"})
            return

        if k != _PSK:
            log.warning("Rejected unauthorized request from %s", self.client_address[0])
            self._send_json(401, {"e": "unauthorized"})
            return

        if not re.match(r"^https?://", u, re.IGNORECASE):
            self._send_json(400, {"e": "bad_url"})
            return

        # Loop guard
        own_host = self.headers.get("Host") or ""
        if _is_loop(own_host, u):
            log.warning("Loop refused: target %s is same host as this exit node", u)
            self._send_json(400, {"e": "exit-node loop refused"})
            return

        payload_bytes = b""
        if isinstance(b64, str) and b64:
            try:
                payload_bytes = base64.b64decode(b64)
            except Exception:
                self._send_json(400, {"e": "bad_base64"})
                return

        log.info("Relaying %s %s", m, u[:100])
        try:
            result = _relay_request(u, m, h, payload_bytes)
        except Exception as exc:
            log.warning("Relay error for %s: %s", u[:80], exc)
            self._send_json(500, {"e": str(exc) or type(exc).__name__})
            return

        log.info("Relay OK %s → HTTP %d (%d B)", u[:80], result["s"], len(result.get("b", "")))
        self._send_json(200, result)


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

def main() -> None:
    parser = argparse.ArgumentParser(description="Python exit node (TypeScript compatible)")
    parser.add_argument("--host", default="127.0.0.1", help="IP to listen on")
    parser.add_argument("--port", type=int, default=8181, help="TCP port")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    parser.add_argument("--psk", default="", help="Pre-shared key (overrides env)")
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    global _PSK
    _PSK = args.psk.strip() or os.environ.get("EXIT_NODE_PSK", "").strip()
    if not _PSK:
        log.error("No PSK configured. Pass --psk or set EXIT_NODE_PSK env var.")
        sys.exit(1)

    server = _ThreadedHTTPServer((args.host, args.port), _ExitNodeHandler)
    log.info("VPS exit node listening on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()

if __name__ == "__main__":
    main()
