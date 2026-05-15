#!/usr/bin/env python3
"""
rust-exit-node.py — Python re‑implementation of MHR-CFW Exit Worker.
Now with proper response decompression (gzip, deflate, brotli).
"""

import argparse
import base64
import concurrent.futures
import gzip
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import urllib.error
import urllib.request
import zlib

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("exit-worker")

# ---------------------------------------------------------------------------
# Constants (kept in sync with the Cloudflare Worker)
# ---------------------------------------------------------------------------
DEFAULT_PSK = "CHANGE_ME_TO_A_STRONG_SECRET"

HEADER_RELAY_HOP = "x-relay-hop"

# Hop‑by‑hop headers stripped from the upstream request.
STRIP_REQUEST_HEADERS = frozenset(
    h.lower()
    for h in (
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        "priority",
        "te",
        # Prevent compression so we don't have to decompress (still handled
        # below as defence‑in‑depth).
        "accept-encoding",
    )
)

MAX_BATCH_SIZE = 40          # must match WORKER_BATCH_CHUNK in Code.cfw.gs
OUTBOUND_TIMEOUT = 30        # seconds per fetch
MAX_RESPONSE_BODY = 64 * 1024 * 1024   # 64 MiB

# ---------------------------------------------------------------------------
# Optional brotli support (install with: pip install brotli)
# ---------------------------------------------------------------------------
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False
    log.info("brotli not installed – brotli responses will not be decompressed")

# ---------------------------------------------------------------------------
# Global PSK
# ---------------------------------------------------------------------------
PSK = ""

# ---------------------------------------------------------------------------
# Outbound HTTP client
# ---------------------------------------------------------------------------
def _build_no_redirect_opener():
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    return opener

_no_redirect_opener = _build_no_redirect_opener()
_default_opener = urllib.request.build_opener()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clean_headers(raw):
    """Return a dict without hop‑by‑hop headers."""
    if not isinstance(raw, dict):
        return {}
    clean = {}
    for k, v in raw.items():
        if isinstance(k, str) and k.lower() not in STRIP_REQUEST_HEADERS:
            clean[k] = str(v) if v is not None else ""
    return clean


def _decompress_body(data: bytes, content_encoding: str) -> bytes:
    """
    Decompress the response body according to the Content-Encoding header.
    Returns the decompressed bytes, or the original data if unsupported.
    """
    enc = content_encoding.lower().strip()
    if not enc or enc == "identity":
        return data
    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(data)
        if enc == "deflate":
            # Try raw deflate first, then zlib-wrapped.
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                return zlib.decompress(data)
        if enc == "br" and HAS_BROTLI:
            return brotli.decompress(data)
    except Exception as e:
        log.warning("Decompression failed for %s: %s", enc, e)
    # Fallback: return compressed data unchanged (client may handle it)
    return data


def _fetch_with_redirect_policy(method: str, url: str, headers: dict,
                                body: bytes | None, follow_redirects: bool):
    """Perform the outbound request, returning (status, resp_headers, bytes)."""
    req = urllib.request.Request(url, method=method, headers=headers, data=body)
    opener = _default_opener if follow_redirects else _no_redirect_opener

    try:
        with opener.open(req, timeout=OUTBOUND_TIMEOUT) as resp:
            raw_data = resp.read(MAX_RESPONSE_BODY)
            # Save original headers before stripping
            raw_headers = dict(resp.headers)
            content_encoding = raw_headers.get("Content-Encoding", "")
            # Decompress the body
            decoded_data = _decompress_body(raw_data, content_encoding)
            # Build final response headers, stripping content‑encoding & content‑length
            clean_headers = {}
            key_map = {}
            for k, v in raw_headers.items():
                kl = k.lower()
                if kl in ("content-encoding", "content-length"):
                    continue
                if kl not in key_map:
                    key_map[kl] = k
                    clean_headers[k] = v
                else:
                    existing = clean_headers[key_map[kl]]
                    if isinstance(existing, list):
                        existing.append(v)
                    else:
                        clean_headers[key_map[kl]] = [existing, v]
            return resp.status, clean_headers, decoded_data
    except urllib.error.HTTPError as exc:
        raw_data = exc.read(MAX_RESPONSE_BODY) if exc.fp else b""
        raw_headers = dict(exc.headers) if exc.headers else {}
        content_encoding = raw_headers.get("Content-Encoding", "")
        decoded_data = _decompress_body(raw_data, content_encoding)
        clean_headers = {}
        for k, v in raw_headers.items():
            kl = k.lower()
            if kl in ("content-encoding", "content-length"):
                continue
            clean_headers[k] = v
        return exc.code, clean_headers, decoded_data


def _process_one(item: dict, self_host: str) -> dict:
    """Process a single item, mirroring the Worker's processOne()."""
    if not isinstance(item, dict):
        return {"e": "bad item"}
    u = item.get("u")
    if not u or not isinstance(u, str) or not re.match(r"^https?://", u, re.IGNORECASE):
        return {"e": "bad url"}

    try:
        target_url = urllib.request.urlparse(u)
        target_host = target_url.hostname or ""
    except Exception:
        return {"e": "bad url"}

    if target_host.lower() == self_host.lower():
        return {"e": "self-fetch blocked"}

    headers = {}
    if "h" in item and isinstance(item["h"], dict):
        for k, v in item["h"].items():
            if k.lower() in STRIP_REQUEST_HEADERS:
                continue
            headers[k] = str(v)
    headers[HEADER_RELAY_HOP] = "1"

    method = str(item.get("m", "GET")).upper()
    follow_redirects = item.get("r") is not False

    body_bytes = None
    if method not in ("GET", "HEAD"):
        b64 = item.get("b")
        if isinstance(b64, str) and b64:
            try:
                body_bytes = base64.b64decode(b64)
            except Exception:
                return {"e": "bad body base64"}
            if "ct" in item and item["ct"] and "content-type" not in {
                    k.lower() for k in headers
            }:
                headers["content-type"] = str(item["ct"])

    try:
        status, resp_headers, data = _fetch_with_redirect_policy(
            method, u, headers, body_bytes, follow_redirects
        )
    except Exception as err:
        return {"e": "fetch failed: " + str(err)}

    b64_body = base64.b64encode(data).decode("ascii")

    return {
        "s": status,
        "h": resp_headers,
        "b": b64_body,
    }


def _process_batch(items: list, self_host: str) -> list:
    """Process a list of items in parallel."""
    if not items:
        return []
    if len(items) > MAX_BATCH_SIZE:
        raise ValueError(f"batch too large ({len(items)} > {MAX_BATCH_SIZE})")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(_process_one, item, self_host) for item in items]
        results = []
        for f in futures:
            try:
                results.append(f.result())
            except Exception as exc:
                results.append({"e": "fetch failed: " + str(exc)})
        return results


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------
class ExitWorkerHandler(http.server.BaseHTTPRequestHandler):
    """Handles POST relay requests; GET returns health status."""

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
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
                "message": "mhrv-rs Cloudflare Worker relay (Python)",
                "usage": "POST JSON with single or batch relay payload.",
            },
        )

    def do_POST(self):
        if self.command != "POST":
            self._send_json(405, {"e": "method not allowed"})
            return

        if self.headers.get(HEADER_RELAY_HOP) == "1":
            self._send_json(508, {"e": "loop detected"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send_json(400, {"e": "empty body"})
            return
        raw = self.rfile.read(content_length)
        try:
            body = json.loads(raw)
        except Exception:
            self._send_json(400, {"e": "bad json"})
            return

        if not isinstance(body, dict) or body.get("k") != PSK:
            log.warning("Unauthorized request from %s", self.client_address[0])
            self._send_json(401, {"e": "unauthorized"})
            return

        host_header = self.headers.get("Host", "")
        self_host = host_header.split(":")[0]

        if "q" in body and isinstance(body.get("q"), list):
            batch = body["q"]
            if len(batch) > MAX_BATCH_SIZE:
                self._send_json(
                    400,
                    {"e": f"batch too large ({len(batch)} > {MAX_BATCH_SIZE})"},
                )
                return
            results = _process_batch(batch, self_host)
            self._send_json(200, {"q": results})
            return

        result = _process_one(body, self_host)
        if "e" in result:
            self._send_json(400, result)
        else:
            self._send_json(200, result)


# ---------------------------------------------------------------------------
# Threaded HTTP server
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="mhrv-rs exit Worker relay (Python)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen interface (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8181, help="Listen port (default 8181)")
    parser.add_argument("--psk", default="", help="Pre‑shared key (or set TUNNEL_AUTH_KEY env var)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    global PSK
    PSK = (args.psk or os.environ.get("TUNNEL_AUTH_KEY", "")).strip()
    if not PSK:
        log.error("No PSK configured. Use --psk or TUNNEL_AUTH_KEY env var.")
        sys.exit(1)
    if PSK == DEFAULT_PSK:
        log.error("Placeholder PSK detected. Set a strong secret before running.")
        sys.exit(1)

    server = ThreadedHTTPServer((args.host, args.port), ExitWorkerHandler)
    log.info("Exit Worker listening on %s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
