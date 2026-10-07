"""Bounded, redacted JSONL audit log for ARTEX's mitmproxy sidecar.

The callback always returns the original stream chunk. Logging failures are
isolated from forwarding so a full disk or malformed payload does not interrupt
LLM SSE streams or ordinary application traffic.
"""

import base64
import json
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler

from mitmproxy import http

BODY_LIMIT = max(0, int(os.getenv("ARTEX_EGRESS_BODY_LIMIT", "65536")))
LOG_DIR = os.getenv("ARTEX_EGRESS_LOG_DIR", "/var/log/artex-egress")
SENSITIVE = re.compile(r"(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|token|secret|password|passwd)")
INLINE_SECRET = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}|((?:api[-_]?key|token|secret|password)\s*[:=]\s*[\"']?)[^\s,\"'}]{4,}")

os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
os.umask(0o077)
logger = logging.getLogger("artex-egress")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "egress.jsonl"),
    maxBytes=max(1024 * 1024, int(os.getenv("ARTEX_EGRESS_LOG_BYTES", "52428800"))),
    backupCount=max(1, int(os.getenv("ARTEX_EGRESS_LOG_BACKUPS", "10"))),
    encoding="utf-8",
)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)
logger.propagate = False


def _headers(headers):
    return {k: "[REDACTED]" if SENSITIVE.search(k) else v for k, v in headers.items(multi=True)}


def _safe_url(flow: http.HTTPFlow) -> str:
    url = flow.request.url
    for key in list(flow.request.query.keys()):
        if SENSITIVE.search(key):
            value = flow.request.query[key]
            if value:
                url = url.replace(value, "[REDACTED]")
    return url


def _body(raw: bytes | None):
    if not raw or BODY_LIMIT == 0:
        return None
    chunk = raw[:BODY_LIMIT]
    try:
        text = chunk.decode("utf-8")
        # Structured payloads get key-aware recursive redaction. The fallback
        # catches common credential syntax in SSE/plaintext without attempting
        # to guess or mutate the forwarded bytes.
        try:
            parsed = json.loads(text)

            def redact(value):
                if isinstance(value, dict):
                    return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [redact(item) for item in value]
                return value

            text = json.dumps(redact(parsed), ensure_ascii=False, separators=(",", ":"))
        except (ValueError, TypeError):
            text = INLINE_SECRET.sub(lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", text)
        return {"text": text, "truncated": len(raw) > len(chunk)}
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(chunk).decode("ascii"), "truncated": len(raw) > len(chunk)}


def _write(event: dict):
    try:
        event["ts"] = time.time()
        logger.info(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        # Audit availability must not become request availability.
        pass


def request(flow: http.HTTPFlow):
    _write({
        "event": "request",
        "id": flow.id,
        "method": flow.request.method,
        "url": _safe_url(flow),
        "host": flow.request.pretty_host,
        "headers": _headers(flow.request.headers),
        "body": _body(flow.request.raw_content),
    })


def responseheaders(flow: http.HTTPFlow):
    content_type = flow.response.headers.get("content-type", "")
    if "text/event-stream" not in content_type.lower():
        return

    _write({"event": "response_headers", "id": flow.id, "status": flow.response.status_code,
            "headers": _headers(flow.response.headers), "sse": True})
    total = 0

    def stream(chunk: bytes):
        nonlocal total
        if chunk and total < BODY_LIMIT:
            keep = chunk[: BODY_LIMIT - total]
            total += len(keep)
            _write({"event": "response_chunk", "id": flow.id, "sse": True, "body": _body(keep),
                    "truncated": len(chunk) > len(keep)})
        return chunk

    flow.response.stream = stream


def response(flow: http.HTTPFlow):
    if "text/event-stream" in flow.response.headers.get("content-type", "").lower():
        _write({"event": "response_end", "id": flow.id, "sse": True})
        return
    _write({"event": "response", "id": flow.id, "status": flow.response.status_code,
            "headers": _headers(flow.response.headers), "body": _body(flow.response.raw_content)})


def error(flow: http.HTTPFlow):
    _write({"event": "error", "id": flow.id, "error": str(flow.error)})
