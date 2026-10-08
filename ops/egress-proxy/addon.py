"""Bounded, redacted JSONL audit log for ARTEX's mitmproxy sidecar.

The callback always returns the original stream chunk. Logging failures are
isolated from forwarding so a full disk or malformed payload does not interrupt
LLM SSE streams or ordinary application traffic.
"""

import json
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler

from mitmproxy import http

BODY_LIMIT = max(0, int(os.getenv("ARTEX_EGRESS_BODY_LIMIT", "0")))
SSE_BODY_LIMIT = max(0, int(os.getenv("ARTEX_EGRESS_SSE_BODY_LIMIT", "4194304")))
SSE_EVENT_LIMIT = max(1024, int(os.getenv("ARTEX_EGRESS_SSE_EVENT_LIMIT", "65536")))
LOG_DIR = os.getenv("ARTEX_EGRESS_LOG_DIR", "/var/log/artex-egress")
SENSITIVE = re.compile(r"(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|token|secret|password|passwd)")
INLINE_SECRET = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}|((?:api[-_]?key|token|secret|password)\s*[:=]\s*[\"']?)[^\s,\"'}]{4,}")
OPENAI_TOKEN = re.compile(r"\b(?:sk|sess|key)-[A-Za-z0-9_-]{8,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----", re.DOTALL)

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


def _body(raw: bytes | None, limit: int = BODY_LIMIT):
    if not raw or limit == 0:
        return None
    chunk = raw[:limit]
    try:
        text = chunk.decode("utf-8")
        # Structured payloads get key-aware recursive redaction. The fallback
        # catches common credential syntax in SSE/plaintext without attempting
        # to guess or mutate the forwarded bytes.
        try:
            candidate = text
            if text.startswith("data:"):
                candidate = text[5:].strip()
            parsed = json.loads(candidate)

            def redact(value):
                if isinstance(value, dict):
                    return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [redact(item) for item in value]
                return value

            redacted = json.dumps(redact(parsed), ensure_ascii=False, separators=(",", ":"))
            text = ("data: " + redacted) if text.startswith("data:") else redacted
        except (ValueError, TypeError):
            text = INLINE_SECRET.sub(lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", text)
        text = OPENAI_TOKEN.sub("[REDACTED]", text)
        text = PRIVATE_KEY.sub("[PRIVATE KEY OMITTED]", text)
        return {"text": text, "truncated": len(raw) > len(chunk)}
    except UnicodeDecodeError:
        return {"binary_omitted": True, "length": len(raw), "truncated": len(raw) > len(chunk)}


def _sse_body(raw: bytes):
    """Parse one complete SSE event and redact its reconstructed data payload."""
    clipped = raw[:SSE_EVENT_LIMIT]
    try:
        text = clipped.decode("utf-8")
    except UnicodeDecodeError:
        return {"binary_omitted": True, "length": len(raw), "truncated": len(raw) > len(clipped)}

    fields = {"data": []}
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line or line.startswith(":"):
            continue
        key, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if key == "data":
            fields["data"].append(value)
        elif key in ("event", "id", "retry"):
            fields[key] = value

    data = "\n".join(fields["data"])
    redacted = _body(data.encode("utf-8"), SSE_EVENT_LIMIT)
    result = {key: value for key, value in fields.items() if key != "data"}
    result["data"] = redacted
    result["length"] = len(raw)
    result["truncated"] = len(raw) > len(clipped)
    return result


def _take_sse_events(buffer: bytes):
    """Return complete SSE events plus the incomplete tail, across TCP chunks."""
    events = []
    while True:
        lf = buffer.find(b"\n\n")
        crlf = buffer.find(b"\r\n\r\n")
        positions = [(lf, 2), (crlf, 4)]
        positions = [(pos, width) for pos, width in positions if pos >= 0]
        if not positions:
            return events, buffer
        pos, width = min(positions)
        events.append(buffer[:pos])
        buffer = buffer[pos + width:]


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
    flow.metadata["artex_sse_bytes"] = 0
    flow.metadata["artex_sse_captured"] = 0
    flow.metadata["artex_sse_buffer"] = b""
    flow.metadata["artex_sse_truncated"] = False

    def stream(chunk: bytes):
        if chunk:
            flow.metadata["artex_sse_bytes"] = flow.metadata.get("artex_sse_bytes", 0) + len(chunk)
            captured = flow.metadata.get("artex_sse_captured", 0)
            remaining = max(0, SSE_BODY_LIMIT - captured)
            accepted = chunk[:remaining]
            flow.metadata["artex_sse_captured"] = captured + len(accepted)
            if len(accepted) < len(chunk):
                flow.metadata["artex_sse_truncated"] = True
            buffer = flow.metadata.get("artex_sse_buffer", b"") + accepted
            events, buffer = _take_sse_events(buffer)
            flow.metadata["artex_sse_buffer"] = buffer
            for event_body in events:
                if event_body:
                    _write({"event": "sse_event", "id": flow.id, "body": _sse_body(event_body)})
        return chunk

    flow.response.stream = stream


def response(flow: http.HTTPFlow):
    if "text/event-stream" in flow.response.headers.get("content-type", "").lower():
        tail = flow.metadata.get("artex_sse_buffer", b"")
        if tail:
            _write({"event": "sse_event", "id": flow.id, "body": _sse_body(tail), "unterminated": True})
        _write({"event": "response_end", "id": flow.id, "sse": True,
                "bytes": flow.metadata.get("artex_sse_bytes", 0),
                "captured_bytes": flow.metadata.get("artex_sse_captured", 0),
                "truncated": flow.metadata.get("artex_sse_truncated", False)})
        return
    _write({"event": "response", "id": flow.id, "status": flow.response.status_code,
            "headers": _headers(flow.response.headers), "body": _body(flow.response.raw_content)})


def error(flow: http.HTTPFlow):
    _write({"event": "error", "id": flow.id, "error": str(flow.error)})
