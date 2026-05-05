"""
HEAVEN — Burp Suite Integration Export.

Generates a Burp-importable XML file from engagement findings. Each finding
becomes a request entry that Burp loads into the Site Map / Repeater for
manual exploitation.

Burp's native format is XML matching the Items export format
(File → Save items). Fields:

    <items>
        <item>
            <time>...</time>
            <url>https://target/path</url>
            <host ip="...">target</host>
            <port>443</port>
            <protocol>https</protocol>
            <method>POST</method>
            <path>/path</path>
            <extension>html</extension>
            <request base64="true">...</request>
            <status>200</status>
            <responselength>1234</responselength>
            <mimetype>HTML</mimetype>
            <response base64="true">...</response>
            <comment>HEAVEN finding ID: ...</comment>
        </item>
    </items>

When Burp Pro imports this it adds the requests to the Site Map and they're
immediately replayable in Repeater.
"""

from __future__ import annotations

import base64
import html
import urllib.parse
from datetime import datetime, timezone
from typing import Iterable


def _build_http_request(method: str, url: str, headers: dict, body: str) -> str:
    """Build a raw HTTP/1.1 request string suitable for Burp's <request> tag."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    lines = [f"{method.upper()} {path} HTTP/1.1"]
    # Host header is mandatory
    if "Host" not in headers and "host" not in headers:
        host = parsed.netloc
        if host:
            lines.append(f"Host: {host}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        if not any(k.lower() == "content-length" for k in headers):
            lines.append(f"Content-Length: {len(body.encode())}")
        if not any(k.lower() == "content-type" for k in headers):
            lines.append("Content-Type: application/x-www-form-urlencoded")
    lines.append("")  # blank line between headers and body
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def _build_http_response(status: int, headers: dict, body: str) -> str:
    """Build a raw HTTP/1.1 response string."""
    status_text = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway",
    }.get(status, "")
    lines = [f"HTTP/1.1 {status} {status_text}".rstrip()]
    body_bytes = body.encode() if body else b""
    if "Content-Length" not in headers and "content-length" not in headers:
        lines.append(f"Content-Length: {len(body_bytes)}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _xml_escape(s: str) -> str:
    return html.escape(str(s), quote=True)


def export_burp_xml(findings: Iterable[dict],
                    engagement_name: str = "HEAVEN") -> str:
    """
    Convert findings to a Burp Suite Items XML file.

    Each finding becomes one <item>. The request includes the actual probe
    HEAVEN sent, so the operator can load it into Repeater and re-fire
    immediately.
    """
    lines = [
        '<?xml version="1.0"?>',
        '<!DOCTYPE items [',
        '  <!ELEMENT items (item*)>',
        '  <!ATTLIST items burpVersion CDATA "">',
        '  <!ATTLIST items exportTime CDATA "">',
        ']>',
        f'<items burpVersion="HEAVEN-export" '
        f'exportTime="{datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Z %Y")}">',
    ]

    for f in findings:
        evidence = f.get("evidence", {}) or {}
        target = (f.get("target") or f.get("target_url")
                  or evidence.get("url") or "")
        if not target.startswith(("http://", "https://")):
            # Burp needs a full URL — skip findings without one (e.g. internal IPs)
            continue

        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        method = (f.get("method") or evidence.get("method") or "GET").upper()
        param = f.get("param") or evidence.get("param") or ""
        payload = evidence.get("payload", "") or f.get("payload", "")

        # Build request URL with payload attached
        request_url = target
        request_body = evidence.get("request_body", "")
        request_headers = dict(evidence.get("request_headers", {}) or {})
        if "User-Agent" not in request_headers:
            request_headers["User-Agent"] = "HEAVEN/Burp-export"

        if param and payload:
            if method == "GET":
                sep = "&" if "?" in target else "?"
                request_url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"
                parsed = urllib.parse.urlparse(request_url)
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
            else:
                if not request_body:
                    request_body = f"{param}={urllib.parse.quote(payload)}"

        raw_request = _build_http_request(method, request_url,
                                           request_headers, request_body)

        # Response data — best-effort from evidence
        status = int(evidence.get("status", 0) or 0)
        response_body = evidence.get("response_body", "") or evidence.get("response_excerpt", "")
        response_headers = evidence.get("response_headers", {}) or {}
        raw_response = _build_http_response(status, response_headers, response_body)
        response_length = len(response_body.encode()) if response_body else 0

        # Determine mimetype guess
        ct = (response_headers.get("Content-Type", "")
              or response_headers.get("content-type", "")).split(";")[0].strip()
        mimetype = "HTML"
        if "json" in ct.lower(): mimetype = "JSON"
        elif "xml" in ct.lower(): mimetype = "XML"
        elif "text" in ct.lower(): mimetype = "text"

        comment = (
            f"HEAVEN finding: {f.get('id', '')}  "
            f"type={f.get('vuln_type', '')}  "
            f"sev={f.get('severity', '')}  "
            f"conf={f.get('confidence', 0):.2f}  "
            f"status={f.get('status', 'open')}"
        )

        lines.extend([
            "  <item>",
            f"    <time>{_xml_escape(f.get('first_seen_at', ''))}</time>",
            f"    <url>{_xml_escape(request_url)}</url>",
            f'    <host ip="">{_xml_escape(host)}</host>',
            f"    <port>{port}</port>",
            f"    <protocol>{parsed.scheme or 'https'}</protocol>",
            f"    <method><![CDATA[{method}]]></method>",
            f"    <path><![CDATA[{path}]]></path>",
            f"    <extension>null</extension>",
            f'    <request base64="true"><![CDATA[{_b64(raw_request)}]]></request>',
            f"    <status>{status}</status>",
            f"    <responselength>{response_length}</responselength>",
            f"    <mimetype>{mimetype}</mimetype>",
            f'    <response base64="true"><![CDATA[{_b64(raw_response)}]]></response>',
            f"    <comment>{_xml_escape(comment)}</comment>",
            "  </item>",
        ])

    lines.append("</items>")
    return "\n".join(lines)


def export_proxy_history_jsonl(findings: Iterable[dict]) -> str:
    """
    Alternate format: JSONL with one finding per line, suitable for tools
    that prefer JSON over Burp's XML (mitmproxy, Caido, etc).
    """
    import json as _json
    out_lines = []
    for f in findings:
        evidence = f.get("evidence", {}) or {}
        target = f.get("target") or f.get("target_url") or ""
        method = (f.get("method") or evidence.get("method") or "GET").upper()
        param = f.get("param") or evidence.get("param") or ""
        payload = evidence.get("payload", "") or f.get("payload", "")

        request_url = target
        if param and payload and method == "GET":
            sep = "&" if "?" in target else "?"
            request_url = f"{target}{sep}{param}={urllib.parse.quote(payload)}"

        rec = {
            "finding_id": f.get("id", ""),
            "vuln_type": f.get("vuln_type", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", 0),
            "request": {
                "method": method,
                "url": request_url,
                "headers": evidence.get("request_headers", {}),
                "body": evidence.get("request_body", ""),
            },
            "response": {
                "status": evidence.get("status", 0),
                "headers": evidence.get("response_headers", {}),
                "body": evidence.get("response_body", "")[:8192],
            },
            "notes": f.get("operator_notes", ""),
        }
        out_lines.append(_json.dumps(rec))
    return "\n".join(out_lines) + "\n"
