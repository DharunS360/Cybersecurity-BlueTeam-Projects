"""Alert ingestion. Turns real artefacts into a normalised Alert with traceable IOCs.

Supported inputs: .eml (phishing mail), .json / .jsonl (Wazuh, Sysmon exports, tool
output), .csv, and any plain-text log. No data is generated or fabricated here.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Iterator

from .ioc import Collector
from .models import Alert

_TITLE_KEYS = ("title", "rule_name", "alert_name", "name", "message", "description", "summary", "event")
_SEV_KEYS = ("severity", "level", "priority", "risk")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _walk(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield path, str(obj)


def _first(obj: Any, keys: tuple[str, ...]) -> str | None:
    if isinstance(obj, dict):
        for k in keys:
            for kk, v in obj.items():
                if kk.lower() == k and isinstance(v, (str, int)) and str(v).strip():
                    return str(v)[:200]
        for v in obj.values():
            r = _first(v, keys)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj[:5]:
            r = _first(v, keys)
            if r:
                return r
    return None


def _hints(rec: Any) -> dict[str, str]:
    """Pull well-known host/rule context from the first record (Wazuh, Sysmon/EVTX exports)."""
    if not isinstance(rec, dict):
        return {}
    out: dict[str, str] = {}
    agent, rule = rec.get("agent"), rec.get("rule")
    if isinstance(agent, dict) and agent.get("name"):
        out["agent"] = str(agent["name"])
    if isinstance(rule, dict):
        if rule.get("id"):
            out["rule_id"] = str(rule["id"])
        if rule.get("groups"):
            out["rule_groups"] = ",".join(map(str, rule["groups"]))[:120]
    for k in rec:
        if k.lower() in ("computer", "computername", "hostname", "host") and isinstance(rec[k], (str, int)):
            out.setdefault("agent", str(rec[k]))
    return out


def _finish(source: str, title: str, sha: str, col: Collector, meta: dict, severity: str | None = None) -> Alert:
    return Alert(source=source, title=title, input_sha256=sha, iocs=col.iocs,
                 skipped=col.skipped, meta=meta, severity=severity)


# -- parsers ------------------------------------------------------------------
def from_text(text: str, source: str = "text", title: str | None = None,
              allowlist: set[str] | None = None) -> Alert:
    col = Collector(allowlist)
    for n, line in enumerate(text.splitlines(), 1):
        col.scan(line, f"line {n}")
    return _finish(source, title or "Text / log input", sha256_bytes(text.encode("utf-8", "replace")), col,
                   {"lines": text.count("\n") + 1})


def from_json(raw: str, source: str, title: str | None, allowlist: set[str] | None) -> Alert:
    sha = sha256_bytes(raw.encode("utf-8", "replace"))
    try:
        data: Any = json.loads(raw)
        fmt = "json"
    except json.JSONDecodeError:
        rows = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))         # raises -> caller reports clear error
        data, fmt = rows, "jsonl"
    col = Collector(allowlist)
    for path, value in _walk(data):
        col.scan(value, path)
    sev = _first(data, _SEV_KEYS)
    meta: dict[str, Any] = {"format": fmt, "records": len(data) if isinstance(data, list) else 1}
    meta.update(_hints(data[0] if isinstance(data, list) and data else data))
    return _finish(source, title or _first(data, _TITLE_KEYS) or Path(source).name, sha, col, meta, sev)


def from_csv(raw: str, source: str, title: str | None, allowlist: set[str] | None) -> Alert:
    col = Collector(allowlist)
    reader = csv.reader(io.StringIO(raw))
    header: list[str] = []
    rows = 0
    for i, row in enumerate(reader):
        if i == 0:
            header = row
            continue
        rows += 1
        for j, cell in enumerate(row):
            col_name = header[j] if j < len(header) else f"col{j}"
            col.scan(cell, f"row {i}, {col_name}")
    return _finish(source, title or Path(source).name, sha256_bytes(raw.encode("utf-8", "replace")), col,
                   {"format": "csv", "rows": rows})


def from_eml(data: bytes, source: str, title: str | None, allowlist: set[str] | None) -> Alert:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    col = Collector(allowlist)
    for h in ("From", "Reply-To", "Return-Path", "Sender", "X-Originating-IP"):
        for v in msg.get_all(h, []):
            col.scan(str(v), f"header:{h}")
    for i, v in enumerate(msg.get_all("Received", []), 1):
        col.scan(str(v), f"header:Received[{i}]")

    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                col.scan(part.get_content(), f"body:{part.get_content_type()}")
            except (LookupError, UnicodeDecodeError):
                continue

    attachments = []
    for att in msg.iter_attachments():
        payload = att.get_payload(decode=True) or b""
        name = att.get_filename() or "(unnamed)"
        sha = sha256_bytes(payload)
        col.add_hash(sha, f"attachment:{name}")
        attachments.append({"filename": name, "size": len(payload), "sha256": sha,
                            "content_type": att.get_content_type()})

    auth: dict[str, str] = {}
    for header_value in msg.get_all("Authentication-Results", []):
        for mechanism, result in _AUTH_RE.findall(str(header_value)):
            auth.setdefault(mechanism.lower(), result.lower())
    meta = {"format": "eml", "from": str(msg.get("From", "")), "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")), "auth_results": auth, "attachments": attachments}
    return _finish(source, f"Email: {meta['subject'] or '(no subject)'}", sha256_bytes(data), col, meta)


# -- public entry points ------------------------------------------------------
def load_alert(path: str | Path, allowlist: set[str] | None = None, title: str | None = None) -> Alert:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"input file not found: {p}")
    data = p.read_bytes()
    ext = p.suffix.lower()
    if ext == ".eml":
        return from_eml(data, p.name, title, allowlist)
    text = data.decode("utf-8-sig", errors="replace")
    if ext in (".json", ".jsonl", ".ndjson"):
        try:
            return from_json(text, p.name, title, allowlist)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{p.name} is not valid JSON/JSONL: {exc}") from None
    if ext == ".csv":
        return from_csv(text, p.name, title, allowlist)
    return from_text(text, p.name, title or p.name, allowlist)


def from_indicators(values: list[str], allowlist: set[str] | None = None) -> Alert:
    alert = from_text("\n".join(values), source="manual", title="Manual indicator lookup", allowlist=allowlist)
    for ioc in alert.iocs:
        ioc.sources = ["manual"]
    return alert