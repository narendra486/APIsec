#!/usr/bin/env python3
"""Aggregate per-finding repro JSON files into a single human-readable report.

Writes `artifacts/repro/report.txt` with one section per finding showing request
details and the response or error.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPRO_DIR = ROOT / "artifacts" / "repro"
OUT_FILE = REPRO_DIR / "report.txt"

files = sorted(REPRO_DIR.glob("*.json"))
if not files:
    print("No repro files found in", REPRO_DIR)
    raise SystemExit(1)

lines = []
for p in files:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        lines.append(f"--- {p.name} (invalid json: {e})\n")
        continue
    idx = data.get("finding_index")
    sink = data.get("sink")
    payload = data.get("payload")
    req = data.get("request", {})
    res = data.get("result", {})
    lines.append("=" * 60)
    lines.append(f"Finding #{idx:02d} — sink={sink}")
    lines.append(f"Payload: {payload}")
    lines.append("-- Request --")
    lines.append(f"{req.get('method','GET')} {req.get('url')}")
    headers = req.get('headers') or {}
    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    if req.get('data'):
        lines.append(f"Form data: {req.get('data')}")
    if req.get('json'):
        lines.append(f"JSON body: {req.get('json')}")
    lines.append("-- Result --")
    if res.get('ok'):
        lines.append(f"Status: {res.get('status_code')} {res.get('reason')}")
        lines.append("Response headers:")
        for k, v in (res.get('headers') or {}).items():
            lines.append(f"  {k}: {v}")
        body = res.get('body_text') or ''
        if body:
            lines.append("Response body (first 1024 chars):")
            lines.append(body[:1024])
        else:
            lines.append("Response body: <empty>")
    else:
        lines.append(f"Error: {res.get('error')}")
    lines.append("")

OUT_FILE.write_text("\n".join(lines), encoding="utf-8")
print("Wrote report:", OUT_FILE)
print(OUT_FILE.read_text(encoding="utf-8"))
