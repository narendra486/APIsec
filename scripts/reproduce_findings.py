#!/usr/bin/env python3
"""Reproduce findings from artifacts/findings.json.

For each finding this script will replay the recorded HTTP request (method, url,
headers, data/json) with redirects disabled and save the full response or error
details to artifacts/repro/<index>_<sink>.json.

This is safe to run locally; network errors are captured and saved. Use the
project venv python to run: `bash scripts/run_in_venv.sh scripts/reproduce_findings.py`.
"""
import json
import os
import sys
from pathlib import Path

try:
    import requests
except Exception:
    print("requests not available in the current interpreter. Install dev deps into .venv and retry.")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "artifacts" / "findings.json"
OUTDIR = ROOT / "artifacts" / "repro"
OUTDIR.mkdir(parents=True, exist_ok=True)

def rewrite_url(url: str) -> str:
    """If MOCK_HOST is set, replace the hostname+port in the URL with the mock host.
    MOCK_HOST may be set as 'host:port' or 'http://host:port'."""
    mock = os.environ.get("MOCK_HOST") or os.environ.get("REPLAY_HOST")
    if not mock:
        return url
    # normalize mock to include scheme
    if not mock.startswith("http://") and not mock.startswith("https://"):
        mock = "http://" + mock
    try:
        from urllib.parse import urlparse, urlunparse

        parts = urlparse(url)
        mock_parts = urlparse(mock)
        new_parts = (mock_parts.scheme, mock_parts.netloc, parts.path, parts.params, parts.query, parts.fragment)
        return urlunparse(new_parts)
    except Exception:
        return url


def replay(req_spec):
    method = req_spec.get("method", "GET").upper()
    url = req_spec.get("url")
    url = rewrite_url(url)
    headers = req_spec.get("headers") or {}
    data = req_spec.get("data")
    json_body = req_spec.get("json")
    try:
        resp = requests.request(method, url, headers=headers, data=data, json=json_body, timeout=10, allow_redirects=False)
        result = {
            "ok": True,
            "status_code": resp.status_code,
            "reason": resp.reason,
            "headers": dict(resp.headers),
            "elapsed_seconds": resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else None,
            "body_text": resp.text,
        }
    except Exception as e:
        result = {"ok": False, "error": str(e)}
    return result


def main():
    if not FINDINGS.exists():
        print(f"Findings file not found: {FINDINGS}")
        sys.exit(1)

    with open(FINDINGS, "r", encoding="utf-8") as f:
        findings = json.load(f)

    summary = []
    for i, f in enumerate(findings, start=1):
        sink = f.get("sink", "unknown")
        req = f.get("request", {})
        outpath = OUTDIR / f"{i:02d}_{sink}.json"
        print(f"Replaying #{i} sink={sink} -> {req.get('method','GET')} {req.get('url')}")
        res = replay(req)
        payload = {
            "finding_index": i,
            "sink": sink,
            "payload": f.get("payload"),
            "request": req,
            "result": res,
        }
        with open(outpath, "w", encoding="utf-8") as out:
            json.dump(payload, out, indent=2, ensure_ascii=False)
        summary.append((i, sink, res))

    print("\nSummary of replay results:")
    for i, sink, res in summary:
        if res.get("ok"):
            print(f"#{i:02d} {sink}: {res['status_code']} {res.get('reason','')} (elapsed={res.get('elapsed_seconds')})")
        else:
            print(f"#{i:02d} {sink}: ERROR -> {res.get('error')}")


if __name__ == '__main__':
    main()
