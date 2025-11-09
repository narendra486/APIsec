Reproduction helpers and report

I added scripts to help reproduce analyzer findings locally and an automated
workflow that uses a small mock server to emulate the recorded responses.

Files added:
- scripts/reproduce_findings.py  — replays requests recorded in artifacts/findings.json
- scripts/mock_server.py        — small local HTTP server that returns 302 /bank/main.jsp
- scripts/generate_repro_report.py — aggregate per-finding JSON into a text report
- scripts/run_full_repro.sh     — wrapper: start mock -> reproduce -> report -> stop mock

How to reproduce locally (no network required)
1. Ensure project venv exists and dev deps installed:
   make install
2. Run the full repro workflow (starts mock server, runs the replay, produces report):
   bash scripts/run_full_repro.sh
3. Report location:
   artifacts/repro/report.txt  (also JSON per-finding in artifacts/repro/ when generated)

Notes:
- To replay against a real target replace the host in artifacts/findings.json or set
  the MOCK_HOST env var (e.g. `MOCK_HOST=target.example.com:80 bash scripts/reproduce_findings.py`).
- Repro outputs are now ignored by git (.gitignore updated). If you want to keep them
  committed for CI or archival, remove `artifacts/repro/` from .gitignore and add them.
