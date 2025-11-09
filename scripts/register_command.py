#!/usr/bin/env python3
"""
Register a shell command in .vscode/commands.json and optionally run it immediately.
Usage:
  python3 scripts/register_command.py "PYTHONPATH=. python3 scripts/run_unit_tests.py" --run
This will add the command to .vscode/commands.json if not present and run it if --run provided.
"""
import argparse
import json
import os
import subprocess
from typing import Dict, Any, List

ROOT = os.path.dirname(os.path.dirname(__file__))
CMD_FILE = os.path.join(ROOT, ".vscode", "commands.json")


def load_commands() -> Dict[str, Any]:
    try:
        with open(CMD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # normalize to object-list
            cmds = data.get("commands", [])
            normalized: List[Dict[str, Any]] = []
            for c in cmds:
                if isinstance(c, str):
                    normalized.append(
                        {"name": None, "command": c, "auto_run": False, "patterns": []}
                    )
                elif isinstance(c, dict):
                    normalized.append(
                        {
                            "name": c.get("name"),
                            "command": c.get("command"),
                            "auto_run": bool(c.get("auto_run", False)),
                            "patterns": (
                                list(c.get("patterns", [])) if c.get("patterns") is not None else []
                            ),
                        }
                    )
            return {"commands": normalized}
    except Exception:
        return {"commands": []}


def save_commands(data: Dict[str, Any]):
    os.makedirs(os.path.dirname(CMD_FILE), exist_ok=True)
    with open(CMD_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def register(
    command: str, name: str = None, auto_run: bool = True, patterns: List[str] = None
) -> bool:
    data = load_commands()
    cmds = data.get("commands", [])
    patterns = patterns or []
    # avoid duplicate by command string
    for c in cmds:
        if c.get("command") == command:
            print("Command already registered")
            return False
    entry = {"name": name, "command": command, "auto_run": bool(auto_run), "patterns": patterns}
    cmds.append(entry)
    data["commands"] = cmds
    save_commands(data)
    print("Registered command:", command)
    return True


def run_cmd(cmd: str, env=None) -> int:
    print("Running:", cmd)
    p = subprocess.Popen(cmd, shell=True, cwd=ROOT, env=env)
    p.communicate()
    return p.returncode


def _parse_patterns(s: str):
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("command", help="Command string to register (quote it)")
    ap.add_argument("--name", help="Optional name for the command")
    ap.add_argument(
        "--auto-run", action="store_true", help="Mark this command to auto-run on changes"
    )
    ap.add_argument(
        "--no-auto-run", action="store_true", help="Do not auto-run this command on changes"
    )
    ap.add_argument(
        "--patterns",
        help='Comma-separated glob patterns that trigger this command (e.g. "src/**,tests/**")',
    )
    ap.add_argument(
        "--run", action="store_true", help="Run the command immediately after registering"
    )
    args = ap.parse_args()

    # default behavior: auto-run new commands unless --no-auto-run is provided
    auto_run_final = (
        False if args.no_auto_run else True if args.auto_run or not args.no_auto_run else True
    )
    registered = register(
        args.command,
        name=args.name,
        auto_run=auto_run_final,
        patterns=_parse_patterns(args.patterns),
    )
    if args.run:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", ROOT)
        rc = run_cmd(args.command, env=env)
        raise SystemExit(rc)
