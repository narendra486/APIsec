#!/usr/bin/env python3
"""
Watch `.vscode/commands.json` for changes and run `scripts/run_registered_commands.py` when it is modified.
This is intentionally dependency-free (no watchdog); it polls the file mtime. It's safe to run in a developer terminal.
"""
import os
import time
import subprocess
import json
import fnmatch
from typing import List, Dict, Any

ROOT = os.path.dirname(os.path.dirname(__file__))
CMD_FILE = os.path.join(ROOT, '.vscode', 'commands.json')
RUNNER = os.path.join(ROOT, 'scripts', 'run_registered_commands.py')

POLL_INTERVAL = 1.0  # seconds


def run_registered(commands: List[Dict[str, Any]] = None):
    """Run provided list of command entries (dicts with 'command'), or all registered."""
    env = os.environ.copy()
    env.setdefault('PYTHONPATH', ROOT)
    if not commands:
        # run all
        print('Running all registered commands...')
        rc = subprocess.call(f'PYTHONPATH=. python3 "{RUNNER}"', shell=True, cwd=ROOT, env=env)
        print('run_registered_commands.py exited with', rc)
        return rc

    # run only selected commands
    for entry in commands:
        cmd = entry.get('command') if isinstance(entry, dict) else entry
        print('\n--- Running registered command:')
        print(cmd)
        p = subprocess.Popen(cmd, shell=True, cwd=ROOT, env=env)
        rc = p.wait()
        print('Command exited with', rc)
        if rc != 0:
            return rc
    return 0


def latest_workspace_mtime(root: str, exclude_dirs=None) -> float:
    exclude_dirs = set(exclude_dirs or ['.git', '.venv', '__pycache__', 'artifacts', '.vscode'])
    latest = 0.0
    for dirpath, dirnames, filenames in os.walk(root):
        # skip excluded directories
        rel = os.path.relpath(dirpath, root)
        parts = rel.split(os.sep)
        if any(p in exclude_dirs for p in parts):
            continue
        for fn in filenames:
            try:
                fp = os.path.join(dirpath, fn)
                m = os.path.getmtime(fp)
                if m > latest:
                    latest = m
            except Exception:
                continue
    return latest


def _load_registered() -> List[Dict[str, Any]]:
    try:
        with open(CMD_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            cmds = data.get('commands', [])
            normalized: List[Dict[str, Any]] = []
            for c in cmds:
                if isinstance(c, str):
                    normalized.append({'name': None, 'command': c, 'auto_run': False, 'patterns': []})
                elif isinstance(c, dict):
                    normalized.append({
                        'name': c.get('name'),
                        'command': c.get('command'),
                        'auto_run': bool(c.get('auto_run', False)),
                        'patterns': list(c.get('patterns', [])) if c.get('patterns') is not None else []
                    })
            return normalized
    except Exception:
        return []


def _match_pattern(path: str, pattern: str) -> bool:
    # normalize to forward slashes
    p = path.replace(os.sep, '/')
    pat = pattern.replace(os.sep, '/')
    if not pat or pat in ('*', '**', '**/*'):
        return True
    # prefix match for patterns like 'src/**'
    if pat.endswith('/**') or pat.endswith('**'):
        prefix = pat.rstrip('*').rstrip('/')
        return p.startswith(prefix)
    return fnmatch.fnmatch(p, pat)


def main():
    if not os.path.exists(CMD_FILE):
        print('No', CMD_FILE, 'found. Create one via scripts/register_command.py')
        return

    # read commands.json to see if auto_run_all is requested
    try:
        with open(CMD_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    auto_all = bool(cfg.get('auto_run_all'))

    # initial mtimes
    if auto_all:
        print('auto_run_all enabled: watching workspace for any file changes')
        last_mtime = latest_workspace_mtime(ROOT)
    else:
        last_mtime = os.path.getmtime(CMD_FILE)
        print('Watching', CMD_FILE, 'for changes. Poll interval:', POLL_INTERVAL, 's')

    # state for coalescing and preventing overlapping runs
    is_running = False
    quiet_period = 1.0  # seconds to wait for burst coalescing

    try:
        while True:
            try:
                changed_files: List[str] = []
                if auto_all:
                    # detect files modified since last_mtime
                    new_mtime = latest_workspace_mtime(ROOT)
                    if new_mtime != last_mtime:
                        # collect files changed
                        for dirpath, dirnames, filenames in os.walk(ROOT):
                            rel = os.path.relpath(dirpath, ROOT)
                            if rel.startswith('.git') or rel.startswith('.venv') or rel.startswith('artifacts'):
                                continue
                            for fn in filenames:
                                fp = os.path.join(dirpath, fn)
                                try:
                                    if os.path.getmtime(fp) > last_mtime:
                                        changed_files.append(fp)
                                except Exception:
                                    continue
                        last_mtime = new_mtime
                else:
                    m = os.path.getmtime(CMD_FILE)
                    if m != last_mtime:
                        last_mtime = m
                        changed_files = [CMD_FILE]

                if changed_files:
                    # wait a quiet period to coalesce rapid changes
                    time.sleep(quiet_period)
                    # load registered commands and select those with auto_run true and matching patterns
                    registry = _load_registered()
                    to_run = []
                    for entry in registry:
                        if not entry.get('auto_run'):
                            continue
                        patterns = entry.get('patterns') or []
                        # if no patterns, treat as global
                        if not patterns:
                            to_run.append(entry)
                            continue
                        # if any changed file matches any pattern, schedule
                        for cf in changed_files:
                            rel = os.path.relpath(cf, ROOT)
                            for pat in patterns:
                                if _match_pattern(rel, pat):
                                    to_run.append(entry)
                                    raise_stop = True
                                    break
                            else:
                                raise_stop = False
                            if raise_stop:
                                break

                    # deduplicate by command
                    unique = {e.get('command'): e for e in to_run}.values()
                    if unique:
                        if is_running:
                            print('A run is already in progress; skipping this trigger')
                        else:
                            is_running = True
                            try:
                                run_registered(list(unique))
                            finally:
                                is_running = False
            except FileNotFoundError:
                print('commands.json removed; waiting for it to reappear...')
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print('\nWatcher stopped by user')


if __name__ == '__main__':
    main()
