#!/usr/bin/env python3
"""
Run all commands listed in .vscode/commands.json sequentially. Exits non-zero if any command fails.
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(__file__))
CMD_FILE = os.path.join(ROOT, '.vscode', 'commands.json')


def load_commands():
    try:
        with open(CMD_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            cmds = data.get('commands', [])
            normalized = []
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


if __name__ == '__main__':
    cmds = load_commands()
    if not cmds:
        print('No commands registered in .vscode/commands.json')
        raise SystemExit(0)

    env = os.environ.copy()
    env.setdefault('PYTHONPATH', ROOT)

    for entry in cmds:
        cmd = entry.get('command') if isinstance(entry, dict) else entry
        print('\n--- Running registered command:')
        print(cmd)
        p = subprocess.Popen(cmd, shell=True, cwd=ROOT, env=env)
        rc = p.wait()
        if rc != 0:
            print(f'Command failed with exit code {rc}: {cmd}')
            raise SystemExit(rc)
    print('\nAll registered commands completed successfully')
