"""Simple runner for the repository's lightweight tests without pytest.
This imports the test modules and runs exported test functions.
"""
import sys
import traceback
import os

# ensure repo root on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TESTS = [
    ('tests.test_analyzer_skip_host', 'test_skip_host_by_default'),
    ('tests.test_analyzer_baseline_similarity', 'test_baseline_and_similarity_and_sql_error_detection'),
]


def run_one(module_name, func_name):
    try:
        mod = __import__(module_name, fromlist=[func_name])
        func = getattr(mod, func_name)
        func()
        print(f'OK: {module_name}.{func_name}')
        return True
    except Exception:
        print(f'FAILED: {module_name}.{func_name}')
        traceback.print_exc()
        return False


def main():
    all_ok = True
    for mod, fn in TESTS:
        ok = run_one(mod, fn)
        all_ok = all_ok and ok
    if not all_ok:
        sys.exit(2)


if __name__ == '__main__':
    main()
