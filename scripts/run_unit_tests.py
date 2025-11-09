"""Simple runner for the repository's lightweight tests without pytest.
This imports the test modules and runs exported test functions.
"""

import sys
import traceback
import os

# ensure repo root on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TESTS = [
    ("tests.test_analyzer_skip_host", "test_skip_host_by_default"),
    (
        "tests.test_analyzer_baseline_similarity",
        "test_baseline_and_similarity_and_sql_error_detection",
    ),
    ("tests.test_integration_analyzer", "test_execute_through_test_engine_skips_demo"),
    ("tests.test_integration_analyzer", "test_execute_through_test_engine_flow"),
    ("tests.test_analyzer_time_probe", "test_run_time_probe_detects_delay"),
    ("tests.test_analyzer_csrf", "test_csrf_presence_and_cookie_delta"),
    ("tests.test_content_type_mismatch", "test_content_type_mismatch_flags_html_in_json"),
    ("tests.test_sql_error_reflection", "test_sql_error_reflection_detects_payload_proximity"),
    ("tests.test_authorization_jwt", "test_authorization_header_and_jwt_tamper_detection"),
    ("tests.test_jwt_expanded", "test_jwt_expanded_variants_used_and_recorded"),
]


def run_one(module_name, func_name):
    try:
        mod = __import__(module_name, fromlist=[func_name])
        func = getattr(mod, func_name)
        func()
        print(f"OK: {module_name}.{func_name}")
        return True
    except Exception:
        print(f"FAILED: {module_name}.{func_name}")
        traceback.print_exc()
        return False


def main():
    all_ok = True
    for mod, fn in TESTS:
        ok = run_one(mod, fn)
        all_ok = all_ok and ok
    if not all_ok:
        sys.exit(2)


if __name__ == "__main__":
    main()
