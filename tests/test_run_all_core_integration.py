import unittest
from unittest.mock import patch
from src.mcp_orchestrator.analyzer import Analyzer


class TestRunAllCoreIntegration(unittest.TestCase):
    @patch.object(Analyzer, "run_idor")
    @patch.object(Analyzer, "run_rate_limit_test")
    @patch.object(Analyzer, "run_session_fixation_test")
    def test_run_all_collects_wrapped_findings(self, mock_sess, mock_rate, mock_idor):
        # setup mocks
        mock_idor.return_value = [
            {
                "id": 1,
                "url": "http://x/1",
                "status": 200,
                "suspicious": True,
                "body_sample": "ok",
                "analysis": {"possible_idor_exposure": True},
            }
        ]
        mock_rate.return_value = {
            "codes": [200, 429, 429],
            "rate_limited": True,
            "lockout_detected": True,
        }
        mock_sess.return_value = {
            "sessionid_after": "ATTACKER",
            "fixation_possible": True,
            "login_status": 200,
        }

        a = Analyzer("http://example.local/doLogin")
        vectors = [
            {"id": "v1", "payload": "p1", "idor_path": "/items/{id}", "idor_ids": [1]},
            {
                "id": "v2",
                "payload": "p2",
                "rate_limit": True,
                "rate_limit_url": "http://example.local/login",
                "rate_limit_attempts": 3,
            },
            {
                "id": "v3",
                "payload": "p3",
                "session_fixation": True,
                "login_data": {"uid": "u", "passw": "p"},
            },
        ]

        findings = a.run_all(vectors)
        # ensure wrapped idor, rate, and session entries are present
        ids = [f["vector_id"] for f in findings]
        self.assertIn("v1_idor", ids)
        self.assertIn("v2_rate", ids)
        self.assertIn("v3_session_fix", ids)


if __name__ == "__main__":
    unittest.main()
