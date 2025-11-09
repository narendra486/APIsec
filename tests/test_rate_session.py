import unittest
from unittest.mock import patch, Mock
from src.mcp_orchestrator.analyzer import Analyzer


class TestRateAndSession(unittest.TestCase):
    @patch("src.mcp_orchestrator.analyzer.requests.Session")
    def test_run_rate_limit_detects_429(self, mock_session_cls):
        mock_session = Mock()
        mock_session_cls.return_value = mock_session

        analyzer = Analyzer(base_url="http://example.com")

        # make a sequence: first 5 -> 200, then 429, then 429
        resp_ok = Mock()
        resp_ok.status_code = 200
        resp_ok.headers = {}
        resp_429 = Mock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "5"}

        side = [resp_ok, resp_ok, resp_ok, resp_ok, resp_ok, resp_429, resp_429]

        def post_side_effect(target, data, timeout, proxies, verify):
            return side.pop(0)

        mock_session.post.side_effect = post_side_effect

        result = analyzer.run_rate_limit_test(
            url="http://example.com/login", attempts=7, interval=0
        )
        self.assertTrue(result["rate_limited"])
        self.assertEqual(result["retry_after"], "5")
        self.assertEqual(len(result["codes"]), 7)

    @patch("src.mcp_orchestrator.analyzer.requests.Session")
    def test_run_session_fixation_detects_acceptance(self, mock_session_cls):
        mock_session = Mock()
        mock_session_cls.return_value = mock_session

        analyzer = Analyzer(base_url="http://example.com/login")

        # session.cookies.get_dict should reflect acceptance of attacker cookie after post
        mock_session.cookies.get_dict.return_value = {"sessionid": "ATTACKER"}

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_session.post.return_value = mock_resp

        result = analyzer.run_session_fixation_test({"uid": "a", "passw": "b"})
        self.assertEqual(result["login_status"], 200)
        self.assertTrue(result["fixation_possible"])


if __name__ == "__main__":
    unittest.main()
