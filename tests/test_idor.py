import unittest
from unittest.mock import patch, Mock
from src.mcp_orchestrator.analyzer import Analyzer


class TestIDOR(unittest.TestCase):
    @patch("src.mcp_orchestrator.analyzer.requests.Session")
    def test_run_idor_varied_responses(self, mock_session_cls):
        # setup analyzer with mocked session
        mock_session = Mock()
        mock_session_cls.return_value = mock_session

        # baseline text for comparison
        analyzer = Analyzer(base_url="http://example.com")
        analyzer.baseline_text = "<html><body>index</body></html>"

        # prepare responses for ids: 1 -> 200 with different body, 2 -> 404, 3 -> exception
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b"<html><body>different content</body></html>"

        resp2 = Mock()
        resp2.status_code = 404
        resp2.content = b"Not Found"

        def get_side_effect(url, timeout, proxies, verify):
            if url.endswith("/items/1"):
                return resp1
            if url.endswith("/items/2"):
                return resp2
            raise Exception("conn fail")

        mock_session.get.side_effect = get_side_effect

        findings = analyzer.run_idor("items/{id}", [1, 2, 3])
        self.assertEqual(len(findings), 3)
        f1, f2, f3 = findings
        # id 1: should be status 200 and suspicious True because body differs
        self.assertEqual(f1["id"], 1)
        self.assertEqual(f1["status"], 200)
        self.assertTrue(f1["suspicious"])
        # id 2: 404 should not be suspicious
        self.assertEqual(f2["status"], 404)
        self.assertFalse(f2["suspicious"])
        # id 3: should contain error
        self.assertIn("error", f3)


if __name__ == "__main__":
    unittest.main()
