import unittest
from unittest.mock import patch, Mock
from src.mcp_orchestrator.analyzer import Analyzer


class TestIDORDeep(unittest.TestCase):
    @patch("src.mcp_orchestrator.analyzer.requests.Session")
    def test_run_idor_value_diffs(self, mock_session_cls):
        mock_session = Mock()
        mock_session_cls.return_value = mock_session

        # prepare responses for ids 1,2,3 with JSON bodies
        resp1 = Mock()
        resp1.status_code = 200
        resp1.content = b'{"id":1,"name":"Alice","email":"alice@example.com"}'
        resp2 = Mock()
        resp2.status_code = 200
        resp2.content = b'{"id":2,"name":"Bob","email":"bob@example.com","admin":true}'
        resp3 = Mock()
        resp3.status_code = 200
        resp3.content = b'{"id":3,"name":"Charlie","email":"charlie@example.com"}'

        def get_side(url, timeout, proxies, verify):
            if url.endswith("/items/1"):
                return resp1
            if url.endswith("/items/2"):
                return resp2
            if url.endswith("/items/3"):
                return resp3
            raise Exception("not found")

        mock_session.get.side_effect = get_side

        analyzer = Analyzer("http://example.local")
        analyzer.baseline_text = ""
        findings = analyzer.run_idor("/items/{id}", [1, 2, 3])
        # expect findings with analysis indicating possible exposure for id 2 and value_diffs present
        self.assertTrue(isinstance(findings, list) and len(findings) == 3)
        f2 = next(f for f in findings if f.get("id") == 2)
        self.assertIn("analysis", f2)
        self.assertTrue(f2["analysis"].get("possible_idor_exposure"))
        # value_diffs should show 'admin' key present for id 2
        vd = f2["analysis"].get("value_diffs")
        self.assertIsNotNone(vd)
        self.assertIn("admin", vd)


if __name__ == "__main__":
    unittest.main()
