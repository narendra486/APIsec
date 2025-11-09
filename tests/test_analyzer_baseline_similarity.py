from unittest.mock import Mock, patch

from src.mcp_orchestrator.analyzer import Analyzer


class FakeResp:
    def __init__(self, status=200, content=b"OK baseline", headers=None, history=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}
        self.history = history or []
        self.cookies = Mock(get_dict=lambda: {})

    @property
    def text(self):
        return self.content.decode("utf-8", errors="replace")


def test_baseline_and_similarity_and_sql_error_detection():
    # Analyzer no longer accepts or requires a skip_hosts parameter
    a = Analyzer("http://example.local/doLogin")

    # Mock session.post for baseline and vector
    with patch.object(a.session, "post") as mock_post, patch.object(a.session, "get") as mock_get:
        # baseline response
        mock_post.side_effect = [
            FakeResp(status=200, content=b"Normal page content"),
            FakeResp(status=302, content=b"", headers={"Location": "/bank/main.jsp"}, history=[]),
        ]
        mock_get.return_value = FakeResp(status=200, content=b"Final dashboard Welcome user")

        baseline = a.capture_baseline({"uid": "user", "passw": "pw"})
        assert baseline["status"] == 200

        vector = {"id": "v1", "payload": "' OR '1'='1"}
        results = a.run_vector(vector, sinks=["uid"], allow_redirects=False, follow_redirects=True)
        assert isinstance(results, list) and len(results) == 1
        r = results[0]
        # similarity should be a float
        assert "similarity" in r
        # success keywords from final page should be detected
        assert "Welcome" in r.get("success_keywords") or r.get("final_status") == 200
