from unittest.mock import patch

from src.mcp_orchestrator.analyzer import Analyzer


class FakeResp:
    def __init__(self, status=200, content=b"OK", headers=None, history=None, url=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}
        self.history = history or []
        self.cookies = {}
        self.elapsed = None
        self.url = url or "http://example.local/doLogin"

    @property
    def text(self):
        try:
            return self.content.decode("utf-8", errors="replace")
        except Exception:
            return str(self.content)


def test_content_type_mismatch_flags_html_in_json():
    a = Analyzer("http://example.local/doLogin")

    # baseline normal HTML
    def fake_post(self, url, *args, **kwargs):
        if not hasattr(fake_post, "called"):
            fake_post.called = True
            return FakeResp(
                status=200,
                content=b"<html><body>Login page</body></html>",
                headers={"Content-Type": "text/html"},
            )
        # subsequent vector returns JSON content-type but HTML body
        return FakeResp(
            status=200,
            content=b"<html><body>Server error page</body></html>",
            headers={"Content-Type": "application/json"},
        )

    with patch("requests.sessions.Session.post", fake_post):
        baseline = a.capture_baseline({"uid": "user", "passw": "pw"})
        results = a.run_vector({"id": "ct1", "payload": "test"}, sinks=["uid"])

    assert isinstance(results, list) and results
    r = results[0]
    assert r["analysis"].get("content_type_mismatch") is True
