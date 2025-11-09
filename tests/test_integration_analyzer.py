from unittest.mock import patch

from src.mcp_orchestrator.test_engine import TestEngine


class FakeResp:
    def __init__(self, status=200, content=b"OK", headers=None, history=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}
        self.history = history or []
        self.cookies = {}
        # requests.Response compatibility
        self.elapsed = None

    @property
    def text(self):
        try:
            return self.content.decode("utf-8", errors="replace")
        except Exception:
            return str(self.content)


def test_execute_through_test_engine_skips_demo():
    te = TestEngine()
    findings = te.execute(
        "http://demo.testfire.net/doLogin", vectors=[{"id": "t1", "payload": "' OR '1'='1"}]
    )
    assert isinstance(findings, list)
    assert findings[0].get("skipped_by_policy") is True


def test_execute_through_test_engine_flow():
    # Simulate baseline POST -> 200 with baseline body, then vector POST -> 302 Location, and GET final -> 200 with Welcome
    posts = []

    def fake_post(self, url, *args, **kwargs):
        # first call baseline
        if not posts:
            posts.append("baseline")
            return FakeResp(status=200, content=b"<html><body>Baseline Login page</body></html>")
        # subsequent calls: return redirect
        return FakeResp(status=302, content=b"", headers={"Location": "/bank/main.jsp"})

    def fake_get(self, url, *args, **kwargs):
        return FakeResp(status=200, content=b"<html><body>Welcome user</body></html>")

    with (
        patch("requests.sessions.Session.post", fake_post),
        patch("requests.sessions.Session.get", fake_get),
    ):
        te = TestEngine()
        vectors = [{"id": "v1", "payload": "' OR '1'='1"}]
        findings = te.execute(
            "http://example.local/doLogin", vectors=vectors, skip_hosts=["demo.testfire.net"]
        )

    assert isinstance(findings, list)
    assert len(findings) >= 1
    f = findings[0]
    # expected keys
    assert "vector_id" in f
    assert "analysis" in f
    assert f.get("skipped_by_policy") is False
