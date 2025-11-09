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


def test_sql_error_reflection_detects_payload_proximity():
    a = Analyzer("http://example.local/doLogin")

    payload = "' OR '1'='1"

    # baseline response
    def fake_post(self, url, *args, **kwargs):
        if not hasattr(fake_post, "called"):
            fake_post.called = True
            return FakeResp(status=200, content=b"<html>Login page</html>")
        # subsequent response contains SQL error with payload nearby
        body = (
            b"Some text before "
            + payload.encode()
            + b" ... Unclosed quotation mark after the character string at line 23"
        )
        return FakeResp(status=500, content=body)

    with patch("requests.sessions.Session.post", fake_post):
        baseline = a.capture_baseline({"uid": "user", "passw": "pw"})
        results = a.run_vector({"id": "s1", "payload": payload}, sinks=["uid"])

    assert isinstance(results, list) and results
    r = results[0]
    assert r["analysis"].get("sql_error_found") is True
    assert r["analysis"].get("sql_error_reflected") in (True, False)
    # when payload is near the error, sql_error_reflected should be True
    assert r["analysis"].get("sql_error_reflected") is True
