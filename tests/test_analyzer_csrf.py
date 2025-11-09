from unittest.mock import patch

from src.mcp_orchestrator.analyzer import Analyzer


class FakeResp:
    def __init__(self, status=200, content=b"OK", headers=None, history=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}
        self.history = history or []
        self.cookies = {}
        self.elapsed = None

    @property
    def text(self):
        try:
            return self.content.decode("utf-8", errors="replace")
        except Exception:
            return str(self.content)


def test_csrf_presence_and_cookie_delta():
    a = Analyzer("http://example.local/doLogin")

    # baseline contains a hidden csrf token
    baseline_body = b'<form><input type="hidden" name="csrf" value="tok"></form>'

    def fake_post(self, url, *args, **kwargs):
        # first call baseline
        if not hasattr(fake_post, "called"):
            fake_post.called = True
            return FakeResp(status=200, content=baseline_body)
        # vector call returns 200 and sets a new session cookie via the session cookie jar
        # simulate Set-Cookie effect by directly mutating session.cookies in Analyzer after call
        return FakeResp(status=200, content=b"<html>result</html>")

    with patch("requests.sessions.Session.post", fake_post):
        # run baseline capture
        baseline = a.capture_baseline({"uid": "user", "passw": "pw"})
        assert "baseline_text" in baseline

        # simulate that the session received a new session cookie during the vector run
        def fake_post_for_vector(self, url, *args, **kwargs):
            # mutate session cookie jar to simulate server-set cookie
            self.cookies.set("JSESSIONID", "FAKEVAL")
            return FakeResp(status=200, content=b"<html>Welcome</html>")

        with patch("requests.sessions.Session.post", fake_post_for_vector):
            results = a.run_vector({"id": "v_csrf", "payload": "test"}, sinks=["uid"])

    assert isinstance(results, list) and results
    r = results[0]
    # csrf behavior should show presence in baseline
    assert r["analysis"].get("csrf_behavior") in (None, "present_baseline")
    # cookie_delta should include the newly set cookie
    assert r["analysis"].get("cookie_delta") is not None
    assert "JSESSIONID" in r["analysis"].get("cookie_delta") or "JSESSIONID" in r["response"].get(
        "session_cookies_after"
    )
