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


def test_authorization_header_and_jwt_tamper_detection():
    a = Analyzer("http://example.local/doLogin")

    # baseline returns 401
    def fake_post(self, url, *args, **kwargs):
        if not hasattr(fake_post, "called"):
            fake_post.called = True
            return FakeResp(status=401, content=b"Unauthorized")
        # vector call returns 200 and sets a session cookie -> simulate acceptance of tampered token
        # also mutate session cookies to simulate server-set cookie
        try:
            self.cookies.set("sessionid", "FAKE")
        except Exception:
            pass
        return FakeResp(
            status=200,
            content=b"<html>Welcome</html>",
            headers={"Set-Cookie": "sessionid=FAKE; HttpOnly"},
        )

    with patch("requests.sessions.Session.post", fake_post):
        baseline = a.capture_baseline({"uid": "user", "passw": "pw"})
        # run vector using authorization sink with a tampered token string
        results = a.run_vector(
            {"id": "jwt1", "payload": "tampered.token.value"}, sinks=["authorization"]
        )

    assert isinstance(results, list) and results
    r = results[0]
    auth_hdr = r["request"]["headers"].get("Authorization")
    assert auth_hdr is not None and auth_hdr.startswith("Bearer ")
    assert r["analysis"].get("jwt_tampering_accepted") is True
    assert r["analysis"].get("suspicious") is True
