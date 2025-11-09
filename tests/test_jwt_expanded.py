from unittest.mock import patch

from src.mcp_orchestrator.analyzer import Analyzer


def test_jwt_expanded_variants_used_and_recorded():
    a = Analyzer("http://example.local/doLogin")

    # monkeypatch _generate_jwt_tamper_variants to return deterministic variants including an accepted one
    def fake_variants(token):
        return [("v1", "bad.token.1"), ("accept_me", "accepted.token")]

    def fake_post(self, url, *args, **kwargs):
        # baseline
        if not hasattr(fake_post, "called"):
            fake_post.called = True
            return type(
                "R",
                (),
                {
                    "status_code": 401,
                    "content": b"Unauthorized",
                    "headers": {},
                    "history": [],
                    "url": url,
                },
            )()
        # subsequent: accept only 'accepted.token'
        hdrs = kwargs.get("headers", {})
        auth = hdrs.get("Authorization") if hdrs else None
        if auth == "Bearer accepted.token":
            return type(
                "R",
                (),
                {
                    "status_code": 200,
                    "content": b"Welcome",
                    "headers": {"Set-Cookie": "s=1"},
                    "history": [],
                    "url": url,
                },
            )()
        return type(
            "R",
            (),
            {"status_code": 403, "content": b"Forbidden", "headers": {}, "history": [], "url": url},
        )()

    with (
        patch.object(a, "_generate_jwt_tamper_variants", fake_variants),
        patch("requests.sessions.Session.post", fake_post),
    ):
        a.capture_baseline({"uid": "u", "passw": "p"})
        res = a.run_vector({"id": "jwtx", "payload": "original.token"}, sinks=["authorization"])

    assert isinstance(res, list)
    r = res[0]
    assert "jwt_tamper_variants_tested" in r["analysis"]
    assert "accept_me" in r["analysis"]["jwt_tamper_variants_tested"] or r["analysis"].get(
        "jwt_tamper_accepted_variant"
    )
    assert r["analysis"].get("jwt_tampering_accepted") is True
