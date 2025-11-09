import time
from src.mcp_orchestrator.analyzer import Analyzer


def test_run_time_probe_detects_delay():
    a = Analyzer("http://example.local/doLogin")

    # define control (fast) and sleep (slow) payload functions
    def ctrl():
        return "normal"

    def sleep_payload():
        return "sleep_payload"

    # monkeypatch session.post to sleep for different durations depending on payload
    original_post = a.session.post

    def fake_post(url, *args, **kwargs):
        data = kwargs.get("data") or (args[1] if len(args) > 1 else {})
        uid = data.get("uid") if isinstance(data, dict) else None
        if uid == "sleep_payload":
            time.sleep(2.5)
        else:
            time.sleep(0.05)

        class R:
            status_code = 200
            content = b"OK"

        return R()

    a.session.post = fake_post
    try:
        res = a.run_time_probe(ctrl, sleep_payload, trials=2)
    finally:
        a.session.post = original_post

    assert "ctrl" in res and "sleep" in res
    assert res["delta"] is not None
    # Should detect ~2.5s greater on mean sleep than control
    assert res["delta"] > 2.0
