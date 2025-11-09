from src.mcp_orchestrator.analyzer import Analyzer


def test_skip_host_by_default():
    """If the Analyzer target host equals demo.testfire.net it must not send requests and
    should return a skipped_by_policy result.
    """
    a = Analyzer("http://demo.testfire.net/doLogin")
    res = a.run_vector({"id": "t1", "payload": "' OR '1'='1"})
    assert isinstance(res, list)
    assert res[0].get("skipped_by_policy") is True
