"""Test execution engine - lightweight integration with Analyzer"""

from typing import List, Dict, Any, Optional

from .analyzer import Analyzer


class TestEngine:
    """Lightweight test execution engine that uses Analyzer.

    This class is intentionally small: it prepares vector lists, instantiates
    Analyzer, performs baseline capture, and runs the analysis engine.
    """

    def __init__(
        self, concurrency: int = 1, proxies: Optional[Dict[str, str]] = None, verify: bool = False
    ):
        self.concurrency = concurrency
        self.proxies = proxies or {}
        self.verify = verify

    def execute(
        self,
        target_url: str,
        vectors: Optional[List[Dict[str, Any]]] = None,
        skip_hosts: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Run Analyzer against target_url using provided vectors or registry list.

        Returns a list of findings (may be empty). If the target is skipped by policy,
        returns [{'skipped_by_policy': True}].
        """
        analyzer = Analyzer(
            target_url,
            proxies=self.proxies,
            verify=self.verify,
            concurrency=self.concurrency,
            skip_hosts=skip_hosts,
        )

        # perform a baseline capture with known-failing credentials
        baseline_data = {"uid": "invalid_user", "passw": "invalid", "btnSubmit": "Login"}
        baseline = analyzer.capture_baseline(baseline_data)
        if baseline.get("skipped_by_policy"):
            return [{"skipped_by_policy": True}]

        # run vectors
        if vectors is None:
            # fall back to registry if caller didn't provide vectors
            from .test_vector_registry import get_registry

            registry = get_registry()
            tvs = registry.get_all_vectors()
            vectors = [{"id": v.id, "payload": v.payload.base} for v in tvs]

        findings = analyzer.run_all(vectors)
        return findings
