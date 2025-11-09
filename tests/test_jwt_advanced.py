import unittest
from src.mcp_orchestrator.analyzer import Analyzer


class TestJWTAdvanced(unittest.TestCase):
    def test_advanced_variants_present(self):
        a = Analyzer("http://example.local/doLogin")
        token = "hdr.payload.sig"
        variants = a._generate_jwt_tamper_variants(token)
        names = [n for n, t in variants]
        self.assertTrue(any("jku_attacker" == n for n in names))
        self.assertTrue(any(n.startswith("rs_to_hs_") for n in names))
        self.assertTrue(
            any("kid_admin_rs256" == n for n in names) or any("alg_confusion" in n for n in names)
        )


if __name__ == "__main__":
    unittest.main()
