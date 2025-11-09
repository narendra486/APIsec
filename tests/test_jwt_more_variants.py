import unittest
from src.mcp_orchestrator.analyzer import Analyzer


class TestJWTVariants(unittest.TestCase):
    def test_generate_jwt_tamper_variants_contains_expected(self):
        a = Analyzer("http://example.local/doLogin")
        token = "hdr.payload.sig"
        variants = a._generate_jwt_tamper_variants(token)
        names = [n for n, t in variants]
        # ensure common variants are present
        self.assertIn("alg_none", names)
        self.assertIn("stripped_sig", names)
        self.assertTrue(any(n.startswith("hs256_") for n in names))
        # alg confusion variant
        self.assertTrue(any("alg_confusion" in n or "kid_admin_rs256" in n for n in names))


if __name__ == "__main__":
    unittest.main()
