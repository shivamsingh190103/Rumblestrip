from __future__ import annotations

import unittest

from rumblestrip.synth.heuristic import synthesize


class SynthesizeUnitTests(unittest.TestCase):
    def test_timeout_correction_generates_ast_pattern_rule(self) -> None:
        rule, check, tests = synthesize({"correction": "Always use timeout for outbound requests"}, 1)
        self.assertEqual(rule["id"], "rs-http-timeout")
        self.assertEqual(rule["kind"], "ast_pattern")
        self.assertEqual(check["required_keyword"], "timeout")
        self.assertTrue(tests["invalid"])
        self.assertTrue(tests["valid"])

    def test_forbidden_import_generates_dependency_rule(self) -> None:
        rule, check, _ = synthesize({"correction": "Do not import requests.sessions"}, 2)
        self.assertEqual(rule["kind"], "dependency")
        self.assertEqual(check["forbidden"], "requests.sessions")

    def test_generic_advisory_is_candidate_specific(self) -> None:
        rule, _, _ = synthesize({"correction": "Please keep this readable"}, 99)
        self.assertEqual(rule["kind"], "advisory")
        self.assertTrue(rule["id"].endswith("-99"))


if __name__ == "__main__":
    unittest.main()
