from __future__ import annotations

import unittest
from pathlib import Path

from rumblestrip.validate.proposal import validate


class ValidateUnitTests(unittest.TestCase):
    def test_advisory_rule_marks_examples_not_applicable(self) -> None:
        rule = {
            "schema_version": 1,
            "id": "rs-readable-names",
            "title": "Use readable names",
            "status": "active",
            "kind": "advisory",
            "severity": "info",
            "statement": "Use readable names.",
            "scope": {"include": ["**/*"], "exclude": []},
        }
        result = validate(Path("."), rule, {}, {"schema_version": 1})
        self.assertTrue(result["ok"])
        self.assertTrue(any(step["step"] == "V2" and step["status"] == "n/a" for step in result["steps"]))

    def test_scope_traversal_is_rejected(self) -> None:
        rule = {
            "schema_version": 1,
            "id": "rs-no-traversal",
            "title": "No traversal",
            "status": "active",
            "kind": "text_regex",
            "severity": "error",
            "statement": "No traversal.",
            "scope": {"include": ["../**/*"], "exclude": []},
        }
        result = validate(Path("."), rule, {"pattern": "eval"}, {"schema_version": 1, "invalid": [{"name": "x", "source": "eval(x)"}], "valid": [{"name": "x", "source": "pass"}]})
        self.assertFalse(result["ok"])

    def test_enforceable_rules_require_valid_and_invalid_examples(self) -> None:
        rule = {
            "schema_version": 1,
            "id": "rs-no-eval",
            "title": "No eval",
            "status": "active",
            "kind": "text_regex",
            "severity": "error",
            "statement": "Do not use eval.",
            "scope": {"include": ["**/*.py"], "exclude": []},
        }
        result = validate(Path("."), rule, {"pattern": "eval"}, {"schema_version": 1, "invalid": [], "valid": []})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
