from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from rumblestrip.cli import command_harvest, command_propose, command_review
from rumblestrip.core.errors import IntegrityError
from rumblestrip.core.paths import init_repository
from rumblestrip.detect.heuristic import correction_windows
from rumblestrip.enforce.runner import run_checks
from rumblestrip.redact.redactor import redact
from rumblestrip.sources.jsonl import read_new_events
from rumblestrip.store.rules_repo import verify_rule, write_rule_bundle
from rumblestrip.synth.heuristic import synthesize


class RumblestripEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_home = os.environ.get("RUMBLESTRIP_HOME")
        os.environ["RUMBLESTRIP_HOME"] = str(self.root / "local-state")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        init_repository(self.root)

    def tearDown(self) -> None:
        if self.old_home is None:
            os.environ.pop("RUMBLESTRIP_HOME", None)
        else:
            os.environ["RUMBLESTRIP_HOME"] = self.old_home
        self.temp.cleanup()

    def test_timeout_proposal_becomes_a_check(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "codex-timeout.jsonl"
        events, _, error = read_new_events(fixture, 0)
        self.assertIsNone(error)
        windows = correction_windows(events)
        self.assertEqual(len(windows), 1)
        rule, check, tests = synthesize(windows[0]["evidence"], 1)
        self.assertEqual(rule["id"], "rs-http-timeout")
        write_rule_bundle(self.root, rule, check, tests)
        source = self.root / "src" / "client.py"
        source.parent.mkdir()
        source.write_text("import requests\nrequests.get(url)\n", encoding="utf-8")
        result = run_checks(self.root, files=["src/client.py"], record_ledger=False)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(result["visible"][0].line, 2)
        source.write_text("import requests\nrequests.get(url, timeout=10)\n", encoding="utf-8")
        result = run_checks(self.root, files=["src/client.py"], record_ledger=False)
        self.assertEqual(result["failure_count"], 0)

    def test_integrity_hash_detects_tampering(self) -> None:
        rule = {"schema_version": 1, "id": "rs-no-eval", "title": "No eval", "status": "active", "kind": "text_regex", "severity": "error", "statement": "Do not use eval.", "scope": {"include": ["**/*.py"], "exclude": []}, "check": {"engine": "builtin", "file": "check.yml"}}
        written = write_rule_bundle(self.root, rule, {"pattern": "eval"}, {"schema_version": 1, "invalid": [], "valid": []})
        self.assertIsNotNone(written.approval["content_hash"])
        with self.assertRaises(IntegrityError):
            verify_rule(written, {"pattern": "exec"}, {"schema_version": 1, "invalid": [], "valid": []})

    def test_redaction_removes_tokens_and_key_values(self) -> None:
        output = redact("api_key=superSecretValueOverTwentyCharacters github ghp_abcdefghijklmnopqrstuvwxyz")
        self.assertNotIn("superSecretValueOverTwentyCharacters", output)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz", output)

    def test_cli_harvest_propose_and_approve(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "codex-timeout.jsonl"
        repo = str(self.root)
        self.assertEqual(command_harvest(Namespace(repo=repo, source=str(fixture), agent="codex")), 0)
        self.assertEqual(command_propose(Namespace(repo=repo)), 0)
        self.assertEqual(command_review(Namespace(repo=repo, approve=1, reject=None, defer=None, baseline=False, reason=None)), 0)
        (self.root / "src").mkdir()
        (self.root / "src" / "client.py").write_text("import requests\nrequests.get(url)\n", encoding="utf-8")
        result = run_checks(self.root, files=["src/client.py"], record_ledger=False)
        self.assertEqual(result["failure_count"], 1)


if __name__ == "__main__":
    unittest.main()
