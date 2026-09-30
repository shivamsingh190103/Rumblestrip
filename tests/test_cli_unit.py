from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

from rumblestrip.cli import command_harvest, command_propose, command_review
from rumblestrip.core.paths import init_repository
from rumblestrip.store.database import StateDB


class CliUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_home = os.environ.get("RUMBLESTRIP_HOME")
        os.environ["RUMBLESTRIP_HOME"] = str(self.root / "local-state")
        init_repository(self.root)

    def tearDown(self) -> None:
        if self.old_home is None:
            os.environ.pop("RUMBLESTRIP_HOME", None)
        else:
            os.environ["RUMBLESTRIP_HOME"] = self.old_home
        self.temp.cleanup()

    def test_low_confidence_candidate_is_deferred(self) -> None:
        db = StateDB()
        source = db.source("codex", self.root / "session.jsonl", self.root)
        created = db.add_candidate(
            int(source["id"]),
            self.root,
            "hash-1",
            {"before": "a", "correction": "short", "after": "a", "source_type": "user"},
            "heuristic",
            cluster_id="cluster-1",
            labels={"quality": {"score": 0.2, "signals": []}},
        )
        self.assertTrue(created)
        db.close()

        code = command_propose(Namespace(repo=str(self.root)))
        self.assertEqual(code, 0)

        db = StateDB()
        rows = db.candidates(self.root, state="deferred")
        db.close()
        self.assertEqual(len(rows), 1)

    def test_review_displays_confidence_column(self) -> None:
        db = StateDB()
        source = db.source("codex", self.root / "session.jsonl", self.root)
        db.add_candidate(
            int(source["id"]),
            self.root,
            "hash-2",
            {"before": "requests.get(url)", "correction": "always add timeout to outbound requests", "after": "requests.get(url, timeout=10)", "source_type": "user"},
            "heuristic",
            cluster_id="cluster-2",
            labels={"quality": {"score": 0.9, "signals": ["always"]}},
        )
        db.close()

        self.assertEqual(command_propose(Namespace(repo=str(self.root))), 0)

        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(command_review(Namespace(repo=str(self.root), approve=None, reject=None, defer=None, baseline=False, reason=None)), 0)
        output = stream.getvalue()
        self.assertIn("confidence:", output)

    def test_harvest_deduplicates_clustered_corrections(self) -> None:
        fixture = self.root / "events.jsonl"
        first = {"type": "assistant", "role": "assistant", "content": "requests.get(url)"}
        second = {"type": "user", "role": "user", "content": "always add timeout to outbound requests"}
        third = {"type": "assistant", "role": "assistant", "content": "requests.get(url, timeout=10)"}
        fixture.write_text("\n".join(json.dumps(item) for item in [first, second, third, first, second, third]) + "\n", encoding="utf-8")

        self.assertEqual(command_harvest(Namespace(repo=str(self.root), source=str(fixture), agent="codex")), 0)
        db = StateDB()
        rows = db.candidates(self.root, state="new")
        db.close()
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
