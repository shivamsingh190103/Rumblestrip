from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rumblestrip.sources.jsonl import read_new_events


class SourceJsonlUnitTests(unittest.TestCase):
    def test_negative_offset_is_handled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            path.write_text(json.dumps({"role": "user", "content": "hello"}) + "\n", encoding="utf-8")
            events, next_offset, error = read_new_events(path, -999)
            self.assertIsNone(error)
            self.assertEqual(len(events), 1)
            self.assertGreater(next_offset, 0)

    def test_malformed_lines_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            path.write_bytes(b"{bad json}\n" + json.dumps({"role": "assistant", "content": "ok"}).encode() + b"\n")
            events, _, error = read_new_events(path, 0)
            self.assertIsNone(error)
            self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
