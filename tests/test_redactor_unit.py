from __future__ import annotations

import unittest

from rumblestrip.redact.redactor import redact


class RedactorUnitTests(unittest.TestCase):
    def test_redacts_sensitive_content(self) -> None:
        text = """
api_key=superSecretValueOverTwentyCharacters
email: person@example.com
ip: 10.10.10.10
github: ghp_abcdefghijklmnopqrstuvwxyz
"""
        output = redact(text)
        self.assertNotIn("superSecretValueOverTwentyCharacters", output)
        self.assertNotIn("person@example.com", output)
        self.assertNotIn("10.10.10.10", output)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz", output)

    def test_redacts_entire_sensitive_file(self) -> None:
        self.assertEqual(redact("token=abc", source_path=".env"), "[REDACTED FILE]")

    def test_ignores_invalid_custom_pattern(self) -> None:
        output = redact("hello", extra_patterns=["("])
        self.assertEqual(output, "hello")


if __name__ == "__main__":
    unittest.main()
