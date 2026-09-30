# Rumblestrip

Rumblestrip turns the corrections you give AI coding agents into deterministic checks that run after edits, before commits, and in CI.

The LLM may propose a rule, but it never runs in enforcement or CI. Every committed rule is readable data under `.rumblestrip/`, and every rule requires human approval.

## Quick start

```sh
python -m pip install -e .
rumblestrip init
rumblestrip check --all
```

Create a rule from a correction session with `rumblestrip harvest`, inspect it using `rumblestrip propose` and `rumblestrip review`, then approve it. The initial release supports local Codex and Claude Code JSONL transcripts, redaction, SQLite-backed candidate storage, and deterministic built-in engines. `ast-grep` is used automatically for custom ast-grep rules when it is installed.

## Rule safety

- Rule checks are declarative; Rumblestrip never executes generated code.
- Local session data is redacted before persistence.
- Enforcement never invokes an LLM.
- Approved rules have an integrity hash, checked in local and CI modes.
- Existing violations can be baselined, so rules ratchet toward compliance.

See `rumblestrip --help` for the available commands.
