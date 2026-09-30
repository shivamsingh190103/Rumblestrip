# Rumblestrip

Rumblestrip turns the corrections you give AI coding agents into deterministic checks that run after edits, before commits, and in CI.

The LLM may propose a rule, but it never runs in enforcement or CI. Every committed rule is readable data under `.rumblestrip/`, and every rule requires human approval.

## Quick start

```sh
python -m pip install -e .
rumblestrip init
rumblestrip check --all
```

## First 10 minutes

Use this flow to go from transcript corrections to enforced checks:

```sh
# 1) initialize repository state
rumblestrip init

# 2) harvest correction candidates from transcripts
rumblestrip harvest --agent codex
# or: rumblestrip harvest --agent claude
# or: rumblestrip harvest --agent all

# 3) generate proposed rules from candidates
rumblestrip propose

# 4) review and approve/reject/defer
rumblestrip review
rumblestrip review --approve 1
# optional: keep current findings as baseline when approving
rumblestrip review --approve 1 --baseline

# 5) enforce checks
rumblestrip check --all
# pre-commit use: rumblestrip check --staged
```

If no proposals appear after `propose`, run `rumblestrip doctor` to verify setup and source discovery.

## Agent and CI setup examples

Install local agent hooks and pre-commit hook:

```sh
rumblestrip install --agent codex --git-hook
rumblestrip install --agent claude
```

Generate a GitHub Actions workflow:

```sh
rumblestrip install --ci github
```

This creates `.github/workflows/rumblestrip.yml` and reports findings directly in pull request annotations.

Create a rule from a correction session with `rumblestrip harvest`, inspect it using `rumblestrip propose` and `rumblestrip review`, then approve it. The initial release supports local Codex and Claude Code JSONL transcripts, redaction, SQLite-backed candidate storage, confidence-scored deduplication, and deterministic built-in engines. `ast-grep` is used automatically for custom ast-grep rules when it is installed.

## Rule safety

- Rule checks are declarative; Rumblestrip never executes generated code.
- Local session data is redacted before persistence.
- Enforcement never invokes an LLM.
- Approved rules have an integrity hash, checked in local and CI modes.
- Existing violations can be baselined, so rules ratchet toward compliance.

See `rumblestrip --help` for the available commands.
