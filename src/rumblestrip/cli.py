"""The command-line interface. Command handlers stay thin over the library layers."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from rumblestrip import __version__
from rumblestrip.core.errors import ConfigError, IntegrityError, RumblestripError
from rumblestrip.core.git import changed_files, git
from rumblestrip.core.paths import config_path, find_repo_root, init_repository, load_config, rs_dir
from rumblestrip.core.serde import dump_data, load_data
from rumblestrip.detect.heuristic import correction_windows
from rumblestrip.enforce.hooks import handle_hook
from rumblestrip.enforce.runner import github_report, json_report, run_checks, sarif_report, text_report
from rumblestrip.engines.builtin import run_rule
from rumblestrip.redact.redactor import redact
from rumblestrip.review.plain import approve, decide, queue
from rumblestrip.sources.jsonl import discover, read_new_events
from rumblestrip.store.database import StateDB
from rumblestrip.store.rules_repo import load_baseline, load_rules, reapprove, retire, save_baseline, verify_rule
from rumblestrip.synth.heuristic import synthesize
from rumblestrip.validate.proposal import validate


def root_from(args: argparse.Namespace) -> Path:
    return find_repo_root(Path(getattr(args, "repo", None) or Path.cwd()))


def installed_command(root: Path) -> str:
    """Return a command hooks can run without relying on an activated shell."""
    invoked = Path(sys.argv[0])
    if invoked.name == "__main__.py":
        return f"{shlex.quote(sys.executable)} -m rumblestrip"
    if invoked.exists():
        resolved = invoked.resolve()
        try:
            relative = resolved.relative_to(root.resolve()).as_posix()
            return shlex.quote("./" + relative)
        except ValueError:
            return shlex.quote(str(resolved))
    return shlex.quote(shutil.which("rumblestrip") or "rumblestrip")


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def command_init(args: argparse.Namespace) -> int:
    root = root_from(args)
    if config_path(root).exists() and not args.force:
        print(f"Rumblestrip is already initialized: {config_path(root)}")
        return 0
    init_repository(root)
    print(f"Initialized .rumblestrip in {root}")
    print("LLM backend: none (harvest will use local heuristics; CI never calls an LLM).")
    return 0


def command_check(args: argparse.Namespace) -> int:
    root = root_from(args)
    mode = "staged" if args.staged else "diff" if args.diff else "all"
    result = run_checks(root, mode=mode, files=args.files, diff_base=args.diff, surface="ci" if os.environ.get("CI") else "manual", record_ledger=not bool(os.environ.get("CI")))
    if args.format == "json":
        print(json_report(result))
    elif args.format == "sarif":
        print(sarif_report(result))
    elif args.format == "github":
        print(github_report(result))
    else:
        print(text_report(result, verbose=args.verbose))
    if result["errors"] and (os.environ.get("CI") or load_config(root)["enforce"].get("on_tool_error") == "fail"):
        return 2
    return 1 if result["failure_count"] else 0


def command_redact(args: argparse.Namespace) -> int:
    path = Path(args.check)
    print(redact(path.read_text(encoding="utf-8", errors="replace"), source_path=path))
    return 0


def command_harvest(args: argparse.Namespace) -> int:
    root = root_from(args)
    db = StateDB()
    paths: list[tuple[str, Path]] = []
    if args.source:
        paths = [(args.agent, Path(args.source))]
    else:
        if args.agent in {"all", "codex"}:
            paths.extend(("codex", path) for path in discover("codex"))
        if args.agent in {"all", "claude"}:
            paths.extend(("claude", path) for path in discover("claude"))
    seen = added = 0
    for kind, path in paths:
        source = db.source(kind, path, root)
        offset = int(source["byte_offset"])
        if path.exists() and path.stat().st_size < offset:
            offset = 0
        events, next_offset, error = read_new_events(path, offset)
        for window in correction_windows(events):
            seen += 1
            if db.add_candidate(int(source["id"]), root, window["hash"], window["evidence"], "heuristic"):
                added += 1
        db.update_source(int(source["id"]), next_offset, path.stat().st_size if path.exists() else 0, error)
    db.close()
    print(f"Harvested {len(paths)} source(s): {added} new correction candidate(s), {seen - added} already known.")
    return 0


def command_propose(args: argparse.Namespace) -> int:
    root = root_from(args)
    db = StateDB()
    candidates = db.candidates(root)
    created = 0
    for candidate in candidates:
        evidence = json.loads(candidate["evidence_json"])
        rule, check, tests = synthesize(evidence, int(candidate["id"]))
        validation = validate(root, rule, check, tests)
        if db.add_proposal(int(candidate["id"]), rule, rule["kind"], {"check": check, "tests": tests}, validation):
            created += 1
    db.close()
    print(f"Created {created} proposal(s). Run: rumblestrip review")
    return 0


def command_review(args: argparse.Namespace) -> int:
    root = root_from(args)
    if args.approve is not None:
        rule_id = approve(root, args.approve, baseline=args.baseline)
        if args.baseline:
            result = run_checks(root, mode="all", record_ledger=False)
            current = load_baseline(root)
            current.update(item.fingerprint for item in result["visible"] if item.rule_id == rule_id)
            save_baseline(root, current)
        print(f"Approved {rule_id}" + (" with current violations baselined." if args.baseline else "."))
        return 0
    if args.reject is not None:
        decide(args.reject, "rejected", args.reason or "rejected in terminal review")
        print(f"Rejected proposal {args.reject}.")
        return 0
    if args.defer is not None:
        decide(args.defer, "deferred", args.reason or "deferred in terminal review")
        print(f"Deferred proposal {args.defer}.")
        return 0
    pending = queue(root)
    if not pending:
        print("No proposals waiting for review.")
        return 0
    print(f"rumblestrip review  repo: {root.name}  {len(pending)} pending\n")
    for proposal in pending:
        rule = proposal["rule"]
        states = ", ".join(f"{entry['step']}:{entry['status']}" for entry in proposal["validation"].get("steps", []))
        print(f"{proposal['id']:>3}  {rule['title']:<55.55} {rule['kind']:<18} {states}")
    print("\nApprove: rumblestrip review --approve ID [--baseline]")
    print("Reject:  rumblestrip review --reject ID --reason 'too specific'")
    return 0


def command_rules(args: argparse.Namespace) -> int:
    root = root_from(args)
    if args.rules_command == "ls":
        rows = load_rules(root, include_inactive=True)
        if not rows:
            print("No rules installed.")
        for rule, _, _, _ in rows:
            print(f"{rule.id:<35} {rule.status:<9} {rule.severity:<7} {rule.statement}")
        return 0
    if args.rules_command == "show":
        rows = [item for item in load_rules(root, include_inactive=True) if item[0].id == args.id]
        if not rows:
            raise ConfigError(f"unknown rule: {args.id}")
        rule, check, tests, _ = rows[0]
        print_json({"rule": rule.to_dict(), "check": check, "tests": tests})
        return 0
    if args.rules_command == "approve":
        rule = reapprove(root, args.id)
        print(f"Reapproved {rule.id}.")
        return 0
    if args.rules_command == "retire":
        rule = retire(root, args.id)
        print(f"Retired {rule.id}.")
        return 0
    if args.rules_command == "test":
        rows = load_rules(root, include_inactive=True)
        selected = [item for item in rows if args.id is None or item[0].id == args.id]
        failures = []
        for rule, check, tests, _ in selected:
            invalid = len(tests.get("invalid") or [])
            valid = len(tests.get("valid") or [])
            if rule.kind == "advisory":
                print(f"{rule.id}: advisory (no deterministic examples)")
                continue
            validation = validate(root, rule.to_dict(), check, tests)
            ok = validation["ok"]
            print(f"{rule.id}: {'ok' if ok else 'FAIL'} — {invalid} invalid, {valid} valid example(s)")
            if not ok:
                failures.append(rule.id)
        return 1 if failures else 0
    raise ConfigError("choose: ls, show, approve, retire, or test")


def command_explain(args: argparse.Namespace) -> int:
    root = root_from(args)
    rows = [item for item in load_rules(root, include_inactive=True) if item[0].id == args.id]
    if not rows:
        raise ConfigError(f"unknown rule: {args.id}")
    rule, _, tests, _ = rows[0]
    print(f"{rule.id}: {rule.statement}\n")
    print(f"Why: {rule.rationale or 'No rationale recorded.'}")
    if rule.fix_hint:
        print(f"Do instead: {rule.fix_hint}")
    if rule.rejected_alternatives:
        print("Rejected alternatives:")
        for alternative in rule.rejected_alternatives:
            print(f"  - {alternative.get('what', '')}: {alternative.get('why_rejected', '')}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    root = root_from(args)
    failures = 0
    print(f"[ok]   repository: {root}")
    try:
        load_config(root)
        print(f"[ok]   config: {config_path(root)} (schema 1)")
    except ConfigError as exc:
        print(f"[fail] config: {exc}")
        return 2
    active = advisory = integrity = 0
    try:
        for rule, check, tests, _ in load_rules(root, include_inactive=True):
            active += rule.status == "active"
            advisory += rule.kind == "advisory"
            if rule.status == "active":
                verify_rule(rule, check, tests)
        print(f"[ok]   rules: {active} active, {advisory} advisory, 0 integrity failures")
    except IntegrityError as exc:
        failures += 1
        print(f"[fail] integrity: {exc}")
    print("[ok]   ast-grep: available" if (shutil.which("ast-grep") or shutil.which("sg")) else "[warn] ast-grep: not found (built-in rules work; custom ast-grep rules require it)")
    print("[ok]   Codex hooks installed" if (root / ".codex" / "hooks.json").exists() else "[info] Codex hooks: not installed")
    print("[ok]   Claude Code hooks installed" if (root / ".claude" / "settings.json").exists() else "[info] Claude Code hooks: not installed")
    hook = root / ".git" / "hooks" / "pre-commit"
    print("[ok]   git pre-commit hook present" if hook.exists() else "[info] git pre-commit hook: not installed")
    db = StateDB()
    pending = len(db.proposals(root))
    db.close()
    print(f"[info] {pending} proposal(s) waiting. Run: rumblestrip review" if pending else "[ok]   no pending proposals")
    return 2 if failures else 0


def command_stats(args: argparse.Namespace) -> int:
    root = root_from(args)
    db = StateDB()
    rows = db.stats(root)
    db.close()
    if not rows:
        print("No local violation history yet.")
        return 0
    print("Rule                                Fires  False positives  Last seen")
    for row in rows:
        print(f"{row['rule_id']:<35} {row['fires']:<6} {row['false_positives'] or 0:<16} {row['last_seen']}")
    return 0


def command_install(args: argparse.Namespace) -> int:
    root = root_from(args)
    load_config(root)
    installed: list[str] = []
    command = installed_command(root)
    if args.git_hook:
        hooks = root / ".git" / "hooks"
        if not hooks.exists():
            raise ConfigError("not a git repository; cannot install pre-commit hook")
        target = hooks / "pre-commit"
        backup = hooks / "pre-commit.rumblestrip.backup"
        if target.exists() and "installed by Rumblestrip" not in target.read_text(encoding="utf-8", errors="replace"):
            if not backup.exists():
                target.replace(backup)
            else:
                raise ConfigError(f"refusing to overwrite {target}; backup already exists")
        target.write_text(f"#!/bin/sh\n# installed by Rumblestrip\n{command} check --staged\n", encoding="utf-8")
        target.chmod(0o755)
        installed.append("git pre-commit")
    agents = [args.agent] if args.agent != "all" else ["codex", "claude"]
    for agent in agents:
        if agent == "codex":
            path = root / ".codex" / "hooks.json"
            path.parent.mkdir(exist_ok=True)
            data = load_data(path) if path.exists() else {"hooks": {}}
            hooks = data.setdefault("hooks", {})
            hooks["PostToolUse"] = [{"matcher": "Edit|Write", "command": f"{command} hook codex post-tool-use"}]
            hooks["Stop"] = [{"command": f"{command} hook codex stop"}]
            hooks["SessionStart"] = [{"command": f"{command} hook codex session-start"}]
            hooks["SessionEnd"] = [{"command": f"{command} hook codex session-end"}]
            dump_data(path, data)
            installed.append("Codex hooks (review them with /hooks)")
        if agent == "claude":
            path = root / ".claude" / "settings.json"
            path.parent.mkdir(exist_ok=True)
            data = load_data(path) if path.exists() else {}
            hooks = data.setdefault("hooks", {})
            hooks["PostToolUse"] = [{"matcher": "Edit|Write|MultiEdit", "hooks": [{"type": "command", "command": f"{command} hook claude post-tool-use"}]}]
            hooks["Stop"] = [{"hooks": [{"type": "command", "command": f"{command} hook claude stop"}]}]
            hooks["SessionEnd"] = [{"hooks": [{"type": "command", "command": f"{command} hook claude session-end"}]}]
            dump_data(path, data)
            installed.append("Claude Code hooks")
    if args.ci == "github":
        workflow = root / ".github" / "workflows" / "rumblestrip.yml"
        if workflow.exists():
            raise ConfigError(f"refusing to overwrite existing {workflow}")
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("name: Rumblestrip\non: [pull_request]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: {fetch-depth: 0}\n      - uses: astral-sh/setup-uv@v5\n      - run: uvx --from rumblestrip rumblestrip check --diff origin/${{ github.base_ref }} --format github\n", encoding="utf-8")
        installed.append("GitHub Actions workflow")
    print("Installed: " + ", ".join(installed) if installed else "Nothing selected. Use --git-hook, --agent, or --ci github.")
    return 0


def command_uninstall(args: argparse.Namespace) -> int:
    root = root_from(args)
    hook = root / ".git" / "hooks" / "pre-commit"
    backup = root / ".git" / "hooks" / "pre-commit.rumblestrip.backup"
    removed: list[str] = []
    if args.git_hook and hook.exists() and "installed by Rumblestrip" in hook.read_text(encoding="utf-8", errors="replace"):
        hook.unlink()
        if backup.exists():
            backup.replace(hook)
        removed.append("git pre-commit")
    for relative in ((".codex", "hooks.json"), (".claude", "settings.json")):
        path = root.joinpath(*relative)
        if args.agent == "all" and path.exists():
            # Only delete a file that is wholly Rumblestrip-managed.
            data = load_data(path)
            if "rumblestrip hook" in json.dumps(data):
                path.unlink()
                removed.append(str(path.relative_to(root)))
    print("Removed: " + ", ".join(removed) if removed else "Nothing managed by Rumblestrip was removed.")
    return 0


def command_hook(args: argparse.Namespace) -> int:
    return handle_hook(args.agent, args.event)


def command_purge(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ConfigError("purge deletes local candidates, proposals, and violation history; rerun with --yes")
    db = StateDB()
    db.purge()
    db.close()
    print("Purged local Rumblestrip state. Committed rule bundles were untouched.")
    return 0


def command_eval(args: argparse.Namespace) -> int:
    root = root_from(args)
    report = root / "eval" / "reports" / "latest.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    db = StateDB()
    candidates = len(db.candidates(root, "new")) + len(db.candidates(root, "proposed"))
    proposals = len(db.proposals(root))
    db.close()
    report.write_text(f"# Rumblestrip evaluation snapshot\n\n- Pending candidates: {candidates}\n- Pending proposals: {proposals}\n- Deterministic rule count: {len(load_rules(root))}\n\nThis local report deliberately makes no unmeasured quality claims.\n", encoding="utf-8")
    print(report)
    return 0


def command_jobs(args: argparse.Namespace) -> int:
    root = root_from(args)
    queue_dir = rs_dir(root) / ".cache" / "queue"
    if not queue_dir.exists():
        print("No queued jobs.")
        return 0
    jobs = sorted(queue_dir.glob("*.json"))
    completed = 0
    for job in jobs:
        try:
            payload = json.loads(job.read_text(encoding="utf-8"))
            source = payload.get("transcript_path")
            if source:
                harvest_args = argparse.Namespace(repo=str(root), source=source, agent="codex")
                command_harvest(harvest_args)
            job.unlink()
            completed += 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Could not process {job.name}: {exc}", file=sys.stderr)
    print(f"Processed {completed} queued job(s).")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="rumblestrip", description="Compile AI-agent corrections into deterministic repository checks.")
    root.add_argument("--version", action="version", version=f"rumblestrip {__version__}")
    root.add_argument("--repo", help="repository root (defaults to current repository)")
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--force", action="store_true"); init.set_defaults(handler=command_init)
    check = sub.add_parser("check"); check.add_argument("--staged", action="store_true"); check.add_argument("--diff", metavar="BASE"); check.add_argument("--files", nargs="+"); check.add_argument("--all", action="store_true"); check.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text"); check.add_argument("--verbose", action="store_true"); check.set_defaults(handler=command_check)
    redact_parser = sub.add_parser("redact"); redact_parser.add_argument("--check", required=True); redact_parser.set_defaults(handler=command_redact)
    harvest = sub.add_parser("harvest"); harvest.add_argument("--source"); harvest.add_argument("--agent", choices=["all", "codex", "claude"], default="all"); harvest.set_defaults(handler=command_harvest)
    propose = sub.add_parser("propose"); propose.set_defaults(handler=command_propose)
    review = sub.add_parser("review"); review.add_argument("--approve", type=int); review.add_argument("--reject", type=int); review.add_argument("--defer", type=int); review.add_argument("--baseline", action="store_true"); review.add_argument("--reason"); review.set_defaults(handler=command_review)
    rules = sub.add_parser("rules"); rule_sub = rules.add_subparsers(dest="rules_command", required=True)
    rules_ls = rule_sub.add_parser("ls"); rules_ls.set_defaults(handler=command_rules)
    for name in ("show", "approve", "retire"):
        item = rule_sub.add_parser(name); item.add_argument("id"); item.set_defaults(handler=command_rules)
    test = rule_sub.add_parser("test"); test.add_argument("id", nargs="?"); test.set_defaults(handler=command_rules)
    explain = sub.add_parser("explain"); explain.add_argument("id"); explain.set_defaults(handler=command_explain)
    doctor = sub.add_parser("doctor"); doctor.set_defaults(handler=command_doctor)
    stats = sub.add_parser("stats"); stats.set_defaults(handler=command_stats)
    install = sub.add_parser("install"); install.add_argument("--agent", choices=["all", "codex", "claude"], default="all"); install.add_argument("--git-hook", action="store_true"); install.add_argument("--ci", choices=["github"]); install.set_defaults(handler=command_install)
    uninstall = sub.add_parser("uninstall"); uninstall.add_argument("--agent", choices=["all"], default="all"); uninstall.add_argument("--git-hook", action="store_true"); uninstall.set_defaults(handler=command_uninstall)
    hook = sub.add_parser("hook"); hook.add_argument("agent", choices=["codex", "claude"]); hook.add_argument("event", choices=["post-tool-use", "stop", "session-start", "session-end"]); hook.set_defaults(handler=command_hook)
    purge = sub.add_parser("purge"); purge.add_argument("--yes", action="store_true"); purge.set_defaults(handler=command_purge)
    evaluate = sub.add_parser("eval"); evaluate.set_defaults(handler=command_eval)
    jobs = sub.add_parser("jobs"); jobs_sub = jobs.add_subparsers(dest="jobs_command", required=True); jobs_run = jobs_sub.add_parser("run"); jobs_run.set_defaults(handler=command_jobs)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        code = args.handler(args)
    except IntegrityError as exc:
        print(f"rumblestrip: integrity failure: {exc}", file=sys.stderr)
        code = 4
    except ConfigError as exc:
        print(f"rumblestrip: configuration error: {exc}", file=sys.stderr)
        code = 2
    except RumblestripError as exc:
        print(f"rumblestrip: {exc}", file=sys.stderr)
        code = 2
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)
