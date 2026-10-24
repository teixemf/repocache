"""Guard the approved CLI boundary for optional governed intake (#127).

The intake service and privileged maintenance helpers are internal modules,
never additional public REPOCACHE executables or automatically installed units.
"""
from __future__ import annotations

import ast
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "src/repocache/intake_service.py",
    "src/repocache/submission_admin.py",
    "src/repocache/submission_keys.py",
)


def test_installed_server_exposes_only_approved_entrypoint() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["scripts"] == {"repocache": "repocache.cli:app"}


def test_disabled_service_invokes_internal_module_from_managed_venv() -> None:
    unit = (ROOT / "deploy/examples/repocache-intake.service").read_text()
    assert unit.startswith("# OPTIONAL EXAMPLE ONLY")
    assert "ConditionPathExists=/etc/repocache-intake/enable-local-intake" in unit
    assert ("ExecStart=/opt/repocache-cli/managed/current/bin/python "
            "-m repocache.intake_service --enable-local-only") in unit
    assert "ExecStart=/usr/bin/repocache-intake" not in unit
    assert "User=repocache-intake" in unit
    assert "NoNewPrivileges=true" in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=localhost" in unit


def test_internal_modules_keep_guarded_main_entrypoints() -> None:
    for filename in MODULES:
        path = ROOT / filename
        source = path.read_text(encoding="utf-8")
        syntax = ast.parse(source, filename=str(path))
        assert any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name == "main" for node in syntax.body)
        assert any(isinstance(node, ast.If)
                   and isinstance(node.test, ast.Compare)
                   and isinstance(node.test.left, ast.Name)
                   and node.test.left.id == "__name__"
                   for node in syntax.body)


def test_client_explicit_send_preserves_canonical_parser_and_fallback() -> None:
    client = (ROOT / "client/repocache_client.py").read_text()
    assert 'repos_cmd = cmds.add_parser("repos", aliases=["repo"])' in client
    assert 'listing = actions.add_parser("list", aliases=["ls"])' in client
    assert 'submit.add_argument("--send", action="store_true"' in client
    assert 'if args.send:' in client
    assert 'if args.output or not args.token_file:' in client
    assert 'result = _send_submission(server, payload, args.token_file)' in client
    assert 'if args.apply:' in client
    assert '"DRY RUN: no APT/DNF configuration was changed."' in client


def test_no_public_alias_bypasses_cli_architecture() -> None:
    architecture = (ROOT / "docs/architecture/CLI_ARCHITECTURE.md").read_text()
    assert 'Server object `requests`, not `submissions`' in architecture
    docs = (ROOT / "docs/SUBMISSIONS_SECURITY_OPERATIONS_V05.md").read_text()
    assert "Canonical CLI reconciliation" in docs
    assert "repocache requests" in docs
    for disallowed in ("repocache-submissions-admin =", "repocache-submissions-keys =",
                       "repocache-intake ="):
        assert disallowed not in (ROOT / "pyproject.toml").read_text()
