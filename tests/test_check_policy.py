#!/usr/bin/env python3
"""Tests for check_policy.py — exercises all four rule kinds."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_DIR = TESTS_DIR.parent
ENGINE = REPO_DIR / "check_policy.py"


def run_engine(repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Run check_policy.py with cwd set to the given repo root."""
    return subprocess.run(
        [sys.executable, str(ENGINE)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )


def make_repo(tmp_path: Path, policy_toml: str, files: dict[str, str]) -> Path:
    """Create a temporary repo layout with policy and source files."""
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "rg-policy.toml").write_text(policy_toml)

    for rel_path, content in files.items():
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    return tmp_path


# --- [[rule]] tests --------------------------------------------------------

def test_rule_pass(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[rule]]
            id = "no-fixme"
            message = "No FIXME markers."
            pattern = 'FIXME'
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/clean.txt": "This file is clean.\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr
    assert "policy checks passed" in result.stdout


def test_rule_fail(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[rule]]
            id = "no-fixme"
            message = "No FIXME markers."
            pattern = 'FIXME'
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/bad.txt": "FIXME: broken\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-fixme" in result.stderr


# --- [[size_rule]] tests ---------------------------------------------------

def test_size_rule_pass(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[size_rule]]
            id = "no-big-files"
            message = "Keep files small."
            max_lines = 5
            glob = ["*.txt"]
            include = ["."]
        '''),
        {"small.txt": "line\n" * 3},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_size_rule_fail(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[size_rule]]
            id = "no-big-files"
            message = "Keep files small."
            max_lines = 5
            glob = ["*.txt"]
            include = ["."]
        '''),
        {"big.txt": "line\n" * 10},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-big-files" in result.stderr


# --- [[path_rule]] tests ---------------------------------------------------

def test_path_rule_pass(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[path_rule]]
            id = "no-secret-files"
            message = "No secret files."
            pattern = '(?:^|/)secret\\.'
            include = ["."]
        '''),
        {"src/config.txt": "ok\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_path_rule_fail(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[path_rule]]
            id = "no-secret-files"
            message = "No secret files."
            pattern = '(?:^|/)secret\\.'
            include = ["."]
        '''),
        {"configs/secret.key": "s3cret\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-secret-files" in result.stderr


# --- [[dynamic_rule]] tests ------------------------------------------------

def test_dynamic_rule_os_identity(tmp_path: Path) -> None:
    """Built-in running-os-identity source runs without error on clean files."""
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[dynamic_rule]]
            id = "no-os-identity"
            message = "No OS identity leaks."
            source = "running-os-identity"
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/neutral.txt": "example-user example.test /srv/example\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


# --- redacted mode tests ---------------------------------------------------

def test_redacted_mode(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            redact_matches = true

            [[rule]]
            id = "no-fixme"
            message = "No FIXME markers."
            pattern = 'FIXME'
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/bad.txt": "FIXME: broken\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "REDACTED_MATCH" in result.stderr
    assert "FIXME: broken" not in result.stderr


# --- plugin sources tests --------------------------------------------------

def test_plugin_source(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[dynamic_rule]]
            id = "no-custom-leak"
            message = "Custom leak detected."
            source = "test-custom"
            include = ["."]
            glob = ["*.txt"]
        '''),
        {
            "src/leaky.txt": "CUSTOM_SECRET_VALUE\n",
            "policy/sources.py": textwrap.dedent('''\
                """Test plugin source."""

                from __future__ import annotations
                from collections.abc import Callable


                def test_custom_source() -> dict[str, str]:
                    return {"custom-secret": "CUSTOM_SECRET_VALUE"}


                SOURCES: dict[str, Callable[[], dict[str, str]]] = {
                    "test-custom": test_custom_source,
                }
            '''),
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-custom-leak" in result.stderr


# --- multiline flag --------------------------------------------------------

def test_multiline_rule_fail(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[rule]]
            id = "no-conflict"
            message = "No merge-conflict block."
            pattern = '^<{7} [\\s\\S]*?^>{7} '
            multiline = true
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/c.txt": "<<<<<<< HEAD\na\n=======\nb\n>>>>>>> x\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-conflict" in result.stderr


def test_multiline_rule_no_false_positive_on_lone_marker(tmp_path: Path) -> None:
    """A bare `=======` line (RST/Markdown underline) must not fire."""
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[rule]]
            id = "no-conflict"
            message = "No merge-conflict block."
            pattern = '^<{7} [\\s\\S]*?^>{7} '
            multiline = true
            include = ["."]
            glob = ["*.md"]
        '''),
        {"README.md": "Heading\n=======\n\nbody\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


# --- require_rule (must-find) ----------------------------------------------

def test_require_rule_pass(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[require_rule]]
            id = "scripts-strict-mode"
            message = "Shell scripts must set strict mode."
            pattern = 'set -euo pipefail'
            include = ["."]
            glob = ["*.sh"]
        '''),
        {"ok.sh": "#!/usr/bin/env bash\nset -euo pipefail\necho hi\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_require_rule_fail(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[require_rule]]
            id = "scripts-strict-mode"
            message = "Shell scripts must set strict mode."
            pattern = 'set -euo pipefail'
            include = ["."]
            glob = ["*.sh"]
        '''),
        {"bad.sh": "#!/usr/bin/env bash\necho hi\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "scripts-strict-mode" in result.stderr
    assert "bad.sh" in result.stderr


# --- extends / base merge --------------------------------------------------

def test_extends_pulls_in_base_rule(tmp_path: Path) -> None:
    """A repo extending `hygiene` inherits no-hardcoded-home-paths."""
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene"]\n',
        {"src/paths.py": 'P = "/home/alice/secret"\n'},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-hardcoded-home-paths" in result.stderr


def test_extends_disable_rules(tmp_path: Path) -> None:
    """disable_rules drops a base rule by id."""
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene"]\ndisable_rules = ["no-hardcoded-home-paths"]\n',
        {"src/paths.py": 'P = "/home/alice/secret"\n'},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_extends_repo_overrides_base_by_id(tmp_path: Path) -> None:
    """A repo rule with the same id replaces the base rule (here: narrower)."""
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            extends = ["hygiene"]

            [[rule]]
            id = "no-hardcoded-home-paths"
            message = "Local override."
            pattern = '(?:/home|/Users)/[A-Za-z0-9._-]+'
            include = ["."]
            glob = ["*.py"]
        '''),
        # .txt would trip the base rule, but the override only scans *.py.
        {"src/notes.txt": "/home/alice\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_extends_unknown_base_errors(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'extends = ["does-not-exist"]\n',
        {"src/clean.txt": "ok\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 2
    assert "unknown base rule set" in result.stderr


def test_extends_security_auth_key(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'extends = ["security"]\n',
        {"src/creds.py": 'password = "hunter2hunter2hunter2"\n'},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-committed-auth-key-values" in result.stderr


# --- missing policy file ---------------------------------------------------

def test_missing_policy(tmp_path: Path) -> None:
    result = run_engine(tmp_path)
    assert result.returncode == 2
    assert "not found" in result.stderr


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    test_functions = [
        v for k, v in sorted(globals().items()) if k.startswith("test_")
    ]
    passed = 0
    failed = 0
    for test_fn in test_functions:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                test_fn(Path(tmp))
                print(f"  PASS  {test_fn.__name__}")
                passed += 1
            except Exception as exc:
                print(f"  FAIL  {test_fn.__name__}: {exc}")
                failed += 1
    total = passed + failed
    print(f"\n{passed}/{total} passed", end="")
    if failed:
        print(f", {failed} failed")
    else:
        print()
    raise SystemExit(1 if failed else 0)
