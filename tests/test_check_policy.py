#!/usr/bin/env python3
"""Tests for check_policy.py — exercises every rule kind in RULE_KIND_KEYS."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

TESTS_DIR = Path(__file__).resolve().parent
REPO_DIR = TESTS_DIR.parent
ENGINE = REPO_DIR / "check_policy.py"

_engine_module: ModuleType | None = None


def engine_module() -> ModuleType:
    """Import check_policy.py for the handful of tests that call it directly.

    Everything else drives the engine as a subprocess, which is the way it
    actually runs; pure functions are cheaper and clearer to assert on here.
    """
    global _engine_module
    if _engine_module is None:
        spec = importlib.util.spec_from_file_location("_check_policy", ENGINE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _engine_module = module
    return _engine_module


def write_sources(repo_root: Path, body: str) -> None:
    """Write a repo-local policy/sources.py exporting one source named by body.

    ``Needle`` is imported the way a real plugin gets it: the engine runs as a
    script, so its own directory is sys.path[0] and the name is importable.
    """
    (repo_root / "policy" / "sources.py").write_text(
        textwrap.dedent('''\
            from __future__ import annotations

            from check_policy import Needle


            def fake_source():
                {body}


            SOURCES = {{"fake-hostname-segment": fake_source}}
        ''').format(body=body)
    )


def run_engine(repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Run check_policy.py with cwd set to the given repo root."""
    return subprocess.run(
        [sys.executable, str(ENGINE)],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )


def run_text(repo_root: Path, text: str) -> subprocess.CompletedProcess[str]:
    """Run ``check_policy.py --check-text -`` with ``text`` on stdin."""
    return subprocess.run(
        [sys.executable, str(ENGINE), "--check-text", "-"],
        cwd=repo_root,
        input=text,
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


BASELINE_POLICY = textwrap.dedent('''\
    [[size_rule]]
    id = "no-big-files"
    message = "Keep files small."
    max_lines = 5
    glob = ["*.txt"]
    include = ["."]
    baseline = "policy/size-baseline.txt"
''')


def test_size_rule_baseline_grandfathers_an_oversized_file(tmp_path: Path) -> None:
    """A listed file over the limit passes — that is what the ratchet is for.

    Written with ``include = ["."]`` on purpose: that is the form, and the
    default when a rule omits ``include``, under which ``rg --files`` prefixes
    every path with ``./`` — so a baseline keyed the obvious way matched nothing
    and the ratchet silently did not apply. The failure was indistinguishable
    from undeclared debt, and its natural "fix" is to raise ``max_lines``,
    switching the rule off for everyone.
    """
    repo = make_repo(
        tmp_path,
        BASELINE_POLICY,
        {
            "big.txt": "line\n" * 10,
            "policy/size-baseline.txt": "# debt\nbig.txt 10\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_size_rule_baseline_still_fails_when_the_file_grows(tmp_path: Path) -> None:
    """The ratchet must be a ceiling, not an exemption.

    Without this, the test above is equally satisfied by a baseline that skips
    listed files outright — which passes whatever the file grows to, and is the
    one outcome the ratchet exists to prevent.
    """
    repo = make_repo(
        tmp_path,
        BASELINE_POLICY,
        {
            "big.txt": "line\n" * 11,
            "policy/size-baseline.txt": "# debt\nbig.txt 10\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-big-files" in result.stderr
    assert "must not grow" in result.stderr


def test_size_rule_baseline_does_not_cover_an_unlisted_file(tmp_path: Path) -> None:
    """A baseline entry grandfathers that path only, not the rule as a whole."""
    repo = make_repo(
        tmp_path,
        BASELINE_POLICY,
        {
            "big.txt": "line\n" * 10,
            "other.txt": "line\n" * 10,
            "policy/size-baseline.txt": "big.txt 10\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "other.txt" in result.stderr
    assert "big.txt" not in result.stderr


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


# --- hostname segments -----------------------------------------------------

def test_hostname_segments_keeps_the_identifying_part(tmp_path: Path) -> None:
    """A compound hostname yields the part that names the machine, not its kind."""
    assert engine_module().hostname_segments("debian-x8664-ARC") == ["arc"]


def test_hostname_segments_drops_generic_and_short_parts(tmp_path: Path) -> None:
    """Distro, architecture, role and two-letter parts are never searched for."""
    segments = engine_module().hostname_segments("arch-linux-dev-vm-x86-01")
    assert segments == []


def test_hostname_segments_skips_a_single_part_hostname(tmp_path: Path) -> None:
    """An unsplittable hostname is already covered by the whole-hostname needle."""
    assert engine_module().hostname_segments("bertha") == []


def test_hostname_segments_handles_an_fqdn_and_underscores(tmp_path: Path) -> None:
    module = engine_module()
    assert module.hostname_segments("proteus_lab.example.test") == ["proteus"]


def test_word_needle_does_not_match_inside_a_longer_word(tmp_path: Path) -> None:
    """The reason short needles need whole-word matching: arc is inside search.

    Without ``--word-regexp`` this fixture fires on ordinary prose, and a rule
    that cries wolf on the word "search" gets switched off rather than obeyed.
    """
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[dynamic_rule]]
            id = "no-host-segment"
            message = "No hostname segments."
            source = "fake-hostname-segment"
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/prose.txt": "Every search here is an arcade of arches.\n"},
    )
    write_sources(repo, 'return {"segment": Needle("arc", word=True)}')
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_word_needle_still_matches_the_segment_standing_alone(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[dynamic_rule]]
            id = "no-host-segment"
            message = "No hostname segments."
            source = "fake-hostname-segment"
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/fixture.txt": "dhcp-host=00:00:5e:00:53:51,198.51.100.51,arc\n"},
    )
    write_sources(repo, 'return {"segment": Needle("arc", word=True)}')
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-host-segment" in result.stderr


def test_plain_string_source_still_matches_substrings(tmp_path: Path) -> None:
    """Sources predating Needle keep substring semantics — a MAC inside wlx… ."""
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[dynamic_rule]]
            id = "no-host-segment"
            message = "No hostname segments."
            source = "fake-hostname-segment"
            include = ["."]
            glob = ["*.txt"]
        '''),
        {"src/iface.txt": "wlx7c3d095094a9\n"},
    )
    write_sources(repo, 'return {"mac": "7c3d095094a9"}')
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-host-segment" in result.stderr


# --- text mode -------------------------------------------------------------

TEXT_POLICY = textwrap.dedent('''\
    [[dynamic_rule]]
    id = "no-host-identity"
    message = "No host identity in published text."
    source = "fake-hostname-segment"
    include = ["."]
    glob = ["*.txt"]
''')


def test_check_text_refuses_the_needle_in_a_body(tmp_path: Path) -> None:
    """The path a file-scanning checker cannot see: a PR body, never a file."""
    repo = make_repo(tmp_path, TEXT_POLICY, {})
    write_sources(repo, 'return {"segment": Needle("arc", word=True)}')
    result = run_text(repo, "Found the hard way: the arc fragment was in there.\n")
    assert result.returncode == 1
    assert "no-host-identity" in result.stderr


def test_check_text_passes_clean_text(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, TEXT_POLICY, {})
    write_sources(repo, 'return {"segment": Needle("arc", word=True)}')
    result = run_text(repo, "Pointer sync for two releases and the pins.\n")
    assert result.returncode == 0, result.stderr


def test_check_text_honours_word_matching(tmp_path: Path) -> None:
    """Text mode must not be a second matcher that drifts from the file one."""
    repo = make_repo(tmp_path, TEXT_POLICY, {})
    write_sources(repo, 'return {"segment": Needle("arc", word=True)}')
    result = run_text(repo, "Every search here is an arcade of arches.\n")
    assert result.returncode == 0, result.stderr


def test_check_text_ignores_path_scoped_rules(tmp_path: Path) -> None:
    """A [[rule]] is scoped to paths, so firing it at a body would be guesswork."""
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
        {},
    )
    result = run_text(repo, "FIXME: this is a body, not a source file.\n")
    assert result.returncode == 0, result.stderr


def test_check_text_falls_back_when_the_repo_declares_no_dynamic_rules(
    tmp_path: Path,
) -> None:
    """`gh pr create` runs wherever the author stands — often a repo with no policy.

    Falling back to "nothing to check" there would leave the guard absent in
    exactly the places nobody configured it, which is where identity gets
    published from.
    """
    repo = tmp_path  # no policy/ at all
    (repo / "src").mkdir(parents=True, exist_ok=True)
    result = run_text(repo, f"my home is {Path.home()} by the way\n")
    assert result.returncode == 1
    assert "no-running-os-identity-metadata" in result.stderr


def test_check_text_fallback_passes_neutral_text(tmp_path: Path) -> None:
    result = run_text(tmp_path, "Use example-user and /srv/example instead.\n")
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


REQUIRE_BASELINE_POLICY = textwrap.dedent('''\
    [[require_rule]]
    id = "scripts-strict-mode"
    message = "Shell scripts must set strict mode."
    pattern = 'set -euo pipefail'
    include = ["."]
    glob = ["*.sh"]
    baseline = "policy/strict-mode-baseline.txt"
''')


def test_require_rule_baseline_grandfathers_a_listed_file(tmp_path: Path) -> None:
    """A must-find rule lands only when everything already complies.

    Which is exactly when nobody needs it: a requirement is written down
    *because* part of the tree does not meet it. Without a way in, the rule is
    either never added or added by first exempting the whole directory.
    """
    repo = make_repo(
        tmp_path,
        REQUIRE_BASELINE_POLICY,
        {
            "old.sh": "#!/usr/bin/env bash\necho hi\n",
            "policy/strict-mode-baseline.txt": "# debt\nold.sh\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_require_rule_baseline_does_not_cover_an_unlisted_file(tmp_path: Path) -> None:
    """The point of paths-not-counts: a listed path may stay bad, a new one may not."""
    repo = make_repo(
        tmp_path,
        REQUIRE_BASELINE_POLICY,
        {
            "old.sh": "#!/usr/bin/env bash\necho hi\n",
            "new.sh": "#!/usr/bin/env bash\necho hi\n",
            "policy/strict-mode-baseline.txt": "old.sh\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "new.sh" in result.stderr
    assert "old.sh: required pattern not found" not in result.stderr


def test_require_rule_baseline_reports_a_paid_off_entry(tmp_path: Path) -> None:
    """Stale detection is inverted here, and has to be.

    For ``[[rule]]`` an entry goes stale when the path stops matching. For a
    must-find rule the debt is paid when the path *starts* matching, and an
    entry left behind then switches the requirement off for a file that had
    already met it.
    """
    repo = make_repo(
        tmp_path,
        REQUIRE_BASELINE_POLICY,
        {
            "old.sh": "#!/usr/bin/env bash\nset -euo pipefail\necho hi\n",
            "policy/strict-mode-baseline.txt": "old.sh\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "stale baseline" in result.stderr
    assert "old.sh" in result.stderr


def test_require_rule_baseline_reports_a_deleted_entry(tmp_path: Path) -> None:
    """A path that is gone no longer describes the tree either."""
    repo = make_repo(
        tmp_path,
        REQUIRE_BASELINE_POLICY,
        {
            "ok.sh": "#!/usr/bin/env bash\nset -euo pipefail\necho hi\n",
            "policy/strict-mode-baseline.txt": "deleted.sh\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "stale baseline" in result.stderr
    assert "deleted.sh" in result.stderr


def test_require_rule_without_baseline_is_unchanged(tmp_path: Path) -> None:
    """The key is optional; a rule that never had one behaves exactly as before."""
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
    assert "stale baseline" not in result.stderr


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


def test_extends_spares_a_go_test_file(tmp_path: Path) -> None:
    """A Go test gets the same allowance a file under tests/ already had.

    The exclusions were a Python and JavaScript layout assumption: Go names a test
    `<name>_test.go` beside what it tests and never produces a `tests/` segment,
    so the stated rationale reached none of a Go repository's tests.
    """
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene", "security"]\n',
        {
            "cmd/thing/leak_test.go": (
                'const secret = "postgres://u:s3cr3tvalue@host:5432/db?sslmode=disable"\n'
            ),
        },
    )
    assert run_engine(repo).returncode == 0


def test_extends_still_refuses_a_secret_in_go_production_code(tmp_path: Path) -> None:
    """The allowance is for TESTS. The same literal in a non-test file still fails.

    Paired with the case above deliberately: an exclusion written one character
    too wide would pass both halves of a one-sided test.
    """
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene", "security"]\n',
        {
            "cmd/thing/main.go": (
                'const secret = "postgres://u:s3cr3tvalue@host:5432/db?sslmode=disable"\n'
            ),
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "cmd/thing/main.go" in result.stderr


def test_extends_status_rule_spares_an_adr(tmp_path: Path) -> None:
    """An ADR states its own status; every other doc still may not.

    Both directions in one test on purpose. An exclusion is only correct if the
    rule still refuses everywhere else -- an over-wide one would pass this half
    and quietly stop being a rule.
    """
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene"]\n',
        {
            "docs/adr/0001-a-decision.md": "# ADR 0001: A decision\n\nStatus: Accepted\n",
            "docs/runbook.md": "Status: InProgress\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "docs/runbook.md" in result.stderr
    assert "0001-a-decision.md" not in result.stderr


def test_extends_status_rule_refuses_an_adr_outside_docs_adr(tmp_path: Path) -> None:
    """The exclusion is a PATH, not a filename shape.

    A file called like an ADR but living elsewhere is not one, and letting the
    name alone buy the exemption would make the rule opt-out by rename.
    """
    repo = make_repo(
        tmp_path,
        'extends = ["hygiene"]\n',
        {"notes/0001-a-decision.md": "# ADR 0001: A decision\n\nStatus: Accepted\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "notes/0001-a-decision.md" in result.stderr


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


# --- [[link_rule]] tests ---------------------------------------------------

LINK_POLICY = '''\
[[link_rule]]
id = "no-broken-doc-links"
message = "Every link must resolve."
include = ["."]
glob = ["*.md"]
'''


def test_link_rule_pass(tmp_path: Path) -> None:
    # The control. Every refusal below is vacuous if a resolvable link fails.
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {
            "README.md": "See [the guide](docs/guide.md) and [an image](img/x.png).\n",
            "docs/guide.md": "# guide\n",
            "img/x.png": "not really a png\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr
    assert "policy checks passed" in result.stdout


def test_link_rule_fails_on_a_moved_target(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {"README.md": "See [the guide](docs/guide.md).\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no-broken-doc-links" in result.stderr
    assert "docs/guide.md -> no such file" in result.stderr


def test_link_rule_resolves_relative_to_the_containing_file(tmp_path: Path) -> None:
    # `../` inside the repo is legitimate and must pass; a renderer reads a link
    # relative to the document, not to the repository root.
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {
            "docs/adr/0001.md": "Schema in [contracts](../../contracts/x.json).\n",
            "contracts/x.json": "{}\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_link_rule_fails_on_a_link_escaping_the_repository(tmp_path: Path) -> None:
    # The failure a plain existence check misses: the path may well resolve on the
    # author's machine and cannot resolve for anyone who cloned this repo alone.
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {"docs/guide.md": "See [the notes](../../elsewhere/notes.md).\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "outside the repository" in result.stderr


def test_link_rule_allow_outside_repo_opts_out(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        LINK_POLICY.replace("glob =", "allow_outside_repo = true\nglob ="),
        {
            "docs/guide.md": "Out [there](../../elsewhere/x.md), here [ok](local.md).\n",
            "docs/local.md": "# local\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_link_rule_ignores_external_schemes_and_fragments(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {
            "README.md": (
                "A [site](https://example.com/nope.md), a [mail](mailto:a@b.c),\n"
                "a [section](#heading) and a [real one](docs/guide.md).\n"
            ),
            "docs/guide.md": "# guide\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_link_rule_ignores_links_inside_fenced_code(tmp_path: Path) -> None:
    # A README that DOCUMENTS a link would otherwise fail on its own example,
    # which is how a rule earns a blanket waiver and stops protecting anything.
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {
            "README.md": (
                "Write it like this:\n\n"
                "```markdown\n"
                "[the guide](docs/does-not-exist.md)\n"
                "```\n\n"
                "and it resolves to [the guide](docs/guide.md).\n"
            ),
            "docs/guide.md": "# guide\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_link_rule_still_sees_links_after_a_closed_fence(tmp_path: Path) -> None:
    # Fence state must CLOSE. If it leaked, everything after the first code block
    # in the file would go unchecked while the rule still reported success.
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {"README.md": "```\ncode\n```\n\nThen [gone](docs/gone.md).\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "docs/gone.md -> no such file" in result.stderr


def test_link_rule_handles_anchors_titles_and_escaped_spaces(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {
            "README.md": (
                "An [anchor](docs/guide.md#section), a [spaced](<docs/a b.md>),\n"
                "a [percent](docs/a%20b.md) and a [reference][ref].\n\n"
                "[ref]: docs/guide.md\n"
            ),
            "docs/guide.md": "# guide\n",
            "docs/a b.md": "# spaced\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_link_rule_reference_definition_is_checked(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        LINK_POLICY,
        {"README.md": "See [it][ref].\n\n[ref]: docs/missing.md\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "docs/missing.md -> no such file" in result.stderr


def test_link_rule_require_any_link_refuses_an_empty_selection(tmp_path: Path) -> None:
    # A narrowed glob and a repository that stopped linking look identical, and
    # only one of them is fine.
    repo = make_repo(
        tmp_path,
        LINK_POLICY.replace("glob =", "require_any_link = true\nglob ="),
        {"README.md": "No links at all here.\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no longer covers anything" in result.stderr


def test_link_rule_require_any_link_refuses_a_glob_that_matches_nothing(
    tmp_path: Path,
) -> None:
    """The floor must fire when the selection is EMPTY, not only when it is linkless.

    This is the case the floor exists for and the one it used to miss. A glob typo
    selects zero files rather than the wrong ones, so "matched nothing" is the
    likeliest narrowing and was the only one that reported a clean pass. The
    sibling test above covers the other half -- files selected, no links in them --
    and passing that one alone is what made the hole invisible.
    """
    repo = make_repo(
        tmp_path,
        LINK_POLICY.replace("glob =", "require_any_link = true\nglob =").replace(
            '"*.md"', '"*.no-such-extension"'
        ),
        {"README.md": "See [it](docs/present.md).\n", "docs/present.md": "here\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "no longer covers anything" in result.stderr
    assert "selected 0 file(s)" in result.stderr


def test_link_rule_without_the_floor_tolerates_an_empty_selection(
    tmp_path: Path,
) -> None:
    """Without require_any_link, an empty selection is still silence, not a failure.

    The floor is opt-in, and it has to stay opt-in: most repositories in a fleet
    have nothing to link, and making the empty case fail by default would force
    them to adopt a check with a denominator of zero.
    """
    repo = make_repo(
        tmp_path,
        LINK_POLICY.replace('"*.md"', '"*.no-such-extension"'),
        {"README.md": "See [it](docs/missing.md).\n"},
    )
    assert run_engine(repo).returncode == 0


def test_link_rule_redacts_the_target_when_asked(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        "redact_matches = true\n" + LINK_POLICY,
        {"README.md": "See [it](docs/secret-name.md).\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "REDACTED_MATCH" in result.stderr
    assert "secret-name" not in result.stderr


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# --- [[rule]] baseline (path-only ratchet) ---------------------------------

_BASELINE_POLICY = """
[[rule]]
id = "no-todo"
message = "no TODO"
pattern = "TODO"
glob = ["*.py"]
include = ["src"]
baseline = "policy/todo-baseline.txt"
"""


def test_pattern_rule_baseline_grandfathers_a_listed_path(tmp_path: Path) -> None:
    """The whole point: a prohibition can land before its cleanup does."""
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# TODO: from before the rule\n",
            "policy/todo-baseline.txt": "# debt\nsrc/old.py\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


def test_pattern_rule_baseline_does_not_cover_an_unlisted_path(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# TODO: grandfathered\n",
            "src/new.py": "# TODO: fresh\n",
            "policy/todo-baseline.txt": "src/old.py\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "src/new.py" in result.stderr
    assert "src/old.py" not in result.stderr, "a listed path must not be reported"


def test_pattern_rule_baseline_tolerates_a_listed_path_getting_worse(
    tmp_path: Path,
) -> None:
    """Path-only, not count-based: internal growth is allowed by design.

    The trade is deliberate — a count baseline churns on reformatting, and a
    baseline that churns is one people stop reading.
    """
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# TODO one\n# TODO two\n# TODO three\n",
            "policy/todo-baseline.txt": "src/old.py\n",
        },
    )
    assert run_engine(repo).returncode == 0


def test_pattern_rule_baseline_reports_a_stale_entry(tmp_path: Path) -> None:
    """A listed path that no longer matches is the rule switched off for it."""
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# cleaned up\n",
            "policy/todo-baseline.txt": "src/old.py\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "stale baseline" in result.stderr
    assert "src/old.py" in result.stderr


def test_a_stale_entry_is_reported_even_while_other_paths_still_match(
    tmp_path: Path,
) -> None:
    """Both failures surface; the stale one must not hide behind the live one."""
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# cleaned up\n",
            "src/still.py": "# TODO: not yet\n",
            "policy/todo-baseline.txt": "src/old.py\nsrc/still.py\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "stale baseline" in result.stderr
    assert "src/old.py" in result.stderr


def test_pattern_rule_baseline_ignores_comments_and_blanks(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {
            "src/old.py": "# TODO: grandfathered\n",
            "policy/todo-baseline.txt": "# a comment\n\n   \nsrc/old.py\n",
        },
    )
    assert run_engine(repo).returncode == 0


def test_pattern_rule_baseline_normalizes_the_dot_slash_spelling(
    tmp_path: Path,
) -> None:
    """``include`` omitted means ``.``, and rg then echoes ``./src/old.py``.

    This is the same trap the size baseline hit: a baseline keyed the obvious way
    matched nothing, and the ratchet silently did not apply.
    """
    repo = make_repo(
        tmp_path,
        """
[[rule]]
id = "no-todo"
message = "no TODO"
pattern = "TODO"
glob = ["*.py"]
baseline = "policy/todo-baseline.txt"
""",
        {
            "src/old.py": "# TODO: grandfathered\n",
            "policy/todo-baseline.txt": "src/old.py\n",
        },
    )
    assert run_engine(repo).returncode == 0


def test_a_rule_without_a_baseline_is_unchanged(tmp_path: Path) -> None:
    """The feature is opt-in: no baseline key, no behaviour change."""
    repo = make_repo(
        tmp_path,
        """
[[rule]]
id = "no-todo"
message = "no TODO"
pattern = "TODO"
glob = ["*.py"]
include = ["src"]
""",
        {"src/old.py": "# TODO\n"},
    )
    assert run_engine(repo).returncode == 1


def test_a_missing_baseline_file_does_not_silently_pass(tmp_path: Path) -> None:
    """An unreadable baseline means no exemptions, not a free pass."""
    repo = make_repo(
        tmp_path,
        _BASELINE_POLICY,
        {"src/old.py": "# TODO\n"},
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "src/old.py" in result.stderr


def test_the_baseline_applies_in_redacted_mode_too(tmp_path: Path) -> None:
    """A rule must not mean different things depending on `redact_matches`."""
    repo = make_repo(
        tmp_path,
        "redact_matches = true\n" + _BASELINE_POLICY,
        {
            "src/old.py": "# TODO: grandfathered\n",
            "policy/todo-baseline.txt": "src/old.py\n",
        },
    )
    assert run_engine(repo).returncode == 0


def test_redacted_mode_still_reports_an_unlisted_path_and_a_stale_entry(
    tmp_path: Path,
) -> None:
    repo = make_repo(
        tmp_path,
        "redact_matches = true\n" + _BASELINE_POLICY,
        {
            "src/new.py": "# TODO: fresh\n",
            "src/gone.py": "# cleaned up\n",
            "policy/todo-baseline.txt": "src/gone.py\n",
        },
    )
    result = run_engine(repo)
    assert result.returncode == 1
    assert "src/new.py" in result.stderr
    assert "REDACTED_MATCH" in result.stderr, "the match itself stays redacted"
    assert "stale baseline" in result.stderr


def test_a_non_utf8_baseline_degrades_instead_of_crashing(tmp_path: Path) -> None:
    """``UnicodeDecodeError`` is a ``ValueError``, so ``except OSError`` misses it.

    An unreadable baseline must mean "no exemptions", the same as a missing one.
    It used to escape as a traceback, which is the policy checker failing in a way
    that says nothing about policy.
    """
    repo = make_repo(tmp_path, _BASELINE_POLICY, {"src/old.py": "# TODO\n"})
    (repo / "policy" / "todo-baseline.txt").write_bytes(b"\xff\xfe\n")

    result = run_engine(repo)
    assert result.returncode == 1, "no exemptions, so the match is still reported"
    assert "Traceback" not in result.stderr
    assert "src/old.py" in result.stderr


def test_a_non_utf8_size_baseline_degrades_instead_of_crashing(tmp_path: Path) -> None:
    """Same hole in the size loader, which this one was copied from."""
    repo = make_repo(
        tmp_path,
        """
[[size_rule]]
id = "no-big-files"
message = "too big"
max_lines = 5
glob = ["*.txt"]
baseline = "policy/size-baseline.txt"
include = ["."]
""",
        {"big.txt": "line\n" * 10},
    )
    (repo / "policy" / "size-baseline.txt").write_bytes(b"\xff\xfe\n")

    result = run_engine(repo)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "big.txt" in result.stderr


# --- language policy -------------------------------------------------------

def test_language_policy_is_off_until_configured(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        "",
        {"src/example.py": "const аdmin = 1;\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 0


def test_global_languages_accept_multiple_writing_systems(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'languages = ["en-US", "ja-JP"]\n',
        {"README.md": "The 在留資格 is ひらがな and カタカナ.\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 0, result.stderr


def test_global_language_rejects_a_letter_from_another_script(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'languages = ["en"]\n',
        {"src/example.js": "const аdmin = 1;\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 1
    assert "src/example.js:1:7" in result.stderr
    assert "Cyrillic" in result.stderr
    assert "U+0430" in result.stderr


def test_language_rule_adds_languages_only_for_matching_paths(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            languages = ["en"]

            [[language_rule]]
            id = "japanese-docs"
            languages = ["ja"]
            glob = ["docs/ja/**"]
        '''),
        {
            "docs/ja/guide.md": "設定ガイドです。\n",
            "src/example.py": "# 設定\n",
        },
    )

    result = run_engine(repo)

    assert result.returncode == 1
    assert "src/example.py" in result.stderr
    assert "docs/ja/guide.md" not in result.stderr


def test_path_only_language_rule_does_not_constrain_other_files(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        textwrap.dedent('''\
            [[language_rule]]
            id = "japanese-docs"
            languages = ["en", "ja"]
            include = ["docs/ja"]
        '''),
        {
            "docs/ja/guide.md": "English と日本語。\n",
            "fixtures/russian.txt": "Пример\n",
        },
    )

    result = run_engine(repo)

    assert result.returncode == 0, result.stderr


def test_language_policy_ignores_script_neutral_visible_unicode(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'languages = ["en"]\n',
        {"README.md": "ship 🚀 ├─ ℂ\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 0, result.stderr


def test_non_iso_language_name_is_a_policy_error_without_a_traceback(
    tmp_path: Path,
) -> None:
    repo = make_repo(
        tmp_path,
        'languages = ["english"]\n',
        {"README.md": "Qapla\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 2
    assert "unsupported ISO 639-1 language code 'english'" in result.stderr
    assert "Traceback" not in result.stderr


def test_language_findings_are_redacted_with_other_matches(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        'redact_matches = true\nlanguages = ["en"]\n',
        {"src/example.js": "const аdmin = 1;\n"},
    )

    result = run_engine(repo)

    assert result.returncode == 1
    assert "src/example.js:1:7" in result.stderr
    assert "[REDACTED_MATCH]" in result.stderr
    assert "CYRILLIC SMALL LETTER A" not in result.stderr


# --- files that are not UTF-8 ---------------------------------------------
#
# A repository may legitimately track one: a web page captured in the encoding
# its venue served, kept byte-for-byte because the bytes are the evidence.
# Shift_JIS 0x8F is the lead byte that found this.

NOT_UTF8 = b'<meta charset="Shift_JIS">\n<!-- FIXME \x8f\x41\x8f\x42 -->\n'


def make_git_repo(tmp_path: Path, policy_toml: str, files: dict[str, str]) -> Path:
    """A repo layout that is also a git repo, so .gitattributes can be read."""
    repo = make_repo(tmp_path, policy_toml, files)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    return repo


FIXME_POLICY = textwrap.dedent('''\
    [[rule]]
    id = "no-fixme"
    message = "No FIXME markers."
    pattern = 'FIXME'
    include = ["."]
    glob = ["*.html", "*.txt"]
''')


def test_a_match_inside_a_non_utf8_file_does_not_kill_the_run(
    tmp_path: Path,
) -> None:
    """It used to end the whole run, naming no rule and no file.

    The failure was not in reading the repository -- ripgrep searched the file
    perfectly well -- but in decoding ripgrep's OWN output, which contains the
    matching line as bytes. No exclusion could prevent it, because it happened
    after the search had already succeeded.
    """
    repo = make_repo(tmp_path, FIXME_POLICY, {"src/clean.txt": "clean\n"})
    (repo / "src" / "page.html").write_bytes(NOT_UTF8)

    result = run_engine(repo)

    assert "codec can't decode" not in result.stderr, result.stderr
    assert result.returncode == 1, result.stderr
    assert "no-fixme" in result.stdout + result.stderr
    assert "src/page.html" in result.stdout + result.stderr, "and it names the file"


def test_a_path_declared_not_text_is_skipped_and_counted(tmp_path: Path) -> None:
    """Skipping without saying so would claim a clean tree nobody examined."""
    repo = make_git_repo(tmp_path, FIXME_POLICY, {"src/clean.txt": "clean\n"})
    (repo / "src" / "page.html").write_bytes(NOT_UTF8)
    (repo / ".gitattributes").write_text("src/page.html -text\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)

    result = run_engine(repo)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "1 path(s) skipped: declared not text" in result.stdout
    assert "src/page.html" in result.stdout, "named, not merely counted"


def test_an_undeclared_non_utf8_file_is_still_searched(tmp_path: Path) -> None:
    """The declaration is what exempts a file -- not the encoding itself.

    Otherwise every rule could be evaded by committing a file the checker
    cannot decode, which is the opposite of what this is for.
    """
    repo = make_git_repo(tmp_path, FIXME_POLICY, {"src/clean.txt": "clean\n"})
    (repo / "src" / "page.html").write_bytes(NOT_UTF8)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)

    result = run_engine(repo)

    assert result.returncode == 1, "the FIXME inside it is still a finding"
    assert "skipped" not in result.stdout


def test_no_declaration_means_no_skip_line(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path, FIXME_POLICY, {"src/clean.txt": "clean\n"})
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr
    assert "skipped" not in result.stdout


def test_it_works_outside_a_git_repository(tmp_path: Path) -> None:
    """The declaration is optional; its absence is not a failure."""
    repo = make_repo(tmp_path, FIXME_POLICY, {"src/clean.txt": "clean\n"})
    result = run_engine(repo)
    assert result.returncode == 0, result.stderr


# Kept last on purpose: this block runs at import time under `python3 tests/…`,
# so any test defined below it would never make it into globals() and would be
# silently skipped — a suite that cannot fail for the tests it forgot to run.
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
