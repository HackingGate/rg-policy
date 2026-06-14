#!/usr/bin/env python3
"""Run repository policy checks with ripgrep.

Unified engine for rg-policy.toml rule evaluation.  Supports four rule kinds:

  [[rule]]          — pattern-match (rg --regexp) that must find zero hits
  [[dynamic_rule]]  — values produced at runtime, each searched via rg
  [[size_rule]]     — source-file line-count limits with optional baseline ratchet
  [[path_rule]]     — regex matched against tracked file paths (no rg)

Repos keep their own ``policy/rg-policy.toml``; this script is consumed as a
shared pre-commit / prek hook from the org's rg-policy repo.

Dynamic-rule *sources* are extensible: built-in sources cover OS identity and
network metadata.  Repos that need custom sources (e.g. hostapd-silent-config,
private-captured-data) place a ``policy/sources.py`` next to their policy file.
That module must expose a ``SOURCES`` dict mapping source names to callables
that return ``dict[str, str]``.

Top-level policy-file keys:

  redact_matches = true   — use JSON rg mode and print [REDACTED_MATCH]
                             instead of raw match content (for repos with
                             sensitive data such as captured credentials)

Exit codes:
  0  all checks passed
  1  one or more policy violations
  2  infrastructure error (missing rg, bad TOML, unknown source, …)
"""

from __future__ import annotations

import fnmatch
import getpass
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _discover_root() -> Path:
    """Walk up from cwd until we find ``policy/rg-policy.toml``."""
    candidate = Path.cwd().resolve()
    while True:
        if (candidate / "policy" / "rg-policy.toml").is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    # Fallback: cwd itself (let the TOML-open fail with a clear message).
    return Path.cwd().resolve()


ROOT = _discover_root()
POLICY_PATH = ROOT / "policy" / "rg-policy.toml"

# Maximum findings shown per rule in redacted mode.
MAX_FINDINGS_PER_RULE = 20

# When passing explicit file lists to rg, chunk to avoid ARG_MAX.
RG_FILE_CHUNK_SIZE = 150

# Users whose names should never be flagged as personal identity leaks.
KNOWN_PUBLIC_IDENTITY_TOKENS = {"runner"}


# ---------------------------------------------------------------------------
# Cfg-test exclusion (Rust)
# ---------------------------------------------------------------------------

CFG_TEST_RE = re.compile(r"#\[cfg\([^)]*\btest\b")
RG_MATCH_RE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):")


def cfg_test_line_set(path: Path) -> set[int]:
    """Return 1-based line numbers inside any ``#[cfg(test)]`` item.

    Inline ``#[cfg(test)] mod tests { … }`` blocks live in regular source
    files; a rule that opts into ``exclude_cfg_test`` filters them here by
    brace-counting each guarded item.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return set()

    test_lines: set[int] = set()
    count = len(lines)
    index = 0
    while index < count:
        if not CFG_TEST_RE.match(lines[index].lstrip()):
            index += 1
            continue
        depth = 0
        opened = False
        end = index
        while end < count:
            code = lines[end].split("//", 1)[0]
            depth += code.count("{") - code.count("}")
            if "{" in code:
                opened = True
            if opened and depth <= 0:
                break
            end += 1
        for line_number in range(index, min(end, count - 1) + 1):
            test_lines.add(line_number + 1)
        index = end + 1
    return test_lines


def drop_cfg_test_matches(stdout: str) -> str:
    """Drop rg matches that fall inside a ``#[cfg(test)]`` region."""
    cache: dict[str, set[int]] = {}
    kept: list[str] = []
    for line in stdout.splitlines():
        match = RG_MATCH_RE.match(line)
        if match and match["path"].endswith(".rs"):
            rel = match["path"]
            test_lines = cache.get(rel)
            if test_lines is None:
                test_lines = cfg_test_line_set(ROOT / rel)
                cache[rel] = test_lines
            if int(match["line"]) in test_lines:
                continue
        kept.append(line)
    return "\n".join(kept)


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

def load_policy() -> dict[str, Any]:
    with POLICY_PATH.open("rb") as policy_file:
        return tomllib.load(policy_file)


def rule_list(policy: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rules = policy.get(key, [])
    if not isinstance(rules, list):
        raise ValueError(f"{POLICY_PATH}: expected [[{key}]] entries")
    return rules


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

# A single failing finding: (label, message, body).
Failure = tuple[str, str, str]

# A single path-based finding: (path, optional line number).
Finding = tuple[str, int | None]


def report_failure(label: str, message: str, body: str) -> None:
    print(f"policy check failed: {label}", file=sys.stderr)
    print(textwrap.dedent(message).strip(), file=sys.stderr)
    print(body.rstrip(), file=sys.stderr)
    print(file=sys.stderr)


class PolicyCheckError(Exception):
    """An rg invocation exited > 1 (a real error, not just "no matches")."""

    def __init__(self, label: str, returncode: int, stderr: str) -> None:
        super().__init__(label)
        self.label = label
        self.returncode = returncode
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Ripgrep helpers — line-mode (standard output)
# ---------------------------------------------------------------------------

RG_SEARCH_BASE = ["rg", "--line-number", "--with-filename", "--color", "never"]


def glob_args(rule: dict[str, Any]) -> list[str]:
    """Build ``--glob`` / ``--glob !exclude`` flags."""
    args: list[str] = []
    for glob in rule.get("glob", []):
        args.extend(["--glob", glob])
    for glob in rule.get("exclude", []):
        args.extend(["--glob", f"!{glob}"])
    return args


def include_args(rule: dict[str, Any]) -> list[str]:
    return rule.get("include", ["."])


def rg_command(rule: dict[str, Any]) -> list[str]:
    return [*RG_SEARCH_BASE, *glob_args(rule), "--regexp", rule["pattern"], *include_args(rule)]


def literal_rg_command(rule: dict[str, Any], value: str) -> list[str]:
    return [
        *RG_SEARCH_BASE,
        "--fixed-strings",
        *glob_args(rule),
        "--regexp",
        value,
        *include_args(rule),
    ]


def rg_files_command(rule: dict[str, Any]) -> list[str]:
    return ["rg", "--files", *glob_args(rule), *include_args(rule)]


def run_rg_line(cmd: list[str], label: str) -> str:
    """Run rg in line-output mode.  Returns stdout; raises on exit > 1."""
    completed = subprocess.run(
        cmd,
        check=False,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode > 1:
        raise PolicyCheckError(label, completed.returncode, completed.stderr)
    return completed.stdout


# ---------------------------------------------------------------------------
# Ripgrep helpers — JSON mode (redacted output)
# ---------------------------------------------------------------------------

def run_rg_json(
    pattern: str,
    files: list[str],
    *,
    fixed_strings: bool = False,
) -> list[Finding]:
    """Run rg in JSON mode against an explicit file list, with chunking."""
    findings: list[Finding] = []
    for start in range(0, len(files), RG_FILE_CHUNK_SIZE):
        chunk = files[start : start + RG_FILE_CHUNK_SIZE]
        cmd = ["rg", "--json", "--color", "never"]
        if fixed_strings:
            cmd.append("--fixed-strings")
        cmd.extend(["--regexp", pattern, "--"])
        cmd.extend(chunk)

        completed = subprocess.run(
            cmd,
            check=False,
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if completed.returncode == 1:
            continue
        if completed.returncode > 1:
            raise RuntimeError(completed.stderr.rstrip())

        for line in completed.stdout.splitlines():
            event = json.loads(line)
            if event.get("type") != "match":
                continue
            data = event["data"]
            path = data["path"]["text"]
            line_number = data.get("line_number")
            findings.append((path, line_number))

    return _dedupe_findings(findings)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[Finding] = set()
    deduped: list[Finding] = []
    for finding in findings:
        if finding in seen:
            continue
        seen.add(finding)
        deduped.append(finding)
    return deduped


# ---------------------------------------------------------------------------
# Candidate-file enumeration (for JSON-mode / path_rule)
# ---------------------------------------------------------------------------

def candidate_files() -> list[str]:
    """List files visible to the repo (git ls-files, or filesystem walk)."""
    git_files = _git_candidate_files()
    if git_files:
        return git_files
    return _filesystem_candidate_files()


def _git_candidate_files() -> list[str]:
    if shutil.which("git") is None:
        return []
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=False,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        return []

    paths: set[str] = set()
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if (ROOT / path).is_file():
            paths.add(path)
    return sorted(paths)


def _filesystem_candidate_files() -> list[str]:
    ignored_dirs = {
        ".git",
        ".venv",
        "__pycache__",
        "artifacts",
        "coverage",
        "data",
        "dist",
        "traces",
    }
    paths: list[str] = []
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        rel_root = Path(root).relative_to(ROOT)
        for filename in files:
            rel_path = (rel_root / filename).as_posix()
            if rel_path == ".":
                rel_path = filename
            paths.append(rel_path)
    return sorted(paths)


def _matches_glob(path: str, pattern: str) -> bool:
    return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern)


def _matches_path_spec(path: str, spec: str) -> bool:
    if spec == ".":
        return True
    if any(char in spec for char in "*?["):
        return _matches_glob(path, spec)
    normalized = spec.rstrip("/")
    return path == normalized or path.startswith(f"{normalized}/")


def selected_files(rule: dict[str, Any], files: list[str]) -> list[str]:
    """Filter a file list by a rule's include / exclude / glob specs."""
    includes = rule.get("include", ["."])
    excludes = rule.get("exclude", [])
    globs = rule.get("glob", [])

    return [
        path
        for path in files
        if any(_matches_path_spec(path, inc) for inc in includes)
        and not any(_matches_glob(path, exc) for exc in excludes)
        and (not globs or any(_matches_glob(path, g) for g in globs))
    ]


# ---------------------------------------------------------------------------
# Size-rule helpers
# ---------------------------------------------------------------------------

def _load_size_baseline(rel_path: str | None) -> dict[str, int]:
    """Load the grandfathered file-size debt as ``{path: max_allowed_lines}``."""
    baseline: dict[str, int] = {}
    if not rel_path:
        return baseline
    try:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
    except OSError:
        return baseline
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path_part, _, count_part = line.rpartition(" ")
        try:
            baseline[path_part.strip()] = int(count_part)
        except ValueError:
            continue
    return baseline


def _line_count(path: Path) -> int:
    """Newline count, matching ``wc -l``."""
    return path.read_bytes().count(b"\n")


# ---------------------------------------------------------------------------
# Built-in dynamic-rule sources
# ---------------------------------------------------------------------------

def _add_metadata_value(
    values: dict[str, str],
    label: str,
    value: str | None,
) -> None:
    if value is None:
        return
    value = value.strip()
    if not value or value in {".", "localhost", "localhost.localdomain"}:
        return
    if label.startswith("hostname") and value.lower() in KNOWN_PUBLIC_IDENTITY_TOKENS:
        return
    values[label] = value


def source_running_os_identity() -> dict[str, str]:
    """Username, home path, hostname of the running OS."""
    values: dict[str, str] = {}
    user = getpass.getuser()
    home = str(Path.home())
    hostname = os.uname().nodename

    _add_metadata_value(values, "home-path", home)
    if user.lower() not in KNOWN_PUBLIC_IDENTITY_TOKENS:
        _add_metadata_value(values, "ssh-user-prefix", f"{user}@")
    if len(user) >= 4 and user.lower() not in KNOWN_PUBLIC_IDENTITY_TOKENS:
        _add_metadata_value(values, "username", user)

    _add_metadata_value(values, "hostname", hostname)
    if "." in hostname:
        _add_metadata_value(values, "hostname-label", hostname.split(".", 1)[0])

    return values


def source_running_default_route() -> dict[str, str]:
    """Default-route gateway/source addresses from ``ip -o -4 route``."""
    if shutil.which("ip") is None:
        return {}
    completed = subprocess.run(
        ["ip", "-o", "-4", "route", "show", "default"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=2,
    )
    if completed.returncode != 0:
        return {}

    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        for field in ("via", "src"):
            match = re.search(rf"(?:^|\s){field}\s+([0-9.]+)(?:\s|$)", line)
            if match is None:
                continue
            address = match.group(1)
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
                continue
            _add_metadata_value(values, f"default-route-{field}-{address}", address)
    return values


def source_running_os_metadata() -> dict[str, str]:
    """Combined OS identity + default-route metadata."""
    values = source_running_os_identity()
    values.update(source_running_default_route())
    return values


BUILTIN_SOURCES: dict[str, Callable[[], dict[str, str]]] = {
    "running-os-identity": source_running_os_identity,
    "running-os-metadata": source_running_os_metadata,
    "running-default-route": source_running_default_route,
}


# ---------------------------------------------------------------------------
# Plugin discovery — repo-local policy/sources.py
# ---------------------------------------------------------------------------

_plugin_cache: dict[str, Callable[[], dict[str, str]]] | None = None


def _load_plugin_sources() -> dict[str, Callable[[], dict[str, str]]]:
    """Import ``policy/sources.py`` from the consuming repo, if present.

    The module must expose ``SOURCES: dict[str, Callable[[], dict[str, str]]]``.
    """
    global _plugin_cache
    if _plugin_cache is not None:
        return _plugin_cache

    sources_path = ROOT / "policy" / "sources.py"
    if not sources_path.is_file():
        _plugin_cache = {}
        return _plugin_cache

    spec = importlib.util.spec_from_file_location("_rg_policy_sources", sources_path)
    if spec is None or spec.loader is None:
        _plugin_cache = {}
        return _plugin_cache

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        print(f"warning: failed to load {sources_path}: {exc}", file=sys.stderr)
        _plugin_cache = {}
        return _plugin_cache

    sources = getattr(module, "SOURCES", None)
    if not isinstance(sources, dict):
        print(
            f"warning: {sources_path} does not export a SOURCES dict",
            file=sys.stderr,
        )
        _plugin_cache = {}
        return _plugin_cache

    _plugin_cache = sources
    return _plugin_cache


def _resolve_source(name: str) -> Callable[[], dict[str, str]]:
    """Look up a dynamic-rule source by name (built-in then plugin)."""
    source_fn = BUILTIN_SOURCES.get(name)
    if source_fn is not None:
        return source_fn

    plugin_sources = _load_plugin_sources()
    source_fn = plugin_sources.get(name)
    if source_fn is not None:
        return source_fn

    raise ValueError(f"{POLICY_PATH}: unknown dynamic rule source {name!r}")


def dynamic_rule_values(rule: dict[str, Any]) -> dict[str, str]:
    source = rule.get("source")
    return _resolve_source(source)()


# ---------------------------------------------------------------------------
# Rule handlers — line mode (standard)
# ---------------------------------------------------------------------------

def pattern_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    stdout = run_rg_line(rg_command(rule), rule["id"])
    if rule.get("exclude_cfg_test"):
        stdout = drop_cfg_test_matches(stdout)
    if stdout.strip():
        return [(rule["id"], rule["message"], stdout)]
    return []


def dynamic_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    failures: list[Failure] = []
    for label, value in dynamic_rule_values(rule).items():
        full_label = f"{rule['id']} ({label})"
        stdout = run_rg_line(literal_rg_command(rule, value), full_label)
        if rule.get("exclude_cfg_test"):
            stdout = drop_cfg_test_matches(stdout)
        if stdout.strip():
            failures.append((full_label, rule["message"], stdout))
    return failures


def size_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    max_lines = int(rule["max_lines"])
    baseline = _load_size_baseline(rule.get("baseline"))
    stdout = run_rg_line(rg_files_command(rule), rule["id"])
    violations: list[str] = []
    for rel in stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        try:
            count = _line_count(ROOT / rel)
        except OSError:
            continue
        allowed = baseline.get(rel)
        if allowed is None:
            if count > max_lines:
                violations.append(f"{rel}: {count} lines (limit {max_lines})")
        elif count > allowed:
            violations.append(f"{rel}: {count} lines (baseline {allowed}; must not grow)")
    if violations:
        return [(rule["id"], rule["message"], "\n".join(sorted(violations)))]
    return []


# ---------------------------------------------------------------------------
# Rule handlers — JSON / file-list mode (path_rule, redacted)
# ---------------------------------------------------------------------------

def _format_redacted_body(findings: list[Finding]) -> str:
    """Format findings as redacted output lines."""
    lines: list[str] = []
    for path, line_number in findings[:MAX_FINDINGS_PER_RULE]:
        location = f"{path}:{line_number}" if line_number is not None else path
        lines.append(f"{location}: [REDACTED_MATCH]")
    remaining = len(findings) - MAX_FINDINGS_PER_RULE
    if remaining > 0:
        lines.append(f"... {remaining} additional redacted matches omitted")
    return "\n".join(lines)


def path_rule_failures_json(
    rule: dict[str, Any],
    files: list[str],
) -> list[Failure]:
    """Evaluate a ``[[path_rule]]``: regex against file paths, no rg."""
    pattern = re.compile(rule["pattern"])
    findings: list[Finding] = [(p, None) for p in files if pattern.search(p)]
    if findings:
        return [(rule["id"], rule["message"], _format_redacted_body(findings))]
    return []


def dynamic_rule_failures_json(
    rule: dict[str, Any],
    files: list[str],
) -> list[Failure]:
    """Evaluate a ``[[dynamic_rule]]`` in JSON/redacted mode."""
    failures: list[Failure] = []
    fixed_strings = rule.get("fixed_strings", True)
    rule_files = selected_files(rule, files)
    if not rule_files:
        return failures
    for label, value in dynamic_rule_values(rule).items():
        findings = run_rg_json(value, rule_files, fixed_strings=fixed_strings)
        if findings:
            full_label = f"{rule['id']} ({label})"
            failures.append((full_label, rule["message"], _format_redacted_body(findings)))
    return failures


def pattern_rule_failures_json(
    rule: dict[str, Any],
    files: list[str],
) -> list[Failure]:
    """Evaluate a ``[[rule]]`` in JSON/redacted mode."""
    rule_files = selected_files(rule, files)
    if not rule_files:
        return []
    findings = run_rg_json(rule["pattern"], rule_files)
    if findings:
        return [(rule["id"], rule["message"], _format_redacted_body(findings))]
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Standard rule kinds — line-mode rg, full match output.
RULE_KINDS: tuple[tuple[str, Callable[[dict[str, Any]], list[Failure]]], ...] = (
    ("rule", pattern_rule_failures),
    ("dynamic_rule", dynamic_rule_failures),
    ("size_rule", size_rule_failures),
)


def main() -> int:
    if shutil.which("rg") is None:
        print(
            "policy check failed: ripgrep executable `rg` was not found",
            file=sys.stderr,
        )
        return 2

    if not POLICY_PATH.is_file():
        print(
            f"policy check failed: {POLICY_PATH} not found "
            f"(searched from {ROOT})",
            file=sys.stderr,
        )
        return 2

    policy = load_policy()
    failures = 0

    # Determine output mode.  Repos that need redacted output set
    # ``redact_matches = true`` at the policy-file top level.
    redacted = policy.get("redact_matches", False)

    try:
        if redacted:
            # JSON / file-list mode — enumerate files once, redact matches.
            files = candidate_files()

            for rule in rule_list(policy, "rule"):
                for label, message, body in pattern_rule_failures_json(rule, files):
                    failures += 1
                    report_failure(label, message, body)

            for rule in rule_list(policy, "dynamic_rule"):
                for label, message, body in dynamic_rule_failures_json(rule, files):
                    failures += 1
                    report_failure(label, message, body)

            for rule in rule_list(policy, "path_rule"):
                rule_files = selected_files(rule, files)
                for label, message, body in path_rule_failures_json(rule, rule_files):
                    failures += 1
                    report_failure(label, message, body)

            # size_rule uses line mode regardless (no match content to redact).
            for rule in rule_list(policy, "size_rule"):
                for label, message, body in size_rule_failures(rule):
                    failures += 1
                    report_failure(label, message, body)

        else:
            # Standard line mode — full match output.
            for key, handler in RULE_KINDS:
                for rule in rule_list(policy, key):
                    for label, message, body in handler(rule):
                        failures += 1
                        report_failure(label, message, body)

            # path_rule always uses file enumeration, but shows full paths.
            path_rules = rule_list(policy, "path_rule")
            if path_rules:
                files = candidate_files()
                for rule in path_rules:
                    rule_files = selected_files(rule, files)
                    for label, message, body in path_rule_failures_json(rule, rule_files):
                        failures += 1
                        report_failure(label, message, body)

    except PolicyCheckError as error:
        print(f"policy check error: {error.label}", file=sys.stderr)
        print(error.stderr.rstrip(), file=sys.stderr)
        return error.returncode
    except RuntimeError as error:
        print(f"policy check error: {error}", file=sys.stderr)
        return 2

    if failures:
        return 1

    print("policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
