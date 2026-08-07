#!/usr/bin/env python3
"""Run repository policy checks with ripgrep.

Unified engine for rg-policy.toml rule evaluation.  Supports seven rule kinds:

  [[rule]]          — pattern-match (rg --regexp) that must find zero hits
  [[dynamic_rule]]  — values produced at runtime, each searched via rg
  [[size_rule]]     — source-file line-count limits with optional baseline ratchet
  [[path_rule]]     — regex matched against tracked file paths (no rg)
  [[require_rule]]  — pattern that *must* match in every selected file (must-find)
  [[link_rule]]      — Markdown links whose local targets must exist
  [[language_rule]]  — add languages for files selected by path/glob

Any ``[[rule]]`` may set ``multiline = true`` to match across line boundaries
(rg ``--multiline --multiline-dotall``).

Repos keep their own ``policy/rg-policy.toml``; this script is consumed as a
shared pre-commit / prek hook from the org's rg-policy repo.  A repo policy may
pull in bundled base rule sets shipped in this repo's ``policy/base/`` via a
top-level ``extends`` key (see below).

Dynamic-rule *sources* are extensible: built-in sources cover OS identity and
network metadata.  Repos that need custom sources (e.g. hostapd-silent-config,
private-captured-data) place a ``policy/sources.py`` next to their policy file.
That module must expose a ``SOURCES`` dict mapping source names to callables
that return ``dict[str, str]`` (a value may also be a ``Needle`` when it must
match whole words only).

Top-level policy-file keys:

  extends = ["hygiene"]   — merge bundled base rule sets from policy/base/*.toml
                             (resolved relative to this script, not the consuming
                             repo).  Repo rules override base rules sharing an id.
  disable_rules = ["id"]  — drop specific base rules by id.
  redact_matches = true   — use JSON rg mode and print [REDACTED_MATCH]
                             instead of raw match content (for repos with
                             sensitive data such as captured credentials)
  languages = ["en", ...] — declare ISO 639-1 language codes used throughout
                             the repo; matching [[language_rule]] entries add
                             to this set

Exit codes:
  0  all checks passed
  1  one or more policy violations
  2  infrastructure error (missing rg, bad TOML, unknown source, …)
"""

from __future__ import annotations

import fnmatch
import getpass
import functools
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
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import unquote


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

# Hostname segments that describe a machine's kind rather than its owner.
# Hostnames are compound — "debian-x8664-ARC" is a distro, an architecture and
# a product line — and only the distinguishing part says whose machine it is.
# Emitting the generic parts would fire on every legitimate mention of a distro
# or an architecture, which is how a rule earns a blanket opt-out.
GENERIC_HOSTNAME_SEGMENTS = frozenset({
    # distributions and operating systems
    "alma", "alpine", "arch", "archlinux", "armbian", "bsd", "cachyos",
    "centos", "darwin", "debian", "endeavour", "endeavouros", "fedora",
    "gentoo", "kali", "linux", "macos", "manjaro", "mint", "nix", "nixos",
    "openwrt", "opensuse", "pop", "popos", "raspbian", "redhat", "rhel",
    "rocky", "suse", "ubuntu", "unix", "void", "windows",
    # architectures
    "aarch64", "amd64", "arm", "arm64", "i386", "i686", "riscv", "riscv64",
    "x86", "x8664", "x64",
    # roles, form factors and other machine-kind words
    "box", "build", "builder", "cloud", "desktop", "dev", "gateway",
    "guest", "home", "host", "lab", "laptop", "local", "machine", "main",
    "media", "nas", "node", "router", "server", "srv", "test", "virt",
    "workstation",
})

# Shortest hostname segment worth searching for. Two characters collide with
# far too much ordinary text even under whole-word matching.
MIN_HOSTNAME_SEGMENT_LEN = 3

# ISO 639-1 language codes are the policy surface; Unicode scripts are the
# mechanism. Region subtags are accepted by resolve_language_scripts(), so
# `pt-BR` and `pt-PT` both inherit `pt` without pretending that locale is
# relevant to homoglyph detection.
ISO_639_1_SCRIPTS: dict[str, tuple[str, ...]] = {
    "af": ("Latin",),
    "am": ("Ethiopic",),
    "ar": ("Arabic",),
    "az": ("Latin", "Cyrillic", "Arabic"),
    "bn": ("Bengali",),
    "bg": ("Cyrillic",),
    "bs": ("Latin", "Cyrillic"),
    "ca": ("Latin",),
    "cs": ("Latin",),
    "cy": ("Latin",),
    "da": ("Latin",),
    "de": ("Latin",),
    "el": ("Greek",),
    "en": ("Latin",),
    "es": ("Latin",),
    "et": ("Latin",),
    "eu": ("Latin",),
    "fa": ("Arabic",),
    "fi": ("Latin",),
    "fr": ("Latin",),
    "ga": ("Latin",),
    "gl": ("Latin",),
    "gu": ("Gujarati",),
    "he": ("Hebrew",),
    "hi": ("Devanagari",),
    "hr": ("Latin",),
    "hu": ("Latin",),
    "hy": ("Armenian",),
    "id": ("Latin",),
    "is": ("Latin",),
    "it": ("Latin",),
    "ja": ("Han", "Hiragana", "Katakana"),
    "ka": ("Georgian",),
    "km": ("Khmer",),
    "kn": ("Kannada",),
    "ko": ("Hangul", "Han"),
    "lo": ("Lao",),
    "lt": ("Latin",),
    "lv": ("Latin",),
    "ml": ("Malayalam",),
    "ms": ("Latin",),
    "mt": ("Latin", "Arabic"),
    "my": ("Myanmar",),
    "nl": ("Latin",),
    "no": ("Latin",),
    "pa": ("Gurmukhi",),
    "pl": ("Latin",),
    "pt": ("Latin",),
    "ro": ("Latin",),
    "ru": ("Cyrillic",),
    "si": ("Sinhala",),
    "sk": ("Latin",),
    "sl": ("Latin",),
    "sq": ("Latin",),
    "sr": ("Cyrillic", "Latin"),
    "sv": ("Latin",),
    "sw": ("Latin",),
    "ta": ("Tamil",),
    "te": ("Telugu",),
    "th": ("Thai",),
    "tl": ("Latin",),
    "tr": ("Latin",),
    "uk": ("Cyrillic",),
    "ur": ("Arabic",),
    "vi": ("Latin",),
    "zh": ("Han", "Bopomofo"),
}

# Tokens are matched against unicodedata.name(). Python's standard library does
# not expose the Unicode Script property, and rg-policy deliberately has no
# runtime dependencies. Unknown names fall back to Common (permitted), making
# this opt-in check conservative instead of blindly rejecting visible Unicode
# that it cannot classify.
SCRIPT_TOKENS: dict[str, tuple[str, ...]] = {
    "Arabic": ("ARABIC",),
    "Armenian": ("ARMENIAN",),
    "Bengali": ("BENGALI",),
    "Bopomofo": ("BOPOMOFO",),
    "Cyrillic": ("CYRILLIC",),
    "Devanagari": ("DEVANAGARI",),
    "Ethiopic": ("ETHIOPIC",),
    "Georgian": ("GEORGIAN",),
    "Greek": ("GREEK",),
    "Gujarati": ("GUJARATI",),
    "Gurmukhi": ("GURMUKHI",),
    "Han": ("CJK", "IDEOGRAPHIC", "KANGXI RADICAL"),
    "Hangul": ("HANGUL",),
    "Hebrew": ("HEBREW",),
    "Hiragana": ("HIRAGANA", "HENTAIGANA"),
    "Kannada": ("KANNADA",),
    "Katakana": ("KATAKANA",),
    "Khmer": ("KHMER",),
    "Lao": ("LAO",),
    "Latin": ("LATIN",),
    "Malayalam": ("MALAYALAM",),
    "Myanmar": ("MYANMAR",),
    "Sinhala": ("SINHALA",),
    "Tamil": ("TAMIL",),
    "Telugu": ("TELUGU",),
    "Thai": ("THAI",),
}

_SCRIPT_TOKEN_LOOKUP: tuple[tuple[str, str], ...] = tuple(
    sorted(
        (
            (token, script)
            for script, tokens in SCRIPT_TOKENS.items()
            for token in tokens
        ),
        key=lambda pair: -len(pair[0]),
    )
)


class Needle(NamedTuple):
    """One runtime value to search for, and how it should be matched.

    ``word`` asks rg for whole-word matching (``--word-regexp``). It exists for
    needles short enough to occur inside unrelated words: the hostname segment
    ``arc`` is a substring of ``search``, so a plain fixed-string search for it
    would fire on ordinary prose. Needles that are *meant* to be found inside a
    larger token must leave it false — a separator-less MAC has to keep matching
    inside an interface name like ``wlx7c3d095094a9``, which is the spelling it
    leaks in.
    """

    value: str
    word: bool = False


# A source may return plain strings; they normalise to substring needles.
SourceValues = dict[str, "str | Needle"]


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

# Rule-kind keys, in evaluation order.  Shared by the merge step and main().
RULE_KIND_KEYS = (
    "rule",
    "dynamic_rule",
    "size_rule",
    "path_rule",
    "require_rule",
    "link_rule",
    "language_rule",
)

# Bundled base rule sets ship inside *this* (the hook) repo, resolved relative
# to the script — not ROOT, which is the consuming repo.
BASE_DIR = Path(__file__).resolve().parent / "policy" / "base"


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as toml_file:
        return tomllib.load(toml_file)


def _merge_rule_kind(
    base: list[dict[str, Any]],
    repo: list[dict[str, Any]],
    disabled: set[str],
) -> list[dict[str, Any]]:
    """Merge one rule kind: base rules first, then repo rules.

    A repo rule overrides a base rule sharing the same ``id``; ids listed in
    ``disabled`` drop the matching base rule.  Entries without an ``id`` are
    kept verbatim.
    """
    repo_ids = {rule["id"] for rule in repo if "id" in rule}
    merged: list[dict[str, Any]] = []
    for rule in base:
        rule_id = rule.get("id")
        if rule_id is not None and (rule_id in disabled or rule_id in repo_ids):
            continue
        merged.append(rule)
    merged.extend(repo)
    return merged


def load_policy() -> dict[str, Any]:
    """Load the repo policy, merging any bundled base sets named in ``extends``.

    Top-level ``extends = ["hygiene", ...]`` pulls in ``policy/base/<name>.toml``
    from the hook repo; ``disable_rules = ["id", ...]`` opts out of base rules by
    id.  Repo-defined rules override base rules sharing the same id.
    """
    policy = _load_toml(POLICY_PATH)

    extends = policy.get("extends", [])
    if not extends:
        return policy
    if not isinstance(extends, list):
        raise ValueError(f"{POLICY_PATH}: 'extends' must be a list of base names")

    disabled = set(policy.get("disable_rules", []))

    bases: dict[str, list[dict[str, Any]]] = {key: [] for key in RULE_KIND_KEYS}
    for name in extends:
        base_path = BASE_DIR / f"{name}.toml"
        if not base_path.is_file():
            raise ValueError(
                f"{POLICY_PATH}: unknown base rule set {name!r} (expected {base_path})"
            )
        base_policy = _load_toml(base_path)
        for key in RULE_KIND_KEYS:
            bases[key].extend(base_policy.get(key, []))

    for key in RULE_KIND_KEYS:
        repo_rules = policy.get(key, [])
        if not isinstance(repo_rules, list):
            raise ValueError(f"{POLICY_PATH}: expected [[{key}]] entries")
        policy[key] = _merge_rule_kind(bases[key], repo_rules, disabled)

    return policy


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


@functools.lru_cache(maxsize=1)
def not_text_paths() -> tuple[str, ...]:
    """Tracked paths this repository declares are NOT TEXT, in .gitattributes.

    `-text` is git's own way of saying a file is not text, and a repository that
    tracks captured artifacts has a real use for it: a web page kept byte-for-
    byte in the encoding its venue served, where the bytes are the evidence and
    re-encoding them to please a checker would destroy what the file is for.

    Content rules are about text somebody wrote. Running them over a document
    nobody here authored produces findings against a third party's prose at
    best, and at worst suggests re-encoding the artifact -- so a file declared
    not-text is skipped, and the count is REPORTED rather than passed over in
    silence. A checker that quietly ignores what it could not read is claiming a
    clean tree it never examined.
    """
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z"],
            check=False,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if listed.returncode != 0 or not listed.stdout:
            return ()
        attrs = subprocess.run(
            ["git", "check-attr", "--stdin", "-z", "text"],
            check=False,
            cwd=ROOT,
            input=listed.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if attrs.returncode != 0:
            return ()
    except OSError:
        # No git, or no repository. Not an error: the declaration is optional
        # and its absence means nothing is declared, not that something failed.
        return ()
    fields = attrs.stdout.split(b"\0")
    found: list[str] = []
    # `check-attr -z` emits path, attribute, value as three NUL-separated fields.
    for index in range(0, len(fields) - 2, 3):
        if fields[index + 2] == b"unset":
            found.append(fields[index].decode("utf-8", errors="surrogateescape"))
    return tuple(found)


def not_text_globs() -> list[str]:
    """`--glob !path` for every path declared not-text."""
    args: list[str] = []
    for path in not_text_paths():
        args.extend(["--glob", f"!{path}"])
    return args


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


def multiline_args(rule: dict[str, Any]) -> list[str]:
    """Enable cross-line matching when a rule sets ``multiline = true``."""
    if rule.get("multiline"):
        return ["--multiline", "--multiline-dotall"]
    return []


def rg_command(rule: dict[str, Any]) -> list[str]:
    return [
        *RG_SEARCH_BASE,
        *multiline_args(rule),
        *glob_args(rule),
        # AFTER the rule's own globs, because ripgrep lets the LAST matching
        # glob win: an exclusion placed first is undone by any rule that then
        # includes the pattern the file happens to match. Caught by the test --
        # the file was reported as skipped and searched anyway.
        *not_text_globs(),
        "--regexp",
        rule["pattern"],
        *include_args(rule),
    ]


def literal_rg_command(rule: dict[str, Any], needle: Needle) -> list[str]:
    return [
        *RG_SEARCH_BASE,
        "--fixed-strings",
        *(["--word-regexp"] if needle.word else []),
        *glob_args(rule),
        *not_text_globs(),  # last: see rg_command
        "--regexp",
        needle.value,
        *include_args(rule),
    ]


def rg_files_command(rule: dict[str, Any]) -> list[str]:
    return [
        "rg",
        "--files",
        *glob_args(rule),
        *not_text_globs(),  # last: see rg_command
        *include_args(rule),
    ]


def run_rg_line(cmd: list[str], label: str) -> str:
    """Run rg in line-output mode.  Returns stdout; raises on exit > 1.

    DECODED LENIENTLY, because this is ripgrep's output and not the policy's
    input. A repository may legitimately track a file that is not UTF-8 -- a web
    page captured in Shift_JIS, kept byte-for-byte because its encoding is part
    of the evidence -- and when a rule matches inside one, rg prints the matching
    line as bytes. Decoding that strictly killed the ENTIRE run with
    `'utf-8' codec can't decode byte 0x8f`, naming no rule and no file, and no
    exclusion could prevent it: the failure happened while reading rg's stdout,
    long after the search had already succeeded.

    `replace` rather than `surrogateescape`: this string is printed to a
    terminal, and a surrogate would move the same crash to the report.
    """
    completed = subprocess.run(
        cmd,
        check=False,
        cwd=ROOT,
        encoding="utf-8",
        errors="replace",
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
    multiline: bool = False,
    word: bool = False,
) -> list[Finding]:
    """Run rg in JSON mode against an explicit file list, with chunking."""
    findings: list[Finding] = []
    for start in range(0, len(files), RG_FILE_CHUNK_SIZE):
        chunk = files[start : start + RG_FILE_CHUNK_SIZE]
        cmd = ["rg", "--json", "--color", "never"]
        if multiline:
            cmd.extend(["--multiline", "--multiline-dotall"])
        if fixed_strings:
            cmd.append("--fixed-strings")
        if word:
            cmd.append("--word-regexp")
        cmd.extend(["--regexp", pattern, "--"])
        cmd.extend(chunk)

        completed = subprocess.run(
            cmd,
            check=False,
            cwd=ROOT,
            # See run_rg_line: a tracked file that is not UTF-8 must not be able
            # to kill the run through rg's own output.
            encoding="utf-8",
            errors="replace",
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
    if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern):
        return True
    # gitignore-style `**/` may match zero leading directories, which fnmatch
    # does not model.  Retry with the prefix stripped so `**/tests/**` also
    # matches a top-level `tests/...` path (keeps redacted-mode globbing aligned
    # with rg's line-mode `--glob` semantics).
    if pattern.startswith("**/"):
        return _matches_glob(path, pattern[3:])
    return False


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
# Language policy
# ---------------------------------------------------------------------------

def _language_list(value: Any, context: str) -> list[str]:
    """Validate one TOML language list and return normalized declarations."""
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(
            f"{POLICY_PATH}: {context} must be a list of ISO 639-1 language codes"
        )
    return [item.strip() for item in value if item.strip()]


def resolve_language_scripts(languages: list[str], context: str) -> frozenset[str]:
    """Resolve ISO 639-1 codes or BCP-47 tags based on them to Unicode scripts."""
    scripts: set[str] = set()
    for language in languages:
        normalized = language.casefold().replace("_", "-")
        mapped = ISO_639_1_SCRIPTS.get(normalized)
        if mapped is None and "-" in normalized:
            mapped = ISO_639_1_SCRIPTS.get(normalized.split("-", 1)[0])
        if mapped is None:
            known = ", ".join(sorted(ISO_639_1_SCRIPTS))
            raise ValueError(
                f"{POLICY_PATH}: {context} names unsupported ISO 639-1 language "
                f"code {language!r}; supported codes: {known}"
            )
        scripts.update(mapped)
    return frozenset(scripts)


def unicode_script(char: str) -> str:
    """Return a known script for a letter, or Common when classification is unsafe."""
    name = unicodedata.name(char, "")
    for token, script in _SCRIPT_TOKEN_LOOKUP:
        if token in name:
            return script
    return "Common"


def language_policy_failures(
    policy: dict[str, Any],
    files: list[str],
    *,
    redacted: bool = False,
) -> list[Failure]:
    """Reject letters outside the languages declared globally or for a path.

    Top-level ``languages`` apply everywhere. Every matching
    ``[[language_rule]]`` adds its languages for that file; additive semantics
    let a repository keep English globally while admitting Japanese only below
    ``docs/ja/**``. With neither form configured, the policy is entirely off.
    """
    global_languages = _language_list(policy.get("languages"), "'languages'")
    scoped_rules = rule_list(policy, "language_rule")
    if not global_languages and not scoped_rules:
        return []

    global_scripts = resolve_language_scripts(global_languages, "'languages'")
    resolved_rules: list[tuple[dict[str, Any], list[str], frozenset[str]]] = []
    for index, rule in enumerate(scoped_rules, start=1):
        languages = _language_list(
            rule.get("languages"), f"language_rule #{index} 'languages'"
        )
        if not languages:
            raise ValueError(
                f"{POLICY_PATH}: language_rule #{index} must declare at least one language"
            )
        scripts = resolve_language_scripts(
            languages, f"language_rule #{index} 'languages'"
        )
        resolved_rules.append((rule, languages, scripts))

    findings: list[str] = []
    for rel in files:
        effective_languages = list(global_languages)
        effective_scripts = set(global_scripts)
        matched_scope = False
        for rule, languages, scripts in resolved_rules:
            if selected_files(rule, [rel]):
                matched_scope = True
                effective_languages.extend(languages)
                effective_scripts.update(scripts)

        # A path-only configuration does not implicitly constrain every other
        # file. A global declaration does.
        if not global_languages and not matched_scope:
            continue

        try:
            text = (ROOT / rel).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        declared = ", ".join(dict.fromkeys(effective_languages))
        for lineno, line in enumerate(text.split("\n"), start=1):
            for column, char in enumerate(line, start=1):
                if not unicodedata.category(char).startswith("L"):
                    continue
                script = unicode_script(char)
                if script == "Common" or script in effective_scripts:
                    continue
                detail = (
                    "[REDACTED_MATCH]"
                    if redacted
                    else f"U+{ord(char):04X} {unicodedata.name(char, 'UNKNOWN')}"
                )
                findings.append(
                    f"{rel}:{lineno}:{column}: {detail} -- script {script} is not "
                    f"declared by the applicable languages ({declared})"
                )

    if not findings:
        return []
    return [(
        "unicode-languages",
        """
        A visible letter uses a Unicode script outside the languages declared
        for its path. Add the language globally or in a matching
        [[language_rule]] when the text is intentional.
        """,
        "\n".join(findings),
    )]


# ---------------------------------------------------------------------------
# Size-rule helpers
# ---------------------------------------------------------------------------

def _normalize_rel(path: str) -> str:
    """Repo-relative path in one spelling, so a baseline lookup can match.

    ``rg --files`` echoes the search roots it was given, so the same file is
    ``TEST_SCENARIOS.md`` under ``include = ["src"]``-style roots and
    ``./TEST_SCENARIOS.md`` under ``include = ["."]`` — which is also the
    *default* when a rule omits ``include``. A baseline keyed the obvious way
    then matched nothing, and the ratchet silently did not apply: every
    grandfathered file reported as a fresh violation, whose natural "fix" is to
    raise ``max_lines`` and switch the rule off for everyone.
    """
    normalized = path.strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _load_size_baseline(rel_path: str | None) -> dict[str, int]:
    """Load the grandfathered file-size debt as ``{path: max_allowed_lines}``."""
    baseline: dict[str, int] = {}
    if not rel_path:
        return baseline
    try:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # UnicodeDecodeError is a ValueError, not an OSError, so a baseline that
        # is not UTF-8 used to escape as a traceback rather than degrading. An
        # unreadable baseline means no exemptions — the same answer as a missing
        # one, and never a free pass.
        return baseline
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path_part, _, count_part = line.rpartition(" ")
        try:
            baseline[_normalize_rel(path_part)] = int(count_part)
        except ValueError:
            continue
    return baseline


def _load_path_baseline(rel_path: str | None) -> set[str]:
    """Load a path-only baseline: one repo-relative path per line.

    Paths rather than counts, deliberately. A count baseline is stricter, but a
    reformat moves a match count without anything real changing, and a rule whose
    baseline churns on unrelated edits is one people stop reading. A listed path
    may get worse internally; what it cannot do is let a *new* path start.
    """
    baseline: set[str] = set()
    if not rel_path:
        return baseline
    try:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # UnicodeDecodeError is a ValueError, not an OSError, so a baseline that
        # is not UTF-8 used to escape as a traceback rather than degrading. An
        # unreadable baseline means no exemptions — the same answer as a missing
        # one, and never a free pass.
        return baseline
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        baseline.add(_normalize_rel(line))
    return baseline


def split_baselined(stdout: str, baseline: set[str]) -> tuple[str, set[str]]:
    """Split rg output into (matches outside the baseline, baselined paths hit).

    The second half is what makes a stale entry detectable: a listed path that
    produced no match is debt that has been paid without the list being updated,
    and an entry that no longer describes the tree is the check switched off for
    that path.
    """
    kept: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        match = RG_MATCH_RE.match(line)
        if match is None:
            kept.append(line)
            continue
        rel = _normalize_rel(match["path"])
        if rel in baseline:
            seen.add(rel)
            continue
        kept.append(line)
    return "\n".join(kept), seen


#: Explains a baseline entry that no longer matches. Separate from the rule's own
#: message, which explains the prohibition — a stale entry is a different problem
#: and telling someone the prohibition again does not help them fix it.
STALE_BASELINE_MESSAGE = (
    "This rule's baseline lists paths that no longer match it. Delete them: an "
    "entry that no longer describes the tree is the rule switched off for that "
    "path, and it will stay off if the file ever regains a match."
)


def _stale_baseline_failure(
    rule: dict[str, Any], baseline: set[str], seen: set[str]
) -> list[Failure]:
    stale = sorted(baseline - seen)
    if not stale:
        return []
    body = "\n".join(f"{path}: no longer matches (drop from baseline)" for path in stale)
    return [(f"{rule['id']} (stale baseline)", STALE_BASELINE_MESSAGE, body)]


#: The must-find counterpart. A ``[[require_rule]]`` baseline lists paths allowed
#: to be MISSING the pattern, so an entry goes stale the other way round: the
#: path acquired what the rule requires, the debt is paid, and the entry now only
#: hides the file losing it again.
STALE_REQUIRE_BASELINE_MESSAGE = (
    "This rule's baseline lists paths that no longer need the exemption -- they "
    "satisfy the rule now, or they are gone. Delete them: an entry that no "
    "longer describes the tree is the requirement switched off for that path if "
    "the pattern ever disappears again."
)


def _stale_require_baseline_failure(
    rule: dict[str, Any], baseline: set[str], still_missing: set[str]
) -> list[Failure]:
    stale = sorted(baseline - still_missing)
    if not stale:
        return []
    body = "\n".join(
        f"{path}: satisfied or gone (drop from baseline)" for path in stale
    )
    return [(f"{rule['id']} (stale baseline)", STALE_REQUIRE_BASELINE_MESSAGE, body)]


def _line_count(path: Path) -> int:
    """Newline count, matching ``wc -l``."""
    return path.read_bytes().count(b"\n")


# ---------------------------------------------------------------------------
# Built-in dynamic-rule sources
# ---------------------------------------------------------------------------

def _add_metadata_value(
    values: SourceValues,
    label: str,
    value: str | None,
    *,
    word: bool = False,
) -> None:
    if value is None:
        return
    value = value.strip()
    if not value or value in {".", "localhost", "localhost.localdomain"}:
        return
    if label.startswith("hostname") and value.lower() in KNOWN_PUBLIC_IDENTITY_TOKENS:
        return
    values[label] = Needle(value, word)


def hostname_segments(hostname: str) -> list[str]:
    """The distinguishing parts of ``hostname``, lowercased, in order.

    Searching only for the whole hostname misses the spelling that actually
    reaches a fixture. Machines are named in parts — ``debian-x8664-ARC`` —
    and what gets typed into a DHCP reservation or a test is one part, ``arc``.
    That fragment is every bit as identifying as the whole: it is the operator's
    hardware, and it is what a reader recognises.

    Only the parts that could name a *particular* machine are returned. Distro,
    architecture and role words are dropped via GENERIC_HOSTNAME_SEGMENTS,
    because a repo may legitimately talk about ``arch`` or ``arm64``, and a rule
    that fires on those gets disabled wholesale rather than fixed.
    """
    label = hostname.split(".", 1)[0]
    segments: list[str] = []
    for raw in re.split(r"[-_]+", label):
        segment = raw.lower()
        if len(segment) < MIN_HOSTNAME_SEGMENT_LEN or segment.isdigit():
            continue
        if segment in GENERIC_HOSTNAME_SEGMENTS or segment in KNOWN_PUBLIC_IDENTITY_TOKENS:
            continue
        if segment == label.lower():
            continue  # already searched for whole, as "hostname"
        if segment not in segments:
            segments.append(segment)
    return segments


def source_running_os_identity() -> SourceValues:
    """Username, home path, hostname (and its parts) of the running OS."""
    values: SourceValues = {}
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
    for segment in hostname_segments(hostname):
        # Whole-word: these are short enough to sit inside unrelated words.
        _add_metadata_value(values, f"hostname-segment ({segment})", segment, word=True)

    return values


def source_running_default_route() -> SourceValues:
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

    values: SourceValues = {}
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


def source_running_os_metadata() -> SourceValues:
    """Combined OS identity + default-route metadata."""
    values = source_running_os_identity()
    values.update(source_running_default_route())
    return values


BUILTIN_SOURCES: dict[str, Callable[[], SourceValues]] = {
    "running-os-identity": source_running_os_identity,
    "running-os-metadata": source_running_os_metadata,
    "running-default-route": source_running_default_route,
}


# ---------------------------------------------------------------------------
# Plugin discovery — repo-local policy/sources.py
# ---------------------------------------------------------------------------

_plugin_cache: dict[str, Callable[[], SourceValues]] | None = None


def _load_plugin_sources() -> dict[str, Callable[[], SourceValues]]:
    """Import ``policy/sources.py`` from the consuming repo, if present.

    The module must expose ``SOURCES: dict[str, Callable[[], dict[str, str]]]``;
    a value may also be a :class:`Needle` when it needs whole-word matching.
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


def _resolve_source(name: str) -> Callable[[], SourceValues]:
    """Look up a dynamic-rule source by name (built-in then plugin)."""
    source_fn = BUILTIN_SOURCES.get(name)
    if source_fn is not None:
        return source_fn

    plugin_sources = _load_plugin_sources()
    source_fn = plugin_sources.get(name)
    if source_fn is not None:
        return source_fn

    raise ValueError(f"{POLICY_PATH}: unknown dynamic rule source {name!r}")


def _as_needle(label: str, value: Any) -> Needle:
    """Coerce one source value to a :class:`Needle`.

    Matched structurally rather than with ``isinstance``, because a repo-local
    plugin doing ``from check_policy import Needle`` imports a *second* copy of
    this module — the engine runs as ``__main__`` — so the plugin's Needle is a
    different class than ours and would fail an identity check. Structure is
    what the engine actually needs.
    """
    if isinstance(value, str):
        return Needle(value)
    text = getattr(value, "value", None)
    if isinstance(text, str):
        return Needle(text, bool(getattr(value, "word", False)))
    raise TypeError(
        f"{POLICY_PATH}: dynamic-rule source produced a non-string value for "
        f"{label!r}: {value!r}"
    )


def dynamic_rule_values(rule: dict[str, Any]) -> dict[str, Needle]:
    """Resolve a rule's source and normalise every value to a :class:`Needle`.

    Sources predate the needle type and may still return plain strings, which
    keep the original substring semantics.
    """
    source = rule.get("source")
    return {
        label: _as_needle(label, value)
        for label, value in _resolve_source(source)().items()
    }


# ---------------------------------------------------------------------------
# Rule handlers — line mode (standard)
# ---------------------------------------------------------------------------

def pattern_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    stdout = run_rg_line(rg_command(rule), rule["id"])
    if rule.get("exclude_cfg_test"):
        stdout = drop_cfg_test_matches(stdout)

    failures: list[Failure] = []
    baseline = _load_path_baseline(rule.get("baseline"))
    if baseline:
        stdout, seen = split_baselined(stdout, baseline)
        failures.extend(_stale_baseline_failure(rule, baseline, seen))

    if stdout.strip():
        failures.append((rule["id"], rule["message"], stdout))
    return failures


def dynamic_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    failures: list[Failure] = []
    for label, needle in dynamic_rule_values(rule).items():
        full_label = f"{rule['id']} ({label})"
        stdout = run_rg_line(literal_rg_command(rule, needle), full_label)
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
        rel = _normalize_rel(rel)
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


def require_rule_failures(rule: dict[str, Any]) -> list[Failure]:
    """Evaluate a ``[[require_rule]]``: each selected file *must* match.

    Inverse of the zero-hit model — a violation is a selected file with zero
    matches (e.g. a shell script missing ``set -euo pipefail``).  Reports file
    paths only, so it is safe in redacted mode.

    ``baseline`` works here for the same reason it works for ``[[rule]]``, and
    it was needed more: a requirement lands only when every selected file
    already satisfies it, which is exactly when nobody needs the rule.  The
    entries list paths permitted to be missing the pattern, so an unlisted path
    can never start missing it.  Stale detection is inverted to match — an entry
    that now satisfies the rule is reported so it gets deleted.
    """
    files = selected_files(rule, candidate_files())
    if not files:
        return []
    base_cmd = ["rg", "--count-matches", "--color", "never"]
    base_cmd.extend(multiline_args(rule))
    if rule.get("fixed_strings"):
        base_cmd.append("--fixed-strings")
    base_cmd.extend(["--regexp", rule["pattern"], "--"])

    missing: list[str] = []
    for path in files:
        completed = subprocess.run(
            [*base_cmd, path],
            check=False,
            cwd=ROOT,
            # See run_rg_line.
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode > 1:
            raise PolicyCheckError(rule["id"], completed.returncode, completed.stderr)
        if completed.returncode == 1 or not completed.stdout.strip():
            missing.append(path)

    failures: list[Failure] = []
    baseline = _load_path_baseline(rule.get("baseline"))
    if baseline:
        still_missing = {_normalize_rel(path) for path in missing}
        failures.extend(_stale_require_baseline_failure(rule, baseline, still_missing))
        missing = [path for path in missing if _normalize_rel(path) not in baseline]

    if missing:
        body = "\n".join(f"{path}: required pattern not found" for path in sorted(missing))
        failures.append((rule["id"], rule["message"], body))
    return failures


# ---------------------------------------------------------------------------
# link_rule — the only kind that asks whether a match NAMES something
# ---------------------------------------------------------------------------

# A Markdown inline link or image target: the `(...)` half of `[text](target)`.
# Angle-bracket form `(<a target.md>)` is accepted because that is how Markdown
# escapes a space, and a target containing a space is otherwise unparseable.
_INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(\s*(?:<(?P<angled>[^>]*)>|(?P<bare>[^()\s]+))")

# A reference definition: `[id]: target "optional title"`.
_REFERENCE_LINK = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(?:<(?P<angled>[^>]*)>|(?P<bare>\S+))")

# A fenced code block opener/closer. Links inside a fence are illustrations, not
# references, and resolving them would fail on every README that documents a
# link. Tracked as state across lines rather than matched per line.
_FENCE = re.compile(r"^\s{0,3}(?P<fence>`{3,}|~{3,})")

# A target with a scheme is out of scope. Resolving it would need the network,
# which a pre-commit hook must not touch, and a hook that silently skips what it
# claims to check is worse than one that states the boundary.
_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _link_targets(text: str) -> list[tuple[int, str]]:
    """Extract ``(line_number, target)`` for every resolvable link in a document.

    Skips fenced code blocks, external schemes, and pure fragments. Returns the
    raw target; resolution is the caller's job.
    """
    found: list[tuple[int, str]] = []
    fence: str | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        opener = _FENCE.match(line)
        if opener:
            marker = opener.group("fence")
            if fence is None:
                fence = marker
                continue
            if marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue

        matches = [_REFERENCE_LINK.match(line)] if _REFERENCE_LINK.match(line) else []
        matches.extend(_INLINE_LINK.finditer(line))
        for match in matches:
            if match is None:
                continue
            target = match.group("angled")
            if target is None:
                target = match.group("bare")
            target = (target or "").strip()
            # A pure fragment points inside this same document; an empty target
            # is not a reference to anything.
            if not target or target.startswith("#"):
                continue
            if _HAS_SCHEME.match(target):
                continue
            found.append((lineno, target))
    return found


def _resolve_link(target: str, containing: str) -> Path:
    """Resolve a link target to a filesystem path.

    Relative to the containing file's directory, which is how every Markdown
    renderer reads it. A leading ``/`` is repository-root-relative, which is how
    the common hosting services render it -- not filesystem-absolute, and
    treating it as absolute would send the check outside the repository.
    """
    cleaned = target.split("#", 1)[0].split("?", 1)[0]
    cleaned = unquote(cleaned)
    if cleaned.startswith("/"):
        return ROOT / cleaned.lstrip("/")
    return (ROOT / containing).parent / cleaned


def link_rule_failures(rule: dict[str, Any], redacted: bool = False) -> list[Failure]:
    """Evaluate a ``[[link_rule]]``: every link target must exist.

    The only rule kind that asks whether a match NAMES something. The
    text-matching kinds ask whether text appears (``path_rule`` asking it of a
    path, ``size_rule`` counting lines instead); none of them reaches a link to a
    path that was moved or renamed, because the text stays well-formed and the
    only way to know is to go and look.

    Escaping the repository is reported separately from being absent, because the
    two have different fixes -- one is a broken path, the other is a link that
    cannot resolve for anyone who cloned this repository alone, however correct
    it looks in a wider checkout.
    """
    files = selected_files(rule, candidate_files())
    allow_outside = bool(rule.get("allow_outside_repo", False))
    findings: list[Finding] = []
    detailed: list[str] = []
    checked = 0

    for rel in sorted(files):
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, target in _link_targets(text):
            checked += 1
            resolved = _resolve_link(target, rel)
            try:
                inside = resolved.resolve().is_relative_to(ROOT.resolve())
            except OSError:
                inside = False
            if not inside:
                if allow_outside:
                    continue
                findings.append((rel, lineno))
                detailed.append(f"{rel}:{lineno}: {target} -> outside the repository")
            elif not resolved.exists():
                findings.append((rel, lineno))
                detailed.append(f"{rel}:{lineno}: {target} -> no such file")

    if rule.get("require_any_link") and not checked:
        # Opt-in floor. A selection that yields no links at all is usually a
        # narrowed glob rather than a repository that stopped linking, and a rule
        # covering nothing reports success exactly as loudly as one that works.
        #
        # `files` is deliberately NOT required to be non-empty. Requiring it meant
        # the floor fired when the glob still matched documents but none of them
        # linked, and was skipped entirely when the glob matched NOTHING -- which
        # is the most complete form of the narrowing this floor exists to catch,
        # and the likeliest, since a glob typo selects zero files rather than the
        # wrong ones. The hole let a rule that had stopped looking at the
        # repository altogether report a clean pass.
        return [
            (
                rule["id"],
                rule["message"],
                f"selected {len(files)} file(s) and found no resolvable link; "
                "the selection no longer covers anything",
            )
        ]

    if findings:
        body = _format_redacted_body(findings) if redacted else "\n".join(detailed)
        return [(rule["id"], rule["message"], body)]
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
    for label, needle in dynamic_rule_values(rule).items():
        findings = run_rg_json(
            needle.value,
            rule_files,
            fixed_strings=fixed_strings,
            word=needle.word,
        )
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
    findings = run_rg_json(
        rule["pattern"],
        rule_files,
        multiline=bool(rule.get("multiline")),
    )

    failures: list[Failure] = []
    # Applied here too, so a rule does not mean different things depending on
    # whether the repo sets `redact_matches`. A baseline that worked in one mode
    # and not the other is the kind of divergence nobody finds until it matters.
    baseline = _load_path_baseline(rule.get("baseline"))
    if baseline:
        seen = {_normalize_rel(path) for path, _ in findings if _normalize_rel(path) in baseline}
        findings = [f for f in findings if _normalize_rel(f[0]) not in baseline]
        failures.extend(_stale_baseline_failure(rule, baseline, seen))

    if findings:
        failures.append((rule["id"], rule["message"], _format_redacted_body(findings)))
    return failures


# ---------------------------------------------------------------------------
# Text mode — check something that never becomes a file
# ---------------------------------------------------------------------------

def run_rg_stdin(needle: Needle, text: str) -> list[tuple[str, str]]:
    """Search ``text`` for one needle. Returns (line number, line) pairs.

    rg rather than a Python search so text mode and file mode cannot disagree
    about what counts as a match — same engine, same flags, same needle.
    """
    cmd = ["rg", "--line-number", "--color", "never", "--fixed-strings"]
    if needle.word:
        cmd.append("--word-regexp")
    cmd.extend(["--regexp", needle.value, "-"])

    completed = subprocess.run(
        cmd, check=False, text=True, input=text, capture_output=True
    )
    if completed.returncode > 1:
        raise RuntimeError(completed.stderr.rstrip())

    hits: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        number, _, content = line.partition(":")
        hits.append((number, content))
    return hits


def text_failures(policy: dict[str, Any], text: str) -> list[Failure]:
    """Run every ``[[dynamic_rule]]``'s needles against arbitrary text.

    For the content that never lands in the tree and so is never scanned: a
    commit message, a pull-request body, release notes. Those are published the
    moment they are written, and a file-scanning checker cannot see them at all.

    Only dynamic rules apply. They are the ones whose needles describe the
    *running host* rather than a repository convention, so they are meaningful
    against any text. ``[[rule]]`` patterns are scoped by ``include``/``glob``
    to particular paths and file types; firing them at a PR body would be
    guesswork, and a guard that guesses gets turned off.
    """
    redacted = bool(policy.get("redact_matches", False))
    failures: list[Failure] = []
    for rule in rule_list(policy, "dynamic_rule"):
        for label, needle in dynamic_rule_values(rule).items():
            hits = run_rg_stdin(needle, text)
            if not hits:
                continue
            body = "\n".join(
                f"line {number}: " + ("[REDACTED_MATCH]" if redacted else content)
                for number, content in hits
            )
            failures.append((f"{rule['id']} ({label})", rule["message"], body))
    return failures


# Used when the caller's repository declares no dynamic rules of its own — or
# has no policy file at all. Text mode is reached from things like `gh pr
# create`, which runs wherever the author happens to be standing: a superproject
# that only tracks submodules, a scratch checkout, someone else's clone. Falling
# back to "nothing to check" there would leave the guard absent in exactly the
# places nobody thought to configure it, which is how identity gets published.
TEXT_FALLBACK_RULE: dict[str, Any] = {
    "id": "no-running-os-identity-metadata",
    "source": "running-os-identity",
    "message": (
        "Do not put identity metadata from the running OS into text that gets "
        "published. The policy checker reads the current username, home path, "
        "and hostname (including the identifying parts of it) at runtime, then "
        "searches the text you are about to send. Use neutral placeholders such "
        "as example-user, example-host, example.test, and /srv/example instead."
    ),
}


def check_text(source: str) -> int:
    """Entry point for ``--check-text``. ``source`` is a path, or ``-``."""
    try:
        text = sys.stdin.read() if source == "-" else Path(source).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as error:
        print(f"policy check failed: {error}", file=sys.stderr)
        return 2

    if POLICY_PATH.is_file():
        try:
            policy = load_policy()
        except (ValueError, tomllib.TOMLDecodeError, OSError) as error:
            print(f"policy check failed: {error}", file=sys.stderr)
            return 2
    else:
        policy = {}

    if not rule_list(policy, "dynamic_rule"):
        policy = {**policy, "dynamic_rule": [TEXT_FALLBACK_RULE]}

    try:
        failures = text_failures(policy, text)
    except (RuntimeError, ValueError) as error:
        print(f"policy check failed: {error}", file=sys.stderr)
        return 2

    for label, message, body in failures:
        report_failure(label, message, body)
    if failures:
        return 1
    print("policy checks passed (text)")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Standard rule kinds — line-mode rg, full match output.
RULE_KINDS: tuple[tuple[str, Callable[[dict[str, Any]], list[Failure]]], ...] = (
    ("rule", pattern_rule_failures),
    ("dynamic_rule", dynamic_rule_failures),
    ("size_rule", size_rule_failures),
    ("require_rule", require_rule_failures),
)


def main() -> int:
    if shutil.which("rg") is None:
        print(
            "policy check failed: ripgrep executable `rg` was not found",
            file=sys.stderr,
        )
        return 2

    argv = sys.argv[1:]
    if argv and argv[0] == "--check-text":
        return check_text(argv[1] if len(argv) > 1 else "-")
    if argv:
        print(f"usage: {Path(sys.argv[0]).name} [--check-text [FILE|-]]", file=sys.stderr)
        return 2

    if not POLICY_PATH.is_file():
        print(
            f"policy check failed: {POLICY_PATH} not found "
            f"(searched from {ROOT})",
            file=sys.stderr,
        )
        return 2

    try:
        policy = load_policy()
    except (ValueError, tomllib.TOMLDecodeError, OSError) as error:
        print(f"policy check failed: {error}", file=sys.stderr)
        return 2

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

            # size_rule and require_rule report paths only (no match content to
            # redact), so they run identically in both modes.
            for rule in rule_list(policy, "size_rule"):
                for label, message, body in size_rule_failures(rule):
                    failures += 1
                    report_failure(label, message, body)

            for rule in rule_list(policy, "require_rule"):
                for label, message, body in require_rule_failures(rule):
                    failures += 1
                    report_failure(label, message, body)

            # A broken link's target is the useful half of the report, so unlike
            # size_rule and require_rule this one does have match content to
            # redact and must be told which mode it is in.
            for rule in rule_list(policy, "link_rule"):
                for label, message, body in link_rule_failures(rule, redacted=True):
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

            for rule in rule_list(policy, "link_rule"):
                for label, message, body in link_rule_failures(rule):
                    failures += 1
                    report_failure(label, message, body)

        # Language rules combine globally and per path, so they are evaluated
        # once as a policy rather than independently like match rules.
        if policy.get("languages") or rule_list(policy, "language_rule"):
            files = candidate_files()
            for label, message, body in language_policy_failures(
                policy, files, redacted=bool(redacted)
            ):
                failures += 1
                report_failure(label, message, body)

    except PolicyCheckError as error:
        print(f"policy check error: {error.label}", file=sys.stderr)
        print(error.stderr.rstrip(), file=sys.stderr)
        return error.returncode
    except (RuntimeError, ValueError) as error:
        print(f"policy check error: {error}", file=sys.stderr)
        return 2

    skipped = not_text_paths()
    if skipped:
        # SAID ALOUD, ALWAYS. The point of skipping a declared artifact is that
        # content rules do not apply to it; the point of counting it is that
        # "we did not check these" and "these were clean" must never look the
        # same in this output.
        print(
            f"{len(skipped)} path(s) skipped: declared not text in .gitattributes"
        )
        for path in skipped:
            print(f"  {path}")

    if failures:
        return 1

    print("policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
