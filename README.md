# rg-policy

Reusable [pre-commit](https://pre-commit.com/) /
[prek](https://github.com/j178/prek) hook that enforces repository content
policies defined in `policy/rg-policy.toml` using
[ripgrep](https://github.com/BurntSushi/ripgrep).

## Rule Kinds

| TOML key | purpose |
|---|---|
| `[[rule]]` | pattern-match (rg `--regexp`) that must find zero hits, with optional path baseline |
| `[[dynamic_rule]]` | values produced at runtime, each searched via rg |
| `[[size_rule]]` | source-file line-count limits with optional baseline ratchet |
| `[[path_rule]]` | regex matched against tracked file paths (no rg) |
| `[[require_rule]]` | pattern that **must** match in every selected file (must-find) |
| `[[link_rule]]` | every documentation link must resolve to a path that exists |
| `[[language_rule]]` | add languages for files selected by path or glob |

Any `[[rule]]` may set `multiline = true` to match across line boundaries
(ripgrep `--multiline --multiline-dotall`).

## Checking Text That Never Becomes a File

```sh
check_policy.py --check-text -          # subject on stdin
check_policy.py --check-text BODY.md    # or a file
```

A commit message, a pull-request body, release notes. They are published the
moment they are written, and a checker that scans the working tree cannot see
them at all — which is how a hostname reaches a public repository from a machine
whose repository content was clean.

Same engine, same needles, same flags as file mode, so the two cannot drift into
disagreeing about what a match is. Two deliberate differences:

- **Only `[[dynamic_rule]]` applies.** Its needles describe the *running host*,
  so they are meaningful against any text. `[[rule]]` patterns are scoped by
  `include`/`glob` to particular paths and file types; firing them at a PR body
  would be guesswork, and a guard that guesses gets turned off.
- **It falls back to the built-in `running-os-identity` rule** when the
  repository declares no dynamic rules, or has no `policy/rg-policy.toml` at
  all. Text mode is called from things like `gh pr create`, which runs wherever
  the author happens to be standing — a superproject that only tracks
  submodules, a scratch checkout. "Nothing to check" there would leave the guard
  absent in exactly the places nobody thought to configure it.

This is the interface the other tiers call rather than reimplement:
[git-guards](https://github.com/HackingGate/git-guards) on the `commit-msg` path
and [cmd-shims](https://github.com/HackingGate/cmd-shims) on the
`gh pr create` path both shell out to it. A second implementation would be a
second rule that agrees with this one until it does not.

### Landing a rule before its cleanup

A `[[rule]]` means zero occurrences from the moment it lands, which keeps out the
rules most worth having: a prohibition usually gets written down *because* someone
noticed the tree is full of the thing. `baseline` is the way in — a file of
repo-relative paths, one per line, `#` comments ignored:

```toml
[[rule]]
id = "no-subprocess-outside-ports"
message = "Run commands through the Executor port."
pattern = '^\s*import subprocess'
glob = ["*.py"]
include = ["src"]
baseline = "policy/subprocess-baseline.txt"
```

Paths, not counts. A listed path may get worse internally; what it cannot do is
let an **unlisted** path start. The trade is deliberate — a count baseline is
stricter, but a reformat moves a count without anything real changing, and a
baseline that churns on unrelated edits is one people stop reading. (`[[size_rule]]`
keeps counts, because there the count *is* the thing being limited.)

**A stale entry is a failure.** A listed path that no longer matches is reported so
you delete it: an entry that no longer describes the tree is the rule switched off
for that path, and it stays off if the file ever regains a match. That check is
specific to `[[rule]]` baselines — `[[size_rule]]` leaves stale entries alone, and
changing that would go red for every existing consumer whose baseline has been paid
down without being tidied.

The baseline applies identically in redacted mode, so a rule does not mean
different things depending on whether the repo sets `redact_matches`.

## Usage

In a consuming repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/HackingGate/rg-policy
    rev: main
    hooks:
      - id: check-policy
```

Then `prek install` (or `pre-commit install`) and create
`policy/rg-policy.toml` with your rules — optionally building on the bundled
[base rule sets](#base-rule-sets).

## Policy File Format

```toml
# Optional: redact match content in output (for repos with sensitive data).
# redact_matches = true

[[rule]]
id = "no-hardcoded-home-paths"
message = """
Do not commit hardcoded user home paths.
"""
pattern = '(?:/home|/Users)/[A-Za-z0-9._-]+'
include = ["src", "scripts"]
exclude = ["**/tests/**"]
glob = ["*.rs", "*.py"]

[[dynamic_rule]]
id = "no-running-os-identity-metadata"
message = """
Do not commit identity metadata from the running OS.
"""
source = "running-os-identity"
include = ["src", "scripts"]
# Optional: exclude inline #[cfg(test)] regions in Rust files.
# exclude_cfg_test = true

[[size_rule]]
id = "no-oversized-source-files"
message = """
Keep source files under the line limit.
"""
max_lines = 800
glob = ["*.rs"]
baseline = "policy/file-size-baseline.txt"
include = ["src", "crates"]

[[path_rule]]
id = "no-tracked-private-data"
message = """
Do not commit ignored local data.
"""
pattern = '^(?:data/private|artifacts)(?:/|$)'
include = ["."]

[[require_rule]]
id = "scripts-set-strict-mode"
message = """
Shell scripts must enable strict mode: set -euo pipefail.
"""
pattern = 'set -euo pipefail'
include = ["."]
glob = ["*.sh"]
```

## Language Rules

Language policy is opt-in. Declare the languages used across the repository
with ISO 639-1 codes at the top level:

```toml
languages = ["en", "ja"]
```

The checker maps human languages to their Unicode writing systems and rejects
letters from a different, recognized script. This catches deceptive identifiers
such as a Cyrillic `а` in an otherwise English codebase without treating all
non-ASCII text as suspicious. Punctuation, numbers, emoji, mathematical
letter-like symbols, and characters whose script cannot be classified safely
remain permitted.

Languages may instead—or additionally—be scoped with the same `include`,
`exclude`, and `glob` selectors as other rule kinds:

```toml
languages = ["en"]

[[language_rule]]
id = "japanese-docs"
languages = ["ja"]
glob = ["docs/ja/**", "fixtures/japanese/**"]
```

Scoped declarations are additive. In this example, matching files may contain
both English and Japanese, while other files remain English-only. When there is
no top-level declaration, only paths selected by a `[[language_rule]]` are
checked; unrelated files are left alone. Multiple matching rules are unioned.

Codes are case-insensitive. Region-tagged BCP 47 forms based on an ISO 639-1
code are also accepted (`en-US`, `ja-JP`, `pt-BR`) and resolve through their
base code. A language name or unsupported code is a configuration error, not an
empty declaration that silently disables checking.

This rule considers visible letters only. Continue using a hidden-Unicode guard
for control, zero-width, bidirectional-format, and non-breaking-space
characters; declaring a language is not an exemption for those characters.

## Link Rules

The text-matching kinds — `rule`, `dynamic_rule` and `require_rule` — ask *does
this text appear?*, and `path_rule` asks the same of a file path. A
`[[link_rule]]` asks something none of them can: *does this text name something
that exists?* A link to a moved file is still perfectly well-formed, so no
pattern reaches it, and the only way to know is to go and look.

```toml
[[link_rule]]
id = "no-broken-doc-links"
message = """
A documentation link points at a path that does not exist.
"""
include = ["."]
glob = ["*.md"]
# allow_outside_repo = true   # permit targets that resolve above the repo root
# require_any_link = true     # fail if the selection yields no links at all
```

Two distinct failures, reported separately because they have different fixes:

- **`no such file`** — the target does not exist. The link was written against a
  path that has since moved or was never there.
- **`outside the repository`** — the target resolves above the repository root.
  It may well work on the author's machine, inside a wider checkout, and cannot
  work for anyone who cloned this repository alone. Set `allow_outside_repo` if
  that is genuinely intended.

Resolution matches how a Markdown renderer reads a document: relative to the
**containing file**, with a leading `/` treated as repository-root-relative. It
covers inline links, images and reference definitions; it strips anchors,
query strings and percent-escapes; and it accepts the `<angle bracket>` form.

Out of scope by design:

- **Anything with a scheme** (`https:`, `mailto:`). Resolving those needs the
  network, which a pre-commit hook must not touch.
- **Links inside fenced code blocks.** A README that documents a link would
  otherwise fail on its own example, and a rule that fires on correct
  documentation gets waived — after which it protects nothing.

`require_any_link` is opt-in rather than default because a repository whose docs
link only to external URLs has no internal links to check, and that is a normal
state rather than a broken selection. Turn it on where internal links are
expected, so a narrowed glob cannot quietly reduce coverage to nothing.

## Base Rule Sets

Common, repo-agnostic rules ship bundled in this repo under
[`policy/base/`](policy/base). Pull them into a repo policy with a top-level
`extends`:

```toml
extends = ["hygiene", "security"]      # merge in the named base sets
disable_rules = ["no-status-source-metadata"]  # opt out of specific base rules

# Your own rules go here as usual. A rule whose `id` matches a base rule
# overrides it (e.g. to re-scope include/exclude).
```

| set | kind | rules |
|---|---|---|
| [`hygiene`](policy/base/hygiene.toml) | non-credential (default) | `no-merge-conflict-markers`, `no-hardcoded-home-paths`, `no-dated-source-metadata`, `no-status-source-metadata` (spares `docs/adr/`), `no-task-tracker-references`, `no-process-history-references`, `no-tracked-private-data-paths` |
| [`security`](policy/base/security.toml) | credential-shaped (opt-in) | `no-committed-secret-material`, `no-committed-auth-key-values`, `no-env-secret-values`, `no-browser-profile-artifacts` |

Base files resolve relative to the **hook repo** (this repo's checkout), so the
rule set comes from whatever `rev:` you track (`main` tracks the latest). Base
rules exclude `**/tests/**` by default; redefine a rule with the same `id` to
change its scope.

## Built-in Dynamic Sources

| source name | values produced |
|---|---|
| `running-os-identity` | username, home path, hostname, and the identifying parts of the hostname |
| `running-os-metadata` | identity + default-route addresses |
| `running-default-route` | default-route gateway/source IPs |

`running-os-identity` searches for the hostname's parts as well as the whole,
because a fixture rarely carries the whole thing: a host named
`debian-x8664-ARC` gets written into a DHCP reservation or a test as `arc`.
Parts naming a machine's *kind* rather than its owner — distributions,
architectures, and role words like `dev` or `server` — are never searched for,
and neither is anything under three characters. Parts are matched whole-word, so
`arc` does not fire on `search`.

## Custom Dynamic Sources

Repos that need custom sources place a `policy/sources.py` next to their
`rg-policy.toml`.  The module exports a `SOURCES` dict:

```python
"""Custom dynamic-rule sources for this repository."""

from __future__ import annotations

from collections.abc import Callable


def my_custom_source() -> dict[str, str]:
    """Return {label: literal_value} pairs to search for."""
    return {"example-label": "example-value"}


SOURCES: dict[str, Callable[[], dict[str, str]]] = {
    "my-custom-source": my_custom_source,
}
```

Values are searched as literal substrings.  A value short enough to occur inside
an unrelated word should be returned as a `Needle` with `word=True`, which
matches whole words only:

```python
from check_policy import Needle

def my_custom_source():
    return {"short-token": Needle("arc", word=True)}
```

Leave `word` off for anything that must be found *inside* a larger token — a
separator-less MAC has to keep matching inside an interface name like
`wlx7c3d095094a9`, which is the spelling it leaks in.

Then reference it in `rg-policy.toml`:

```toml
[[dynamic_rule]]
id = "no-custom-leaks"
source = "my-custom-source"
message = "..."
include = ["src"]
```

## Files That Are Not Text

A repository may legitimately track a file that is not UTF-8: a web page
captured in the encoding its venue served, kept byte-for-byte because the
encoding is part of the evidence. Two things follow.

**A match inside one no longer ends the run.** ripgrep searches such a file
happily and prints the matching line as bytes; decoding that strictly used to
fail the whole check with `'utf-8' codec can't decode byte 0x8f`, naming no rule
and no file. No exclusion could prevent it, because it happened after the search
had already succeeded. Output is now decoded leniently and the finding is
reported with the file named.

**A file declared `-text` in `.gitattributes` is skipped, and the skip is
counted.**

```
# .gitattributes
tests/fixtures/*.sjis.* -text
```

```
1 path(s) skipped: declared not text in .gitattributes
  tests/fixtures/page.sjis.html
```

Content rules are about text somebody wrote. Running them over a document nobody
in the repository authored produces findings against a third party's prose at
best, and at worst suggests re-encoding the artifact — which destroys the thing
it exists to prove. The count is printed always: "we did not check these" and
"these were clean" must never look the same.

There is deliberately **no encoding allowlist**. Accepting a second encoding
would decode the artifact and run the rules over it anyway. And a file that is
merely undecodable, without a declaration, is still searched — the declaration
is what exempts it, not the encoding, or any rule could be evaded by committing
a file the checker cannot read.

## Redacted Output

Set `redact_matches = true` at the top of `rg-policy.toml` to use JSON rg mode
and print `[REDACTED_MATCH]` instead of raw match content.  Useful for repos
handling captured credentials or private financial data.

## Updating

Consumers track `rev: main`, so edits here reach every repo on its next
`prek autoupdate` (or `prek clean`) — no per-release `rev:` bump to make here or
in the consumers. The `v1.1.0` tag marks a stable snapshot you can pin instead of
`main` if you ever need to. Because [base rule sets](#base-rule-sets) ship inside
this repo, the `rev:` you track also fixes which base rules a consumer gets.
