# rg-policy

Reusable [pre-commit](https://pre-commit.com/) / [prek](https://github.com/j178/prek)
hook that enforces repository content policies defined in `policy/rg-policy.toml`
using [ripgrep](https://github.com/BurntSushi/ripgrep).

## Usage

In a consuming repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/HackingGate/rg-policy
    rev: v1.0.0
    hooks:
      - id: check-policy
```

Then `prek install` (or `pre-commit install`) and create `policy/rg-policy.toml`
with your rules, optionally building on the bundled [base rule sets](#base-rule-sets).

```sh
check_policy.py --check-text -          # subject on stdin
check_policy.py --check-text BODY.md    # or a file
```

Text mode checks a commit message, PR body or release notes — text a working-tree
scan cannot see. Same engine, needles and flags as file mode, with two differences:
only `[[dynamic_rule]]` applies, and it falls back to the built-in
`running-os-identity` rule when the repository declares no dynamic rules or has no
`policy/rg-policy.toml` at all. It is the interface
[cmd-shims](https://github.com/HackingGate/cmd-shims) calls on the `gh pr create`
path rather than reimplement.

## Rule Kinds

| TOML key | purpose |
|---|---|
| `[[rule]]` | pattern-match (rg `--regexp`) that must find zero hits, with optional path baseline; `multiline = true` matches across line boundaries |
| `[[dynamic_rule]]` | values produced at runtime, each searched via rg |
| `[[size_rule]]` | source-file line-count limits, with an optional baseline ratchet that keeps counts rather than paths |
| `[[path_rule]]` | regex matched against tracked file paths (no rg) |
| `[[require_rule]]` | pattern that **must** match in every selected file (must-find) |
| `[[link_rule]]` | every documentation link must resolve to a path that exists |
| `[[language_rule]]` | add languages for files selected by path or glob |

## Policy Keys

```toml
[[rule]]
id = "no-hardcoded-home-paths"
message = """
Do not commit hardcoded user home paths.
"""
pattern = '(?:/home|/Users)/[A-Za-z0-9._-]+'
include = ["src", "scripts"]
exclude = ["**/tests/**"]
glob = ["*.rs", "*.py"]
```

`pattern` must be a TOML **literal** string in single quotes; in double quotes every
backslash needs doubling. [`policy/rg-policy.toml`](policy/rg-policy.toml) and
[`policy/base/hygiene.toml`](policy/base/hygiene.toml) are working examples.

| key | applies to | meaning |
|---|---|---|
| `id` | every rule | the name reported, and the key an `extends` rule is overridden by |
| `message` | every rule | what is printed on a hit |
| `include` / `exclude` / `glob` | every rule | path prefixes, exclusion globs, and file globs selecting what is scanned |
| `pattern` | `rule`, `path_rule`, `require_rule` | the regex |
| `multiline` | `rule` | match across line boundaries (`--multiline --multiline-dotall`) |
| `fixed_strings` | `rule`, `require_rule` | treat `pattern` as a literal, not a regex |
| `source` | `dynamic_rule` | a built-in or custom dynamic source name |
| `exclude_cfg_test` | `dynamic_rule` | skip inline `#[cfg(test)]` regions in Rust files |
| `max_lines` | `size_rule` | the line limit |
| `baseline` | `rule`, `require_rule`, `size_rule` | a file of repo-relative paths, one per line, `#` comments ignored, letting a rule land before its cleanup. For `rule` the entries are paths permitted to match; for `require_rule`, paths permitted to be *missing* the pattern. An unlisted path can never start. A stale entry fails for both — and inverts with the rule, so a `require_rule` entry goes stale once the path *satisfies* the pattern or is gone. `size_rule` stores `<path> <count>` and leaves stale entries alone |
| `allow_outside_repo` | `link_rule` | permit targets that resolve above the repo root |
| `require_any_link` | `link_rule` | fail if the selection yields no links at all |
| `extends` | top level | base rule sets to merge in |
| `disable_rules` | top level | base rule ids to opt out of |
| `languages` | top level | ISO 639-1 codes declared repository-wide |
| `redact_matches` | top level | print `[REDACTED_MATCH]` instead of raw match content |

Baselines apply identically in redacted mode.

## Language Rules

Opt-in. Declare `languages = ["en", "ja"]` at the top level, or scope it with a
`[[language_rule]]` using the same `include`/`exclude`/`glob` selectors — scoped
declarations are additive and unioned, and with no top-level declaration only selected
paths are checked. Codes are case-insensitive and BCP 47 region forms (`en-US`) resolve
through their base code; a language name or unsupported code is a configuration error.

The checker maps languages to Unicode writing systems and rejects letters from a
different recognized script. Punctuation, numbers, emoji and letter-like symbols remain
permitted. It considers **visible letters only** — keep a hidden-Unicode guard for
control, zero-width, bidi and non-breaking-space characters.

## Link Rules

Targets resolve relative to the **containing file**, with a leading `/` treated as
repository-root-relative. Inline links, images and reference definitions are covered;
anchors, query strings and percent-escapes are stripped, and the `<angle bracket>` form
is accepted. `no such file` and `outside the repository` are reported separately. Out
of scope: anything with a scheme (`https:`, `mailto:`), and links inside fenced code
blocks.

## Files That Are Not Text

A match inside a non-UTF-8 file no longer ends the run: output is decoded leniently and
the finding is reported with the file named. A file declared `-text` in `.gitattributes`
is skipped, and the skip is **counted** — "we did not check these" and "these were
clean" must not look the same.

```
# .gitattributes
tests/fixtures/*.sjis.* -text
```

There is deliberately no encoding allowlist, and a file that is merely undecodable
without a declaration is still searched — the declaration is what exempts it, not the
encoding.

## Base Rule Sets

Common, repo-agnostic rules ship bundled under [`policy/base/`](policy/base). Pull
them in with `extends = ["hygiene", "security"]`; `disable_rules` drops individual
base rules, and a local rule whose `id` matches a base rule overrides it.

| set | kind | rules |
|---|---|---|
| [`hygiene`](policy/base/hygiene.toml) | non-credential (default) | `no-merge-conflict-markers`, `no-hardcoded-home-paths`, `no-dated-source-metadata`, `no-status-source-metadata` (spares `docs/adr/`), `no-task-tracker-references`, `no-process-history-references`, `no-tracked-private-data-paths` |
| [`security`](policy/base/security.toml) | credential-shaped (opt-in) | `no-committed-secret-material`, `no-committed-auth-key-values`, `no-env-secret-values`, `no-browser-profile-artifacts` |

Base files resolve relative to the **hook repo**, so the rule set comes from whatever
`rev:` you track. Base rules exclude `**/tests/**` by default.

## Dynamic Sources

| source name | values produced |
|---|---|
| `running-os-identity` | username, home path, hostname, and the identifying parts of the hostname |
| `running-os-metadata` | identity + default-route addresses |
| `running-default-route` | default-route gateway/source IPs |

`running-os-identity` searches the hostname's identifying parts as well as the whole,
matched whole-word. Parts naming a machine's *kind* — distributions, architectures,
role words like `dev` or `server` — are never searched for, nor is anything under three
characters. For custom sources, place a `policy/sources.py` next to `rg-policy.toml`
exporting a `SOURCES` dict of `{name: callable}`, each callable returning `{label: value}`:

```python
from check_policy import Needle

def my_custom_source() -> dict[str, str]:
    return {"example-label": "example-value", "short-token": Needle("arc", word=True)}

SOURCES = {"my-custom-source": my_custom_source}
```

Values are searched as literal substrings. Wrap one in `Needle(..., word=True)` when
it is short enough to occur inside an unrelated word; leave `word` off for anything
that must be found *inside* a larger token. Reference it with
`source = "my-custom-source"` in a `[[dynamic_rule]]`.

## Updating

`v1.0.0` is the only released tag. Because base rule sets ship inside this repo, the
`rev:` you track also fixes which base rules a consumer gets. Runners cache by `rev`,
so a machine that already fetched a tag keeps its copy until `prek clean`.
