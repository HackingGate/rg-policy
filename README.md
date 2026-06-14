# rg-policy

Reusable [pre-commit](https://pre-commit.com/) /
[prek](https://github.com/j178/prek) hook that enforces repository content
policies defined in `policy/rg-policy.toml` using
[ripgrep](https://github.com/BurntSushi/ripgrep).

## Rule Kinds

| TOML key | purpose |
|---|---|
| `[[rule]]` | pattern-match (rg `--regexp`) that must find zero hits |
| `[[dynamic_rule]]` | values produced at runtime, each searched via rg |
| `[[size_rule]]` | source-file line-count limits with optional baseline ratchet |
| `[[path_rule]]` | regex matched against tracked file paths (no rg) |
| `[[require_rule]]` | pattern that **must** match in every selected file (must-find) |

Any `[[rule]]` may set `multiline = true` to match across line boundaries
(ripgrep `--multiline --multiline-dotall`).

## Usage

In a consuming repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/HackingGate/rg-policy
    rev: v1.1.0
    hooks:
      - id: check-policy
```

Then create `policy/rg-policy.toml` with your rules — optionally building on the
bundled [base rule sets](#base-rule-sets).

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

## Base Rule Sets

Common, repo-agnostic rules ship bundled in this repo under `policy/base/`. Pull
them into a repo policy with a top-level `extends`:

```toml
extends = ["hygiene", "security"]      # merge in the named base sets
disable_rules = ["no-status-source-metadata"]  # opt out of specific base rules

# Your own rules go here as usual. A rule whose `id` matches a base rule
# overrides it (e.g. to re-scope include/exclude).
```

| set | kind | rules |
|---|---|---|
| `hygiene` | non-credential (default) | `no-merge-conflict-markers`, `no-hardcoded-home-paths`, `no-dated-source-metadata`, `no-status-source-metadata`, `no-task-tracker-references`, `no-process-history-references`, `no-tracked-private-data-paths` |
| `security` | credential-shaped (opt-in) | `no-committed-secret-material`, `no-committed-auth-key-values`, `no-env-secret-values`, `no-browser-profile-artifacts` |

Base files resolve relative to the **hook repo** (this repo's checkout), so the
rule set is versioned by the `rev:` you pin. Base rules exclude `**/tests/**` by
default; redefine a rule with the same `id` to change its scope.

## Built-in Dynamic Sources

| source name | values produced |
|---|---|
| `running-os-identity` | username, home path, hostname |
| `running-os-metadata` | identity + default-route addresses |
| `running-default-route` | default-route gateway/source IPs |

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

Then reference it in `rg-policy.toml`:

```toml
[[dynamic_rule]]
id = "no-custom-leaks"
source = "my-custom-source"
message = "..."
include = ["src"]
```

## Redacted Output

Set `redact_matches = true` at the top of `rg-policy.toml` to use JSON rg mode
and print `[REDACTED_MATCH]` instead of raw match content.  Useful for repos
handling captured credentials or private financial data.

## Versioning

Callers pin an exact tag (e.g. `@v1.1.0`).  Bump the pin when adopting a new
release.  Because [base rule sets](#base-rule-sets) ship inside this repo, the
pinned tag also fixes which base rules a consumer gets.
