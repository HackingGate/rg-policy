#!/usr/bin/env python3
"""The promoted base rules must still match everything the local copies matched.

WHY THIS FILE EXISTS

Three rules in `policy/base/supply-chain.toml` and two key names in
`no-env-secret-values` arrived here by promotion: they were found hand-copied
into a fleet of 39 consuming repositories, and the point of promoting them is
that those 39 copies can be deleted in favour of one `extends` line.

That deletion is the dangerous half. A repository whose local rule matched
something this base rule does not would LOSE that coverage at the moment it
migrates, silently, because a rule that stops matching produces no output at all
-- the gate goes green and stays green, and the thing it was watching is simply
no longer watched.

So the promotion is not trusted; it is checked. `fixtures/promotion-corpus.json`
holds concrete lines derived MECHANICALLY from the alternation members present in
those 39 local copies -- not hand-picked, because a hand-picked corpus tests the
author's memory of what the rules covered rather than what they covered.

WHAT A FAILURE HERE MEANS

Not "fix the corpus". It means the base rule is narrower than the copies it is
replacing, and either the base pattern grows or that repository must keep its
local rule. The corpus is the record of what the fleet was actually protected
against, and it outranks the tidiness of the merge.

The values are placeholders. A corpus of credential SHAPES cannot carry a real
credential, which is the same rule the fixtures under `tests/` already follow.
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_DIR = TESTS_DIR.parent
BASE_DIR = REPO_DIR / "policy" / "base"
CORPUS = TESTS_DIR / "fixtures" / "promotion-corpus.json"


def base_patterns() -> dict[str, str]:
    """{rule id: pattern} across every shipped base pack."""
    out: dict[str, str] = {}
    for pack in sorted(BASE_DIR.glob("*.toml")):
        policy = tomllib.loads(pack.read_text(encoding="utf-8"))
        for kind in ("rule", "path_rule", "dynamic_rule", "link_rule"):
            for rule in policy.get(kind, []):
                if rule.get("id") and rule.get("pattern"):
                    out[rule["id"]] = rule["pattern"]
    return out


def base_rules() -> dict[str, dict]:
    """{rule id: the whole rule} — patterns are half of what a rule declares."""
    out: dict[str, dict] = {}
    for pack in sorted(BASE_DIR.glob("*.toml")):
        policy = tomllib.loads(pack.read_text(encoding="utf-8"))
        for kind in ("rule", "path_rule", "dynamic_rule", "link_rule"):
            for rule in policy.get(kind, []):
                if rule.get("id"):
                    out[rule["id"]] = rule
    return out


class PromotedRulesStillMatch(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.patterns = base_patterns()

    def test_every_corpus_line_still_matches_its_rule(self) -> None:
        missed: list[str] = []
        for rule_id, lines in sorted(self.corpus.items()):
            self.assertIn(
                rule_id, self.patterns, f"{rule_id} is in the corpus and in no base pack"
            )
            rx = re.compile(self.patterns[rule_id], re.MULTILINE)
            for line in lines:
                if not rx.search(line):
                    missed.append(f"{rule_id}: {line!r}")
        self.assertEqual(
            [],
            missed,
            "the promoted rule is NARROWER than the copies it replaces; those repos "
            "would lose this coverage on migrating:\n" + "\n".join(missed),
        )

    def test_the_corpus_is_not_empty_for_any_promoted_rule(self) -> None:
        """A rule whose corpus emptied would pass the test above vacuously.

        The same failure the test is written to catch, one level up: nothing to
        check reads exactly like nothing wrong.
        """
        for rule_id, lines in sorted(self.corpus.items()):
            self.assertTrue(lines, f"{rule_id} has an empty corpus")

    def test_the_two_promoted_key_names_are_the_reason_this_exists(self) -> None:
        """APP_ID and SUBSCRIPTION_KEY, asserted by name.

        Nine of the 39 repositories had locally redefined `no-env-secret-values`
        for the single purpose of adding APP_ID, and two for SUBSCRIPTION_KEY.
        Those are the alternatives whose loss would be invisible, so they are
        pinned here rather than left to the generated corpus alone -- a
        regenerated corpus that dropped them would take the evidence with it.
        """
        rx = re.compile(self.patterns["no-env-secret-values"], re.MULTILINE)
        for line in ("ESTAT_APP_ID=notarealvalue", "TDNET_SUBSCRIPTION_KEY=notarealvalue"):
            self.assertRegex(line, rx)

    def test_a_sops_vault_is_not_flagged_as_a_committed_secret(self) -> None:
        """The exclusion half, which the first version of this file did not check.

        A corpus of PATTERNS proves the promoted rule still matches what the
        local copies matched. It proves nothing about what they DECLINED to
        match, and the fleet's local copies carried exclusions too -- nine of
        them excluded their SOPS vault by name. Migrating on a pattern-only
        proof turned a whole fleet red on ciphertext, which is how this test
        learned it was half a test.

        The rule kinds this file checks are `exclude` lists, so the assertion is
        on the list rather than on a match: the pattern SHOULD match a vault
        line -- that is what a vault line looks like -- and the file is skipped
        before the pattern is ever applied.
        """
        packs = base_rules()
        rule = packs["no-env-secret-values"]
        for name in ("*.enc.env", ".env.enc"):
            self.assertIn(
                name,
                rule.get("exclude", []),
                "a secret detector that fires on the file whose purpose is to make "
                "secrets safe to commit teaches its reader to skim its findings",
            )

    def test_a_placeholder_env_line_is_still_allowed(self) -> None:
        """The rule must not fire on an empty or commented example value.

        Widening a credential pattern is the easy half; keeping `.env.example`
        legal is what stops the widening from being reverted a week later.
        """
        rx = re.compile(self.patterns["no-env-secret-values"], re.MULTILINE)
        for line in ("ESTAT_APP_ID=", "ESTAT_APP_ID=  # set me", "# ESTAT_APP_ID=x"):
            self.assertNotRegex(line, rx)


if __name__ == "__main__":
    unittest.main()
