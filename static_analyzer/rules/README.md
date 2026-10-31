# YARA rules baked into the static image

Each folder is one ruleset: its upstream repository as a **git submodule** in `<name>/upstream/`, checked out at the
commit pinned in `<name>/SOURCE.json` (source URL, commit, archive SHA-256, licence, SHA-256 of every rule file).
Clone with `git clone --recursive` (or run `git submodule update --init --recursive`); a GitHub "Download ZIP" has
no submodule contents, and the image build then fails on zero rules. The image build compiles
everything here into `/opt/chimera-static/rules.yarc` (`chimera_static.rules_build`) and **fails** on zero
rules or a compile error. `static.json` reports the rule count and pins under `universal.yara_ruleset`.

| Folder | Source | Commit | Licence | Rules |
|---|---|---|---|---|
| `reversinglabs/` | https://github.com/reversinglabs/reversinglabs-yara-rules | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` (3 Nov 2025) | MIT, `reversinglabs/upstream/LICENSE` | 1240 (931 certificate, 308 malware, 1 exploit) |

Severity in findings: ReversingLabs `MALWARE`/`EXPLOIT` rules with `tc_detection_factor` ≥ 4 → high,
other malware rules → medium, `INFO` certificate rules (signer seen on malware, leaked certificate) → medium.
A YARA match is evidence in the static score; it never sets a malware family on its own.

To add a ruleset: `git submodule add <url> static_analyzer/rules/<name>/upstream`, check out the commit you
reviewed, and write `<name>/SOURCE.json` in the same shape (`tests/test_rules.py` checks every rule file's hash); check redistribution terms first (`docs/chimera/plan/static-engine-design.md` §2.2).
