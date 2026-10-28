# Changelog

Each version is published once. Any change gets a new version and new hashes; a published release is never replaced in place.

## 1.2.1 - 2026-10-28

- Uses the selected PHPFixes mouse company icon in Codex and Claude plugin metadata.
- Updates version markers and release links. Diagnostic code, permissions, advisory facts and licenses stay unchanged.

## 1.2.0 - 2026-10-23

- Added a declared local stdio MCP server for supplied evidence, saved inventory and explicitly authorized local Linux collection.
- Kept helper execution inside that declared server. The assistant skill no longer invokes Python or terminal commands directly and has no execution fallback.
- Kept startup and tool discovery separate from local metadata collection. No public endpoint, remote domain, PHP execution, network request or package/service update is added.
- Added exact Claude privacy/support listing fields and disclosed desktop/local host requirements and OpenAI local-MCP directory eligibility limits.
- Package comparison rules, advisory facts and freshness windows are unchanged.

## 1.1.0 - 2026-10-23

- Added an offline inventory normalizer and explicitly opted-in bounded Linux metadata collector. Neither executes PHP or makes network requests.
- Added specific findings for multiple PHP branches, deleted/different executables, conditional vendor-threshold comparisons and incomplete coverage, with free local inspection commands.
- Kept normalized origin/provenance unknown and running versions unset until stronger evidence is supplied.
- Bounded Debian 12/13 comparisons to documented upstream bases and canonical packaging revision lineages after reproducing an unsupported-revision false positive.
- Removed commercial helpers, plan recommendations, pricing and purchase routing from the public bundle. Publisher information is available only for requested installation questions.
- Rejected noncanonical release identities across vendor and upstream paths, including private upstream suffixes, leading-zero aliases and Unicode digits.
- Retained affected verdicts for the two exact older Debian builds listed by primary advisories; other unlisted bases stay unknown. Fixed thresholds and their original review date are unchanged.
- Converted unrepresentable timezone timestamps to ordinary safe input errors. Added concrete inspection guidance and clarified assistant handling of helper output.
- Licenses and original synthetic assessment examples are unchanged.

## 1.0.3 - 2026-10-23

Bundled advisory facts remain dated 2026-10-22, with the same freshness window.

- The offline helper now runs with Python's `-I` isolated mode.
- Evidence with `package: null` or no installed package record and a running `package_version` produces an unknown running verdict instead of crashing. A running package version alone cannot establish its repository or package lineage.
- Updated installation links and corrected the record of published 1.0.2 installation tests.
- Added regression tests for isolated runs and missing installed package records.

## 1.0.2 - 2026-10-23

Same verdicts and the same advisory facts (checked 2026-10-22) as 1.0.1.

- Moved the checker from `scripts/` to `php2shell/`, and the facts, schema and guide from `references/` to `data/`. Update saved command lines.
- Earlier versions included an optional service helper. Version 1.1.0 removes it from this directory bundle; original engineering files are retained outside the public source.
- Added the Claude Code plugin and marketplace manifests, a plugin icon, tests, a CI workflow, security reporting instructions and a file inventory.
- Rewrote assessment and evidence guidance.
- Released under the MIT License.

## 1.0.1 - 2026-10-22

- Removed build metadata that users do not need and kept a single source ledger inside the skill folder.
- Added a copyright notice.
- Updated the installation and evidence instructions.
- Assessment logic and advisory facts unchanged from 1.0.0.

## 1.0.0 - 2026-10-22

- First version: assessment of supplied evidence, an optional offline helper and bundled advisory facts dated 2026-10-22.
