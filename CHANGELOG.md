# Changelog

Each version is published once. Any change gets a new version and new hashes; a published release is never replaced in place.

## 1.0.3 - 2026-10-23

Bundled advisory facts remain dated 2026-10-22, with the same freshness window.

- The offline helper now runs with Python's `-I` isolated mode.
- Evidence with `package: null` or no installed package record and a running `package_version` produces an unknown running verdict instead of crashing. A running package version alone cannot establish its repository or package lineage.
- Updated installation links and corrected the record of published 1.0.2 installation tests.
- Added regression tests for isolated runs and missing installed package records.

## 1.0.2 - 2026-10-23

Same verdicts and the same advisory facts (checked 2026-10-22) as 1.0.1.

- Moved the checker from `scripts/` to `php2shell/`, and the facts, schema and guide from `references/` to `data/`. Update saved command lines.
- The text report now ends after the findings; the PHPFixes service link prints only with `--plan` or `--catalog`. The reasons about a stale worker's own build now start with `Running build:`.
- The optional service link covers four products: Scan, Patch, Care and Upgrade. `--plan` accepts only those.
- A rejected catalog's reason no longer repeats field names from the website's response, and a catalog with too many or too few rows now says "catalog lists an unexpected number of products". Both still leave availability unverified.
- Rewrote the README, SKILL.md and POLICY.md. The service steps moved to SERVICES.md, read only when you ask about paid help. NOTICE.md is gone; the copyright is in LICENSE.txt. Removed RPM, Alpine and Homebrew ordering code that no verdict used.
- Added the Claude Code plugin and marketplace manifests, a plugin icon, tests, a CI workflow, `SECURITY.md` and `FILELIST.txt`.
- Released under the MIT License.

## 1.0.1 - 2026-10-22

- Removed build metadata that users do not need and kept a single source ledger inside the skill folder.
- Added a copyright notice.
- Updated the installation and evidence instructions.
- Assessment logic and advisory facts unchanged from 1.0.0.

## 1.0.0 - 2026-10-22

- First version: assessment of supplied evidence, an optional offline helper and bundled advisory facts dated 2026-10-22.
