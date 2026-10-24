# phpfixes-php2shell

PHPFixes is a free skill for PHP owners and administrators using Codex or Claude Code. It checks supplied PHP2Shell evidence, explains installed and running PHP separately, and can collect a small local Linux inventory when the owner explicitly asks. It helps find multiple PHP branches, deleted or different FPM executables and missing records before an update decision.

Version 1.2.0. The free diagnostic works without a PHPFixes account or purchase. Python 3.9 or later runs the declared local MCP server and standalone helpers. The assistant uses the declared MCP tools for executable checks; it does not invoke helpers through a terminal.

Bundled advisory facts were checked on 2026-10-22. They support a positive `FIXED_EVIDENCE` finding for at most 14 days, through 2026-11-05 UTC. Evidence must also be no older than 24 hours. Expired facts or stale records leave positive findings unknown.

## Supported hosts and execution

This version uses a local MCP server, a program the assistant starts and calls through declared tools. Claude Code and Cowork support local execution; Claude web/mobile chat does not run this local server. Codex local plugin support must be available on the chosen surface. OpenAI public-directory local MCP eligibility requires the submitting organization to be allowlisted; this release does not claim that eligibility or a directory listing.

By default, the skill reads supplied records. Structured assessment and saved-inventory checks use the declared tools. Local metadata collection is a separate tool and needs a direct owner request with explicit authorization. The server starts without inspecting packages/processes and keeps helper execution inside its declared process. It makes no HTTP request or PHPFixes upload.

## Manual supplied-evidence check

The following commands are for an owner running the standalone helpers directly. The assistant skill uses MCP tools instead.

From the skill directory:

```text
python3 php2shell/assess.py --evidence examples/mixed-workers.json
```

With the clock pinned to 2026-10-23 at 12:05 UTC, it prints:

```text
PHPFixes PHP2Shell assessment 1.2.0
Scope: Synthetic example: fixed package on disk, stale running workers.
Assessment covers only supplied records. It does not establish a complete server inventory, internet exposure, absence of compromise, or whole-server safety.

example-fpm (fpm): installed UNKNOWN; running AFFECTED
  Installed package 8.3.6-0ubuntu0.24.04.13 is at or above vendor fixed package 8.3.6-0ubuntu0.24.04.13.
  Evidence is older than 24 hours or has a future collection time.
  Running workers differ from installed package or binary evidence; a fixed package on disk does not establish fixed workers.
  Running build: Installed package 8.3.6-0ubuntu0.24.04.12 is below vendor fixed package 8.3.6-0ubuntu0.24.04.13.
  Needed: Fresh process mappings and version identity for every serving worker, including deleted executables.
  Needed: Fresh evidence and current primary vendor advisories before any positive fixed finding.
  Source: https://ubuntu.com/security/notices/USN-8948-1
```

This example is synthetic. Its worker record identifies an older affected package while the installed package is newer. The installed finding is unknown because the snapshot is more than 24 hours old at the displayed assessment time. Real findings depend on supplied records and current time.

## Manual local inventory

For saved minimal metadata:

```text
python3 -I php2shell/inventory.py --input /absolute/path/inventory.json --format text
```

Only with permission to inspect this local Linux system:

```text
python3 -I php2shell/inventory.py --collect-local --authorized --format text
```

The collector reads bounded package/process metadata. It runs no PHP binary or subprocess, changes no server files and makes no network request. Automatic skill selection does not authorize collection. Saved-input mode does not inspect the local system. Read [inventory-guide.md](skills/phpfixes-php2shell/data/inventory-guide.md) for exact sources, limits and omitted runtimes.

A conditional comparison can say that an installed package reaches Ubuntu's or Debian's bundled published revision. It keeps installed and running fix status unknown until separate records establish installed origin and running identity. It never infers a fixed worker from a package on disk.

## Fix evidence

PHP2Shell covers [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). Bundled upstream fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. A distribution backport can retain an older upstream number, so its full package revision and installed source matter.

| Vendor release | Bundled fixed package | Primary source |
| --- | --- | --- |
| debian 13 | `8.4.27-1~deb13u1` | [php8.4](https://security-tracker.debian.org/tracker/CVE-2026-109618) |
| debian 12 | `8.2.35-1~deb12u1` | [php8.2](https://security-tracker.debian.org/tracker/CVE-2026-109618) |
| ubuntu 26.10 | `8.5.9-0ubuntu2.1` | [php8.5](https://ubuntu.com/security/notices/USN-8948-1) |
| ubuntu 26.04 | `8.5.4-0ubuntu1.5` | [php8.5](https://ubuntu.com/security/notices/USN-8948-1) |
| ubuntu 24.04 | `8.3.6-0ubuntu0.24.04.13` | [php8.3](https://ubuntu.com/security/notices/USN-8948-1) |
| ubuntu 22.04 | `8.1.2-1ubuntu2.28` | [php8.1](https://ubuntu.com/security/notices/USN-8948-1) |

Debian 12/13 positive comparisons cover only the documented upstream base and revision `1~deb12uN` or `1~deb13uN`, where N is a canonical integer from 0 through 9999. Primary advisories explicitly list Debian 12 `8.2.32-1~deb12u1` and Debian 13 `8.4.24-1~deb13u1` as affected. Other bases, revisions and private suffixes need a current matching advisory. Canonical ASCII release identities are required; Unicode digits, leading-zero aliases and private upstream suffixes cannot inherit fix thresholds. An origin label or installed package control field alone does not prove source.

[POLICY.md](skills/phpfixes-php2shell/POLICY.md) defines assessment rules. [evidence-guide.md](skills/phpfixes-php2shell/data/evidence-guide.md) describes stronger supplied records, including repository provenance and known running versions. [advisories.json](skills/phpfixes-php2shell/data/advisories.json) and [source-ledger.json](skills/phpfixes-php2shell/data/source-ledger.json) retain reviewed facts and sources. The fixed thresholds and their 2026-10-22 review date remain unchanged. The source ledger adds the two exact affected Debian builds checked on 2026-10-23.

## Installation

Install a pinned release or copy the standalone skill. The repository root is the complete plugin with its declared local server. A copied standalone skill can read supplied records; install the full plugin to make its MCP tools available. No terminal fallback is used by the skill. For manual ZIP installation, follow INSTALL.md in the extracted plugin folder.

In Codex, use the skill installer with this pinned path:

```text
$skill-installer install https://github.com/phpfixes/phpfixes-php2shell/tree/v1.2.0/skills/phpfixes-php2shell
```

For a pinned source checkout:

```text
git clone --depth 1 --branch v1.2.0 https://github.com/phpfixes/phpfixes-php2shell
```

For a local installation, copy only `skills/phpfixes-php2shell` into the selected Codex skills directory or the project's `.claude/skills/` directory. Claude Code can also install this repository as its `phpfixes` plugin. Invoke `/phpfixes:phpfixes-php2shell` for that plugin, `/phpfixes-php2shell` for a copied Claude skill, or `$phpfixes-php2shell` in Codex.

## Publisher and privacy

Read [privacy](PRIVACY.md) for supplied records, collector fields and assistant-platform handling. Use [support](SUPPORT.md) for installation questions and minimal nonsecret examples.

The diagnostic and inventory helpers work without an account, API key, telemetry or purchase. They make no HTTP request or upload to PHPFixes. Output consumed by Codex or Claude can enter that platform's normal tool and conversation processing. [SERVICES.md](skills/phpfixes-php2shell/SERVICES.md) contains requested publisher and installation information only.

## Tests and license

The pinned source repository includes tests; the release ZIP excludes them. From the source repository root, run `python3 -B -m unittest -v`. Tests use synthetic evidence and simulated collector reads. They check assessment behavior, malformed-input handling, canonical package identities, collection boundaries and the absence of commerce actions. A test run does not establish a real server's status or a completed assistant conversation.

MIT licensed by SnowRock, LLC. Root [LICENSE](LICENSE) and skill [LICENSE.txt](skills/phpfixes-php2shell/LICENSE.txt) retain the same notice. PHP and distribution advisory sources remain attributed in the source ledger.
