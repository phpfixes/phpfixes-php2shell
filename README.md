# phpfixes-php2shell

A read-only skill that reads the PHP evidence you already have and tells you whether that PHP is fixed for PHP2Shell. It never contacts your server.

PHP2Shell is the name used for two PHP remote-code-execution bugs disclosed on 2026-10-21: CVE-2026-109618 ("RCE via OOM corruption") and CVE-2026-109619 ("RCE via stale global state"). php.net says configuration mitigations are only partial; updating to a fixed build is required for a complete fix. Given a `php -v`, a package version and a process list that you paste or save, this skill says whether that PHP is fixed, still affected, or not yet knowable from what you supplied.

Version 1.0.3. The bundled advisory facts were checked on 2026-10-22. A `FIXED_EVIDENCE` verdict is offered only while those facts are at most 14 days old, so the last day this release can give one is 2026-11-05 (UTC). After that it says `UNKNOWN` until the facts are refreshed.

## A 10-second example

The repository ships three synthetic evidence files. This one is an Ubuntu 24.04 server whose package was upgraded but whose PHP-FPM workers were never restarted. The part that matters:

```text
"package": {"manager": "apt", "name": "php8.3-fpm", "version": "8.3.6-0ubuntu0.24.04.13",
            "repository": "ubuntu", "provenance": "installed-repository-record", ...},
"running": {"state": "observed", "binary_identity": "deleted-or-different",
            "package_version": "8.3.6-0ubuntu0.24.04.12", ...}
```

Run the checker on it:

```bash
cd skills/phpfixes-php2shell
python3 php2shell/assess.py --evidence examples/mixed-workers.json
```

Once the records are more than 24 hours old (after 2026-10-23T12:00Z), and until 2026-11-05 (UTC), it prints:

```text
PHPFixes PHP2Shell assessment 1.0.3
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

Read the verdict line first. `running AFFECTED`: a worker still maps the deleted `.12` build, which is below Ubuntu's fixed `.13`. A fixed file on disk did not fix the live site, and waiting does not change that. `installed UNKNOWN`: the package on disk is the fixed build (the next line says so), but these records were collected at 2026-10-22T12:00Z and are now more than 24 hours old, so the checker will not call anything fixed from them. On the first day the same line read `installed FIXED_EVIDENCE`; `tests/test_skill.py` pins the clock to that moment.

To check a real server, copy an example, replace its records with yours and follow [`data/evidence-guide.md`](skills/phpfixes-php2shell/data/evidence-guide.md); [`data/evidence.schema.json`](skills/phpfixes-php2shell/data/evidence.schema.json) is the exact contract. Or paste the raw output into Claude Code or Codex and let the skill build the file. Remove passwords, tokens and customer data first. Add `--format json` for a machine-readable report.

## What it will not do

- It never contacts, logs in to, scans or probes your server.
- The checker makes no network requests, writes no files and starts no other process.
- The skill's instructions let your assistant read two kinds of public page, read-only: an official PHP or vendor advisory newer than the bundled facts, and, only if you ask about PHPFixes services, `https://phpfixes.com/api/services` before it quotes a price or availability.
- It does not run PHP, exploit code, or anything found inside your evidence.
- It does not install packages, change configuration or restart services.
- It believes the records you give it. It checks that they are well-formed, consistent and fresh, not that they are true.
- It never calls a whole server safe, and never rules out compromise. A verdict covers one runtime and these two CVEs only.
- It will not call anything fixed from stale input. Records older than 24 hours, or facts past their 14-day window, turn any `FIXED_EVIDENCE` into `UNKNOWN`.

## Why a version number can lie

The obvious check -- is `php -v` at least the fixed release? -- is wrong in both directions. It calls a fixed Ubuntu package affected, and it calls a server fixed while old workers still serve the affected code.

**Backports keep the old number.** Ubuntu 24.04 fixed PHP2Shell in the package `8.3.6-0ubuntu0.24.04.13`. The upstream number in that string is still `8.3.6`, the same `8.3.6` that shipped affected. The fix lives in the `-0ubuntu0.24.04.13` revision, not in `8.3.6`. So `php -v` alone (`PHP 8.3.6`) cannot tell you whether you are fixed. You have to read the full package version, and you have to know it came from Ubuntu's own archive (for example `noble-security`) and not from somewhere that reused the number. The extreme case is Ubuntu 22.04: PHP 8.1 gets no upstream fix at all, yet `8.1.2-1ubuntu2.28` is fixed.

**Vendor build strings are not upstream releases.** A build from a third-party PHP repository, such as `8.3.35-1+ubuntu24.04.1+deb.sury.org+1` (origin `sury` in the evidence) or a `.remi` package (origin `remi`), never borrows Ubuntu's backport row. It counts as fixed only if it already carries the upstream fixed release (8.3.36 or later for 8.3) and an installed-repository record shows it came from that repository. The `8.3.35` build above stays `UNKNOWN` until that repository's own advisory settles it.

**Even an upstream number needs provenance.** `PHP 8.3.36` from a php.net build or an official image is `UNKNOWN` until a build record or image digest ties that exact binary to the release. A version string is easy to print, and an image tag can move. [`examples/cli-only.json`](skills/phpfixes-php2shell/examples/cli-only.json) shows this.

**Installed is not running.** PHP-FPM and Apache workers load PHP once and keep it. Upgrade the package and the old workers go on serving the old code until the service is restarted. A process can even map a binary that has already been deleted from disk. So a fixed package, a fixed `php -v`, even a fixed CLI, tells you nothing certain about the workers answering web requests. The checker keeps `installed` and `running` as two separate verdicts and never lets one stand in for the other.

## Verdicts

Each runtime gets two: `installed`, for the files on disk, and `running`, for the workers serving requests.

| Verdict | Meaning |
| --- | --- |
| `FIXED_EVIDENCE` | The records meet a bundled fix threshold for this runtime and these two CVEs. It does not mean the server is safe. |
| `AFFECTED` | The records show a build below the fix threshold. |
| `UNKNOWN` | The records cannot settle it. The report names the evidence that would. |
| `CLI_ONLY` | Running only: the evidence is command-line PHP, which says nothing about the PHP serving the website. |
| `NOT_RUNNING_IN_EVIDENCE` | Running only: process evidence says this runtime was not running when the records were collected. |

## How the check works

The distribution-package rule is the heart of it. This is the real function from [`php2shell/assess.py`](skills/phpfixes-php2shell/php2shell/assess.py), unedited; a test fails if the two ever differ:

```python
def vendor_backport_verdict(runtime, result):
    """Judge an Ubuntu or Debian package by its vendor's fixed package, not by php.net's number.

    Returns True when this rule has the final word (even if that word is UNKNOWN), or False
    to let the next rule judge the package by the upstream release it carries.
    """
    package, os_info = runtime["package"], runtime["os"]
    why, needed = result["why"], result["needed_evidence"]
    epoch, upstream, revision = deb_split(package["version"])
    row = vendor_fixed_row(os_info, "php" + php_branch(upstream))
    # Only a package that an installed-repository record ties to this OS's own archive may use
    # the OS's backport row. A version that merely looks like Ubuntu's, a candidate upgrade from
    # somewhere else, or a third-party build never borrows the distribution's threshold.
    from_vendor_archive = (runtime["origin"] == "distro" and package["manager"] in DEB_MANAGERS
                           and package["repository"] == os_info["id"]
                           and package["provenance"] == "installed-repository-record"
                           and not third_party_vendor(package["version"]))
    if not (row and from_vendor_archive):
        return False
    fixed = row["fixed"]
    fixed_epoch, fixed_upstream, fixed_revision = deb_split(fixed)
    result.update(fixed_threshold=fixed, source_urls=[row["source"]])
    if epoch != fixed_epoch:
        why.append("Package epoch differs from the recorded vendor package lineage.")
        needed.append("Current vendor advisory matching this package epoch and revision.")
        return True
    if compare_php_versions(upstream, fixed_upstream) > 0:
        # A newer upstream release than the row's is judged by the upstream fix instead.
        why.append("This package has a newer upstream number than the vendor backport row.")
        return False
    if fixed_revision and not revision:
        why.append("Vendor fix depends on a package revision that was not supplied.")
        needed.append("Full installed package version, including its revision.")
        return True
    # The fix lives in the revision: 8.3.6-0ubuntu0.24.04.13 is fixed and .12 is not.
    fixed_enough = deb_version_compare(package["version"], fixed) >= 0
    result["status"] = "FIXED_EVIDENCE" if fixed_enough else "AFFECTED"
    why.append("Installed package %s is %s vendor fixed package %s."
               % (package["version"], "at or above" if fixed_enough else "below", fixed))
    return True
```

Returning `False` hands the package to the next rule, where a build that already carries the upstream fix, with a record of where it came from, can still earn `FIXED_EVIDENCE`. Before this function, records that contradict each other get `UNKNOWN`: the package name, PHP branch, interface and version must agree. After it, stale evidence, expired facts and a FrankenPHP runtime each turn any `FIXED_EVIDENCE` into `UNKNOWN`.

`deb_version_compare` follows dpkg's ordering rules, reimplemented in `php2shell/version_compare.py`: a `~` sorts before everything, even the end of the string, so `8.2.35-1~deb12u1` is lower than `8.2.35-1`, and an epoch (`1:`) outranks everything after it. Plain PHP release numbers use PHP's own rule, where `8.5.12RC1` sorts below `8.5.12`.

These are the fixed versions bundled in 1.0.3, each from a primary source, all checked on 2026-10-22:

| Stream | Package | Fixed in | Source |
| --- | --- | --- | --- |
| PHP upstream | 8.2 / 8.3 / 8.4 / 8.5 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |
| Ubuntu 22.04 | php8.1 | 8.1.2-1ubuntu2.28 | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| Ubuntu 24.04 | php8.3 | 8.3.6-0ubuntu0.24.04.13 | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| Ubuntu 26.04 | php8.5 | 8.5.4-0ubuntu1.5 | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| Ubuntu 26.10 | php8.5 | 8.5.9-0ubuntu2.1 | [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) |
| Debian 12 | php8.2 | 8.2.35-1~deb12u1 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618) |
| Debian 13 | php8.4 | 8.4.27-1~deb13u1 | [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618) |

Packages with no row here -- other distributions (RPM, Alpine, Homebrew and the rest), other releases, private builds and same-version backports -- come out `UNKNOWN`, with the missing evidence named, unless the package already carries the upstream fixed release and either an installed-repository record ties it to Ubuntu's or Debian's own archive or to the sury or remi repository, or, for an upstream or official-image build, build provenance ties the exact binary to that release. Settling the rest takes a current vendor advisory, which you or your assistant read separately. The facts, their sources and their check dates are in [`data/advisories.json`](skills/phpfixes-php2shell/data/advisories.json) and [`data/source-ledger.json`](skills/phpfixes-php2shell/data/source-ledger.json).

## Install

Three ways in, one line each.

**Claude Code.** From your shell:

```bash
claude plugin marketplace add phpfixes/phpfixes-php2shell && claude plugin install phpfixes@phpfixes
```

Then use `/phpfixes:phpfixes-php2shell`, or just ask about PHP2Shell and let Claude Code pick it.

**Codex.** Inside Codex:

```text
$skill-installer install https://github.com/phpfixes/phpfixes-php2shell/tree/v1.0.3/skills/phpfixes-php2shell
```

Then use `$phpfixes-php2shell` or pick it from `/skills`. If it does not appear, restart Codex.

**Plain Python.** No assistant required; the checker is stdlib-only and runs on Python 3.9 or newer:

```bash
git clone --depth 1 --branch v1.0.3 https://github.com/phpfixes/phpfixes-php2shell && cd phpfixes-php2shell/skills/phpfixes-php2shell && python3 php2shell/assess.py --evidence examples/mixed-workers.json
```

To install by hand instead, copy the `skills/phpfixes-php2shell/` folder into `.claude/skills/` (Claude Code) or `.agents/skills/` (Codex). A copied skill is invoked as `/phpfixes-php2shell` or `$phpfixes-php2shell`. The [releases page](https://github.com/phpfixes/phpfixes-php2shell/releases) has the same folder as two ZIPs, one per assistant, with `SHA256SUMS`; check a ZIP against its line first (`shasum -a 256` on macOS, `sha256sum` on Linux).

## Repository layout

```text
README.md  LICENSE  SECURITY.md  CHANGELOG.md
FILELIST.txt                   SHA-256, size and mode of every other file
.claude-plugin/                plugin and marketplace manifests and the plugin icon for Claude Code
.github/workflows/tests.yml    runs the tests on push and pull request
tests/                         repository and skill tests
skills/phpfixes-php2shell/     the skill itself:
  SKILL.md  POLICY.md  SERVICES.md  LICENSE.txt
  php2shell/                   assess.py and version_compare.py, the checker
  data/                        advisory facts, sources, evidence schema and guide
  examples/                    three synthetic evidence files
```

Codex, a manual copy and the release ZIPs install only `skills/phpfixes-php2shell/`, so the checker and everything it reads live inside it. The Claude Code plugin is the whole repository, and its skill is that same folder. See [CHANGELOG.md](CHANGELOG.md) for what changed in each version.

## Tests

From the repository root, `python3 -m unittest` runs every test. The release checks also run the helper with `python3 -I`, which isolates Python from user settings and the working directory. `.github/workflows/tests.yml` runs tests on Python 3.9, 3.12 and 3.14 for every push and pull request. Published 1.0.2 passed that matrix. Its GitHub clone and Claude Code plugin installs were tested on 2026-10-23; the Codex installer was tested against a local archive of that release. Version 1.0.3 has separate release checks; those earlier installation results apply to 1.0.2.

## License and attribution

MIT License, Copyright (c) 2026 SnowRock, LLC, which owns and operates PHPFixes. See [LICENSE](LICENSE). The package-version comparison is adapted from PHPFixes phpseal.

PHPFixes is independent and is not affiliated with or endorsed by the PHP project, Canonical, Debian, Anthropic, OpenAI or any other vendor or repository named here.

Need it fixed on a server? See [phpfixes.com](https://phpfixes.com), which publishes this skill and shows the current status of PHPFixes services. This skill is free and needs no account.
