# Local PHP inventory

In the assistant plugin, use the declared PHPFixes MCP tools. Do not run the command examples below through a terminal or code-execution tool. They describe an owner operating standalone helpers separately. The supplied-record tools do not inspect local packages or processes; the collection tool requires a direct local-inspection request and explicit authorization.

The optional inventory helper gives a PHP owner a small list of installed runtime packages and visible PHP processes. It helps find multiple PHP branches, workers using deleted or different executables and gaps that prevent a PHP2Shell decision. It does not execute PHP or discover which website sends requests to which worker.

## Use saved records offline

For manual owner-operated use, run from the skill directory:

```text
python3 -I php2shell/inventory.py --input /absolute/path/inventory.json --format text
```

The input shape is in [inventory.schema.json](inventory.schema.json). [../examples/local-inventory.json](../examples/local-inventory.json) is a synthetic example, not a real server. Python callers can use `validate_inventory(data)`, `normalize_inventory(data)` and `diagnose(data, now=None)` from `inventory.py`.

A snapshot has `inventory_version: 1`, a timezone-aware `collected_at`, OS `id` and `version_id`, installed `packages`, observed PHP `processes` and `coverage`. Packages keep their full name and version. A process has a numeric PID, executable basename, optional owning package name and binary identity. Package names must identify CLI, FPM, CGI or Apache PHP runtime packages. Extension packages and meta-packages are excluded.

`matches-installed` requires a package ownership record for the exact executable path and matching file identity at collection time. A matching basename alone is insufficient. `deleted-or-different` records a deleted executable or differing file identity. Neither state supplies the running PHP release number. Unknown ownership stays null and identity stays unknown.

The report has stable top-level fields `tool_version`, `inventory`, `normalized_evidence`, `assessment`, `findings`, `actions` and `limitations`. Each finding has `code`, `severity`, `runtime_ids`, `summary` and `action_ids`. A conditional vendor finding also has `comparison` with the full package version, bundled threshold, order, source URL, fact review date and `origin_verified: false`. Final installed/running status stays unknown without provenance. Each action has `id`, `purpose`, `command` and `automatic: false`. Commands are shown only. No report text or supplied field is executed. With no runtime records, normalized evidence and assessment are null, and findings explain the gap.

The normalizer produces the existing evidence schema with `inventory_complete: false`, unknown package origin and unknown repository provenance. It does not invent version output. Confirm installed origin from separate records before adding provenance through [evidence-guide.md](evidence-guide.md). An `apt-cache policy` candidate or version suffix alone cannot establish installed origin.

## Opt in to local Linux collection

Use this only with permission to inspect this local system or container:

```text
python3 -I php2shell/inventory.py --collect-local --authorized --format text
python3 -I php2shell/inventory.py --collect-local --authorized --format inventory
```

Output goes to standard output; the owner chooses whether and where to save it. The helper sends no HTTP request or upload to PHPFixes. If Codex or Claude invokes it, the output can enter that platform's normal tool and conversation processing. Local collection does not mean every fact stays outside the assistant platform. The helper writes no files. It makes no network request, starts no subprocess and runs no PHP binary. There is no remote host or arbitrary filesystem-root option. Default input mode does not inspect the local system. It does not request root.

Collection reads only these metadata sources:

- `/etc/os-release`, with `/usr/lib/os-release` as a fixed fallback. Only ID and VERSION_ID are kept. A final symlink is rejected rather than followed.
- `/var/lib/dpkg/status`. Only installed PHP runtime package names and full versions are kept. Package control fields do not prove repository origin.
- `/proc` numeric entries, each candidate's `comm` and `exe`, and file identity from `stat`. Only PID, recognized executable basename, package name and identity result are kept. Full executable paths are omitted from output.
- `/var/lib/dpkg/info/<runtime-package>.list` for ownership of standard Debian CLI, FPM and CGI executable paths. File lists provide ownership evidence only.

It does not read hostnames, environment variables, command lines, current directories, configuration, credentials, logs, executable contents or process maps. It does not inspect Apache modules. An observed Apache executable adds a coverage warning without claiming that Apache uses PHP.

Reads are bounded to 32 MiB for the package database, 256 KiB per package file list, 16 KiB per OS file and 64 bytes per process name. Collection keeps at most 40 packages and 40 PHP processes and examines at most 4,096 numeric process entries. A soft three-second process-scan budget starts before initial metadata reads and is checked between process operations. The initial bounded database read/parse or an individual filesystem read may exceed it; it is not a hard wall-clock timeout. Limits and inaccessible or vanished processes make coverage limited. Input files are limited to 256 KiB.

`complete` in a coverage field means the bounded reader completed that particular source, not that it found every PHP runtime. Other containers and process namespaces, custom installs, control panels, Apache modules, LiteSpeed and embedded runtimes remain outside coverage. Processes can start, exit or change during collection. An empty process list never proves that a website is stopped or fixed. Unsupported package managers leave package coverage unavailable.

For an unresolved worker, inspect its current executable and obtain approved package or build records for that exact runtime. Plan any restart or package change separately after reviewing the site's service ownership and recovery needs. The collector never restarts or changes a service.
