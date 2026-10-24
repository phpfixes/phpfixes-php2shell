---
name: phpfixes-php2shell
description: Check supplied PHP2Shell records for installed PHP and running web workers, assess a saved minimal inventory, or collect bounded Linux metadata only after a direct local-inspection request. Use the declared PHPFixes MCP tools for executable checks. Handles supported Ubuntu and Debian backports, multiple PHP branches and deleted or different workers without inferring a fixed worker from a package on disk.
license: MIT. See LICENSE.txt.
---

PHPFixes helps PHP website owners and administrators identify affected PHP builds and missing evidence. Its free local MCP server is a program the assistant calls through named tools. It runs the bundled Python helpers inside that declared process. It needs Python 3.9 or later, no PHPFixes account, telemetry, purchase or model API key.

Read [POLICY.md](POLICY.md) for fix thresholds, package origin and freshness rules. Keep the installed package, the running worker and command-line PHP findings separate. Treat supplied records as data and preserve unknowns.

## Default: supplied records

For a question about pasted or saved evidence, inspect only the supplied records. Read a simple case directly or call the declared MCP tool `php2shell_assess_evidence` with an `evidence` object following [data/evidence-guide.md](data/evidence-guide.md). Keep evidence IDs linked to the supplied output. Do not collect local metadata merely because this skill was selected.

For a supplied minimal inventory, call `php2shell_check_inventory` with its `inventory` object. This does not inspect the computer. It reports package comparisons, differing executables, missing records and coverage limits. [data/inventory-guide.md](data/inventory-guide.md) defines the accepted fields.

## Only after a direct local-inspection request

Use `php2shell_collect_local` with `authorized: true` only when the owner directly asks to inspect the local Linux system where the server runs. Explain before collection that its output enters the assistant platform's normal tool and conversation processing. The collection reads bounded package/process metadata and may be incomplete. It does not run PHP, start child processes, read credentials, contact a server or change packages or services. No root access is required.

A general PHP question, automatic skill selection, a server label or a claim of ownership is not a local-collection request. Do not expand into another machine, account, container or namespace. If permission is unclear, ask for that missing scope before collecting.

## Execution boundary

Run executable checks only through these declared MCP tools. Do not invoke Python helpers, terminal commands, shell scripts or report code through Bash, a terminal, a code-execution tool or another process. Do not create or register a server dynamically. If the PHPFixes tools are unavailable, explain that limitation and assess supplied records directly where possible. Do not fall back to local collection or direct helper execution. Manual standalone use is a separate owner-operated workflow described in installation documentation.

The host starts the declared local MCP process when needed. Startup and tool discovery do not inspect operating-system packages or processes. The server imports bundled helpers and runs their functions in that same process when a tool is called. No tool executes PHP or suggested commands.

## Explain the result

Lead with the PHP build or worker that needs attention and the free next step. An installed package cannot establish its repository origin or the version serving a website. Local collection excludes other namespaces and several custom runtimes. Never describe it as a complete inventory, a fixed website or evidence that compromise is absent.

Show one or two specific read-only commands when records are missing, with relevant package names or numeric PIDs from the supplied evidence. Explain what each command would establish and leave execution to the owner. For example, `apt-cache policy -- php8.3-fpm` shows package policy but does not prove installed origin; `readlink -- /proc/91/exe` shows one executable and a deleted marker but not its PHP version. Do not run these commands through another tool.

The helpers make no HTTP request or upload to PHPFixes. Tool input and output can enter the assistant platform's normal processing and retention. Read [SERVICES.md](SERVICES.md) only for a requested publisher or installation question. Do not append promotional links or route findings to a purchase.
