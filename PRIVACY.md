# PHPFixes diagnostic privacy

PHPFixes is a free local diagnostic for PHP owners and administrators. Its Python helpers assess records you supply and can collect a small Linux inventory when you explicitly request local inspection. They need no PHPFixes account and make no network request, upload or automatic data transmission to PHPFixes.

## Declared local server

The assistant host starts the bundled Python MCP server locally. Startup and tool discovery do not inspect package/process metadata. Assessment and saved-inventory tools receive the JSON records you supply; local collection is a separate tool that requires a direct inspection request and explicit authorization. Helper functions run inside that declared server, not in separately launched scripts. The server uses standard input/output with its host, makes no HTTP request and keeps no request or report store. The host may retain tool input/output under its own policies.

## Records you supply

A saved JSON file or text you give an assistant can contain personal information, such as names, email addresses or identifying server details. Supply only the records needed for the question. Remove credentials, customer information and unrelated private data before sharing anything. The declared MCP tools receive evidence or saved inventory as JSON arguments and do not inspect your system. If you run a standalone helper yourself, it reads the named JSON file you select.

## Optional local inventory

In the assistant plugin, local collection requires your direct request to inspect that Linux namespace and the `php2shell_collect_local` argument `authorized: true`. If you run the standalone inventory helper yourself, both `--collect-local --authorized` are required. The collector reads bounded operating-system identification, installed runtime package records and process metadata. It retains exactly these inventory fields:

- Inventory format version and collection time in UTC.
- Operating-system ID and release version.
- Recognized installed PHP runtime package names and their full versions.
- Recognized PHP process IDs, executable basenames, a matching runtime package name when known, and a file-identity result: matches-installed, deleted-or-different or unknown.
- Package and process coverage states, counts of unreadable and vanished processes, the count of observed Apache processes, and names of reached collection limits.

Package-file lists, full executable paths and file metadata can be checked temporarily to compare ownership and identity. Full paths, device/inode values, file sizes and file timestamps are not retained in inventory output. The collector does not read executable contents. It does not inspect credentials, environment variables, process command lines, PHP or web-server configuration, logs or hostnames. It does not execute PHP, start subprocesses, install software or change services.

The resulting report also contains normalized evidence, findings, source references, missing information and suggested manual commands derived from those records. Suggested commands are shown rather than run. Package origin and a running worker's patch status can remain unknown. Read the [inventory guide](skills/phpfixes-php2shell/data/inventory-guide.md) for the exact input files, bounds and coverage limits.

## Output and sharing

The declared MCP server keeps records in memory while running and returns JSON tool results to its host over standard input/output. Standalone helpers print results to standard output. Neither mode creates a data store or automatically saves reports. Your shell or assistant can save output to a file if you direct it to do so. You control those files and any later sharing.

Output supplied to Codex, Claude or another assistant can enter that platform's normal conversation, tool processing and retention. Its settings and policies apply. This local helper does not set that platform's retention period. PHPFixes does not receive the output unless you separately choose to share it, for example in a support request. Public GitHub issues are visible to others and are subject to GitHub's policies. No fixed retention period is promised here.

Use [support](SUPPORT.md) for installation questions and minimal nonsecret examples. Follow [security reporting](SECURITY.md) for a vulnerability; do not publish private server records.
