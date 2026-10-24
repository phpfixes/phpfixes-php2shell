# PHPFixes diagnostic privacy

PHPFixes is a free local diagnostic for PHP owners and administrators. Its Python helpers assess records you supply and can collect a small Linux inventory when you explicitly request local inspection. They need no PHPFixes account and make no network request, upload or automatic data transmission to PHPFixes.

## Records you supply

A saved JSON file or text you give an assistant can contain personal information, such as names, email addresses or identifying server details. Supply only the records needed for the question. Remove credentials, customer information and unrelated private data before sharing anything. The evidence helper reads the JSON file you select. Saved-inventory mode reads the inventory you select and does not inspect your system.

## Optional local inventory

Local collection requires both `--collect-local --authorized` and permission to inspect that Linux namespace. The collector reads bounded operating-system identification, installed runtime package records and process metadata. It retains exactly these inventory fields:

- Inventory format version and collection time in UTC.
- Operating-system ID and release version.
- Recognized installed PHP runtime package names and their full versions.
- Recognized PHP process IDs, executable basenames, a matching runtime package name when known, and a file-identity result: matches-installed, deleted-or-different or unknown.
- Package and process coverage states, counts of unreadable and vanished processes, the count of observed Apache processes, and names of reached collection limits.

Package-file lists, full executable paths and file metadata can be checked temporarily to compare ownership and identity. Full paths, device/inode values, file sizes and file timestamps are not retained in inventory output. The collector does not read executable contents. It does not inspect credentials, environment variables, process command lines, PHP or web-server configuration, logs or hostnames. It does not execute PHP, start subprocesses, install software or change services.

The resulting report also contains normalized evidence, findings, source references, missing information and suggested manual commands derived from those records. Suggested commands are shown rather than run. Package origin and a running worker's patch status can remain unknown. Read the [inventory guide](skills/phpfixes-php2shell/data/inventory-guide.md) for the exact input files, bounds and coverage limits.

## Output and sharing

The helpers keep records in memory while running and print results to standard output. They do not create a data store or automatically save reports. Your shell or assistant can save output to a file if you direct it to do so. You control those files and any later sharing.

Output supplied to Codex, Claude or another assistant can enter that platform's normal conversation, tool processing and retention. Its settings and policies apply. This local helper does not set that platform's retention period. PHPFixes does not receive the output unless you separately choose to share it, for example in a support request. Public GitHub issues are visible to others and are subject to GitHub's policies. No fixed retention period is promised here.

Use [support](SUPPORT.md) for installation questions and minimal nonsecret examples. Follow [security reporting](SECURITY.md) for a vulnerability; do not publish private server records.
