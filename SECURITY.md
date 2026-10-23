# Security

## Report a vulnerability

Email security@phpfixes.com. Please include:

- the version, from `.claude-plugin/plugin.json` or `python3 skills/phpfixes-php2shell/php2shell/assess.py --version`,
- what you found, and how to reproduce it with synthetic data,
- the effect you expect it to have.

Please do not include real server evidence, credentials, customer data or working exploit code. Please do not open a public issue for a vulnerability before a fixed version is released.

## In scope

- Skill instructions that would lead an assistant to run a command, contact a system or share data beyond what [README.md](README.md) describes.
- The helper (`skills/phpfixes-php2shell/php2shell/assess.py` and `skills/phpfixes-php2shell/php2shell/version_compare.py`) reading anything beyond its bundled files and the files named on its command line, writing anything beyond its printed output, or reporting `FIXED_EVIDENCE` when the supplied evidence does not support it.
- Release files that do not match `SHA256SUMS` or `FILELIST.txt`.

## Wrong or outdated findings

A wrong fixed version or a missed vendor advisory is a correctness problem. Open an issue with a link to the official advisory. If the error could lead someone to treat an affected server as fixed, email security@phpfixes.com instead.

## Supported versions

Only the latest release receives fixes, and a fix ships as a new version.

## Other PHPFixes services

This repository has no server component. Security issues in the PHPFixes website or other PHPFixes services can be reported to the same address.
