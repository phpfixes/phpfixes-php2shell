# Install PHPFixes 1.2.1

This free plugin checks supplied PHP2Shell evidence and provides an optional local PHP inventory. It needs no PHPFixes account, purchase or model API key. Your assistant account is separate. Python 3.9 or later is required for the declared local MCP server. The assistant host starts it locally and calls its three tools. Startup does not inspect packages/processes. This local server is supported in Claude Code and Cowork, not Claude web/mobile chat. OpenAI public-directory local MCP access requires an eligible allowlisted organization; no directory listing is claimed.

Download the release ZIP from https://github.com/phpfixes/phpfixes-php2shell/releases/tag/v1.2.1 and check it against the accompanying SHA256SUMS before extracting it. Keep the extracted plugin folder while using a local marketplace. Installing from this package is separate from public directory availability.

Read [privacy](PRIVACY.md) before sharing records and [support](SUPPORT.md) for installation help.

In the commands below, replace /absolute/path/to/phpfixes with the extracted folder containing plugin.json and skills/.

## Claude Code

```sh
claude plugin marketplace add /absolute/path/to/phpfixes
claude plugin install phpfixes@phpfixes
```

Start a new session. Use /phpfixes:phpfixes-php2shell or ask about PHP2Shell evidence and PHP runtime inventory. Local installation is separate from the Claude directory.

## Codex

```sh
codex plugin marketplace add /absolute/path/to/phpfixes
codex plugin add phpfixes@phpfixes
codex plugin list --json
```

Start a new session. Invoke $phpfixes-php2shell. Plugins require a supported Codex surface. For a standalone skill, copy skills/phpfixes-php2shell into the project's .agents/skills/ folder instead; standalone skill support differs from plugin support.

## Tool behavior

The declared tools assess supplied evidence, check a supplied inventory or collect bounded local Linux metadata after a direct owner request. The skill never invokes Python, Bash or suggested commands outside the declared server. If tools are unavailable, it can read supplied records directly and reports the missing tool.

## Use without an assistant

From this folder, inspect the included synthetic inventory without inspecting your computer:

```sh
python3 -I -B skills/phpfixes-php2shell/php2shell/inventory.py --input skills/phpfixes-php2shell/examples/local-inventory.json --format text
```

For a bounded inventory of the local Linux namespace you are allowed to inspect, opt in explicitly:

```sh
python3 -I -B skills/phpfixes-php2shell/php2shell/inventory.py --collect-local --authorized --format text
```

The collector reads limited package/process metadata. It does not execute PHP, inspect environment variables or configuration, contact a server, upload data or change packages. Output shown to your assistant can enter its normal conversation and tool-data handling. Read data/inventory-guide.md inside the skill for coverage and limits. A version string or matching executable file does not prove that a server is fixed. Supplied evidence can still be assessed with php2shell/assess.py.

Source and license: https://github.com/phpfixes/phpfixes-php2shell. Copyright 2026 SnowRock, LLC. MIT license. Keep required licenses with the skill.
