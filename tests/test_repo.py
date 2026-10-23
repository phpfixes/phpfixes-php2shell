"""The repository keeps its promises: manifests, version, licence, links and file list all agree.

Run `python3 -m unittest` from the repository root. Each test name states one promise.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/phpfixes-php2shell"
sys.path.insert(0, str(SKILL / "php2shell"))
import assess

# Local clutter that git ignores and no release ships.
IGNORED_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache"}
IGNORED_FILES = {".DS_Store"}


def frontmatter(path):
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not match:
        raise AssertionError("SKILL.md has no frontmatter")
    fields = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def repository_files():
    found = []
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        # A symlinked directory is reported as an entry so it can never match the file list.
        found.extend((Path(folder) / d).relative_to(ROOT).as_posix()
                     for d in dirs if (Path(folder) / d).is_symlink())
        for name in sorted(files):
            if name in IGNORED_FILES or name.endswith((".pyc", ".pyo")):
                continue
            found.append((Path(folder) / name).relative_to(ROOT).as_posix())
    return sorted(found)


class ManifestTests(unittest.TestCase):
    def load(self, relative):
        data = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        self.assertFalse([key for key in data if key.startswith("_")], relative)
        return data

    def test_plugin_version_and_licence_match_the_helper(self):
        plugin = self.load(".claude-plugin/plugin.json")
        self.assertEqual(plugin["name"], "phpfixes")
        self.assertEqual(plugin["version"], assess.VERSION)
        self.assertEqual(plugin["license"], "MIT")
        self.assertRegex(plugin["version"], r"^\d+\.\d+\.\d+$")

    def test_marketplace_lists_exactly_this_repository_as_its_one_plugin(self):
        plugin = self.load(".claude-plugin/plugin.json")
        market = self.load(".claude-plugin/marketplace.json")
        self.assertEqual(len(market["plugins"]), 1)
        entry = market["plugins"][0]
        self.assertEqual(entry["name"], plugin["name"])
        self.assertEqual(entry["source"], "./")
        self.assertEqual(entry["description"], plugin["description"])

    def test_skill_frontmatter_is_valid_for_claude_code_and_codex(self):
        fields = frontmatter(SKILL / "SKILL.md")
        self.assertEqual(fields["name"], SKILL.name)
        self.assertRegex(fields["name"], r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        self.assertLessEqual(len(fields["name"]), 64)
        self.assertLessEqual(len(fields["description"]), 1024)
        self.assertNotRegex(fields["description"], r"[<>]")
        # A ": " inside an unquoted YAML value would break the frontmatter for strict parsers.
        self.assertNotIn(": ", fields["description"])
        self.assertTrue(set(fields) <= {"name", "description", "license", "allowed-tools", "metadata"})

    def test_the_mit_licence_ships_at_the_root_and_inside_the_skill(self):
        root_license = (ROOT / "LICENSE").read_bytes()
        self.assertEqual(root_license, (SKILL / "LICENSE.txt").read_bytes())
        self.assertIn(b"MIT License", root_license)
        self.assertIn(b"Copyright (c) 2026 SnowRock, LLC", root_license)

    def test_readme_and_changelog_state_the_current_version_and_freshness_window(self):
        facts = json.loads((SKILL / "data/advisories.json").read_text(encoding="utf-8"))
        facts_date = dt.date.fromisoformat(facts["facts_as_of"])
        last_fixed_day = facts_date + dt.timedelta(days=facts["max_facts_age_days"])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Version %s." % assess.VERSION, readme)
        self.assertIn(facts_date.isoformat(), readme)
        self.assertIn(last_fixed_day.isoformat(), readme)
        self.assertIn("/tree/v%s/skills/phpfixes-php2shell" % assess.VERSION, readme)
        self.assertIn("--branch v%s " % assess.VERSION, readme)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertRegex(changelog, r"\n## %s " % re.escape(assess.VERSION))
        first = re.search(r"\n## (\d+\.\d+\.\d+) ", changelog).group(1)
        self.assertEqual(first, assess.VERSION)

    def test_the_readme_shows_the_real_vendor_backport_rule_unedited(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        source = (SKILL / "php2shell/assess.py").read_text(encoding="utf-8")
        blocks = re.findall(r"```python\n(.*?)```", readme, re.S)
        self.assertTrue(blocks)
        for block in blocks:
            self.assertIn(block, source)

    def test_every_relative_link_in_the_markdown_files_resolves(self):
        for path in sorted(ROOT.rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
                if re.match(r"^[a-z]+:", target):
                    continue
                with self.subTest(file=path.relative_to(ROOT).as_posix(), link=target):
                    self.assertTrue((path.parent / target).exists())

    def test_the_plugin_icon_is_a_square_png_the_plugin_directory_accepts(self):
        # The directory takes a square PNG of 512 to 2048 pixels, under 2 MB. Text chunks could
        # carry tool or path metadata, so only image chunks are allowed.
        data = (ROOT / ".claude-plugin/icon.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertLess(len(data), 2 * 1024 * 1024)
        chunks, offset = [], 8
        while offset < len(data):
            length = int.from_bytes(data[offset:offset + 4], "big")
            chunks.append((data[offset + 4:offset + 8], data[offset + 8:offset + 8 + length]))
            offset += 12 + length
        self.assertEqual(offset, len(data))
        kind, header = chunks[0]
        width, height = int.from_bytes(header[:4], "big"), int.from_bytes(header[4:8], "big")
        self.assertEqual((kind, chunks[-1][0]), (b"IHDR", b"IEND"))
        self.assertEqual(width, height)
        self.assertTrue(512 <= width <= 2048, width)
        image_chunks = {b"IHDR", b"PLTE", b"tRNS", b"pHYs", b"IDAT", b"IEND"}
        self.assertLessEqual({kind for kind, _ in chunks}, image_chunks)

    def test_a_product_this_release_does_not_offer_is_named_only_where_its_row_is_dropped(self):
        for plan in assess.NOT_OFFERED:
            hits = []
            for path in repository_files():
                if path.endswith(".png"):
                    continue
                for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
                    if plan in line.lower():
                        hits.append((path, line.strip()))
            self.assertEqual(hits, [("skills/phpfixes-php2shell/php2shell/assess.py",
                                     'NOT_OFFERED = ("%s",)' % plan)])

    def test_the_helper_prints_its_own_version(self):
        process = subprocess.run([sys.executable, "-B", str(SKILL / "php2shell/assess.py"), "--version"],
                                 cwd=str(ROOT), universal_newlines=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), assess.VERSION)


class FileListTests(unittest.TestCase):
    def rows(self):
        rows = {}
        for line in (ROOT / "FILELIST.txt").read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            digest, size, mode, path = line.split("  ", 3)
            self.assertNotIn(path, rows, "duplicate entry " + path)
            rows[path] = (digest, int(size), mode)
        return rows

    def test_the_file_list_names_every_file_with_its_true_hash_size_and_mode(self):
        rows = self.rows()
        actual = [path for path in repository_files() if path != "FILELIST.txt"]
        self.assertEqual(sorted(rows), actual)
        for path, (digest, size, mode) in rows.items():
            with self.subTest(path=path):
                full = ROOT / path
                info = full.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode), "not a regular file")
                self.assertEqual(mode, "100644")
                self.assertEqual(info.st_mode & 0o111, 0, "unexpected executable bit")
                data = full.read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_every_listed_path_is_plain_and_relative(self):
        for path in self.rows():
            with self.subTest(path=path):
                parts = path.split("/")
                self.assertFalse(path.startswith("/") or "\\" in path or ".." in parts or "" in parts)
                self.assertRegex(path, r"^[A-Za-z0-9._/-]+$")


if __name__ == "__main__":
    unittest.main()
