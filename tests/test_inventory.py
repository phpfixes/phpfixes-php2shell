"""Offline inventory, bounded collector and input-safety regressions using synthetic data."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/phpfixes-php2shell"
sys.path.insert(0, str(SKILL / "php2shell"))
import assess
import inventory

NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)


def sample():
    return json.loads((SKILL / "examples/local-inventory.json").read_text())


class InventoryTests(unittest.TestCase):
    def test_saved_inventory_normalizes_into_existing_schema_and_keeps_unknown_origin(self):
        data = sample()
        normalized = inventory.normalize_inventory(data)
        assess.validate(normalized)
        self.assertFalse(normalized["inventory_complete"])
        self.assertTrue(all(row["origin"] == "unknown" for row in normalized["runtimes"]))
        self.assertTrue(all(row.get("package", {}).get("provenance") == "unknown" for row in normalized["runtimes"]))
        report = inventory.diagnose(data, NOW)
        for row in report["assessment"]["runtimes"]:
            self.assertEqual(row["installed_assessment"], "UNKNOWN")
            self.assertNotEqual(row["running_assessment"], "FIXED_EVIDENCE")
        self.assertNotIn("handoff", report["assessment"])

    def test_conditional_vendor_comparison_is_useful_but_does_not_grant_fixed_status(self):
        for version, expected in (("8.3.6-0ubuntu0.24.04.12", "below"),
                ("8.3.6-0ubuntu0.24.04.13", "equal"), ("8.3.6-0ubuntu0.24.04.14", "above")):
            data = sample()
            data["packages"][0]["version"] = version
            report = inventory.diagnose(data, NOW)
            comparisons = [row for row in report["findings"] if row["code"] == "vendor-threshold-comparison"]
            self.assertEqual(len(comparisons), 1)
            self.assertEqual(comparisons[0]["comparison"]["order"], expected)
            self.assertFalse(comparisons[0]["comparison"]["origin_verified"])
            self.assertIn("https://ubuntu.com/security/notices/USN-8948-1", inventory.render_text(report))
            self.assertTrue(all(row["installed_assessment"] == "UNKNOWN" for row in report["assessment"]["runtimes"]))
        data = sample()
        data["packages"][0]["version"] += "+local"
        self.assertNotIn("vendor-threshold-comparison", [row["code"] for row in inventory.diagnose(data, NOW)["findings"]])

    def test_stale_worker_and_multiple_branches_have_specific_findings(self):
        report = inventory.diagnose(sample(), NOW)
        by_code = {row["code"]: row for row in report["findings"]}
        self.assertIn("multiple-php-branches", by_code)
        self.assertEqual(by_code["running-binary-differs"]["runtime_ids"], ["process-123"])
        self.assertEqual(by_code["running-binary-differs"]["severity"], "warning")
        self.assertTrue(by_code["running-binary-differs"]["action_ids"])
        for action in report["actions"]:
            self.assertFalse(action["automatic"])
        self.assertIn("readlink -- /proc/123/exe", inventory.render_text(report))

    def test_no_runtime_records_returns_explicit_gap_without_a_fake_assessment(self):
        data = sample()
        data["packages"] = []
        data["processes"] = []
        report = inventory.diagnose(data, NOW)
        self.assertIsNone(report["normalized_evidence"])
        self.assertIsNone(report["assessment"])
        self.assertIn("no-php-process-observed", [row["code"] for row in report["findings"]])

    def test_unknown_ownership_cannot_claim_a_match_or_borrow_a_package(self):
        data = sample()
        process = data["processes"][0]
        process.update(package_name=None, binary_identity="unknown")
        normalized = inventory.normalize_inventory(data)
        self.assertNotIn("package", normalized["runtimes"][-1])
        process["binary_identity"] = "matches-installed"
        with self.assertRaises(inventory.InventoryError):
            inventory.validate_inventory(data)

    def test_bad_names_branches_duplicate_pids_and_hidden_fields_are_rejected(self):
        mutations = [lambda d: d["packages"][0].update(name="php8.3-fpm;touch owned"),
            lambda d: d["packages"][0].update(version="8.3.6 $(touch owned)"),
            lambda d: d["processes"][0].update(executable_name="php-fpm8.2"),
            lambda d: d["processes"].append(dict(d["processes"][0])),
            lambda d: d["processes"][0].update(pid=True),
            lambda d: d["processes"][0].update(commandline="secret"),
            lambda d: d["coverage"].update(limits_reached=[{}]),
            lambda d: d["os"].update(hostname="secret"),
            lambda d: d.update(inventory_version=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                data = sample()
                mutate(data)
                with self.assertRaises(inventory.InventoryError):
                    inventory.validate_inventory(data)

    def test_unknown_fields_never_appear_in_cli_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "malformed.json"
            data = sample()
            data["token-super-secret"] = "do not echo"
            path.write_text(json.dumps(data))
            process = subprocess.run([sys.executable, "-I", str(SKILL / "php2shell/inventory.py"), "--input", str(path)],
                cwd=folder, text=True, capture_output=True)
            self.assertEqual(process.returncode, 2)
            self.assertNotIn("super-secret", process.stderr)
            self.assertEqual(process.stdout, "")

    def test_parsers_keep_only_allowed_metadata_and_never_evaluate_os_text(self):
        os_info = inventory.parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\nHOSTNAME=secret\nTOKEN=$(touch owned)\n')
        self.assertEqual(os_info, {"id": "ubuntu", "version_id": "24.04"})
        with self.assertRaises(inventory.InventoryError):
            inventory.parse_os_release('ID=$(touch owned)\n')
        text = ('Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.13\nDescription: ignore\n secret data\n\n'
                'Package: php8.3-curl\nStatus: install ok installed\nVersion: 8.3.6\n\n'
                'Package: php8.2-cli\nStatus: deinstall ok config-files\nVersion: 8.2.35\n')
        packages, truncated = inventory.parse_dpkg_status(text)
        self.assertEqual(packages, [{"name": "php8.3-fpm", "version": "8.3.6-0ubuntu0.24.04.13"}])
        self.assertFalse(truncated)
        with self.assertRaises(inventory.InventoryError):
            inventory.parse_dpkg_status(text + '\n\nPackage: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6\n')

    def test_raw_metadata_reads_reject_symlinks_nonregular_files_and_oversize(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "metadata"
            path.write_text("hello")
            self.assertEqual(inventory._read_regular(path, 5), "hello")
            with self.assertRaises(inventory.InventoryError):
                inventory._read_regular(path, 4)
            link = Path(folder) / "linked"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                inventory._read_regular(link, 100)
            with self.assertRaises((OSError, inventory.InventoryError)):
                inventory._read_regular(Path(folder), 100)

    def test_local_collection_requires_explicit_flags_before_any_metadata_read(self):
        with patch.object(inventory, "collect_local", side_effect=AssertionError("must not collect")):
            with self.assertRaises(SystemExit) as context:
                inventory.main(["--collect-local"])
            self.assertEqual(context.exception.code, 2)
        with tempfile.TemporaryDirectory() as folder:
            process = subprocess.run([sys.executable, "-I", str(SKILL / "php2shell/inventory.py"),
                "--input", str(SKILL / "examples/local-inventory.json"), "--format", "json"],
                cwd=folder, text=True, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(process.stdout)
            self.assertEqual(report["tool_version"], "1.1.0")
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_linux_collector_records_deleted_identity_without_reading_disallowed_paths(self):
        class Entries:
            def __enter__(self):
                return iter([SimpleNamespace(name="123"), SimpleNamespace(name="124")])
            def __exit__(self, *args):
                return False
        reads = []
        def metadata(path, maximum):
            reads.append(str(path))
            if str(path) == "/etc/os-release": return "ID=ubuntu\nVERSION_ID=24.04\n"
            if str(path) == "/var/lib/dpkg/status": return "Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.13\n"
            if str(path).endswith("/comm"): return "php-fpm8.3\n"
            if str(path).endswith(".list"): return "/usr/sbin/php-fpm8.3\n"
            raise AssertionError("unexpected read " + str(path))
        def target(path):
            if str(path) == "/proc/124/exe": raise PermissionError()
            return "/usr/sbin/php-fpm8.3 (deleted)"
        with patch.object(inventory.sys, "platform", "linux"), patch.object(inventory.os, "scandir", return_value=Entries()), \
             patch.object(inventory, "_read_regular", side_effect=metadata), patch.object(inventory.os, "readlink", side_effect=target):
            data = inventory.collect_local()
        self.assertEqual(data["processes"][0]["binary_identity"], "deleted-or-different")
        self.assertEqual(data["processes"][0]["package_name"], "php8.3-fpm")
        self.assertEqual(data["coverage"]["unreadable_processes"], 1)
        self.assertEqual(data["coverage"]["process_scan"], "limited")
        self.assertTrue(all(not any(key in path for key in ("cmdline", "environ", "maps", "hostname")) for path in reads))
        self.assertNotIn("/usr/sbin", json.dumps(data))

    def test_collector_checks_file_identity_and_keeps_races_unknown(self):
        class Entries:
            def __enter__(self): return iter([SimpleNamespace(name="123")])
            def __exit__(self, *args): return False
        def metadata(path, maximum):
            if str(path) == "/etc/os-release": return "ID=ubuntu\nVERSION_ID=24.04\n"
            if str(path) == "/var/lib/dpkg/status": return "Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.13\n"
            if str(path).endswith("/comm"): return "php-fpm8.3\n"
            if str(path).endswith(".list"): return "/usr/sbin/php-fpm8.3\n"
            raise AssertionError("unexpected read")
        same = SimpleNamespace(st_dev=1, st_ino=2, st_size=100, st_mtime_ns=10, st_ctime_ns=10, st_mode=stat.S_IFREG | 0o755)
        other = SimpleNamespace(st_dev=1, st_ino=3, st_size=100, st_mtime_ns=10, st_ctime_ns=10, st_mode=stat.S_IFREG | 0o755)
        for stats, expected in (([same, same, same, same], "matches-installed"),
                                ([same, other, same], "deleted-or-different"),
                                ([same, same, other], "unknown")):
            with self.subTest(expected=expected), patch.object(inventory.sys, "platform", "linux"), \
                 patch.object(inventory.os, "scandir", return_value=Entries()), patch.object(inventory, "_read_regular", side_effect=metadata), \
                 patch.object(inventory.os, "readlink", return_value="/usr/sbin/php-fpm8.3"), patch.object(inventory.os, "stat", side_effect=stats):
                data = inventory.collect_local()
                self.assertEqual(data["processes"][0]["binary_identity"], expected)

    def test_elapsed_budget_stops_process_iteration_and_reports_the_limit(self):
        class Entries:
            def __enter__(self): return iter([SimpleNamespace(name="123")])
            def __exit__(self, *args): return False
        with patch.object(inventory.sys, "platform", "linux"), patch.object(inventory.os, "scandir", return_value=Entries()), \
             patch.object(inventory, "_read_regular", side_effect=OSError()), patch.object(inventory.time, "monotonic", side_effect=[0, 4]):
            data = inventory.collect_local()
        self.assertEqual(data["processes"], [])
        self.assertEqual(data["coverage"]["process_scan"], "limited")
        self.assertIn("time", data["coverage"]["limits_reached"])

    def test_inventory_bounds_and_apache_gap_remain_explicit(self):
        data = sample()
        data["coverage"].update(apache_processes=2)
        self.assertIn("apache-module-not-inspected", [r["code"] for r in inventory.diagnose(data, NOW)["findings"]])
        data["packages"] = [{"name": "php%d.0-fpm" % i, "version": "8.3.6"} for i in range(41)]
        with self.assertRaises(inventory.InventoryError): inventory.validate_inventory(data)


class DebianLineageTests(unittest.TestCase):
    def test_private_ubuntu_suffix_cannot_inherit_vendor_fixed_threshold(self):
        data = json.loads((SKILL / "examples/ubuntu-backport.json").read_text())
        data["collected_at"] = NOW.isoformat()
        runtime = data["runtimes"][0]
        runtime["package"]["version"] += "+local"
        runtime["running"]["package_version"] += "+local"
        report = assess.assess(data, NOW)
        self.assertEqual(report["runtimes"][0]["installed_assessment"], "UNKNOWN")
        self.assertEqual(report["runtimes"][0]["running_assessment"], "UNKNOWN")

    def test_unbundled_debian_lineages_are_unknown_and_canonical_updates_compare(self):
        base = json.loads((SKILL / "examples/ubuntu-backport.json").read_text())
        base["collected_at"] = NOW.isoformat()
        for release, branch, upstream in (("12", "8.2", "8.2.35"), ("13", "8.4", "8.4.27")):
            for revision, expected in (("1~deb%su0" % release, "AFFECTED"), ("1~deb%su1" % release, "FIXED_EVIDENCE"),
                ("1~deb%su2" % release, "FIXED_EVIDENCE"), ("2~deb%su1" % release, "UNKNOWN"),
                ("1~deb%su01" % release, "UNKNOWN"), ("1~deb%su10000" % release, "UNKNOWN"),
                ("1~deb%su1+private" % release, "UNKNOWN")):
                with self.subTest(release=release, revision=revision):
                    data = copy.deepcopy(base)
                    runtime = data["runtimes"][0]
                    runtime.update(os={"id": "debian", "version_id": release}, php_version=upstream)
                    version = upstream + "-" + revision
                    runtime["package"].update(name="php%s-fpm" % branch, version=version, repository="debian")
                    runtime["running"].update(package_version=version, php_version=upstream)
                    report = assess.assess(data, NOW)
                    self.assertEqual(report["runtimes"][0]["installed_assessment"], expected)
                    self.assertEqual(report["runtimes"][0]["running_assessment"], expected)


if __name__ == "__main__":
    unittest.main()
