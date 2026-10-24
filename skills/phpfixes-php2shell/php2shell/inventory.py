#!/usr/bin/env python3
"""Normalize minimal PHP inventories; collect Linux metadata only with explicit opt-in."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import assess

VERSION = "1.1.0"
MAX_PACKAGES = 40
MAX_PROCESSES = 40
MAX_PIDS = 4096
MAX_SECONDS = 3.0
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_LIST_BYTES = 256 * 1024
MAX_OS_BYTES = 16384
COVERAGE_STATES = ("complete", "limited", "unavailable")
IDENTITIES = ("matches-installed", "deleted-or-different", "unknown")
# Runtime packages only. Meta-packages and extensions cannot identify a PHP binary.
PACKAGE_RE = re.compile(r"(?:php(?:[0-9]+(?:\.[0-9]+)?)?-(?:cli|fpm|cgi)|libapache2-mod-php(?:[0-9]+(?:\.[0-9]+)?)?)(?::[a-z0-9][a-z0-9-]{0,19})?\Z")
EXE_RE = re.compile(r"php(?:-fpm|-cgi)?(?:[0-9]+(?:\.[0-9]+)?)?\Z")
OS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,49}\Z")
RELEASE_RE = re.compile(r"[A-Za-z0-9._-]{0,50}\Z")
LIMITS = ("time", "process-count", "process-records", "package-count", "database-bytes", "package-list-bytes")


class InventoryError(assess.EvidenceError):
    pass


def fields(value, required, optional=(), where="inventory"):
    # Do not repeat unknown fields or raw values in an error.
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise InventoryError(where + " has missing or unsupported fields")


def bounded_int(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def valid_name(value, pattern):
    return isinstance(value, str) and len(value) <= 100 and bool(pattern.fullmatch(value))


def validate_inventory(data):
    fields(data, ("inventory_version", "collected_at", "os", "packages", "processes", "coverage"))
    if type(data["inventory_version"]) is not int or data["inventory_version"] != 1:
        raise InventoryError("inventory_version must be 1")
    assess.timestamp(data["collected_at"], "collected_at")
    fields(data["os"], ("id", "version_id"), where="os")
    if not valid_name(data["os"]["id"], OS_RE) or not valid_name(data["os"]["version_id"], RELEASE_RE):
        raise InventoryError("os contains an unsupported id or version")
    if not isinstance(data["packages"], list) or len(data["packages"]) > MAX_PACKAGES:
        raise InventoryError("packages must contain at most 40 runtime packages")
    names = set()
    for row in data["packages"]:
        fields(row, ("name", "version"), where="package")
        if (not valid_name(row["name"], PACKAGE_RE) or row["name"] in names
                or not assess.valid_version(row["version"], assess.PKG_RE, 200)):
            raise InventoryError("package has an invalid or duplicate name or version")
        names.add(row["name"])
    if not isinstance(data["processes"], list) or len(data["processes"]) > MAX_PROCESSES:
        raise InventoryError("processes must contain at most 40 PHP processes")
    pids = set()
    for row in data["processes"]:
        fields(row, ("pid", "executable_name", "package_name", "binary_identity"), where="process")
        if not bounded_int(row["pid"], 2 ** 31 - 1) or row["pid"] == 0 or row["pid"] in pids:
            raise InventoryError("process has an invalid or duplicate pid")
        pids.add(row["pid"])
        if not valid_name(row["executable_name"], EXE_RE) or row["binary_identity"] not in IDENTITIES:
            raise InventoryError("process has an unsupported executable or identity")
        name = row["package_name"]
        if name is not None and (not isinstance(name, str) or name not in names):
            raise InventoryError("process package must reference an included runtime package")
        if row["binary_identity"] == "matches-installed" and name is None:
            raise InventoryError("matching identity requires an included package")
        if name is not None and package_sapi(name) != executable_sapi(row["executable_name"]):
            raise InventoryError("process executable and package identify different interfaces")
        package_branch = assess.branch_in_package_name(name or "")
        exe_branch = assess.branch_in_package_name(row["executable_name"].replace("php-fpm", "php").replace("php-cgi", "php"))
        if package_branch and exe_branch and package_branch != exe_branch:
            raise InventoryError("process executable and package identify different PHP branches")
    coverage = data["coverage"]
    fields(coverage, ("package_database", "process_scan", "unreadable_processes", "vanished_processes"),
           ("apache_processes", "limits_reached"), "coverage")
    if any(coverage[key] not in COVERAGE_STATES for key in ("package_database", "process_scan")):
        raise InventoryError("coverage has an unsupported state")
    if any(not bounded_int(coverage[key], MAX_PIDS) for key in ("unreadable_processes", "vanished_processes")):
        raise InventoryError("coverage count is outside supported limits")
    if not bounded_int(coverage.get("apache_processes", 0), MAX_PIDS):
        raise InventoryError("apache_processes is outside supported limits")
    limits = coverage.get("limits_reached", [])
    if not isinstance(limits, list) or len(limits) > len(LIMITS) or any(item not in LIMITS for item in limits) or len(set(limits)) != len(limits):
        raise InventoryError("coverage limits are unsupported")
    return data


def package_sapi(name):
    name = name.split(":", 1)[0]
    return "apache2handler" if name.startswith("libapache2-mod-php") else name.rsplit("-", 1)[1]


def executable_sapi(name):
    return "fpm" if "-fpm" in name else "cgi" if "-cgi" in name else "cli"


def parse_os_release(text):
    """Read only ID and VERSION_ID; never evaluate shell syntax or retain other fields."""
    found = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("ID", "VERSION_ID"):
            if key in found:
                raise InventoryError("duplicate operating-system field")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            pattern = OS_RE if key == "ID" else RELEASE_RE
            if not valid_name(value, pattern):
                raise InventoryError("unsupported operating-system field")
            found[key] = value
    return {"id": found.get("ID", "unknown"), "version_id": found.get("VERSION_ID", "")}


def parse_dpkg_status(text):
    """Return installed runtime package names/full versions; ignore every other field."""
    packages = []
    seen = set()
    for paragraph in text.split("\n\n"):
        row = {}
        duplicate = False
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, sep, value = line.partition(": ")
            if sep and key in ("Package", "Status", "Version"):
                if key in row:
                    duplicate = True
                row[key] = value
        name = row.get("Package", "")
        if not valid_name(name, PACKAGE_RE) or row.get("Status") != "install ok installed":
            continue
        if duplicate or name in seen or not assess.valid_version(row.get("Version"), assess.PKG_RE, 200):
            raise InventoryError("invalid or duplicate PHP package database record")
        packages.append({"name": name, "version": row["Version"]})
        seen.add(name)
        if len(packages) > MAX_PACKAGES:
            return sorted(packages[:MAX_PACKAGES], key=lambda item: item["name"]), True
    return sorted(packages, key=lambda item: item["name"]), False


def _read_regular(path, maximum):
    """Read a bounded regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InventoryError("metadata source is not a regular file")
        parts, remaining = [], maximum + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        data = b"".join(parts)
        if len(data) > maximum:
            raise InventoryError("metadata source exceeds its byte limit")
        return data.decode("utf-8", errors="strict")
    finally:
        os.close(fd)


def _binary_key(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _expected_path(package, executable):
    """Only standard Debian PHP runtime binary locations are eligible for ownership checks."""
    name = package["name"].split(":", 1)[0]
    branch = assess.branch_in_package_name(name)
    if not branch:
        return None
    sapi = package_sapi(name)
    prefix = {"fpm": "/usr/sbin/php-fpm", "cli": "/usr/bin/php", "cgi": "/usr/bin/php-cgi"}.get(sapi)
    expected = prefix + branch if prefix else None
    return expected if expected and Path(expected).name == executable else None


def _owner_for_path(path, executable, packages, deadline, coverage):
    for package in packages:
        if time.monotonic() >= deadline:
            coverage["limits_reached"].append("time")
            return None
        if _expected_path(package, executable) != path:
            continue
        # File lists establish ownership only; they do not establish repository provenance.
        list_path = Path("/var/lib/dpkg/info") / (package["name"] + ".list")
        try:
            lines = _read_regular(list_path, MAX_PACKAGE_LIST_BYTES).splitlines()
        except (OSError, UnicodeError, InventoryError):
            return None
        if path in lines:
            return package["name"]
    return None


def collect_local():
    """Inspect this Linux process namespace. No PHP, subprocess, config or network access."""
    if sys.platform != "linux":
        raise InventoryError("local collection supports Linux only; use --input for saved inventory")
    deadline = time.monotonic() + MAX_SECONDS
    coverage = {"package_database": "unavailable", "process_scan": "unavailable", "unreadable_processes": 0,
                "vanished_processes": 0, "apache_processes": 0, "limits_reached": []}
    os_info = {"id": "unknown", "version_id": ""}
    # /etc/os-release is commonly a symlink. The fixed fallback avoids following it.
    for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            os_info = parse_os_release(_read_regular(path, MAX_OS_BYTES))
            break
        except (OSError, UnicodeError, InventoryError):
            pass
    packages = []
    try:
        packages, truncated = parse_dpkg_status(_read_regular(Path("/var/lib/dpkg/status"), MAX_DATABASE_BYTES))
        coverage["package_database"] = "limited" if truncated else "complete"
        if truncated:
            coverage["limits_reached"].append("package-count")
    except (OSError, UnicodeError, InventoryError):
        pass
    processes = []
    try:
        with os.scandir("/proc") as entries:
            scanned = 0
            coverage["process_scan"] = "complete"
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdigit():
                    continue
                scanned += 1
                if scanned > MAX_PIDS or time.monotonic() >= deadline:
                    coverage["limits_reached"].append("process-count" if scanned > MAX_PIDS else "time")
                    coverage["process_scan"] = "limited"
                    break
                pid = int(entry.name)
                if not 0 < pid <= 2 ** 31 - 1:
                    continue
                try:
                    # Read no cmdline, environment, cwd, configuration, maps or file contents.
                    comm = _read_regular(Path("/proc") / entry.name / "comm", 64).strip()
                    if not (EXE_RE.fullmatch(comm) or comm in ("apache2", "httpd")):
                        continue
                    proc_exe = Path("/proc") / entry.name / "exe"
                    target = os.readlink(proc_exe)
                    deleted = target.endswith(" (deleted)")
                    actual_path = target[:-10] if deleted else target
                    executable = Path(actual_path).name
                    if executable in ("apache2", "httpd"):
                        coverage["apache_processes"] += 1
                        continue
                    if not EXE_RE.fullmatch(executable):
                        continue
                    if len(processes) >= MAX_PROCESSES:
                        coverage["limits_reached"].append("process-records")
                        coverage["process_scan"] = "limited"
                        break
                    owner = _owner_for_path(actual_path, executable, packages, deadline, coverage)
                    identity = "deleted-or-different" if deleted else "unknown"
                    if owner and not deleted:
                        try:
                            before = _binary_key(os.stat(proc_exe))
                            disk = _binary_key(os.stat(actual_path, follow_symlinks=False))
                            after = _binary_key(os.stat(proc_exe))
                            if before != after:
                                identity = "unknown"
                            elif before == disk and stat.S_ISREG(os.stat(actual_path, follow_symlinks=False).st_mode):
                                identity = "matches-installed"
                            else:
                                identity = "deleted-or-different"
                        except OSError:
                            identity = "unknown"
                    processes.append({"pid": pid, "executable_name": executable,
                                      "package_name": owner, "binary_identity": identity})
                except FileNotFoundError:
                    coverage["vanished_processes"] += 1
                except (OSError, UnicodeError, InventoryError):
                    coverage["unreadable_processes"] += 1
    except OSError:
        coverage["process_scan"] = "unavailable"
    if coverage["unreadable_processes"] or coverage["vanished_processes"] or coverage["limits_reached"]:
        if coverage["process_scan"] == "complete":
            coverage["process_scan"] = "limited"
    coverage["limits_reached"] = sorted(set(coverage["limits_reached"]))
    return validate_inventory({"inventory_version": 1,
        "collected_at": dt.datetime.now(assess.UTC).isoformat().replace("+00:00", "Z"),
        "os": os_info, "packages": packages, "processes": sorted(processes, key=lambda item: item["pid"]),
        "coverage": coverage})


def normalize_inventory(data):
    """Preserve minimal records as v1 evidence. Never invent origin, version output or coverage."""
    validate_inventory(data)
    sources = [{"id": "local-os", "kind": "os-release", "text": json.dumps(data["os"], sort_keys=True)}]
    runtimes = []
    packages = {row["name"]: row for row in data["packages"]}
    pkg_refs = {}
    for index, row in enumerate(data["packages"], 1):
        ref = "package-%d" % index
        pkg_refs[row["name"]] = ref
        sources.append({"id": ref, "kind": "installed-package", "text": json.dumps(row, sort_keys=True)})
        runtimes.append({"id": ref, "sapi": package_sapi(row["name"]), "origin": "unknown",
            "os": dict(data["os"]), "evidence_ids": ["local-os", ref],
            "package": {"manager": "dpkg", "name": row["name"], "version": row["version"],
                "repository": "unknown", "provenance": "unknown", "evidence_ids": [ref]},
            "running": {"state": "unknown", "binary_identity": "unknown", "evidence_ids": []}})
    for row in data["processes"]:
        ref = "process-%d" % row["pid"]
        sources.append({"id": ref, "kind": "process-mapping", "text": json.dumps(row, sort_keys=True)})
        package = packages.get(row["package_name"])
        item = {"id": ref, "sapi": executable_sapi(row["executable_name"]), "origin": "unknown",
            "os": dict(data["os"]), "evidence_ids": ["local-os", ref],
            "running": {"state": "observed", "binary_identity": row["binary_identity"], "evidence_ids": [ref]}}
        if package:
            pkg_ref = pkg_refs[package["name"]]
            item["evidence_ids"].append(pkg_ref)
            item["package"] = {"manager": "dpkg", "name": package["name"], "version": package["version"],
                "repository": "unknown", "provenance": "unknown", "evidence_ids": [pkg_ref]}
        runtimes.append(item)
    if not runtimes:
        return None
    result = {"schema_version": 1, "authorized": True,
        "scope": "Supplied local PHP package and process metadata in one Linux namespace",
        "collected_at": data["collected_at"], "inventory_complete": False,
        "evidence": sources, "runtimes": runtimes}
    assess.validate(result)
    return result


def diagnose(data, now=None):
    validate_inventory(data)
    evidence = normalize_inventory(data)
    result = assess.assess(evidence, now=now) if evidence else None
    findings, actions = [], []
    action_ids = set()

    def action(ident, purpose, command):
        if ident not in action_ids:
            actions.append({"id": ident, "purpose": purpose, "command": command, "automatic": False})
            action_ids.add(ident)
        return ident

    def finding(code, severity, refs, summary, next_actions=()):
        findings.append({"code": code, "severity": severity, "runtime_ids": refs,
                         "summary": summary, "action_ids": list(next_actions)})

    package_ids = ["package-%d" % index for index in range(1, len(data["packages"]) + 1)]
    branches = sorted(set(filter(None, (assess.branch_in_package_name(row["name"]) for row in data["packages"]))))
    if len(branches) > 1:
        finding("multiple-php-branches", "notice", package_ids,
                "Installed PHP runtime packages name these branches: %s. Each web runtime needs its own running identity." % ", ".join(branches))
    for index, row in enumerate(data["packages"], 1):
        ref = "package-%d" % index
        name = row["name"]
        query = action("package-source-%d" % index,
            "Inspect installed-version policy. Candidate repository rows alone cannot prove the installed package source.",
            "apt-cache policy -- " + name)
        finding("package-source-unverified", "evidence-needed", [ref],
            "%s %s is installed. Package database metadata does not establish its repository or a PHP2Shell fix." % (name, row["version"]), [query])
        epoch, upstream, revision = assess.deb_split(row["version"])
        branch = assess.branch_in_package_name(name)
        vendor = assess.vendor_fixed_row(data["os"], "php" + (branch or ""))
        if vendor and not assess.third_party_vendor(row["version"]):
            fixed_epoch, fixed_upstream, fixed_revision = assess.deb_split(vendor["fixed"])
            # Compare only the exact vendor base and canonical numeric update lineage.
            prefix = re.sub(r"[0-9]+$", "", fixed_revision)
            lineage = re.fullmatch(re.escape(prefix) + r"(?:0|[1-9][0-9]{0,3})", revision)
            if epoch == fixed_epoch and upstream == fixed_upstream and lineage:
                order = assess.deb_version_compare(row["version"], vendor["fixed"])
                relation = "below" if order < 0 else "equal" if order == 0 else "above"
                finding("vendor-threshold-comparison", "notice", [ref],
                    "%s %s compares %s the bundled %s %s fixed package %s. This applies only if the installed package came from that vendor archive; provenance and running fix status remain unresolved." %
                    (name, row["version"], relation, data["os"]["id"], data["os"]["version_id"], vendor["fixed"]), [query])
                findings[-1]["comparison"] = {"package_version": row["version"],
                    "fixed_threshold": vendor["fixed"], "order": relation,
                    "source_url": vendor["source"], "facts_as_of": assess.FACTS["facts_as_of"],
                    "origin_verified": False}
    for row in data["processes"]:
        ref = "process-%d" % row["pid"]
        inspect = action("process-executable-%d" % row["pid"],
            "Inspect this process executable locally. A process may exit or change after this snapshot.",
            "readlink -- /proc/%d/exe" % row["pid"])
        if row["binary_identity"] == "deleted-or-different":
            finding("running-binary-differs", "warning", [ref],
                "PHP process %d has a deleted executable or differs from the installed file. Its running PHP version and patch status remain unknown; inspect it before planning a service restart." % row["pid"], [inspect])
        elif row["binary_identity"] == "unknown":
            finding("running-binary-unverified", "evidence-needed", [ref],
                "PHP process %d could not be tied to an installed runtime file. A package update on disk cannot settle its running patch status." % row["pid"], [inspect])
        else:
            finding("running-binary-linked", "notice", [ref],
                "PHP process %d matches a runtime file owned by %s at collection time. Repository and fix evidence are still required." % (row["pid"], row["package_name"]))
    if data["coverage"].get("apache_processes", 0):
        apache_action = action("apache-process-list", "List Apache process names and PIDs only. Use the owner's deployment records to identify the site's PHP interface before a separate approved inspection.",
            "pgrep -l -x 'apache2|httpd'")
        finding("apache-module-not-inspected", "evidence-needed", [],
            "Apache processes were seen. This collector does not inspect loaded modules or configuration, so it cannot establish whether Apache embeds PHP or forwards requests to FPM. Confirm the site's PHP interface from its deployment records.", [apache_action])
    if not data["processes"]:
        process_action = action("local-process-list", "List matching process names and PIDs only. For a container-hosted site, repeat the opted-in inventory inside its known container namespace with the owner's permission.",
            "pgrep -l -x 'php(-fpm|-cgi)?[0-9.]*|apache2|httpd'")
        finding("no-php-process-observed", "evidence-needed", [],
            "No recognized PHP executable was observed in this process namespace. This does not establish that a website is stopped or uses fixed PHP. Check the known site/container environment and visible process names.", [process_action])
    if data["coverage"]["package_database"] != "complete" or data["coverage"]["process_scan"] != "complete":
        package_action = action("installed-runtime-list", "Read local dpkg runtime package names, full versions and installation states. This supplies package records, not repository provenance or running identity.",
            "dpkg-query -W -f='${binary:Package}\\t${Version}\\t${db:Status-Status}\\n' -- 'php*-cli' 'php*-fpm' 'php*-cgi' 'libapache2-mod-php*'")
        finding("collection-incomplete", "evidence-needed", [],
            "Package or process inspection was incomplete. Review coverage counts and limits; inaccessible or unexamined processes may use another PHP build. Obtain the missing local runtime records from an administrator already authorized to read them.", [package_action])
    finding("inventory-scope-limited", "evidence-needed", [],
        "Coverage excludes other containers and process namespaces, custom PHP paths, Apache modules, LiteSpeed and embedded runtimes. No whole-server fixed finding is possible from this inventory.")
    if result and not result["evidence_fresh"]:
        finding("inventory-stale", "evidence-needed", [], "This inventory is older than 24 hours or dated in the future. Collect a fresh snapshot before a positive fixed finding.")
    return {"tool_version": VERSION, "inventory": data, "normalized_evidence": evidence,
        "assessment": result, "findings": findings, "actions": actions,
        "limitations": ["No PHP binary was executed. No repository origin was inferred.",
            "Matching an executable file does not prove package contents are authentic or identify every web worker.",
            "This free offline report does not require an account, telemetry, network access or a purchase."]}


def render_text(report):
    lines = ["PHPFixes local PHP inventory %s" % VERSION,
             "Collected: " + report["inventory"]["collected_at"],
             "Packages: %d; PHP processes: %d" % (len(report["inventory"]["packages"]), len(report["inventory"]["processes"]))]
    for finding in report["findings"]:
        lines.append("[%s] %s" % (finding["code"], finding["summary"]))
        if "comparison" in finding:
            lines.append("  Source: %s (facts reviewed %s)" %
                (finding["comparison"]["source_url"], finding["comparison"]["facts_as_of"]))
    if report["actions"]:
        lines.append("Local inspection commands, shown only and never run by this helper:")
        for action in report["actions"]:
            lines.extend([action["purpose"], "  " + action["command"]])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", help="saved minimal inventory JSON; no local inspection")
    mode.add_argument("--collect-local", action="store_true", help="opt in to bounded local Linux metadata reads")
    parser.add_argument("--authorized", action="store_true", help="confirm permission to inspect this local Linux namespace")
    parser.add_argument("--format", choices=("json", "text", "inventory", "evidence"), default="text")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.collect_local and not args.authorized:
        parser.error("--collect-local also requires --authorized for this local namespace")
    try:
        inventory = collect_local() if args.collect_local else validate_inventory(assess.read_json(args.input))
        report = diagnose(inventory)
        if args.format == "text":
            print(render_text(report))
        else:
            output = inventory if args.format == "inventory" else report["normalized_evidence"] if args.format == "evidence" else report
            print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (assess.EvidenceError, OSError, UnicodeError, ValueError):
        print("Inventory input or local metadata could not be read safely; no fixed finding was made.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
