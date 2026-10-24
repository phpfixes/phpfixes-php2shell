#!/usr/bin/env python3
"""Read the PHP2Shell evidence you already have, and say what it does and does not prove.

The idea in one breath: a PHP version number can lie. A distribution backports the fix while
keeping an old upstream number, so 8.3.6 on Ubuntu can be either the vulnerable build or the
fixed one. And a package fixed on disk is not the code a running worker still serves. So this
reads supplied records only -- no server, no network, no PHP executed -- compares them against
dated vendor facts, keeps "installed" and "running" apart, and names the evidence still missing.
A fixed verdict is deliberately hard to earn; "unknown" is a normal, honest answer.

The installed verdict comes from the first of these rules that has an answer:
  1. consistency_problem        records that contradict each other settle nothing
  2. vendor_backport_verdict    an Ubuntu or Debian package, by its vendor's fixed package
  3. packaged_upstream_verdict  any other package, by the upstream release it carries
  4. upstream_verdict           an upstream or official-image build, which also needs provenance
running_verdict then judges the workers, and withhold_fixed turns FIXED_EVIDENCE into UNKNOWN
when the evidence is stale, the facts have expired, or the runtime is FrankenPHP.
"""
import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

# Read-only means read-only: do not leave a __pycache__ folder inside the skill either.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
# Isolated Python omits the script directory; load only this skill's bundled helper.
sys.path.insert(0, str(HERE))

from version_compare import (compare_php_versions, deb_split, deb_version_compare, php_branch,
                             rpm_split)

VERSION = "1.1.0"
FACTS = json.loads((HERE.parent / "data" / "advisories.json").read_text(encoding="utf-8"))
UTC = dt.timezone.utc

MAX_INPUT_BYTES = 256 * 1024
EVIDENCE_MAX_HOURS = 24
CLOCK_SKEW_MINUTES = 5  # a timestamp up to this far in the future is clock skew, not an error

DEB_MANAGERS = ("apt", "dpkg", "deb")
RPM_MANAGERS = ("rpm", "dnf", "yum", "zypper")
MANAGERS = DEB_MANAGERS + RPM_MANAGERS + ("apk", "brew")
KINDS = ("version-output", "os-release", "installed-package", "repository", "process-mapping",
         "changelog", "inventory", "build-provenance")
SAPIS = ("cli", "fpm", "apache2handler", "cgi", "litespeed", "frankenphp", "unknown")
ORIGINS = ("upstream", "docker-official", "distro", "sury", "remi", "source", "control-panel",
           "unknown")
UPSTREAM_ORIGINS = ("upstream", "docker-official")
REPOSITORIES = ("ubuntu", "debian", "sury", "remi", "other", "unknown")
PROVENANCES = ("installed-repository-record", "version-marker", "unknown")
RUNNING_STATES = ("observed", "not-running", "unknown")
BINARY_IDENTITIES = ("matches-installed", "deleted-or-different", "unknown")

CANONICAL_NUMBER = r"(?:0|[1-9][0-9]*)"
CANONICAL_PHP_RE = re.compile(
    r"^" + CANONICAL_NUMBER + r"\." + CANONICAL_NUMBER + r"\." + CANONICAL_NUMBER
    + r"(?:[-.]?(?:alpha|beta|rc|dev|snapshot)(?:0|[1-9][0-9]*)?)?$", re.I | re.ASCII)
PHP_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-.]?(?:alpha|beta|rc|dev|snapshot)\d*)?$", re.I)
PKG_RE = re.compile(r"^\d[A-Za-z0-9.+:~_%\-]*$")
PKG_NAME_RE = re.compile(r"(?:php|libapache2-mod-php|ea-php|alt-php|plesk-php)[A-Za-z0-9.+@_:\-]*")
# A third-party build must be recognised first: a distribution's backport table never applies to it.
SURY_RE = re.compile(r"deb\.sury\.org|\+0~20\d{6}|\+debian\d+~\d+\.gbp")
REMI_RE = re.compile(r"\.remi\b")


class EvidenceError(ValueError):
    pass


# --- Reading and checking the evidence file -------------------------------------------------

def require_fields(value, required, optional=(), where="object"):
    if not isinstance(value, dict):
        raise EvidenceError(where + " must be an object")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        raise EvidenceError("%s has missing fields %s or unsupported fields %s"
                            % (where, sorted(missing), sorted(extra)))


def require_text(value, where, maximum=500, empty=False):
    if (not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip())
            or "\x00" in value):
        raise EvidenceError(where + " must be nonempty text of at most %d characters" % maximum)
    return value


def require_choice(value, options, where):
    if value not in options or not isinstance(value, str):
        raise EvidenceError(where + " has an unsupported value")
    return value


def require_refs(value, source_map, where, kind=None):
    if (not isinstance(value, list) or not value
            or any(not isinstance(ident, str) or ident not in source_map for ident in value)):
        raise EvidenceError(where + " must reference existing evidence ids")
    if kind and not any(source_map[ident]["kind"] == kind for ident in value):
        raise EvidenceError(where + " must include " + kind + " evidence")


def valid_version(value, pattern, maximum):
    return isinstance(value, str) and len(value) <= maximum and bool(pattern.fullmatch(value))


def timestamp(value, where):
    require_text(value, where, 50)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        raise EvidenceError(where + " must be a representable ISO 8601 time with a timezone")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON field: " + key)
        result[key] = value
    return result


def reject_constant(value):
    # json accepts NaN and Infinity; evidence never needs them.
    raise EvidenceError("invalid JSON number")


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise EvidenceError("input must be a local JSON file of at most 256 KiB")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid UTF-8 JSON: " + str(error))


def validate(data):
    """Check the evidence against data/evidence.schema.json's rules; return records by id."""
    require_fields(data, ("schema_version", "authorized", "scope", "collected_at",
                          "inventory_complete", "evidence", "runtimes"), where="evidence")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise EvidenceError("schema_version must be 1")
    if data["authorized"] is not True:
        raise EvidenceError("owner or administrator authorization for this supplied evidence "
                            "is required")
    require_text(data["scope"], "scope", 1000)
    timestamp(data["collected_at"], "collected_at")
    if type(data["inventory_complete"]) is not bool:
        raise EvidenceError("inventory_complete must be true or false")
    source_map = validate_sources(data["evidence"])
    runtimes = data["runtimes"]
    if not isinstance(runtimes, list) or not 1 <= len(runtimes) <= 100:
        raise EvidenceError("runtimes must contain 1 to 100 entries")
    runtime_ids = set()
    for runtime in runtimes:
        validate_runtime(runtime, source_map, runtime_ids)
    return source_map


def validate_sources(sources):
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise EvidenceError("evidence must contain 1 to 100 source records")
    source_map = {}
    for source in sources:
        require_fields(source, ("id", "kind", "text"), where="source record")
        ident = require_text(source["id"], "source id", 100)
        require_choice(source["kind"], KINDS, "source kind")
        require_text(source["text"], "source text", 16000)
        if ident in source_map:
            raise EvidenceError("source ids must be unique")
        source_map[ident] = source
    return source_map


def validate_runtime(runtime, source_map, runtime_ids):
    require_fields(runtime, ("id", "sapi", "origin", "os", "evidence_ids", "running"),
                   ("php_version", "package"), "runtime")
    ident = require_text(runtime["id"], "runtime id", 100)
    if ident in runtime_ids:
        raise EvidenceError("runtime ids must be unique")
    runtime_ids.add(ident)
    require_choice(runtime["sapi"], SAPIS, "sapi")
    require_choice(runtime["origin"], ORIGINS, "origin")
    require_fields(runtime["os"], ("id", "version_id"), where="os")
    require_text(runtime["os"]["id"], "os id", 100)
    require_text(runtime["os"]["version_id"], "os version_id", 100, empty=True)
    require_refs(runtime["evidence_ids"], source_map, "runtime evidence_ids")
    if "php_version" in runtime and not valid_version(runtime["php_version"], PHP_RE, 100):
        raise EvidenceError("php_version must be a complete PHP release or prerelease number")
    if runtime.get("package") is not None:
        validate_package(runtime["package"], source_map)
    validate_running(runtime["running"], source_map)


def validate_package(package, source_map):
    require_fields(package, ("manager", "name", "version", "repository", "provenance",
                             "evidence_ids"), where="package")
    require_choice(package["manager"], MANAGERS, "package manager")
    name = require_text(package["name"], "package name", 200)
    if not PKG_NAME_RE.fullmatch(name):
        raise EvidenceError("package must identify a PHP package")
    if not valid_version(package["version"], PKG_RE, 200):
        raise EvidenceError("package version must be a full package version without whitespace")
    require_choice(package["repository"], REPOSITORIES, "package repository")
    require_choice(package["provenance"], PROVENANCES, "package provenance")
    require_refs(package["evidence_ids"], source_map, "package evidence_ids", "installed-package")
    if package["provenance"] == "installed-repository-record":
        require_refs(package["evidence_ids"], source_map, "package repository evidence_ids",
                     "repository")


def validate_running(running, source_map):
    require_fields(running, ("state", "binary_identity", "evidence_ids"),
                   ("php_version", "package_version"), "running")
    require_choice(running["state"], RUNNING_STATES, "running state")
    require_choice(running["binary_identity"], BINARY_IDENTITIES, "running binary_identity")
    if running["state"] != "unknown":
        require_refs(running["evidence_ids"], source_map, "running evidence_ids", "process-mapping")
    elif running["evidence_ids"]:
        require_refs(running["evidence_ids"], source_map, "running evidence_ids")
    for field, pattern in (("php_version", PHP_RE), ("package_version", PKG_RE)):
        if field in running and not valid_version(running[field], pattern, 200):
            raise EvidenceError("running " + field + " is invalid")


# --- What the installed files prove ---------------------------------------------------------

def package_parts(package):
    """Split a package version into (epoch, upstream, revision) by its manager's rules."""
    manager, version = package["manager"], package["version"]
    if manager in DEB_MANAGERS:
        return deb_split(version)
    if manager in RPM_MANAGERS:
        return rpm_split(version)
    # apk's "-r1" and Homebrew's "_1" are package revisions, not part of the PHP release.
    return "0", re.sub(r"(?:-r\d+|_\d+)$", "", version), ""


def canonical_package_release(package):
    """Require the exact ASCII release identity before any comparator may grant a verdict.

    Comparators intentionally order numeric prefixes. They cannot establish that an alias or
    private upstream suffix identifies an official release. Revisions remain manager-specific.
    """
    raw = package["version"]
    if ":" in raw:
        epoch, remainder = raw.split(":", 1)
        if not re.fullmatch(CANONICAL_NUMBER, epoch, flags=re.ASCII) or ":" in remainder:
            return False
    return bool(CANONICAL_PHP_RE.fullmatch(package_parts(package)[1]))


def branch_in_package_name(name):
    """'php8.3-fpm' -> '8.3'; 'ea-php83' -> '8.3'; None when the name carries no branch."""
    match = (re.search(r"php(\d)\.(\d+)", name)
             or re.search(r"(?:php|ea-php|alt-php|plesk-php)(\d)(\d)(?:-|$)", name))
    return ".".join(match.groups()) if match else None


def package_fits_sapi(name, sapi):
    """A -cli package cannot describe an FPM worker, an -fpm package cannot describe Apache..."""
    wrong_cli = name.endswith("-cli") and sapi != "cli"
    wrong_fpm = name.endswith("-fpm") and sapi != "fpm"
    wrong_apache = name.startswith("libapache2-mod-php") and sapi != "apache2handler"
    return not (wrong_cli or wrong_fpm or wrong_apache)


def third_party_vendor(version):
    """'sury' or 'remi' when the package version itself names that repository, else ''."""
    if SURY_RE.search(version):
        return "sury"
    if REMI_RE.search(version):
        return "remi"
    return ""


def consistency_problem(runtime):
    """Return (why, needed) when the records contradict each other, else None.

    A package name, package version and php -v that disagree describe no single binary, so
    no threshold can be applied to them.
    """
    package = runtime.get("package")
    version = runtime.get("php_version", "")
    upstream = package_parts(package)[1] if package else ""
    if ((version and not CANONICAL_PHP_RE.fullmatch(version))
            or (package and not canonical_package_release(package))):
        return ("PHP release or package epoch is not a canonical ASCII release identity.",
                "Exact official release and package records; private upstream suffixes, Unicode "
                "digits and leading-zero aliases cannot inherit a fix threshold.")
    if package:
        name_branch = branch_in_package_name(package["name"])
        if name_branch and name_branch != php_branch(upstream):
            return ("PHP branch in the package name disagrees with its package version.",
                    "Package ownership and version records for this exact runtime.")
        if not package_fits_sapi(package["name"], runtime["sapi"]):
            return ("Package name identifies a different PHP interface from the supplied runtime.",
                    "Installed package ownership for the exact CLI or web binary being assessed.")
        if version and php_branch(upstream) != php_branch(version):
            return ("Package and PHP output name different PHP branches.",
                    "Package ownership and version output for this exact PHP binary.")
        if version and compare_php_versions(upstream, version) != 0:
            return ("Package version and binary version disagree.",
                    "Matching package and binary records from the same environment and time.")
    if not php_branch(version or upstream):
        return ("No usable PHP version was supplied.",
                "PHP version output for this runtime and its installed package version, "
                "if packaged.")
    vendor = third_party_vendor(package["version"]) if package else ""
    if vendor and (package["repository"] not in (vendor, "unknown")
                   or runtime["origin"] not in (vendor, "unknown")):
        return ("Package version identifies %s, but supplied repository or origin says "
                "something else." % vendor,
                "Installed repository records for this exact package, not the candidate upgrade.")
    return None


def vendor_fixed_row(os_info, source_package):
    """The bundled vendor fix for this OS release and PHP source package, or None."""
    for row in FACTS["vendor_fixed"]:
        if (row["os_id"] == os_info["id"] and row["os_version_id"] == os_info["version_id"]
                and row["package"] == source_package):
            return row
    return None


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
    # These exact older builds are explicitly listed vulnerable by primary vendor pages.
    # Do not turn every hypothetical older packaging base into an affected assertion.
    affected = next((item for item in FACTS.get("vendor_affected", ())
                     if item["os_id"] == os_info["id"]
                     and item["os_version_id"] == os_info["version_id"]
                     and item["package"] == row["package"]
                     and item["version"] == package["version"]), None)
    if affected:
        result.update(status="AFFECTED", source_urls=[affected["source"]])
        why.append("Vendor advisory explicitly lists installed package %s as vulnerable."
                   % package["version"])
        return True
    if os_info["id"] == "debian" and (
            upstream != fixed_upstream or not re.fullmatch(
                r"1~deb%su(?:0|[1-9][0-9]{0,3})" % re.escape(os_info["version_id"]), revision,
                flags=re.ASCII)):
        why.append("Debian package is outside the documented upstream base and packaging "
                   "revision lineage.")
        needed.append("Current Debian advisory for this exact upstream base and package "
                      "revision; the bundled threshold cannot establish this build.")
        return True
    if os_info["id"] == "ubuntu":
        if upstream != fixed_upstream:
            if compare_php_versions(upstream, fixed_upstream) > 0:
                # A canonical newer release may be judged by the upstream fixed release.
                why.append("This package has a newer upstream number than the vendor backport row.")
                return False
            why.append("Ubuntu package upstream base is outside the documented backport lineage.")
            needed.append("Current Ubuntu advisory matching this exact upstream base and revision.")
            return True
        prefix = re.sub(r"[0-9]+$", "", fixed_revision)
        if not re.fullmatch(re.escape(prefix) + r"(?:0|[1-9][0-9]{0,3})", revision,
                            flags=re.ASCII):
            why.append("Ubuntu package revision is outside the documented vendor update lineage.")
            needed.append("Current Ubuntu advisory for this exact revision; private suffixes "
                          "and other packaging lineages do not inherit the bundled threshold.")
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


def packaged_upstream_verdict(runtime, result):
    """A package no vendor row settled is fixed only if it already carries the upstream fix.

    Even then it needs a record of where the installed package came from: this OS's own
    archive for a distribution package, or the named repository for a third-party build.
    """
    package, version, origin = runtime["package"], runtime.get("php_version", ""), runtime["origin"]
    why, needed = result["why"], result["needed_evidence"]
    fixed = FACTS["upstream_fixed"].get(php_branch(version))
    recorded = package["provenance"] == "installed-repository-record" and (
        (origin == "distro" and package["repository"] == runtime["os"]["id"])
        or (origin in ("sury", "remi") and package["repository"] == origin))
    if fixed and version and compare_php_versions(version, fixed) >= 0 and recorded:
        result.update(status="FIXED_EVIDENCE", fixed_threshold=fixed,
                      source_urls=FACTS["upstream_sources"])
        why.append("Matching package and PHP output reach the upstream fixed release %s." % fixed)
        return
    why.append("A distro or third-party backport cannot be decided from the upstream number alone.")
    needed.append("Current vendor advisory for this repository and full installed package "
                  "revision, or build provenance for both CVE fixes.")


def upstream_verdict(runtime, source_map, result):
    """An upstream or official-image build: php.net's number counts, but only with provenance.

    A version string is easy to print and an image tag can move, so FIXED_EVIDENCE also needs a
    build-provenance record tying this exact binary to a fixed release or an image digest.
    """
    version = runtime.get("php_version", "")
    why, needed = result["why"], result["needed_evidence"]
    if runtime["origin"] not in UPSTREAM_ORIGINS:
        why.append("Origin is not an established upstream build; same-version backports need "
                   "vendor or build evidence.")
        needed.append("Installed package record and repository, or source commit and binary "
                      "identity for this exact build.")
        return
    if not version:
        why.append("PHP output for the exact upstream binary is missing.")
        needed.append("Version output for this runtime, separate from installed package lists "
                      "and image tags.")
        return
    branch = php_branch(version)
    fixed = FACTS["upstream_fixed"].get(branch)
    if not fixed:
        why.append("PHP branch %s has no bundled fixed upstream release. A later build date alone "
                   "proves no patch." % branch)
        needed.append("Current vendor backport or source commit evidence for both CVEs and this "
                      "exact binary.")
        return
    reaches_fix = compare_php_versions(version, fixed) >= 0
    has_provenance = any(source_map[ident]["kind"] == "build-provenance"
                         for ident in runtime["evidence_ids"])
    if reaches_fix and not has_provenance:
        why.append("Upstream version reaches the fixed release, but exact binary or immutable "
                   "image provenance was not supplied.")
        needed.append("Build provenance tying the actual binary to an official fixed release or "
                      "immutable image digest; a version tag alone is insufficient.")
        return
    result.update(status="FIXED_EVIDENCE" if reaches_fix else "AFFECTED", fixed_threshold=fixed,
                  source_urls=FACTS["upstream_sources"])
    why.append("Upstream PHP %s is %s final fixed release %s; prereleases sort below final "
               "releases." % (version, "at or above" if reaches_fix else "below", fixed))


def installed_verdict(runtime, source_map):
    """What the installed files prove, from the first rule that has an answer."""
    result = {"status": "UNKNOWN", "why": [], "needed_evidence": [], "fixed_threshold": None,
              "source_urls": []}
    problem = consistency_problem(runtime)
    if problem:
        result["why"].append(problem[0])
        result["needed_evidence"].append(problem[1])
        return result
    package = runtime.get("package")
    if package and vendor_backport_verdict(runtime, result):
        return result
    if package and runtime["origin"] not in UPSTREAM_ORIGINS:
        packaged_upstream_verdict(runtime, result)
        return result
    upstream_verdict(runtime, source_map, result)
    return result


# --- What the running workers prove ---------------------------------------------------------

def workers_differ(runtime):
    running = runtime["running"]
    differs = ((running.get("php_version") and running["php_version"] != runtime.get("php_version"))
               or (running.get("package_version")
                   and running["package_version"] != (runtime.get("package") or {}).get("version")))
    return bool(differs) or running["binary_identity"] == "deleted-or-different"


def stale_worker_verdict(runtime, source_map):
    """Judge the older build a stale worker still runs, from the versions recorded for it."""
    running = runtime["running"]
    reasons = ["Running workers differ from installed package or binary evidence; a fixed package "
               "on disk does not establish fixed workers."]
    if not (running.get("package_version") and runtime.get("package")):
        return "UNKNOWN", reasons
    worker = copy.deepcopy(runtime)
    worker["package"]["version"] = running["package_version"]
    if running.get("php_version"):
        worker["php_version"] = running["php_version"]
    worker_finding = installed_verdict(worker, source_map)
    # A stale worker is AFFECTED only when its own build is proven below the fix.
    if worker_finding["status"] != "AFFECTED":
        return "UNKNOWN", reasons
    return "AFFECTED", reasons + ["Running build: " + reason for reason in worker_finding["why"]]


def running_verdict(runtime, installed, source_map):
    """What the evidence proves about the PHP actually serving requests.

    A package fixed on disk says nothing about a worker started before the upgrade, so the
    installed verdict is copied only when process evidence ties the workers to that binary.
    Returns (status, reasons) and adds missing evidence to installed["needed_evidence"].
    """
    running, needed = runtime["running"], installed["needed_evidence"]
    if runtime["sapi"] == "cli":
        return "CLI_ONLY", ["CLI evidence describes command-line PHP and does not establish the "
                            "PHP version serving a website."]
    if running["state"] == "not-running":
        return "NOT_RUNNING_IN_EVIDENCE", ["Supplied process evidence reports this runtime was not "
                                           "running at collection time."]
    if running["state"] != "observed":
        needed.append("Process mappings for the actual FPM, Apache, or other web workers.")
        return "UNKNOWN", ["Installed package records do not show which PHP workers are actually "
                           "running."]
    if workers_differ(runtime):
        needed.append("Fresh process mappings and version identity for every serving worker, "
                      "including deleted executables.")
        return stale_worker_verdict(runtime, source_map)
    if running["binary_identity"] == "matches-installed" and runtime["sapi"] != "unknown":
        return installed["status"], ["Process mapping evidence links this running runtime to the "
                                     "assessed installed binary."]
    needed.append("Process mappings that identify the exact web PHP binary, separate from CLI "
                  "output.")
    return "UNKNOWN", ["Running binary identity or serving interface is not established."]


# --- Putting it together --------------------------------------------------------------------

def withhold_fixed(verdicts, finding, why, needed):
    """Turn FIXED_EVIDENCE into UNKNOWN and say why. AFFECTED and the others stand."""
    finding["why"].append(why)
    finding["needed_evidence"].append(needed)
    return ["UNKNOWN" if verdict == "FIXED_EVIDENCE" else verdict for verdict in verdicts]


def apply_freshness(verdicts, finding, evidence_fresh, facts_fresh):
    """Stale evidence or expired facts can still show AFFECTED, but never FIXED_EVIDENCE."""
    needed = ("Fresh evidence and current primary vendor advisories before any positive fixed "
              "finding.")
    if not evidence_fresh:
        why = "Evidence is older than 24 hours or has a future collection time."
        verdicts = withhold_fixed(verdicts, finding, why, needed)
    if not facts_fresh:
        why = "Bundled advisory facts are outside their 14-day review period."
        verdicts = withhold_fixed(verdicts, finding, why, needed)
    return verdicts


def assess_runtime(runtime, source_map, evidence_fresh, facts_fresh):
    finding = installed_verdict(runtime, source_map)
    running_status, running_why = running_verdict(runtime, finding, source_map)
    verdicts = [finding["status"], running_status]
    if runtime["sapi"] == "frankenphp":
        # FrankenPHP embeds PHP in its own binary, and that wrapper has advisories of its own.
        why = ("Embedded PHP version alone does not establish the FrankenPHP wrapper's security "
               "status.")
        needed = ("Current FrankenPHP advisory and wrapper version, as well as embedded PHP "
                  "evidence.")
        verdicts = withhold_fixed(verdicts, finding, why, needed)
    installed_status, running_status = apply_freshness(verdicts, finding, evidence_fresh,
                                                       facts_fresh)
    return {"id": runtime["id"], "sapi": runtime["sapi"], "php_version": runtime.get("php_version"),
            "package": runtime.get("package"), "installed_assessment": installed_status,
            "running_assessment": running_status, "why": finding["why"], "running_why": running_why,
            "needed_evidence": list(dict.fromkeys(finding["needed_evidence"])),
            "fixed_threshold": finding["fixed_threshold"], "source_urls": finding["source_urls"],
            "evidence_ids": runtime["evidence_ids"]}


def assess(data, now=None):
    source_map = validate(data)
    now = now or dt.datetime.now(UTC)
    age_hours = (now - timestamp(data["collected_at"], "collected_at")).total_seconds() / 3600
    evidence_fresh = -CLOCK_SKEW_MINUTES / 60 <= age_hours <= EVIDENCE_MAX_HOURS
    facts_age_days = (now.date() - dt.date.fromisoformat(FACTS["facts_as_of"])).days
    facts_fresh = 0 <= facts_age_days <= FACTS["max_facts_age_days"]
    runtimes = [assess_runtime(runtime, source_map, evidence_fresh, facts_fresh)
                for runtime in data["runtimes"]]
    return {"skill_version": VERSION, "assessed_at": now.isoformat().replace("+00:00", "Z"),
            "cves": FACTS["cves"], "scope": data["scope"],
            "inventory_complete_claimed": data["inventory_complete"],
            "collected_at": data["collected_at"], "evidence_fresh": evidence_fresh,
            "facts_as_of": FACTS["facts_as_of"], "facts_fresh": facts_fresh,
            "scope_statement": "Assessment covers only supplied records. It does not establish "
                               "a complete server inventory, internet exposure, absence of "
                               "compromise, or whole-server safety.",
            "runtimes": runtimes}


# --- Command line ---------------------------------------------------------------------------

def text_report(report):
    lines = ["PHPFixes PHP2Shell assessment " + VERSION, "Scope: " + report["scope"],
             report["scope_statement"], ""]
    for runtime in report["runtimes"]:
        lines.append("%s (%s): installed %s; running %s" % (runtime["id"], runtime["sapi"],
                     runtime["installed_assessment"], runtime["running_assessment"]))
        lines.extend("  " + value for value in runtime["why"] + runtime["running_why"])
        lines.extend("  Needed: " + value for value in runtime["needed_evidence"])
        lines.extend("  Source: " + value for value in runtime["source_urls"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Reads local JSON only. No PHP execution, shell calls, network requests, root "
               "requirement, paid model key, or server changes.")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--evidence", required=True,
                        help="local evidence JSON matching data/evidence.schema.json")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        data = read_json(args.evidence)
        report = assess(data)
        report["input_sha256"] = hashlib.sha256(Path(args.evidence).read_bytes()).hexdigest()
        if args.format == "json":
            sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        else:
            sys.stdout.write(text_report(report))
        return 0
    except (EvidenceError, OSError) as error:
        sys.stderr.write("Evidence error: " + str(error) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
