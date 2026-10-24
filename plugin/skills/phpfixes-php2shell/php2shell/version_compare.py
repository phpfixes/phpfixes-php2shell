"""Order PHP release numbers and Debian package versions the way PHP and dpkg do.

This is the quiet half of the checker. "Is 8.3.6-0ubuntu0.24.04.12 at or above the fixed
8.3.6-0ubuntu0.24.04.13?" is not a numeric comparison. dpkg has its own rules: a `~` sorts
before everything, even the end of the string, so 8.2.35-1~deb12u1 is lower than 8.2.35-1,
and an epoch (`1:`) outranks everything after it. PHP's release numbers follow a different
rule, where 8.5.12RC1 sorts below 8.5.12. Only these two orderings reach a verdict today, so
only these two live here. Read-only: no collection, shell, network or remediation.

Adapted from PHPFixes phpseal.
"""
import re

_PHP_VER_RE = re.compile(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?"
                         r"(?:[-.]?(alpha|beta|rc|RC|dev|snapshot)\.?(\d*))?", re.I)

_STAGE_RANK = {"dev": -2, "snapshot": -2, "alpha": -1, "beta": 0, "rc": 1}


def php_version_key(v):
    """'8.5.12RC1' -> (8,5,12,1,1); '8.5.12' -> (8,5,12,9,0): a final release sorts last."""
    if not v:
        return (0, 0, 0, 0, 0)
    m = _PHP_VER_RE.match(str(v))
    if not m:
        return (0, 0, 0, 0, 0)
    major, minor, patch, stage, num = m.groups()
    rank = 9
    if stage:
        rank = _STAGE_RANK.get(stage.lower(), 0)
    return (int(major), int(minor), int(patch or 0), rank, int(num or 0))


def php_branch(v):
    """'8.3.36' -> '8.3'; '' when no PHP release number can be read."""
    k = php_version_key(v)
    return "%d.%d" % (k[0], k[1]) if k[0] else ""


def compare_php_versions(a, b):
    """-1, 0 or 1, like a <=> b, by PHP's release ordering."""
    ka, kb = php_version_key(a), php_version_key(b)
    return (ka > kb) - (ka < kb)


def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    # dpkg's verrevcmp: alternate non-digit and digit runs; '~' sorts before everything,
    # even the end of the string.
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        while (ia < len(a) and not a[ia].isdigit()) or (ib < len(b) and not b[ib].isdigit()):
            ac = _deb_order(a[ia]) if ia < len(a) and not a[ia].isdigit() else 0
            bc = _deb_order(b[ib]) if ib < len(b) and not b[ib].isdigit() else 0
            if ac != bc:
                return (ac > bc) - (ac < bc)
            if ia < len(a) and not a[ia].isdigit():
                ia += 1
            if ib < len(b) and not b[ib].isdigit():
                ib += 1
        na = ""
        while ia < len(a) and a[ia].isdigit():
            na += a[ia]
            ia += 1
        nb = ""
        while ib < len(b) and b[ib].isdigit():
            nb += b[ib]
            ib += 1
        na_i, nb_i = int(na or 0), int(nb or 0)
        if na_i != nb_i:
            return (na_i > nb_i) - (na_i < nb_i)
    return 0


def deb_split(v):
    """'1:8.3.6-0ubuntu0.24.04.13' -> (1, '8.3.6', '0ubuntu0.24.04.13')."""
    v = str(v).strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if e.isdigit():
            epoch = int(e)
    if "-" in v:
        upstream, rev = v.rsplit("-", 1)
    else:
        upstream, rev = v, ""
    return epoch, upstream, rev


def rpm_split(v):
    """'8.0.30-8.el9_8' -> ('0', '8.0.30', '8.el9_8'). Used only to read the upstream release."""
    v = str(v).strip()
    epoch = "0"
    if ":" in v:
        epoch, v = v.split(":", 1)
    if "-" in v:
        ver, rel = v.split("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel


def deb_version_compare(a, b):
    """-1, 0 or 1, like a <=> b, by dpkg's ordering: epoch first, then upstream, then revision."""
    ea, ua, ra = deb_split(a)
    eb, ub, rb = deb_split(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    c = _verrevcmp(ua, ub)
    if c:
        return c
    return _verrevcmp(ra, rb)
