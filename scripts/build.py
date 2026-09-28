#!/usr/bin/env python3
"""Build the data files behind the Debian Linux-kernel CVE tracker.

Sources
-------
Debian Security Tracker JSON
    Authoritative per-suite status for the kernel source packages.  This is
    the same data the tracker web UI renders, so a status here is what the
    Debian security team actually says about that suite.

kernel.org vulns.git
    The Linux kernel CNA's own records: title, description, CVSS vector and
    the introduced/fixed version pairs for every stable series.  The date a
    CVE was published is recovered from the git history (the commit that
    first added the CVE's record), because the published JSON itself carries
    no timestamp.

Outputs, all under site/data/
-----------------------------
meta.json            Suite definitions, kernel versions, counts, build time.
index.json           One compact row per CVE, newest first.
details/<n>.json     Descriptions and extras, fetched on demand by the page.
feeds/<column>.xml   Atom feed of newly published CVEs open in that column.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import lzma
import math
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEBIAN_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
VULNS_REPO = "https://git.kernel.org/pub/scm/linux/security/vulns.git"

# Triage inputs.  Every one of these is a published dataset looked up by CVE
# id; nothing here is inferred, scored by hand, or guessed at.
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ADVISORY_URLS = {
    "DSA": "https://salsa.debian.org/security-tracker-team/security-tracker"
           "/-/raw/master/data/DSA/list",
    "DLA": "https://salsa.debian.org/security-tracker-team/security-tracker"
           "/-/raw/master/data/DLA/list",
}

# Source packages in Debian that ship a Linux kernel.  `linux` is the kernel
# of each suite; `linux-6.12` is the 6.12 series offered to bookworm users
# through bookworm-backports and bookworm-security.
PACKAGES = ("linux", "linux-6.12")

# Suite -> (Debian release name, role).  Unknown suites still get a column,
# they just fall back to a generic label, so a new Debian release appears on
# the site without a code change.
SUITE_INFO = {
    "bullseye": ("Debian 11", "oldoldstable (LTS)"),
    "bookworm": ("Debian 12", "oldstable"),
    "trixie": ("Debian 13", "stable"),
    "forky": ("Debian 14", "testing"),
    "sid": ("Debian unstable", "unstable"),
}
SUITE_ORDER = ["bullseye", "bookworm", "trixie", "forky", "sid"]

# Per-column status codes used in index.json.  Documented in meta.json too, so
# anyone consuming the raw data does not have to read this file.
STATUS_CODES = {
    "V": "vulnerable - no fix in this suite yet",
    "F": "fixed - a fixed package version is available",
    "N": "not affected - this suite never shipped the vulnerable code",
    "I": "no-dsa - known, but the security team will not issue an update",
    "U": "undetermined - Debian has not finished triaging this one",
    "-": "not applicable - this package is not in that suite",
}

# Codes for the "is a fix waiting upstream?" column, derived purely by
# comparing version numbers - see upstream_state().
PENDING_CODES = {
    "P": "fix exists in the upstream stable series, not yet in this suite",
    "W": "no upstream fix for this suite's stable series yet",
    ".": "not applicable - this suite is not vulnerable",
}

DETAIL_CHUNK = 400  # CVEs per lazily-loaded detail file
FEED_ENTRIES = 100

# The CNA prefixes every description with this boilerplate followed by the
# CVE title.  Both are stored separately, so strip them from the body.
DESC_PREFIX = "In the Linux kernel, the following vulnerability has been resolved:"


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------


def log(msg: str) -> None:
    print(f"[build] {msg}", file=sys.stderr, flush=True)


def download(url: str, path: Path, offline: bool) -> Path:
    """Fetch `url` into `path`, or reuse the cached copy when offline."""
    if offline:
        if not path.exists():
            sys.exit(f"--offline given but {path} is missing")
        log(f"using cached {path.name}")
        return path
    log(f"downloading {url}")
    tmp = path.with_name(path.name + ".tmp")
    req = urllib.request.Request(
        url, headers={"User-Agent": "debian-kernel-cve-tracker/1.0"}
    )
    with urllib.request.urlopen(req, timeout=300) as resp, tmp.open("wb") as fh:
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    tmp.replace(path)
    log(f"  {path.name}: {path.stat().st_size / 1e6:.1f} MB")
    return path


def sync_vulns(cache: Path, offline: bool) -> Path:
    repo = cache / "vulns"
    if offline:
        if not repo.exists():
            sys.exit(f"--offline given but {repo} is missing")
        log("using cached vulns.git checkout")
        return repo
    if repo.exists():
        log("updating vulns.git")
        subprocess.run(
            ["git", "-C", str(repo), "pull", "--ff-only", "--quiet"], check=True
        )
    else:
        log(f"cloning {VULNS_REPO} (this takes a minute the first time)")
        subprocess.run(
            ["git", "clone", "--quiet", "--single-branch", VULNS_REPO, str(repo)],
            check=True,
        )
    return repo


# --------------------------------------------------------------------------
# Debian tracker parsing
# --------------------------------------------------------------------------


def _skip_json_value(text: str, i: int) -> int:
    """Return the index just past the JSON value starting at `i`."""
    depth = 0
    in_str = False
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
            if depth == 0:
                return i + 1
        elif depth == 0 and c in ",}":
            return i  # a bare scalar ended
        i += 1
    return i


def extract_packages(path: Path, wanted: tuple[str, ...]) -> dict[str, dict]:
    """Pull just the packages we care about out of the 75 MB tracker dump.

    Decoding the whole document costs well over a gigabyte of memory for data
    we throw away, so walk the top-level object and only decode the handful of
    packages we actually want.
    """
    text = path.read_text(encoding="utf-8")
    dec = json.JSONDecoder()
    out: dict[str, dict] = {}
    n = len(text)
    i = text.index("{") + 1
    while i < n and len(out) < len(wanted):
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n or text[i] == "}":
            break
        key, i = dec.raw_decode(text, i)
        while text[i] in " \t\r\n":
            i += 1
        i += 1  # the ':'
        while text[i] in " \t\r\n":
            i += 1
        if key in wanted:
            value, i = dec.raw_decode(text, i)
            out[key] = value
            log(f"debian: {key} -> {len(value)} CVEs")
        else:
            i = _skip_json_value(text, i)
    missing = [p for p in wanted if p not in out]
    if missing:
        log(f"warning: packages not present in tracker data: {missing}")
    return out


def classify(entry: dict) -> tuple[str, str | None]:
    """Map a tracker release entry onto a status code and a detail string."""
    status = entry.get("status")
    if status == "resolved":
        fixed = entry.get("fixed_version")
        # The tracker spells "this suite was never vulnerable" as a fix in
        # version 0, which would otherwise render as a nonsense version.
        if fixed in (None, "0"):
            return "N", None
        return "F", fixed
    if status == "open":
        if entry.get("nodsa"):
            return "I", entry.get("nodsa")
        return "V", None
    return "U", None


# --------------------------------------------------------------------------
# kernel.org vulns.git parsing
# --------------------------------------------------------------------------


def publication_dates(repo: Path, cache: Path) -> dict[str, int]:
    """Map CVE id -> unix timestamp of the commit that first published it.

    Walking the whole history takes ~20s, so the result is cached and only the
    commits added since the last build are replayed.
    """
    cache_file = cache / "publication-dates.json"
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    dates: dict[str, int] = {}
    since = None
    if cache_file.exists():
        cached = json.loads(cache_file.read_text())
        if cached.get("head") == head:
            log(f"publication dates: cache hit ({len(cached['dates'])} CVEs)")
            return cached["dates"]
        dates = cached.get("dates", {})
        since = cached.get("head")

    rev_range = f"{since}..HEAD" if since else "HEAD"
    log(f"scanning vulns.git history for publication dates ({rev_range})")
    proc = subprocess.run(
        [
            "git", "-C", str(repo), "log", rev_range,
            "--diff-filter=A", "--name-only", "--format=C%at", "--", "cve/published",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    stamp = 0
    for line in proc.stdout.splitlines():
        if line.startswith("C"):
            stamp = int(line[1:])
        elif line.endswith(".json"):
            cve = Path(line).stem
            # A file can be added more than once (published, withdrawn, and
            # published again); the earliest add is the publication date.
            if cve not in dates or stamp < dates[cve]:
                dates[cve] = stamp
    cache_file.write_text(json.dumps({"head": head, "dates": dates}))
    log(f"publication dates: {len(dates)} CVEs")
    return dates


CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss_base_score(vector: str) -> float | None:
    """CVSS v3.x base score for a vector string, or None if it is unusable."""
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().split("/")[1:])
        changed = parts["S"] == "C"
        av = CVSS_WEIGHTS["AV"][parts["AV"]]
        ac = CVSS_WEIGHTS["AC"][parts["AC"]]
        ui = CVSS_WEIGHTS["UI"][parts["UI"]]
        pr = {
            "N": 0.85,
            "L": 0.68 if changed else 0.62,
            "H": 0.50 if changed else 0.27,
        }[parts["PR"]]
        c = CVSS_WEIGHTS["C"][parts["C"]]
        i = CVSS_WEIGHTS["I"][parts["I"]]
        a = CVSS_WEIGHTS["A"][parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if changed else 1.0) * (impact + exploitability), 10.0)
    # CVSS "roundup": round up to one decimal place.
    return math.ceil(raw * 10 - 1e-9) / 10


def severity_of(score: float | None) -> str:
    if score is None:
        return "unrated"
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


VERSION_RE = re.compile(r"^\d+\.\d+")

# "AV:N - The flaw is in skb_gro_receive() ..." followed by indented
# continuation lines.  The kernel CNA writes one of these per CVSS metric,
# which is the only place the reasoning behind a score is published.
CVSS_REASON_RE = re.compile(r"^([A-Z]{1,2}):([A-Z])\s+-\s+(.*)$")


def parse_cvss_reasons(text: str) -> dict[str, str]:
    """Metric code -> the CNA's written justification for that metric."""
    reasons: dict[str, str] = {}
    metric = None
    parts: list[str] = []

    def flush() -> None:
        if metric and parts:
            reasons[metric] = " ".join(" ".join(parts).split())

    for line in text.split("\n")[1:]:  # line 0 is the vector itself
        head = CVSS_REASON_RE.match(line)
        if head:
            flush()
            metric, parts = head.group(1), [head.group(3)]
        elif metric and line.startswith((" ", "\t")) and line.strip():
            parts.append(line.strip())
        elif not line.strip():
            continue
        else:
            flush()
            metric, parts = None, []
    flush()
    return reasons


def parse_dyad(path: Path) -> list[dict]:
    """Parse a .dyad file into introduced/fixed version pairs."""
    pairs = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 4:
            continue
        intro_ver, _intro_sha, fixed_ver, fixed_sha = fields
        pairs.append([intro_ver, fixed_ver, fixed_sha[:12]])
    return pairs


def series_of(version: str) -> str | None:
    """'6.1.188' -> '6.1'.  Mainline releases like '6.19' map to themselves."""
    m = VERSION_RE.match(version)
    return m.group(0) if m else None


def load_kernel_records(repo: Path) -> dict[str, dict]:
    """Read every published CVE record out of the vulns.git checkout."""
    published = repo / "cve" / "published"
    records: dict[str, dict] = {}
    for json_path in sorted(published.rglob("*.json")):
        cve = json_path.stem
        try:
            doc = json.loads(json_path.read_text(encoding="utf-8"))
            cna = doc["containers"]["cna"]
        except (ValueError, KeyError):
            continue

        title = (cna.get("title") or "").strip()
        description = ""
        for d in cna.get("descriptions", []):
            if d.get("lang", "en").startswith("en"):
                description = d.get("value", "")
                break
        # Strip the CNA boilerplate and the repeated title from the body.
        if description.startswith(DESC_PREFIX):
            description = description[len(DESC_PREFIX):].lstrip("\n")
        if title and description.startswith(title):
            description = description[len(title):].lstrip("\n")

        record = {
            "title": title,
            "description": description.strip(),
            "files": cna.get("affected", [{}])[0].get("programFiles", []),
        }

        dyad = json_path.with_suffix(".dyad")
        if dyad.exists():
            record["pairs"] = parse_dyad(dyad)

        cvss_file = json_path.with_suffix(".cvss")
        if cvss_file.exists():
            raw = cvss_file.read_text(encoding="utf-8", errors="replace")
            for token in raw.split("\n", 1)[0].split():
                if token.startswith("CVSS:"):
                    record["cvss_vector"] = token
                    break
            reasons = parse_cvss_reasons(raw)
            if reasons:
                record["cvss_reasons"] = reasons

        records[cve] = record
    log(f"kernel.org: {len(records)} published CVE records")
    return records


# --------------------------------------------------------------------------
# triage inputs
# --------------------------------------------------------------------------


def load_kev(cache: Path, offline: bool) -> tuple[dict[str, dict], str]:
    """CISA's Known Exploited Vulnerabilities catalogue, keyed by CVE id.

    Presence in this catalogue is the single strongest triage signal there is:
    CISA only lists a CVE once it has evidence of exploitation in the wild.
    """
    path = download(KEV_URL, cache / "kev.json", offline)
    doc = json.loads(path.read_text(encoding="utf-8"))
    kev = {}
    for item in doc.get("vulnerabilities", []):
        kev[item["cveID"]] = {
            "added": item.get("dateAdded"),
            "due": item.get("dueDate"),
            "ransomware": item.get("knownRansomwareCampaignUse") == "Known",
            "name": item.get("vulnerabilityName"),
            "action": item.get("requiredAction"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
        }
    version = doc.get("catalogVersion", "")
    log(f"CISA KEV: {len(kev)} entries (catalogue {version})")
    return kev, version


def load_epss(cache: Path, offline: bool) -> tuple[dict[str, tuple[float, float]], str]:
    """FIRST's EPSS scores: modelled probability of exploitation in 30 days.

    Published daily as a CSV of (cve, epss, percentile).  It is a lookup, not
    a judgement call - the same CVE gives the same number for everyone.
    """
    path = download(EPSS_URL, cache / "epss.csv.gz", offline)
    scores: dict[str, tuple[float, float]] = {}
    score_date = ""
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                m = re.search(r"score_date:(\S+)", line)
                if m:
                    score_date = m.group(1).rstrip(",")
                continue
            if line.startswith("cve,"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) != 3:
                continue
            try:
                scores[parts[0]] = (float(parts[1]), float(parts[2]))
            except ValueError:
                continue
    log(f"EPSS: {len(scores)} scores (scored {score_date})")
    return scores, score_date


ADVISORY_HEADER = re.compile(
    r"^\[(?P<date>[^\]]+)\]\s+(?P<id>D[SL]A-[\w.-]+)\s+(?P<pkg>\S+)"
)
ADVISORY_RELEASE = re.compile(
    r"^\[(?P<suite>[a-z-]+)\]\s*-\s*(?P<pkg>\S+)\s+(?P<version>\S+)"
)


def load_advisories(cache: Path, offline: bool) -> dict[str, list[dict]]:
    """Map CVE id -> the Debian security advisories that fixed it.

    A DSA (stable) or DLA (LTS) means the security team shipped an update for
    this specific issue, which is a stronger statement than the tracker simply
    marking it resolved by a routine version bump.
    """
    out: dict[str, list[dict]] = {}
    for kind, url in ADVISORY_URLS.items():
        path = download(url, cache / f"{kind.lower()}-list.txt", offline)
        current = None
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            header = ADVISORY_HEADER.match(line)
            if header:
                pkg = header.group("pkg")
                # Only kernel advisories are of interest here.
                current = None
                if pkg == "linux" or pkg.startswith("linux-"):
                    try:
                        when = datetime.strptime(
                            header.group("date").strip(), "%d %b %Y"
                        ).strftime("%Y-%m-%d")
                    except ValueError:
                        when = header.group("date").strip()
                    current = {
                        "id": header.group("id"),
                        "kind": kind,
                        "date": when,
                        "package": pkg,
                        "releases": {},
                    }
                continue
            stripped = line.strip()
            if not current:
                continue
            if stripped.startswith("{") and stripped.endswith("}"):
                for cve in stripped[1:-1].split():
                    if cve.startswith("CVE-"):
                        out.setdefault(cve, []).append(current)
            else:
                # "[bookworm] - linux 6.1.158-1": which suite this advisory
                # actually shipped to, and at what version.
                rel = ADVISORY_RELEASE.match(stripped)
                if rel:
                    current["releases"][rel.group("suite")] = rel.group("version")
    for entries in out.values():
        entries.sort(key=lambda a: a["date"], reverse=True)
    log(f"Debian advisories: {len(out)} CVEs covered by a DSA or DLA")
    return out


# --------------------------------------------------------------------------
# kernel source exposure: subsystem, Kconfig symbol, Debian's config
# --------------------------------------------------------------------------
#
# The CNA tells us which source files a CVE touches.  Three published data
# sets turn that into something a sysadmin can act on:
#
#   MAINTAINERS  - the kernel's own file-pattern -> subsystem table, so the
#                  bug gets the name people search for rather than a path.
#   kbuild       - the Makefiles map an object file onto the CONFIG_ symbol
#                  that decides whether it is compiled, and onto the .ko it
#                  ends up in.
#   debian/config- Debian publishes the exact .config it builds each flavour
#                  with, so the symbol's value says whether *this* release
#                  builds the vulnerable code at all.
#
# Every step is a lookup or a textual match in one of those files.  Nothing
# is inferred: where a file has no Makefile entry, or a symbol no value, the
# field is simply absent.

# GitHub's mirror of linux-stable rather than git.kernel.org, because
# kernel.org's server refuses partial clones ("filtering not recognized by
# server") and a shallow clone there costs 286 MB and a minute *per tag*.
# The mirror serves a blobless clone plus a Makefile-only sparse checkout in
# about 3 s and 17 MB, which is what makes a tree per Debian release
# affordable.  Tag objects were checked against kernel.org and match.
LINUX_MIRROR = "https://github.com/gregkh/linux.git"

# Fallback for the subsystem lookup alone, if no tree can be fetched.
MAINTAINERS_URL = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    "/plain/MAINTAINERS"
)

# Only Makefiles, Kbuild files and MAINTAINERS are checked out; the rest of
# the tree is never fetched.
TREE_SPARSE_PATTERNS = ("/Makefile", "**/Makefile", "**/Kbuild", "/MAINTAINERS")

# Debian source packages live in the main archive until a release moves to
# the security archive, so try both.  The file name is fully determined by
# the source package and its version, which is why no index is downloaded.
DEBIAN_POOLS = (
    "https://deb.debian.org/debian/pool/main/l/{dir}/{file}",
    "https://deb.debian.org/debian-security/pool/updates/main/l/{dir}/{file}",
)

# Config states, as reported per Debian release.  Debian builds one config
# per architecture and flavour, so a single letter has to say both what the
# affected code is and whether every flavour agrees.  Lower case means every
# flavour this release builds does the same thing; upper case means the rest
# of them do not build the code at all.  The full per-flavour answer is in
# the detail chunk either way - this letter is a badge, not the evidence.
CONFIG_CODES = {
    "y": "built into the kernel image on every flavour - only a patch removes it",
    "Y": "built in where it is built at all; some flavours do not build it",
    "m": "a loadable module on every flavour - check lsmod, can be blacklisted",
    "M": "a module where it is built at all; some flavours do not build it",
    "b": "built in on some flavours, a module on others",
    "B": "built in on some, a module on others, absent on the rest",
    "n": "not enabled on any flavour - this release does not build the code",
    "?": "not established - no Makefile entry for the affected file",
}


def try_download(url: str, path: Path, offline: bool, quiet: bool = False) -> Path | None:
    """download(), but a missing or unreachable source is not fatal.

    Everything in this section is enrichment: if it cannot be fetched the
    build still has to produce a complete site, just without these fields.
    `quiet` is for the probes where a 404 is the expected answer rather than
    a problem - not every architecture gets every package.
    """
    if offline:
        if path.exists():
            return path
        if not quiet:
            log(f"warning: --offline and {path.name} is not cached, skipping")
        return None
    try:
        if quiet:
            req = urllib.request.Request(
                url, headers={"User-Agent": "debian-kernel-cve-tracker/1.0"}
            )
            tmp = path.with_name(path.name + ".tmp")
            with urllib.request.urlopen(req, timeout=300) as resp, tmp.open("wb") as fh:
                while chunk := resp.read(1 << 20):
                    fh.write(chunk)
            tmp.replace(path)
            return path
        return download(url, path, offline)
    except Exception as exc:  # noqa: BLE001 - any network/HTTP error is fine here
        if not quiet:
            log(f"warning: {url} unavailable ({exc})")
        return None


# --------------------------------------------------------------------------
# MAINTAINERS
# --------------------------------------------------------------------------

MAINTAINERS_FIELD = re.compile(r"^([A-Z]):\t(.*)$")
GLOB_CHARS = re.compile(r"[*?\[]")


def _glob_to_re(pattern: str) -> re.Pattern:
    """MAINTAINERS globs: '*' stops at a '/', a trailing '/' means a subtree."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    body = "".join(out)
    if pattern.endswith("/"):
        return re.compile("^" + body + ".*$")
    return re.compile("^" + body + "(/.*)?$")


def _literal_prefix(pattern: str) -> str:
    """The deepest directory of a pattern that contains no wildcard."""
    parts = pattern.rstrip("/").split("/")
    keep = []
    for part in parts[:-1] if not pattern.endswith("/") else parts:
        if GLOB_CHARS.search(part):
            break
        keep.append(part)
    return "/".join(keep)


class Maintainers:
    """The kernel's own file -> subsystem table.

    Matching follows what the file documents: an F: pattern claims a path, an
    X: pattern in the same section takes it back, and where several sections
    claim the same path the most specific pattern wins.  Patterns are bucketed
    by their wildcard-free directory prefix so a lookup only compares against
    the handful of patterns that could possibly match.
    """

    def __init__(self, text: str) -> None:
        self.sections: list[dict] = []
        self.buckets: dict[str, list[tuple]] = {}
        self._cache: dict[str, dict | None] = {}
        self._parse(text)

    def _parse(self, text: str) -> None:
        lines = text.split("\n")
        current: dict | None = None
        for n, line in enumerate(lines):
            field = MAINTAINERS_FIELD.match(line)
            if field and current is not None:
                current.setdefault(field.group(1), []).append(field.group(2).strip())
                continue
            # A section header is a bare line immediately followed by fields.
            if (
                line.strip()
                and not line.startswith((" ", "\t"))
                and n + 1 < len(lines)
                and MAINTAINERS_FIELD.match(lines[n + 1])
            ):
                current = {"name": line.strip()}
                self.sections.append(current)
            elif not line.strip():
                current = None
        for section in self.sections:
            excludes = [_glob_to_re(x) for x in section.get("X", [])]
            for pattern in section.get("F", []):
                entry = (
                    len(pattern),
                    pattern.count("/"),
                    pattern,
                    _glob_to_re(pattern),
                    excludes,
                    section,
                )
                self.buckets.setdefault(_literal_prefix(pattern), []).append(entry)

    def lookup(self, path: str) -> dict | None:
        """The most specific section claiming `path`, or None."""
        if path in self._cache:
            return self._cache[path]
        parts = path.split("/")
        best = None
        for depth in range(len(parts)):
            prefix = "/".join(parts[:depth])
            for entry in self.buckets.get(prefix, ()):
                if not entry[3].match(path):
                    continue
                if any(x.match(path) for x in entry[4]):
                    continue
                if best is None or entry[:3] > best[:3]:
                    best = entry
        result = None
        if best is not None:
            section = best[5]
            result = {
                "name": section["name"],
                "pattern": best[2],
                "list": _mailing_list(section.get("L", [])),
                "status": (section.get("S") or [""])[0],
            }
        self._cache[path] = result
        return result


def _mailing_list(entries: list[str]) -> str:
    """The first L: address, without the '(moderated ...)' annotation."""
    if not entries:
        return ""
    return entries[0].split(" (")[0].strip()


# The catch-all section at the bottom of MAINTAINERS ("F: *").  It matches
# every path, so it is a statement that no subsystem claims the file, not a
# subsystem name worth showing anyone.
MAINTAINERS_CATCHALL = "THE REST"


# --------------------------------------------------------------------------
# kbuild: source file -> CONFIG_ symbol -> module
# --------------------------------------------------------------------------

MAKE_CONTINUATION = re.compile(r"\\\n")
MAKE_ASSIGN = re.compile(r"^\s*([A-Za-z0-9_$()\-./]+)\s*[:+?]?=\s*(.*)$")
MAKE_CONFIG = re.compile(r"\$\(CONFIG_([A-Za-z0-9_]+)\)")
MAKE_IFDEF = re.compile(r"^\s*(ifdef|ifndef)\s+CONFIG_([A-Za-z0-9_]+)")
MAKE_IFEQ = re.compile(
    r"^\s*ifeq\s*\(\s*\$\(CONFIG_([A-Za-z0-9_]+)\)\s*,\s*([ym])?\s*\)"
)
MAKE_STEM = re.compile(r"-(?:y|m|objs|objs-y|@)$")

# Left-hand sides that add objects to the build directly rather than to a
# composite module.  'lib-y' lands in lib.a, which is linked into vmlinux.
KBUILD_OBJ_LHS = {"obj-@", "obj-y", "obj-m", "lib-y", "lib-m", "lib-@"}

# Makefile variables that end in '-y' but are not composite objects.
KBUILD_NOT_OBJECTS = {
    "obj", "lib", "core", "drivers", "net", "libs", "always", "hostprogs",
    "targets", "clean-files", "extra", "ccflags", "asflags", "cflags",
    "subdir", "header-test", "quiet_cmd", "KBUILD_CFLAGS", "GCOV_PROFILE",
}

SOURCE_SUFFIXES = (".c", ".S", ".rs")


class KbuildDir:
    """What one directory's Makefile says about the objects in it."""

    __slots__ = ("objects", "parts", "subdirs")

    def __init__(self) -> None:
        self.objects: dict[str, set] = {}   # object -> symbols guarding it
        self.parts: dict[str, dict] = {}    # composite -> {member: symbols}
        self.subdirs: dict[str, set] = {}   # subdirectory -> symbols


def parse_makefile(text: str, into: KbuildDir) -> None:
    """Record every 'obj-$(CONFIG_X) += foo.o' style rule in one Makefile.

    This is a textual read, not an evaluation: make variables other than
    CONFIG_ ones are ignored, and an `else` branch drops its guard rather
    than pretending the negation can be expressed.  The result is therefore
    conservative - it can miss a guard, never invent one.
    """
    text = MAKE_CONTINUATION.sub(" ", text)
    guards: list[set] = []
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0]
        stripped = line.strip()
        if not stripped:
            continue
        cond = MAKE_IFDEF.match(line)
        if cond:
            guards.append({cond.group(2)} if cond.group(1) == "ifdef" else set())
            continue
        cond = MAKE_IFEQ.match(line)
        if cond:
            guards.append({cond.group(1)} if cond.group(2) else set())
            continue
        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            guards.append(set())
            continue
        if stripped.startswith("else"):
            if guards:
                guards[-1] = set()
            continue
        if stripped.startswith("endif"):
            if guards:
                guards.pop()
            continue
        assign = MAKE_ASSIGN.match(line)
        if not assign:
            continue
        lhs, rhs = assign.group(1), assign.group(2)
        tokens = [t for t in rhs.split() if not t.startswith("$(")]
        objects = [t[:-2] for t in tokens if t.endswith(".o")]
        subdirs = [t[:-1] for t in tokens if t.endswith("/")]
        if not objects and not subdirs:
            continue
        symbols = set(MAKE_CONFIG.findall(lhs))
        for guard in guards:
            symbols |= guard
        normalised = MAKE_CONFIG.sub("@", lhs)
        if normalised in KBUILD_OBJ_LHS:
            target = into.objects
        else:
            stem = MAKE_STEM.sub("", normalised)
            if stem == normalised or stem in KBUILD_NOT_OBJECTS or not stem:
                continue
            target = into.parts.setdefault(stem, {})
        for obj in objects:
            target.setdefault(obj, set()).update(symbols)
        for sub in subdirs:
            into.subdirs.setdefault(sub, set()).update(symbols)


class KernelTree:
    """One kernel version's Makefiles, plus its MAINTAINERS.

    Makefiles are parsed on first use rather than up front: a build only ever
    asks about the ~1,800 directories the CNA's file lists mention, out of
    the ~3,300 in the tree.
    """

    def __init__(self, root: Path, tag: str) -> None:
        self.tag = tag
        self.root = root
        self.dirs: dict[str, KbuildDir | None] = {}
        self._cache: dict[str, tuple | None] = {}
        # Built on demand: compiling the ~10,000 F: patterns takes ~3 s and
        # only one tree's table is ever used.
        self.maintainers_file = root / "MAINTAINERS"
        self._maintainers: Maintainers | None = None

    def maintainers(self) -> Maintainers | None:
        if self._maintainers is None and self.maintainers_file.exists():
            self._maintainers = Maintainers(
                self.maintainers_file.read_text(errors="replace")
            )
        return self._maintainers

    def _dir(self, rel: str) -> KbuildDir | None:
        if rel in self.dirs:
            return self.dirs[rel]
        entry = None
        for name in ("Makefile", "Kbuild"):
            path = self.root / rel / name if rel else self.root / name
            if not path.is_file():
                continue
            entry = entry or KbuildDir()
            try:
                parse_makefile(path.read_text(errors="replace"), entry)
            except OSError:
                pass
        self.dirs[rel] = entry
        return entry

    def resolve(self, path: str) -> tuple[list[str], str | None] | None:
        """Source file -> (CONFIG_ symbols that must all be on, module base).

        The symbols are every guard between the object and the top of the
        tree: the one on its own obj- line, any on the composite module it is
        linked into, and any on the directories above it.  The file is built
        only if all of them are on, which is what makes the list the right
        thing to look up in a .config.

        Returns None when the file has no Makefile entry at all - a header, a
        source file #included by another, or a path that does not exist in
        this kernel version.  That is an absent answer, not a negative one.
        """
        if path in self._cache:
            return self._cache[path]
        self._cache[path] = result = self._resolve(path)
        return result

    def _resolve(self, path: str) -> tuple[list[str], str | None] | None:
        if "/" not in path:
            return None
        dirname, filename = path.rsplit("/", 1)
        stem = None
        for suffix in SOURCE_SUFFIXES:
            if filename.endswith(suffix):
                stem = filename[: -len(suffix)]
                break
        if stem is None:
            return None
        entry = self._dir(dirname)
        if entry is None:
            return None

        symbols: set = set()
        module = None
        current = stem
        seen = set()
        while True:
            if current in seen:
                return None  # a cycle: refuse to guess
            seen.add(current)
            if current in entry.objects:
                symbols |= entry.objects[current]
                module = current
                break
            for composite, members in entry.parts.items():
                if current in members:
                    symbols |= members[current]
                    current = composite
                    break
            else:
                return None

        # Descending into a directory is itself conditional; walk up to the
        # top-level directory, which the root Makefile always builds.
        parts = dirname.split("/")
        for depth in range(len(parts), 1, -1):
            parent = self._dir("/".join(parts[: depth - 1]))
            if parent:
                symbols |= parent.subdirs.get(parts[depth - 1], set())
        return sorted(symbols), module


def sync_kernel_tree(cache: Path, tag: str, offline: bool) -> Path | None:
    """Check out just the Makefiles of one kernel tag, or reuse the cache.

    A tag is immutable, so a cached tree is never refreshed.  `.git` is
    dropped afterwards: it holds a second copy of every blob and nothing here
    ever needs git again.
    """
    dest = cache / "trees" / tag
    if (dest / "MAINTAINERS").exists():
        log(f"kernel tree {tag}: cached")
        return dest
    if offline:
        log(f"warning: --offline and kernel tree {tag} is not cached, skipping")
        return None
    log(f"fetching Makefiles for {tag}")
    shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "git", "clone", "--quiet", "--filter=blob:none", "--depth", "1",
                "--no-checkout", "--branch", tag, LINUX_MIRROR, str(dest),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set", "--no-cone",
             *TREE_SPARSE_PATTERNS],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--quiet"],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        log(f"warning: could not fetch kernel tree {tag} ({exc})")
        shutil.rmtree(dest, ignore_errors=True)
        return None
    shutil.rmtree(dest / ".git", ignore_errors=True)
    size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    log(f"  {tag}: {size / 1e6:.1f} MB of Makefiles")
    return dest


# --------------------------------------------------------------------------
# Debian's published kernel configuration
# --------------------------------------------------------------------------

KCONFIG_SET = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
KCONFIG_UNSET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
RULES_GEN_ARCH = re.compile(r"\bARCH='([a-z0-9]+)'")
CONFIG_MEMBER = re.compile(r"/config\.([a-z0-9]+)_([a-z0-9-]+)_([a-z0-9._-]+)\.xz$")


def _pool_urls(source: str, filename: str) -> tuple[str, ...]:
    return tuple(t.format(dir=source, file=filename) for t in DEBIAN_POOLS)


def _epochless(version: str) -> str:
    # Debian file names carry the version without its epoch.
    return version.split(":", 1)[-1]


def fetch_debian_packaging(
    cache: Path, source: str, version: str, offline: bool
) -> Path | None:
    """The debian/ directory of one kernel source package, as shipped.

    Only used for the list of architectures the release is built for; the
    configuration itself comes from the binary packages below, because
    debian/config/ holds *fragments* - it records what Debian overrides, not
    the config that comes out the other end of `make olddefconfig`.
    """
    name = f"{source}_{_epochless(version)}.debian.tar.xz"
    return _cached_fetch(cache / "debian-config", name, _pool_urls(source, name), offline)


def _cached_fetch(
    directory: Path, name: str, urls: tuple[str, ...], offline: bool,
    quiet: bool = False,
) -> Path | None:
    """Fetch the first of `urls` that exists, or reuse what is cached.

    A source package moves from the main archive to the security archive when
    its release stops being stable, so both pools are tried.  Archive files
    are immutable once published, so a cached copy is never re-fetched.
    """
    path = directory / name
    if path.exists():
        return path
    if offline:
        log(f"warning: --offline and {name} is not cached, skipping")
        return None
    directory.mkdir(parents=True, exist_ok=True)
    for url in urls:
        got = try_download(url, path, offline, quiet)
        if got:
            return got
    return None


def _ar_members(data: bytes):
    """Walk a Unix `ar` archive, which is all a .deb is on the outside."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii", "replace").strip())
        except ValueError:
            return
        offset += 60
        yield name, data[offset : offset + size]
        offset += size + (size % 2)


class DebianConfig:
    """Every kernel configuration one Debian release actually builds with.

    Source: the `linux-config-<series>` binary packages, one per
    architecture, which exist precisely so that people can rebuild a Debian
    kernel with Debian's configuration.  Each carries the final, expanded
    .config for every flavour of that architecture - the same file that ends
    up as /boot/config-* on an installed system.
    """

    def __init__(self) -> None:
        self.flavours: list[str] = []
        self.values: dict[str, dict[str, str]] = {}

    def add_package(self, deb: Path) -> int:
        """Read one architecture's .deb; returns the flavours it added."""
        data = deb.read_bytes()
        added = 0
        for name, body in _ar_members(data):
            if not name.startswith("data.tar"):
                continue
            with tarfile.open(fileobj=io.BytesIO(body)) as tar:
                for member in tar.getmembers():
                    matched = CONFIG_MEMBER.search(member.name)
                    if not member.isfile() or not matched:
                        continue
                    arch, featureset, flavour = matched.groups()
                    key = (
                        f"{arch}/{flavour}"
                        if featureset == "none"
                        else f"{arch}/{featureset}/{flavour}"
                    )
                    if key in self.values:
                        continue
                    text = lzma.decompress(
                        tar.extractfile(member).read()
                    ).decode("utf-8", "replace")
                    self.values[key] = _parse_kconfig(text)
                    self.flavours.append(key)
                    added += 1
        self.flavours.sort()
        return added

    def state(self, symbols: list[str], flavour: str) -> str:
        """'y', 'm' or 'n' for a set of symbols that must all be enabled.

        A symbol missing from a finished .config is one whose dependencies
        were not met, so it is off - which is why an absent symbol is 'n'
        here but would have meant nothing in a config fragment.
        """
        values = self.values[flavour]
        result = "y"
        for symbol in symbols:
            value = values.get("CONFIG_" + symbol, "n")
            if value == "n":
                return "n"
            if value == "m":
                result = "m"
        return result


def load_debian_config(
    cache: Path, source: str, version: str, offline: bool
) -> DebianConfig | None:
    """All of one release's configs, one binary package per architecture."""
    packaging = fetch_debian_packaging(cache, source, version, offline)
    if packaging is None:
        return None
    try:
        with tarfile.open(packaging) as tar:
            member = tar.getmember("debian/rules.gen")
            rules = tar.extractfile(member).read().decode("utf-8", "replace")
    except (KeyError, tarfile.TarError, OSError) as exc:
        log(f"warning: unreadable packaging for {source} {version} ({exc})")
        return None
    arches = sorted(set(RULES_GEN_ARCH.findall(rules)))
    # The configuration package is named after the kernel series, not the
    # source package: linux-6.12 6.12.107-1~deb12u1 ships linux-config-6.12.
    base = upstream_version(version) or ""
    series = ".".join(base.split(".")[:2])
    if not series:
        return None

    # Not every architecture the source builds for is a release architecture,
    # so a 404 here is the archive saying "no such port", not a failure.
    config = DebianConfig()
    for arch in arches:
        name = f"linux-config-{series}_{_epochless(version)}_{arch}.deb"
        deb = _cached_fetch(
            cache / "debian-config", name, _pool_urls(source, name), offline,
            quiet=True,
        )
        if deb is None:
            continue
        try:
            config.add_package(deb)
        except (ValueError, tarfile.TarError, lzma.LZMAError, OSError) as exc:
            log(f"warning: unreadable {name} ({exc})")
    return config if config.flavours else None


def _parse_kconfig(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.split("\n"):
        set_ = KCONFIG_SET.match(line)
        if set_:
            value = set_.group(2)
            # Only tristates matter here; a string or number means "enabled".
            out[set_.group(1)] = value if value in ("y", "m") else "y"
            continue
        unset = KCONFIG_UNSET.match(line)
        if unset:
            out[unset.group(1)] = "n"
    return out


def load_exposure_sources(
    cache: Path, columns: list[dict], offline: bool
) -> tuple[dict[str, KernelTree], dict[str, DebianConfig], Maintainers | None]:
    """One kernel tree per distinct upstream version, one config per column."""
    trees: dict[str, KernelTree] = {}
    for tag in sorted({_tree_tag(col) for col in columns} - {None}):
        root = sync_kernel_tree(cache, tag, offline)
        if root is None:
            continue
        trees[tag] = KernelTree(root, tag)

    configs: dict[str, DebianConfig] = {}
    for col in columns:
        if not col.get("version"):
            continue
        config = load_debian_config(cache, col["package"], col["version"], offline)
        if config is None:
            log(f"warning: no published configuration for {col['id']}")
            continue
        configs[col["id"]] = config
        log(
            f"  {col['id']}: {len(config.flavours)} flavours, "
            f"{len(config.values[config.flavours[0]])} symbols in "
            f"{config.flavours[0]}"
        )

    # The subsystem table is the same job in every tree; use the newest one
    # that came back, and only reach for the network if none did.
    maintainers = None
    for tag in sorted(trees, key=lambda t: version_key(t.lstrip("v")), reverse=True):
        if trees[tag].maintainers_file.exists():
            maintainers = trees[tag].maintainers()
            log(f"MAINTAINERS: from {tag}, {len(maintainers.sections)} sections")
            break
    if maintainers is None:
        path = try_download(MAINTAINERS_URL, cache / "MAINTAINERS", offline)
        if path:
            maintainers = Maintainers(path.read_text(errors="replace"))
            log(f"MAINTAINERS: from kernel.org, {len(maintainers.sections)} sections")
    return trees, configs, maintainers


def _tree_tag(col: dict) -> str | None:
    """The upstream git tag matching the kernel version a column ships."""
    base = upstream_version(col.get("version", ""))
    return f"v{base}" if base else None


class Exposure:
    """Per-CVE answers to 'what is it called, and does my release build it?'"""

    def __init__(
        self,
        columns: list[dict],
        trees: dict[str, KernelTree],
        configs: dict[str, DebianConfig],
        maintainers: Maintainers | None,
    ) -> None:
        self.columns = columns
        self.trees = trees
        self.configs = configs
        self.maintainers = maintainers
        self._states: dict[tuple, tuple[str, dict]] = {}

    def subsystem(self, files: list[str]) -> dict | None:
        """The MAINTAINERS section for the first file that a subsystem claims."""
        if not self.maintainers:
            return None
        fallback = None
        for path in files:
            hit = self.maintainers.lookup(path)
            if hit is None:
                continue
            if hit["name"] != MAINTAINERS_CATCHALL:
                return hit
            fallback = fallback or hit
        return fallback

    def build(self, files: list[str]) -> dict:
        """Everything derivable about one CVE's files.

        Each release is resolved against its own kernel tree and its own
        published config, so the answer for Debian 12 comes from 6.1's
        Makefiles and 6.1's .config, not from whatever the newest kernel
        happens to do.  A release is left out when its tree has no Makefile
        entry for the file - "we do not know" has to stay distinguishable
        from "not enabled".

        The symbols and the module are almost always the same in every
        release, so they are hoisted out of the per-release map and only the
        exceptions are repeated under "by".
        """
        columns: dict[str, dict] = {}
        for col in self.columns:
            tree = self.trees.get(_tree_tag(col) or "")
            if tree is None:
                continue
            resolved = None
            for path in files:
                resolved = tree.resolve(path)
                if resolved is not None:
                    break
            if resolved is None:
                continue
            symbols, module = resolved
            entry: dict = {"sym": symbols, "mod": module or ""}
            config = self.configs.get(col["id"])
            if config is not None:
                summary, per_flavour = self._config_state(col["id"], config, symbols)
                entry["state"] = summary
                # One letter per flavour, in the order meta.json lists them
                # for this column.  Only stored where the flavours disagree:
                # where they agree the summary letter already says it.
                if len(set(per_flavour)) > 1:
                    entry["flav"] = per_flavour
            columns[col["id"]] = entry
        if not columns:
            return {}

        shapes = {(tuple(e["sym"]), e["mod"]) for e in columns.values()}
        common = next(iter(shapes)) if len(shapes) == 1 else None
        out: dict = {
            "state": {c: e["state"] for c, e in columns.items() if "state" in e},
            "flav": {c: e["flav"] for c, e in columns.items() if "flav" in e},
        }
        out = {k: v for k, v in out.items() if v}
        if common is not None:
            # Kept even when empty: an empty symbol list means the file is
            # compiled unconditionally, which is an answer, not a gap.
            out["sym"] = list(common[0])
            out["mod"] = common[1]
        else:
            out["by"] = {
                c: {"sym": e["sym"], "mod": e["mod"]} for c, e in columns.items()
            }
        return out

    def _config_state(
        self, col_id: str, config: DebianConfig, symbols: list[str]
    ) -> tuple[str, str]:
        """(summary letter, one letter per flavour of this release)."""
        key = (col_id, tuple(symbols))
        cached = self._states.get(key)
        if cached is not None:
            return cached
        per_flavour = "".join(
            config.state(symbols, flavour) for flavour in config.flavours
        )
        built = set(per_flavour) - {"n"}
        if not built:
            summary = "n"
        else:
            summary = built.pop() if len(built) == 1 else "b"
            # Upper case where some flavours do not build the code at all,
            # which is usually an architecture that has no such hardware.
            if "n" in per_flavour:
                summary = summary.upper()
        self._states[key] = result = (summary, per_flavour)
        return result


# --------------------------------------------------------------------------
# version arithmetic
# --------------------------------------------------------------------------

UPSTREAM_RE = re.compile(r"^(?:\d+:)?(\d+(?:\.\d+)*)")


def upstream_version(debian_version: str) -> str | None:
    """'6.1.187-1~deb12u1' -> '6.1.187'.  None if it does not look like one."""
    if not debian_version:
        return None
    m = UPSTREAM_RE.match(debian_version)
    return m.group(1) if m else None


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".") if part.isdigit())


def upstream_state(code: str, shipped: str, upstream: dict[str, str]) -> str:
    """Has upstream already fixed this for the series a suite ships?

    Pure version arithmetic over the CNA's own fixed-version list, so the
    answer is reproducible from the published data alone.
    """
    if code not in ("V", "I"):
        return "."
    base = upstream_version(shipped)
    if not base:
        return "W"
    series = series_of(base)
    fix = upstream.get(series) if series else None
    if not fix:
        return "W"
    try:
        return "P" if version_key(fix) > version_key(base) else "W"
    except ValueError:
        return "W"


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------


def build_columns(packages: dict[str, dict]) -> list[dict]:
    """One column per (package, suite) pair that actually carries data."""
    columns = []
    suites = {s for cves in packages["linux"].values() for s in cves["releases"]}
    for suite in sorted(suites, key=lambda s: SUITE_ORDER.index(s) if s in SUITE_ORDER else 99):
        release, role = SUITE_INFO.get(suite, (suite, ""))
        columns.append(
            {
                "id": suite,
                "package": "linux",
                "suite": suite,
                "label": suite,
                "release": release,
                "role": role,
            }
        )
    for pkg, cves in packages.items():
        if pkg == "linux":
            continue
        pkg_suites = {s for c in cves.values() for s in c["releases"]}
        for suite in sorted(pkg_suites, key=lambda s: SUITE_ORDER.index(s) if s in SUITE_ORDER else 99):
            release, role = SUITE_INFO.get(suite, (suite, ""))
            columns.append(
                {
                    "id": f"{suite}-{pkg}",
                    "package": pkg,
                    "suite": suite,
                    "label": f"{suite} · {pkg}",
                    "release": release,
                    "role": f"{role} backport",
                }
            )
    return columns


def archive_versions(packages: dict[str, dict], columns: list[dict]) -> dict[str, str]:
    """The kernel version each column currently ships, per the tracker data."""
    versions: dict[str, str] = {}
    for col in columns:
        for cve in packages[col["package"]].values():
            entry = cve["releases"].get(col["suite"])
            if not entry:
                continue
            repos = entry.get("repositories", {})
            # Prefer the security pocket, it is the one that carries fixes.
            for pocket in (f"{col['suite']}-security", col["suite"], f"{col['suite']}-backports"):
                if pocket in repos:
                    versions[col["id"]] = repos[pocket]
                    break
            if col["id"] in versions:
                break
    return versions


def subsystem_of(files: list[str]) -> tuple[str, str]:
    """('net/batman-adv', 'net') from the CNA's list of touched files."""
    if not files:
        return "", ""
    parts = files[0].split("/")
    area = parts[0] if parts else ""
    subsystem = "/".join(parts[:2]) if len(parts) > 2 else area
    return subsystem, area


def assemble(
    packages: dict[str, dict],
    kernel: dict[str, dict],
    dates: dict[str, int],
    columns: list[dict],
    kev: dict[str, dict],
    epss: dict[str, tuple[float, float]],
    advisories: dict[str, list[dict]],
    exposure: Exposure | None,
):
    all_cves = sorted({cve for pkg in packages.values() for cve in pkg})
    rows = []
    details: dict[str, dict] = {}
    # Subsystem names and module names repeat across thousands of CVEs, so
    # index.json stores an offset into a table in meta.json instead of the
    # string.  That is the difference between ~40 bytes and ~4 per row.
    subsystems: list[list[str]] = []
    subsystem_index: dict[str, int] = {}
    modules: list[str] = []
    module_index: dict[str, int] = {}
    # Newest kernel first: where columns disagree about the module name the
    # newest tree is the one that matches the code as it stands today.
    by_kernel = sorted(
        columns,
        key=lambda c: version_key(upstream_version(c.get("version", "")) or "0"),
        reverse=True,
    )
    # Kept out of the detail chunks: the justification text is ~2 KB per CVE
    # and most readers never open it, so it is served from its own files and
    # fetched only when someone actually asks why a score is what it is.
    reasons: dict[str, dict] = {}

    for cve in all_cves:
        codes = []
        fixes = []
        notes = {}
        urgency = ""
        for col in columns:
            entry = packages[col["package"]].get(cve, {}).get("releases", {}).get(col["suite"])
            if not entry:
                codes.append("-")
                fixes.append("")
                continue
            code, detail = classify(entry)
            codes.append(code)
            fixes.append(detail or "")
            if code == "I" and detail:
                notes[col["id"]] = detail
            u = entry.get("urgency")
            if u and u != "not yet assigned":
                urgency = u

        rec = kernel.get(cve, {})
        vector = rec.get("cvss_vector")
        score = cvss_base_score(vector) if vector else None

        upstream = {}
        for _intro, fixed, _sha in rec.get("pairs", []):
            fixed_series = series_of(fixed)
            if fixed_series:
                upstream[fixed_series] = fixed
        pending = "".join(
            upstream_state(codes[n], col.get("version", ""), upstream)
            for n, col in enumerate(columns)
        )

        subsystem, area = subsystem_of(rec.get("files", []))
        kev_entry = kev.get(cve)
        epss_entry = epss.get(cve)
        advs = advisories.get(cve, [])

        # The advisory that actually shipped the fix to each suite, which is
        # the only firm "this was fixed on <date>" the archive gives us.
        fix_dates, fix_ids = [], []
        for col in columns:
            hit = ""
            for adv in sorted(advs, key=lambda a: a["date"]):
                if adv["package"] == col["package"] and col["suite"] in adv["releases"]:
                    hit = adv
                    break
            fix_dates.append(hit["date"] if hit else "")
            fix_ids.append(hit["id"] if hit else "")

        deb = packages["linux"].get(cve) or packages.get("linux-6.12", {}).get(cve, {})
        summary = rec.get("title") or first_sentence(deb.get("description", "")) or cve

        files = rec.get("files", [])
        exp = exposure.build(files) if exposure and files else {}
        maint = exposure.subsystem(files) if exposure and files else None
        states = exp.get("state", {})
        # One character per column, in the same order as "st": what this
        # release's own kernel configuration does with the affected code.
        config_states = "".join(states.get(col["id"], "?") for col in columns)
        # The name to type into lsmod, but only where some flavour really
        # does build it as a module.  Newest kernel first, because that is
        # the tree whose file layout matches the code as it stands now.
        module_name = ""
        if any(c in "mMbB" for c in config_states):
            for col in by_kernel:
                per_col = exp.get("by", {}).get(col["id"])
                name = per_col["mod"] if per_col else exp.get("mod", "")
                if name and col["id"] in states:
                    module_name = name
                    break

        published = dates.get(cve)
        row = {
            "id": cve,
            "sum": summary,
            "st": "".join(codes),
        }
        if maint and maint["name"] != MAINTAINERS_CATCHALL:
            key = maint["name"]
            if key not in subsystem_index:
                subsystem_index[key] = len(subsystems)
                subsystems.append([key, maint["list"], maint["status"]])
            row["sub"] = subsystem_index[key]
        if set(config_states) != {"?"}:
            row["cfg"] = config_states
        if module_name:
            if module_name not in module_index:
                module_index[module_name] = len(modules)
                modules.append(module_name)
            row["mod"] = module_index[module_name]
        if published:
            row["pub"] = published
        if score is not None:
            row["cvss"] = score
            row["sev"] = severity_of(score)
        if any(fixes):
            row["fix"] = fixes
        if urgency:
            row["urg"] = urgency
        if notes:
            row["nodsa"] = notes
        if "P" in pending or "W" in pending:
            row["up"] = pending
        if kev_entry:
            row["kev"] = 1
            if kev_entry["ransomware"]:
                row["ransom"] = 1
        if epss_entry:
            row["epss"] = round(epss_entry[0], 5)
            row["epct"] = round(epss_entry[1], 5)
        if advs:
            row["adv"] = advs[0]["id"]
        if any(fix_dates):
            row["fd"] = fix_dates
            row["fa"] = fix_ids
        if area:
            row["area"] = area
        if vector:
            # Attack vector and privileges required split kernel bugs more
            # usefully than the score alone does.
            parts = dict(x.split(":", 1) for x in vector.split("/")[1:])
            row["av"] = parts.get("AV", "")
            row["pr"] = parts.get("PR", "")
        rows.append(row)

        if rec.get("cvss_reasons"):
            reasons[cve] = rec["cvss_reasons"]

        details[cve] = {
            "desc": rec.get("description") or deb.get("description", ""),
            "vector": vector,
            "pairs": rec.get("pairs", []),
            "upstream": upstream,
            "files": rec.get("files", [])[:12],
            "debianbug": deb.get("debianbug"),
            "scope": deb.get("scope"),
            "subsystem": subsystem,
            "maintainers": maint,
            "exposure": exp or None,
            "has_reasons": bool(rec.get("cvss_reasons")),
            "kev": kev_entry,
            "advisories": advs,
            "pending": pending,
        }

    # Newest first.  CVEs with no publication date (mostly pre-2024, before the
    # kernel became its own CNA) sort after dated ones, newest id first.
    rows.sort(key=lambda r: (r.get("pub", 0), r["id"]), reverse=True)

    for n, row in enumerate(rows):
        row["c"] = n // DETAIL_CHUNK

    return rows, details, reasons, subsystems, modules


def _has_symbol(exposure: dict) -> bool:
    """Did any release map the affected file onto a CONFIG_ symbol?"""
    if exposure.get("sym"):
        return True
    return any(entry.get("sym") for entry in exposure.get("by", {}).values())


def first_sentence(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    if not text:
        return ""
    cut = text.find(". ")
    if 0 < cut < limit:
        return text[:cut]
    return text[:limit].rstrip() + ("…" if len(text) > limit else "")


def fix_lag(rows: list[dict], columns: list[dict]) -> dict:
    """Days from CVE publication to the advisory that fixed it, per column.

    Only advisory-fixed CVEs have a firm fix date, so this measures the
    security-update path - which is the one that matters when you are waiting
    on a fix for a release you run.
    """
    out = {}
    for idx, col in enumerate(columns):
        lags = []
        for row in rows:
            if not row.get("pub") or not row.get("fd"):
                continue
            when = row["fd"][idx]
            if not when:
                continue
            fixed = datetime.strptime(when, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days = (fixed.timestamp() - row["pub"]) / 86400
            if days >= 0:
                lags.append(days)
        lags.sort()
        if lags:
            out[col["id"]] = {
                "n": len(lags),
                "median": round(lags[len(lags) // 2]),
                "p90": round(lags[min(len(lags) - 1, int(len(lags) * 0.9))]),
            }
        else:
            out[col["id"]] = {"n": 0}
    return out


def counts_per_column(rows: list[dict], columns: list[dict]) -> dict:
    out = {}
    for idx, col in enumerate(columns):
        tally = {code: 0 for code in STATUS_CODES}
        for row in rows:
            tally[row["st"][idx]] += 1
        out[col["id"]] = tally
    return out


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------


def atom_feed(column: dict, rows: list[dict], details: dict, idx: int, built: str, base: str) -> str:
    """Atom feed of recently published CVEs that are open in this column."""
    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    selected = [r for r in rows if r.get("pub") and r["st"][idx] in ("V", "I")][:FEED_ENTRIES]
    title = f"Linux kernel CVEs open in Debian {column['label']}"
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        f"<title>{esc(title)}</title>",
        f"<id>urn:debian-kernel-cve-tracker:{esc(column['id'])}</id>",
        f"<updated>{built}</updated>",
        f'<link rel="alternate" href="{esc(base)}"/>',
        f'<link rel="self" href="{esc(base)}data/feeds/{esc(column["id"])}.xml"/>',
    ]
    for row in selected:
        stamp = datetime.fromtimestamp(row["pub"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        detail = details.get(row["id"], {})
        body = detail.get("desc", "")[:1500]
        status = "no fix planned (no-dsa)" if row["st"][idx] == "I" else "no fix available yet"
        summary = f"{status}\n\n{body}"
        parts += [
            "<entry>",
            f"<title>{esc(row['id'])}: {esc(row['sum'])}</title>",
            f'<link rel="alternate" href="{esc(base)}#{esc(row["id"])}"/>',
            f"<id>urn:cve:{esc(row['id'])}</id>",
            f"<updated>{stamp}</updated>",
            f"<summary>{esc(summary)}</summary>",
            "</entry>",
        ]
    parts.append("</feed>")
    return "\n".join(parts)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, separators=(",", ":"), sort_keys=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", default=".cache", type=Path)
    ap.add_argument("--out", default="site/data", type=Path)
    ap.add_argument("--offline", action="store_true", help="use cached inputs only")
    ap.add_argument("--base-url", default="./", help="site URL, used in the feeds")
    args = ap.parse_args()

    started = time.time()
    args.cache.mkdir(parents=True, exist_ok=True)

    # GitHub Pages reports a custom domain's base URL as http:// until
    # "Enforce HTTPS" is switched on, which would leave every feed link
    # pointing at a redirect.  Pages always serves https, so normalise.
    if args.base_url.startswith("http://"):
        args.base_url = "https://" + args.base_url[len("http://"):]
        log(f"base URL upgraded to {args.base_url}")

    debian_path = download(
        DEBIAN_JSON_URL, args.cache / "debian-tracker.json", args.offline
    )
    repo = sync_vulns(args.cache, args.offline)

    packages = extract_packages(debian_path, PACKAGES)
    if "linux" not in packages:
        sys.exit("the tracker data has no 'linux' source package - aborting")
    kernel = load_kernel_records(repo)
    dates = publication_dates(repo, args.cache)
    kev, kev_version = load_kev(args.cache, args.offline)
    epss, epss_date = load_epss(args.cache, args.offline)
    advisories = load_advisories(args.cache, args.offline)

    # Columns and their shipped kernel versions have to exist before the rows
    # do: the "fix pending upstream" check compares against those versions.
    columns = build_columns(packages)
    versions = archive_versions(packages, columns)
    for col in columns:
        col["version"] = versions.get(col["id"], "")

    trees, configs, maintainers = load_exposure_sources(
        args.cache, columns, args.offline
    )
    exposure = (
        Exposure(columns, trees, configs, maintainers)
        if (trees or maintainers)
        else None
    )
    for col in columns:
        col["kernel_tree"] = _tree_tag(col) if _tree_tag(col) in trees else ""
        col["config_flavours"] = (
            configs[col["id"]].flavours if col["id"] in configs else []
        )

    rows, details, reasons, subsystems, modules = assemble(
        packages, kernel, dates, columns, kev, epss, advisories, exposure
    )

    built = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = args.out

    # Detail chunks, aligned with the sort order so scrolling loads them in
    # sequence rather than at random.
    chunks: dict[int, dict] = {}
    for row in rows:
        chunks.setdefault(row["c"], {})[row["id"]] = details[row["id"]]
    for path in (out / "details").glob("*.json"):
        path.unlink()
    for n, chunk in chunks.items():
        write_json(out / "details" / f"{n}.json", chunk)

    reason_chunks: dict[int, dict] = {}
    for row in rows:
        if row["id"] in reasons:
            reason_chunks.setdefault(row["c"], {})[row["id"]] = reasons[row["id"]]
    for path in (out / "rationale").glob("*.json"):
        path.unlink()
    for n, chunk in reason_chunks.items():
        write_json(out / "rationale" / f"{n}.json", chunk)

    write_json(out / "index.json", {"rows": rows})

    meta = {
        "built": built,
        "columns": columns,
        "status_codes": STATUS_CODES,
        "pending_codes": PENDING_CODES,
        "kev_catalog": kev_version,
        "subsystems": subsystems,
        "modules": modules,
        "config_codes": CONFIG_CODES,
        "epss_scored": epss_date,
        "kev_count": sum(1 for r in rows if r.get("kev")),
        "rationale_count": len(reasons),
        "advisory_count": sum(1 for r in rows if r.get("adv")),
        "chunk_size": DETAIL_CHUNK,
        "chunks": len(chunks),
        "total": len(rows),
        "counts": counts_per_column(rows, columns),
        "fix_lag": fix_lag(rows, columns),
        "sources": {
            "debian": "https://security-tracker.debian.org/tracker/source-package/linux",
            "kernel": "https://git.kernel.org/pub/scm/linux/security/vulns.git",
            "kev": KEV_URL,
            "epss": EPSS_URL,
            "advisories": ADVISORY_URLS["DSA"],
            "maintainers": MAINTAINERS_URL,
            "kernel_tree": LINUX_MIRROR,
            "debian_config": "https://deb.debian.org/debian/pool/main/l/linux/",
        },
        "packages": list(packages),
    }
    write_json(out / "meta.json", meta)

    for path in (out / "feeds").glob("*.xml"):
        path.unlink()
    (out / "feeds").mkdir(parents=True, exist_ok=True)
    for idx, col in enumerate(columns):
        feed = atom_feed(col, rows, details, idx, built, args.base_url)
        (out / "feeds" / f"{col['id']}.xml").write_text(feed, encoding="utf-8")

    log(f"wrote {len(rows)} CVEs, {len(chunks)} detail chunks in {time.time() - started:.1f}s")
    with_subsystem = sum(1 for r in rows if "sub" in r)
    with_symbol = sum(
        1
        for r in rows
        if _has_symbol(details[r["id"]].get("exposure") or {})
    )
    with_state = sum(1 for r in rows if "cfg" in r and set(r["cfg"]) != {"?"})
    not_built = sum(1 for r in rows if "n" in r.get("cfg", ""))
    with_module = sum(1 for r in rows if "mod" in r)
    log(
        f"  exposure: {with_subsystem} with a subsystem name "
        f"({len(subsystems)} distinct), {with_symbol} with a Kconfig symbol, "
        f"{with_state} with a per-release config state, "
        f"{with_module} with a module name ({len(modules)} distinct); "
        f"{not_built} not built in at least one release"
    )
    log(
        f"  triage: {meta['kev_count']} in CISA KEV, "
        f"{meta['advisory_count']} covered by a DSA/DLA, "
        f"{meta['rationale_count']} with a written CVSS justification"
    )
    for col in columns:
        tally = meta["counts"][col["id"]]
        log(
            f"  {col['label']:<28} {col['version']:<18} "
            f"vulnerable={tally['V']:<6} no-dsa={tally['I']:<4} fixed={tally['F']}"
        )


if __name__ == "__main__":
    main()
