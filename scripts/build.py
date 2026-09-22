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

CISA Vulnrichment
    CISA's ADP container for CVE records: the three SSVC decision points
    (Exploitation, Automatable, Technical Impact), plus a CVSS vector and a
    CWE where the CNA supplied neither.  Coverage of kernel CVEs is partial
    (32%) and thins out sharply for recent ones, and on this corpus the
    "active" exploitation value selects exactly the KEV set and nothing more
    - so read docs/vulnrichment.md before building anything on it.

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
import json
import math
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEBIAN_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
VULNS_REPO = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
VULNRICHMENT_REPO = "https://github.com/cisagov/vulnrichment.git"
VULNRICHMENT_BRANCH = "develop"

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


def sync_vulnrichment(cache: Path, offline: bool) -> Path | None:
    """Keep a bare, shallow mirror of CISA's Vulnrichment repo in the cache.

    The repo is ~187k small JSON files.  A normal clone checks all of them out
    for 1.5 GB of working tree we would immediately throw away, and a blobless
    partial clone makes every record a separate round trip.  A *bare* shallow
    clone is the cheap middle: one packfile, no checkout, and the ~6k records
    we actually want come straight out of it with `git cat-file`.

    Enrichment is optional, so every failure here degrades to "no Vulnrichment
    data" rather than failing the build.
    """
    repo = cache / "vulnrichment"
    if offline:
        if not repo.exists():
            log("warning: --offline and no vulnrichment mirror cached - skipping")
            return None
        log("using cached vulnrichment mirror")
        return repo
    try:
        if repo.exists():
            log("updating vulnrichment mirror")
            # Fetch straight onto the local branch HEAD points at, so that
            # HEAD is the tip afterwards - a bare repo has no checkout to
            # move for us.
            subprocess.run(
                [
                    "git", "-C", str(repo), "fetch", "--quiet", "--depth", "1",
                    "--force", "origin",
                    f"{VULNRICHMENT_BRANCH}:refs/heads/{VULNRICHMENT_BRANCH}",
                ],
                check=True,
            )
        else:
            log(f"cloning {VULNRICHMENT_REPO} (~170 MB, once)")
            subprocess.run(
                [
                    "git", "clone", "--quiet", "--bare", "--depth", "1",
                    "--single-branch", "--branch", VULNRICHMENT_BRANCH,
                    VULNRICHMENT_REPO, str(repo),
                ],
                check=True,
            )
    except (subprocess.CalledProcessError, OSError) as exc:
        log(f"warning: vulnrichment mirror unavailable ({exc}) - continuing without it")
        return repo if repo.exists() else None
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
            first = cvss_file.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0]
            for token in first.split():
                if token.startswith("CVSS:"):
                    record["cvss_vector"] = token
                    break

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


# CISA's own ADP container is identified by this org id.  A record can carry
# several ADP containers (the CVE Program's own, a supplier's); matching on
# the id rather than on position or title is the only reliable way to pick
# CISA's out.
CISA_ADP_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

# SSVC decision-point values, compacted to one character each for index.json
# and published in meta.json so the codes are self-describing.
SSVC_CODES = {
    "order": ["exploitation", "automatable", "technical_impact"],
    "exploitation": {
        "n": "none - no public exploit code or observed exploitation",
        "p": "poc - a public proof of concept exists",
        "a": "active - exploitation observed in the wild",
    },
    "automatable": {
        "y": "yes - reconnaissance through exploitation can be automated",
        "n": "no - an attacker cannot reliably automate all four steps",
    },
    "technical_impact": {
        "p": "partial - limited control of the affected component",
        "t": "total - total control of the affected component",
    },
}


def vulnrichment_path(cve: str) -> str | None:
    """'CVE-2024-57951' -> '2024/57xxx/CVE-2024-57951.json'."""
    parts = cve.split("-", 2)
    if len(parts) != 3 or not parts[2].isdigit():
        return None
    _, year, num = parts
    return f"{year}/{num[:-3] or '0'}xxx/{cve}.json"


def load_vulnrichment(repo: Path | None, cves: list[str]) -> dict[str, dict]:
    """CISA Vulnrichment ADP data for the CVEs we track, keyed by CVE id.

    Only the records we need are read: asking `git cat-file --batch` for a
    path that is not in the tree costs a "missing" line and nothing else, so
    one pass over our own CVE list is enough - no directory listing, no
    per-file process, no network.

    Everything taken here is a value CISA published against that CVE id.  The
    SSVC decision points are CISA's analysts' recorded answers, not something
    this build derives.
    """
    if repo is None:
        return {}

    wanted = [(cve, vulnrichment_path(cve)) for cve in cves]
    wanted = [(cve, path) for cve, path in wanted if path]
    query = "".join(f"HEAD:{path}\n" for _cve, path in wanted)
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input=query.encode(),
            check=True,
            stdout=subprocess.PIPE,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        log(f"warning: could not read vulnrichment mirror ({exc}) - skipping")
        return {}

    data = proc.stdout
    out: dict[str, dict] = {}
    pos = 0
    for cve, _path in wanted:
        end = data.find(b"\n", pos)
        if end < 0:
            break
        header = data[pos:end].decode("utf-8", "replace")
        pos = end + 1
        if header.endswith(" missing"):
            continue
        try:
            size = int(header.rsplit(" ", 1)[1])
        except (IndexError, ValueError):
            break
        body = data[pos:pos + size]
        pos += size + 1  # git writes a newline after each object
        record = parse_vulnrichment(body)
        if record:
            out[cve] = record

    log(f"CISA Vulnrichment: {len(out)} of {len(cves)} tracked CVEs enriched")
    return out


def parse_vulnrichment(body: bytes) -> dict | None:
    """Pull CISA's ADP container out of one CVE record."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    adp = None
    for container in doc.get("containers", {}).get("adp", []):
        if container.get("providerMetadata", {}).get("orgId") == CISA_ADP_ORG:
            adp = container
            break
    if adp is None:
        return None

    record: dict = {}
    for metric in adp.get("metrics", []):
        other = metric.get("other") or {}
        if other.get("type") == "ssvc":
            content = other.get("content", {})
            for option in content.get("options", []):
                for key, value in option.items():
                    # "Technical Impact" -> "technical_impact"
                    record[key.lower().replace(" ", "_")] = value
            record["scored"] = (content.get("timestamp") or "")[:10]
        # CISA only adds a CVSS when the CNA published none.  A record can
        # carry more than one version of it, so take the newest and keep it.
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in metric and "cvss_vector" not in record:
                record["cvss_vector"] = metric[key].get("vectorString")
                record["cvss_score"] = metric[key].get("baseScore")
                break

    cwes = []
    for problem in adp.get("problemTypes", []):
        for desc in problem.get("descriptions", []):
            if desc.get("cweId"):
                cwes.append({"id": desc["cweId"], "name": desc.get("description", "")})
    if cwes:
        record["cwe"] = cwes

    record["updated"] = (adp.get("providerMetadata", {}).get("dateUpdated") or "")[:10]
    return record or None


def ssvc_code(record: dict) -> str:
    """The three SSVC decision points as one three-character string.

    A '?' means CISA published a container for this CVE but not that decision
    point - absent, not assumed.
    """
    return (
        (record.get("exploitation") or "?")[0]
        + (record.get("automatable") or "?")[0]
        + (record.get("technical_impact") or "?")[0]
    )


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
    vulnrichment: dict[str, dict],
):
    all_cves = sorted({cve for pkg in packages.values() for cve in pkg})
    rows = []
    details: dict[str, dict] = {}

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
        vr = vulnrichment.get(cve)

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

        published = dates.get(cve)
        row = {
            "id": cve,
            "sum": summary,
            "st": "".join(codes),
        }
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
        if vr:
            # Three characters carry all three decision points, which keeps
            # the cost of this on the critical path down to ~80 KB overall.
            row["ssvc"] = ssvc_code(vr)
            if vr.get("cwe"):
                row["cwe"] = vr["cwe"][0]["id"]
            # CISA fills CVSS in only where the CNA published none, so these
            # stay in their own fields rather than being merged into `cvss`:
            # two authorities scoring the same CVE disagree often enough that
            # silently blending them would misrepresent both.
            vr_score = vr.get("cvss_score")
            if vr_score is not None and "cvss" not in row:
                row["vcvss"] = vr_score
                row["vsev"] = severity_of(vr_score)
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

        details[cve] = {
            "desc": rec.get("description") or deb.get("description", ""),
            "vector": vector,
            "pairs": rec.get("pairs", []),
            "upstream": upstream,
            "files": rec.get("files", [])[:12],
            "debianbug": deb.get("debianbug"),
            "scope": deb.get("scope"),
            "subsystem": subsystem,
            "kev": kev_entry,
            "advisories": advs,
            "pending": pending,
            "vulnrichment": vr,
        }

    # Newest first.  CVEs with no publication date (mostly pre-2024, before the
    # kernel became its own CNA) sort after dated ones, newest id first.
    rows.sort(key=lambda r: (r.get("pub", 0), r["id"]), reverse=True)

    for n, row in enumerate(rows):
        row["c"] = n // DETAIL_CHUNK

    return rows, details


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
    vr_repo = sync_vulnrichment(args.cache, args.offline)

    packages = extract_packages(debian_path, PACKAGES)
    if "linux" not in packages:
        sys.exit("the tracker data has no 'linux' source package - aborting")
    kernel = load_kernel_records(repo)
    dates = publication_dates(repo, args.cache)
    kev, kev_version = load_kev(args.cache, args.offline)
    epss, epss_date = load_epss(args.cache, args.offline)
    advisories = load_advisories(args.cache, args.offline)
    # Vulnrichment is read per CVE id, so it needs the tracked set first.
    tracked = sorted({cve for pkg in packages.values() for cve in pkg})
    vulnrichment = load_vulnrichment(vr_repo, tracked)

    # Columns and their shipped kernel versions have to exist before the rows
    # do: the "fix pending upstream" check compares against those versions.
    columns = build_columns(packages)
    versions = archive_versions(packages, columns)
    for col in columns:
        col["version"] = versions.get(col["id"], "")

    rows, details = assemble(
        packages, kernel, dates, columns, kev, epss, advisories, vulnrichment
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

    write_json(out / "index.json", {"rows": rows})

    meta = {
        "built": built,
        "columns": columns,
        "status_codes": STATUS_CODES,
        "pending_codes": PENDING_CODES,
        "kev_catalog": kev_version,
        "epss_scored": epss_date,
        "kev_count": sum(1 for r in rows if r.get("kev")),
        "advisory_count": sum(1 for r in rows if r.get("adv")),
        "ssvc_codes": SSVC_CODES,
        "vulnrichment_count": sum(1 for r in rows if r.get("ssvc")),
        "vulnrichment_exploitation": {
            name: sum(1 for r in rows if r.get("ssvc", "")[:1] == code)
            for code, name in (("n", "none"), ("p", "poc"), ("a", "active"))
        },
        "vulnrichment_cwe_count": sum(1 for r in rows if r.get("cwe")),
        "vulnrichment_cvss_count": sum(1 for r in rows if r.get("vcvss")),
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
            "vulnrichment": "https://github.com/cisagov/vulnrichment",
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
    log(
        f"  triage: {meta['kev_count']} in CISA KEV, "
        f"{meta['advisory_count']} covered by a DSA/DLA"
    )
    exploitation = meta["vulnrichment_exploitation"]
    log(
        f"  vulnrichment: {meta['vulnrichment_count']}/{len(rows)} CVEs enriched "
        f"({100 * meta['vulnrichment_count'] / len(rows):.1f}%), "
        f"exploitation none={exploitation['none']} poc={exploitation['poc']} "
        f"active={exploitation['active']}, "
        f"{meta['vulnrichment_cwe_count']} with a CWE, "
        f"{meta['vulnrichment_cvss_count']} given a CVSS the CNA never published"
    )
    for col in columns:
        tally = meta["counts"][col["id"]]
        log(
            f"  {col['label']:<28} {col['version']:<18} "
            f"vulnerable={tally['V']:<6} no-dsa={tally['I']:<4} fixed={tally['F']}"
        )


if __name__ == "__main__":
    main()
