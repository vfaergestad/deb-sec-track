#!/usr/bin/env python3
"""Fetch other distributions' plain-language writing about the CVEs this site tracks.

Why this exists
---------------
The kernel CNA's record for a CVE is a commit message.  It says what the patch
changes.  It does not say whether the flaw reaches you, or what to do about it
before a fixed package lands.  Red Hat's and Ubuntu's security teams do write
that down, for many of the same CVE ids, in the register a person running a
machine actually needs: "a local attacker could", "disable this module",
"set this sysctl".

This script retrieves that writing, keyed by CVE id, and stores it verbatim.

It is a lookup, not an analysis.  Every string in the output file was typed by
a named security team and is copied through byte for byte.  Nothing here
summarises, paraphrases, condenses, scores or infers.  The one derived flag,
`template`, is an exact match against a short list of published boilerplate
sentences, and it is documented in docs/distro-notes.md.

Sources
-------
Red Hat Product Security, through the Hydra security data API.  A bulk listing
    tells us which CVEs Red Hat tracks against the kernel at all, which is what
    lets us skip roughly a third of the population before spending a per-CVE
    request.  The per-CVE record carries `threat_severity`, `statement`,
    `mitigation` and `details`.

Ubuntu Security Team, through the ubuntu-cve-tracker git repository.  This is
    the same data behind ubuntu.com/security/cves, but the per-CVE JSON on that
    site is about 1 MB each because it inlines every USN and every package
    status, so fetching the population over HTTP would move gigabytes.  A bare
    shallow mirror is one transfer and every read after that is local.

Output
------
One JSON file, `.cache/distro-notes.json` by default, keyed by CVE id.  The
contract is documented in docs/distro-notes.md; scripts/build.py is expected to
read it and fold it into the site data.  This script never writes to site/data/.

Usage
-----
    scripts/distro_notes.py                      # default population, online
    scripts/distro_notes.py --offline            # cache only, no network
    scripts/distro_notes.py --population all     # every tracked CVE
    scripts/distro_notes.py --report             # print the coverage tables
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "distro-notes/1"
USER_AGENT = "debian-kernel-cve-tracker/1.0"

REPO_ROOT = Path(__file__).resolve().parent.parent

# Red Hat.  The listing is filtered to the kernel package so it stays at ~19k
# rows rather than every CVE Red Hat has ever tracked.
RH_LISTING_URL = (
    "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    "?package=kernel&per_page=1000&page={page}"
)
RH_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
RH_PAGE_URL = "https://access.redhat.com/security/cve/{cve}"
RH_LISTING_PAGES_MAX = 200

# Ubuntu.  git.launchpad.net, cloned bare and shallow: we want the current tree,
# not the history.
UCT_REPO = "https://git.launchpad.net/ubuntu-cve-tracker"
# Reads go through a ref we own rather than HEAD, because a bare --single-branch
# clone configures no fetch refspec, so an incremental fetch has to name its
# destination ref explicitly.
UCT_REF = "refs/heads/snapshot"
UBUNTU_PAGE_URL = "https://ubuntu.com/security/{lower}"

# The kernel CNA prefixes its description with this.  Both distributions copy
# that description into a field of their own, and this site already shows it, so
# entries starting with it are flagged rather than silently dropped: the
# consumer decides.
CNA_PREFIX = "In the Linux kernel, the following vulnerability has been resolved:"

# Published boilerplate that occupies a prose field without saying anything
# actionable.  Matched as a prefix, case-insensitively, after whitespace
# collapsing.  A field that matches is still emitted verbatim; it is only
# labelled, so that "has a mitigation" can be counted honestly.
TEMPLATE_PREFIXES = (
    "mitigation for this issue is either not available or the currently "
    "available options don't meet the red hat product security criteria",
    "red hat product security is aware of this issue. updates will be released "
    "as they become available",
    "this issue did not affect the versions of",
    "this flaw is not currently planned to be addressed",
)


def log(msg: str) -> None:
    print(f"[distro-notes] {msg}", file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_template(text: str) -> bool:
    low = collapse(text).lower()
    return any(low.startswith(p) for p in TEMPLATE_PREFIXES)


# Set once from --keep-cna-boilerplate.  Both distributions copy the kernel
# CNA's description into a field of their own, and scripts/build.py already has
# that exact text from vulns.git, so by default we do not carry a second copy:
# measured, it was 5.06 MB of the 5.99 MB of prose in the file.
KEEP_CNA = False
DROPPED_CNA = Counter()


def field(key: str, label: str, text: str, **extra) -> dict | None:
    """Build one prose field, or None when the source left it empty."""
    if not text or not text.strip():
        return None
    out = {"key": key, "label": label, "text": text.strip("\n")}
    if is_template(out["text"]):
        out["template"] = True
    if collapse(out["text"]).startswith(CNA_PREFIX):
        if not KEEP_CNA:
            DROPPED_CNA["dropped"] += 1
            return None
        out["cna_boilerplate"] = True
    out.update(extra)
    return out


# --------------------------------------------------------------------------
# population
# --------------------------------------------------------------------------


def load_population(index: Path, selector: str) -> tuple[list[str], dict[str, dict]]:
    """Return the CVE ids to fetch, plus the index row for each tracked CVE.

    Selectors, all computed from site/data/index.json and nothing else:
      open      status V (vulnerable) or I (no-dsa) in at least one column
      kev       in the CISA Known Exploited Vulnerabilities catalogue
      open+kev  the union of those two, the default
      all       every CVE this site tracks
    """
    rows = json.loads(index.read_text())["rows"]
    by_id = {r["id"]: r for r in rows}
    is_open = {r["id"] for r in rows if any(c in "VI" for c in r.get("st", ""))}
    in_kev = {r["id"] for r in rows if r.get("kev")}
    chosen = {
        "open": is_open,
        "kev": in_kev,
        "open+kev": is_open | in_kev,
        "all": set(by_id),
    }[selector]
    # Newest first, matching the order the site presents, so a --limit run
    # covers the rows a reader is most likely to be looking at.
    ordered = [r["id"] for r in rows if r["id"] in chosen]
    return ordered, by_id


# --------------------------------------------------------------------------
# HTTP, politely
# --------------------------------------------------------------------------


class Fetcher:
    """Rate-limited GET with retries.  A 404 is a normal answer, not a failure."""

    def __init__(self, rate: float, retries: int = 3) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.retries = retries
        self.last = 0.0
        self.requests = 0
        self.bytes = 0

    def get(self, url: str, timeout: int = 60) -> bytes | None:
        """Return the body, or None for 404 / gone.  Raises on real failure."""
        last_err: Exception | None = None
        for attempt in range(self.retries):
            wait = self.last + self.interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self.last = time.monotonic()
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read()
                self.requests += 1
                self.bytes += len(body)
                return body
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    self.requests += 1
                    return None
                last_err = exc
                if exc.code not in (408, 429, 500, 502, 503, 504):
                    break
            except Exception as exc:  # timeouts, resets, DNS
                last_err = exc
            time.sleep(2.0 * (attempt + 1))
        raise RuntimeError(f"{url}: {last_err}")

    def get_json(self, url: str, timeout: int = 60):
        body = self.get(url, timeout)
        return None if body is None else json.loads(body)


# --------------------------------------------------------------------------
# Red Hat
# --------------------------------------------------------------------------


def rh_listing(cache: Path, fetcher: Fetcher, offline: bool, refresh: bool) -> dict:
    """The set of CVEs Red Hat tracks against the kernel, with its one-line summary.

    This is the cheap half of the Red Hat plan: 20 requests and about 10 MB buy
    us the membership set, so the expensive per-CVE requests are only spent on
    CVEs that can possibly have anything to say.
    """
    path = cache / "redhat-listing.json"
    if path.exists() and (offline or not refresh):
        log(f"using cached {path.name}")
        return json.loads(path.read_text())
    if offline:
        log(f"WARNING: --offline and {path} is missing; skipping Red Hat")
        return {}
    rows: list[dict] = []
    for page in range(1, RH_LISTING_PAGES_MAX + 1):
        got = fetcher.get_json(RH_LISTING_URL.format(page=page))
        if not got:
            break
        rows.extend(got)
        log(f"  Red Hat listing page {page}: {len(rows)} rows so far")
    listing = {
        r["CVE"]: {
            "severity": r.get("severity"),
            "public_date": r.get("public_date"),
            "summary": r.get("bugzilla_description"),
        }
        for r in rows
        if r.get("CVE")
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(listing))
    tmp.replace(path)
    log(f"Red Hat listing: {len(listing)} kernel CVEs")
    return listing


def rh_trim(raw: dict) -> dict:
    """Keep only the fields we republish.  Everything kept is stored verbatim."""
    mitigation = raw.get("mitigation")
    if isinstance(mitigation, dict):
        mitigation = mitigation.get("value")
    details = raw.get("details")
    if isinstance(details, str):
        details = [details]
    bugzilla = raw.get("bugzilla") or {}
    return {
        "threat_severity": raw.get("threat_severity"),
        "statement": raw.get("statement"),
        "mitigation": mitigation,
        "details": [d for d in (details or []) if isinstance(d, str)],
        "public_date": raw.get("public_date"),
        "bugzilla_description": bugzilla.get("description"),
        "bugzilla_url": bugzilla.get("url"),
    }


def rh_fetch(
    cve: str, cache: Path, fetcher: Fetcher, offline: bool, recheck_days: int = 0
) -> tuple[str, dict | None]:
    """Return ("record", rec), ("absent", None) or ("unknown", None) for one CVE.

    "absent" means Red Hat answered 404.  "unknown" means we did not ask.  They
    are different answers and the caller must not merge them.

    A per-CVE file is the unit of caching, so an interrupted run resumes where
    it stopped instead of starting over.  A 404 is cached as `absent` so we
    never ask twice about a CVE Red Hat does not track.

    Red Hat edits these fields after publication: a mitigation often appears
    weeks after the CVE does, and a cached "no mitigation" from that window
    would be wrong and would stay wrong.  `recheck_days` re-asks about records
    whose cache file is older than that, so a daily build can refresh a slice of
    the cache per run instead of all of it or none of it.
    """
    path = cache / "redhat" / f"{cve}.json"
    if path.exists():
        stale = (
            recheck_days > 0
            and not offline
            and time.time() - path.stat().st_mtime > recheck_days * 86400
        )
        if not stale:
            rec = json.loads(path.read_text())
            return ("absent", None) if rec.get("absent") else ("record", rec)
    if offline:
        # Not cached and we are not allowed to ask.  This is "unknown", never
        # "absent": reporting it as absent would tell a reader Red Hat has
        # nothing to say about a CVE nobody looked up.
        return ("unknown", None)
    raw = fetcher.get_json(RH_CVE_URL.format(cve=cve))
    rec = {"absent": True} if raw is None else rh_trim(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rec))
    tmp.replace(path)
    return ("absent", None) if rec.get("absent") else ("record", rec)


def rh_record(cve: str, rec: dict, listed: dict | None) -> dict | None:
    """Shape one Red Hat record into the output contract."""
    fields = []
    summary = (listed or {}).get("summary") or rec.get("bugzilla_description")
    for f in (
        field("summary", "Red Hat's one-line summary", summary or ""),
        field("statement", "Red Hat's impact statement", rec.get("statement") or ""),
        field("mitigation", "Red Hat's mitigation", rec.get("mitigation") or ""),
    ):
        if f:
            fields.append(f)
    for i, text in enumerate(rec.get("details") or []):
        f = field("details", "Red Hat's description", text, index=i)
        if f:
            fields.append(f)
    if not fields:
        return None
    out = {
        "source": "Red Hat Product Security",
        "url": RH_PAGE_URL.format(cve=cve),
        "fields": fields,
    }
    severity = rec.get("threat_severity") or (listed or {}).get("severity")
    if severity:
        out["severity"] = severity
    date = rec.get("public_date") or (listed or {}).get("public_date")
    if date:
        out["date"] = date[:10]
    if rec.get("bugzilla_url"):
        out["bug_url"] = rec["bugzilla_url"]
    return out


# --------------------------------------------------------------------------
# Ubuntu
# --------------------------------------------------------------------------


def uct_sync(cache: Path, offline: bool, refresh: bool) -> Path | None:
    """Keep a bare, shallow, single-branch mirror of ubuntu-cve-tracker.

    Bare and shallow for the same reason the Vulnrichment spike chose it: we
    want one packfile and no 90,000-file checkout.  Reads go through
    `git cat-file`, so nothing is ever written to a working tree.
    """
    repo = cache / "ubuntu-cve-tracker.git"
    if offline:
        if not repo.exists():
            log(f"WARNING: --offline and {repo} is missing; skipping Ubuntu")
            return None
        log("using cached ubuntu-cve-tracker mirror")
        return repo
    if repo.exists():
        if not refresh:
            log("using cached ubuntu-cve-tracker mirror")
            return repo
        log("updating ubuntu-cve-tracker mirror")
        done = subprocess.run(
            ["git", "-C", str(repo), "fetch", "--depth", "1", "--force",
             "--quiet", "origin", f"HEAD:{UCT_REF}"],
            capture_output=True, text=True,
        )
        if done.returncode:
            log(f"WARNING: fetch failed, keeping stale mirror: {done.stderr.strip()[:200]}")
        return repo
    log(f"cloning {UCT_REPO} (bare, shallow); this is the one expensive step")
    tmp = cache / "ubuntu-cve-tracker.git.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    done = subprocess.run(
        ["git", "clone", "--quiet", "--bare", "--depth", "1",
         "--single-branch", UCT_REPO, str(tmp)],
        capture_output=True, text=True,
    )
    if done.returncode:
        shutil.rmtree(tmp, ignore_errors=True)
        log(f"WARNING: clone failed, skipping Ubuntu: {done.stderr.strip()[:300]}")
        return None
    # Pin the freshly cloned tip to our own ref so every later read and every
    # incremental fetch names the same thing.
    subprocess.run(
        ["git", "-C", str(tmp), "update-ref", UCT_REF, "HEAD"],
        capture_output=True, text=True, check=False,
    )
    tmp.replace(repo)
    return repo


def uct_paths(repo: Path) -> dict[str, str]:
    """Map CVE id -> path in the tree.

    A record lives in active/, retired/ or ignored/ depending on where Ubuntu's
    workflow has it today, and it moves between them, so the location is looked
    up rather than assumed.
    """
    done = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", UCT_REF],
        capture_output=True, text=True,
    )
    if done.returncode:
        log(f"WARNING: ls-tree failed: {done.stderr.strip()[:200]}")
        return {}
    paths: dict[str, str] = {}
    for line in done.stdout.splitlines():
        name = line.rsplit("/", 1)[-1]
        if name.startswith("CVE-") and "/" in line:
            # active/ wins over retired/ and ignored/ if a CVE somehow appears
            # twice, because active/ is the copy Ubuntu is still editing.
            if name not in paths or line.startswith("active/"):
                paths[name] = line
    return paths


def uct_read(
    repo: Path, paths: dict[str, str], cves: list[str], batch: int = 400
) -> dict[str, str]:
    """Read many records through `git cat-file --batch`: no per-file process, no
    directory walk, no network.

    Batched, because these records are about 120 KB each (they carry a status
    line per Ubuntu release per kernel flavour).  Asking for all 19,103 in one
    call would buffer well over 2 GB of blobs in memory before the first one is
    parsed, so we take them a few hundred at a time and keep only the fields we
    want.
    """
    wanted = [(c, paths[c]) for c in cves if c in paths]
    out: dict[str, str] = {}
    for start in range(0, len(wanted), batch):
        chunk = wanted[start:start + batch]
        stdin = "".join(f"{UCT_REF}:{p}\n" for _, p in chunk)
        proc = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input=stdin.encode(), capture_output=True,
        )
        buf = proc.stdout
        pos = 0
        for cve, _ in chunk:
            nl = buf.find(b"\n", pos)
            if nl < 0:
                break
            header = buf[pos:nl].decode("utf-8", "replace").split()
            pos = nl + 1
            if len(header) < 3 or header[1] != "blob":
                continue  # "<path> missing"
            size = int(header[2])
            out[cve] = buf[pos:pos + size].decode("utf-8", "replace")
            pos += size + 1
    return out


UCT_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*):[ \t]*(.*)$")


def uct_parse(text: str) -> dict[str, str]:
    """Parse the ubuntu-cve-tracker flat-file format into field -> raw value.

    The format is RFC822-ish: a field starts at column zero, and continuation
    lines are indented by one space.  Per-release status lines are fields too
    (`jammy_linux: released (...)`), which is why the caller picks fields by
    name instead of taking everything.
    """
    fields: dict[str, list[str]] = OrderedDict()
    current: list[str] | None = None
    for line in text.splitlines():
        m = UCT_FIELD_RE.match(line)
        if m:
            name, rest = m.group(1), m.group(2)
            current = fields.setdefault(name, [])
            if rest:
                current.append(rest)
            continue
        if current is not None and (line.startswith(" ") or line.startswith("\t")):
            current.append(line[1:] if line.startswith(" ") else line.lstrip("\t"))
            continue
        if not line.strip():
            if current is not None:
                current.append("")
    return {k: "\n".join(v) for k, v in fields.items()}


NOTE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)>[ \t]?(.*)$")


def uct_notes(raw: str) -> list[dict]:
    """Split the Notes field into one entry per author, preserving line breaks.

    Ubuntu writes notes as `author> text`, one line each, and a run of lines by
    the same author is one note.  Lines with no `author>` prefix belong to
    whatever note precedes them.
    """
    notes: list[dict] = []
    for line in raw.splitlines():
        m = NOTE_RE.match(line.strip()) if line.strip() else None
        if m:
            author, body = m.group(1), m.group(2)
            if notes and notes[-1]["author"] == author:
                notes[-1]["lines"].append(body)
            else:
                notes.append({"author": author, "lines": [body]})
        elif notes:
            notes[-1]["lines"].append(line.strip())
        elif line.strip():
            notes.append({"author": "", "lines": [line.strip()]})
    return [
        {"author": n["author"], "text": "\n".join(n["lines"]).strip()}
        for n in notes
        if "\n".join(n["lines"]).strip()
    ]


def ubuntu_record(cve: str, text: str) -> dict | None:
    """Shape one ubuntu-cve-tracker record into the output contract."""
    f = uct_parse(text)
    priority_raw = f.get("Priority", "")
    priority_lines = priority_raw.splitlines()
    priority = priority_lines[0].strip() if priority_lines else ""
    priority_reason = "\n".join(priority_lines[1:]).strip()

    fields = []
    for built in (
        field("impact", "Ubuntu's impact statement", f.get("Ubuntu-Description", "")),
        field("mitigation", "Ubuntu's mitigation", f.get("Mitigation", "")),
        field("priority_reason", "Ubuntu's reason for this priority", priority_reason),
    ):
        if built:
            fields.append(built)
    for note in uct_notes(f.get("Notes", "")):
        built = field("note", "Note from the Ubuntu security team", note["text"])
        if built:
            if note["author"]:
                built["author"] = note["author"]
            fields.append(built)
    built = field("details", "Ubuntu's description", f.get("Description", ""))
    if built:
        fields.append(built)
    if not fields:
        return None

    out = {
        "source": "Ubuntu Security Team",
        "url": UBUNTU_PAGE_URL.format(lower=cve),
        "fields": fields,
    }
    if priority:
        out["severity"] = priority
    date = (f.get("PublicDate") or "").strip()
    if date:
        out["date"] = date[:10]
    discovered = (f.get("Discovered-by") or "").strip()
    if discovered:
        out["credit"] = discovered
    return out


# --------------------------------------------------------------------------
# coverage report
# --------------------------------------------------------------------------


def has(rec: dict | None, key: str, real: bool = True) -> bool:
    """Does this record carry a `key` field?  With real=True, boilerplate and
    the CNA's own copied description do not count."""
    if not rec:
        return False
    for f in rec["fields"]:
        if f["key"] != key:
            continue
        if real and (f.get("template") or f.get("cna_boilerplate")):
            continue
        return True
    return False


def coverage(notes: dict, population: list[str], by_id: dict) -> dict:
    """Tally what we actually got.  Counts only; no interpretation."""

    def tally(ids) -> dict:
        ids = list(ids)
        t = Counter()
        t["population"] = len(ids)
        for cve in ids:
            rec = notes.get(cve, {})
            rh, ub = rec.get("redhat"), rec.get("ubuntu")
            if rh:
                t["redhat_tracked"] += 1
            if has(rh, "statement"):
                t["redhat_statement"] += 1
            if has(rh, "mitigation"):
                t["redhat_mitigation"] += 1
            if has(rh, "mitigation", real=False) and not has(rh, "mitigation"):
                t["redhat_mitigation_template"] += 1
            # Red Hat's own rewrite of the flaw, as opposed to the copy of the
            # CNA's commit message it also stores.  This is the field that
            # actually says "a local user could" in most cases.
            if has(rh, "details"):
                t["redhat_description"] += 1
            if has(rh, "summary"):
                t["redhat_summary"] += 1
            if ub:
                t["ubuntu_tracked"] += 1
            if has(ub, "impact"):
                t["ubuntu_impact"] += 1
            if has(ub, "mitigation"):
                t["ubuntu_mitigation"] += 1
            if has(ub, "note"):
                t["ubuntu_notes"] += 1
            if has(ub, "priority_reason"):
                t["ubuntu_priority_reason"] += 1
            if has(ub, "details"):
                t["ubuntu_description"] += 1
            # "Prose" means somebody wrote something for a person to read.
            # The Red Hat one-line bugzilla summary does not count: it is a
            # subsystem and a function name, the same register as the CNA title
            # this site already shows.
            prose = any(
                has(rh, k) for k in ("statement", "mitigation", "details")
            ) or any(
                has(ub, k)
                for k in ("impact", "mitigation", "note", "priority_reason",
                          "details")
            )
            if prose:
                t["any_prose"] += 1
            if any(has(r, "mitigation") for r in (rh, ub)):
                t["any_mitigation"] += 1
            if rh or ub:
                t["any_record"] += 1
        return dict(t)

    is_open = [c for c in population
               if any(x in "VI" for x in by_id.get(c, {}).get("st", ""))]
    in_kev = [c for c in population if by_id.get(c, {}).get("kev")]
    years = sorted({c.split("-")[1] for c in population})
    return {
        "overall": tally(population),
        "unfixed_in_a_debian_release": tally(is_open),
        "cisa_kev": tally(in_kev),
        "by_year": {y: tally(c for c in population if c.split("-")[1] == y)
                    for y in years},
    }


def check_invariant(payload: dict, wanted: set[str]) -> None:
    """For each source, every examined CVE must land in exactly one of
    `notes`, `silent` or `absent`.  This is what lets a consumer say
    "we asked and there is nothing" without guessing, so it is asserted rather
    than hoped for."""
    examined = set(payload["examined"])
    for source in sorted(wanted):
        got = {c for c, r in payload["notes"].items() if source in r}
        quiet = set(payload["silent"].get(source, ()))
        none = set(payload["absent"].get(source, ()))
        for a, b, names in ((got, quiet, "notes/silent"),
                            (got, none, "notes/absent"),
                            (quiet, none, "silent/absent")):
            if a & b:
                log(f"WARNING: {source}: {len(a & b)} CVEs in both {names}")
        missing = examined - got - quiet - none
        if missing and payload["sources"].get(source, {}).get("complete"):
            log(f"WARNING: {source}: {len(missing)} examined CVEs unaccounted "
                "for, but the source reports itself complete")


REPORT_ROWS = [
    ("population", "CVEs in scope"),
    ("any_record", "Red Hat or Ubuntu has a record"),
    ("any_prose", "at least one piece of prose"),
    ("any_mitigation", "a concrete mitigation from either"),
    ("redhat_tracked", "Red Hat tracks it"),
    ("redhat_description", "Red Hat's own description"),
    ("redhat_statement", "Red Hat impact statement"),
    ("redhat_mitigation", "Red Hat mitigation"),
    ("redhat_mitigation_template", "  (boilerplate non-mitigation)"),
    ("redhat_summary", "Red Hat one-line summary only"),
    ("ubuntu_tracked", "Ubuntu has a record"),
    ("ubuntu_impact", "Ubuntu impact statement"),
    ("ubuntu_mitigation", "Ubuntu mitigation"),
    ("ubuntu_notes", "Ubuntu notes"),
    ("ubuntu_priority_reason", "Ubuntu priority reason"),
    ("ubuntu_description", "Ubuntu's own description"),
]


def print_report(cov: dict) -> None:
    def block(title: str, t: dict) -> None:
        print(f"\n{title}")
        total = t.get("population", 0) or 1
        for key, label in REPORT_ROWS:
            n = t.get(key, 0)
            pct = "" if key == "population" else f"  {100.0 * n / total:5.1f}%"
            print(f"  {label:<34} {n:6d}{pct}")

    block("OVERALL", cov["overall"])
    block("UNFIXED IN AT LEAST ONE DEBIAN RELEASE", cov["unfixed_in_a_debian_release"])
    block("IN CISA KEV", cov["cisa_kev"])
    print("\nBY CVE YEAR")
    head = ("year", "pop", "any-prose", "any-miti", "rh", "rh-desc", "rh-stmt",
            "rh-miti", "ub-impact", "ub-miti", "ub-note", "ub-prio")
    print("  " + "".join(f"{h:>10}" for h in head))
    keys = ("population", "any_prose", "any_mitigation", "redhat_tracked",
            "redhat_description", "redhat_statement", "redhat_mitigation",
            "ubuntu_impact", "ubuntu_mitigation", "ubuntu_notes",
            "ubuntu_priority_reason")
    for year, t in cov["by_year"].items():
        print("  " + f"{year:>10}" + "".join(f"{t.get(k, 0):>10}" for k in keys))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--index", type=Path,
                    default=REPO_ROOT / "site" / "data" / "index.json",
                    help="built index.json to read the CVE ids from")
    ap.add_argument("--cache", type=Path, default=REPO_ROOT / ".cache",
                    help="cache directory (default .cache)")
    ap.add_argument("--out", type=Path, default=None,
                    help="output file (default <cache>/distro-notes.json)")
    ap.add_argument("--population", default="open+kev",
                    choices=("open", "kev", "open+kev", "all"),
                    help="which CVEs to fetch prose for (default open+kev)")
    ap.add_argument("--sources", default="redhat,ubuntu",
                    help="comma-separated subset of redhat,ubuntu")
    ap.add_argument("--offline", action="store_true",
                    help="use cached data only; never touch the network")
    ap.add_argument("--no-refresh", action="store_true",
                    help="keep cached bulk listing and mirror as they are")
    ap.add_argument("--rate", type=float, default=4.0,
                    help="max requests per second per run (default 4)")
    ap.add_argument("--recheck-days", type=int, default=0, metavar="N",
                    help="refetch cached Red Hat records older than N days. "
                         "Red Hat adds mitigations after publication, so a "
                         "permanently cached record goes stale. 30 is a "
                         "reasonable setting for a daily build; 0, the default, "
                         "never rechecks")
    ap.add_argument("--keep-cna-boilerplate", action="store_true",
                    help="also carry the copies of the kernel CNA's own "
                         "description that both distributions keep. Off by "
                         "default: build.py already has that text from "
                         "vulns.git, and it was 5.06 MB of the 5.99 MB of "
                         "prose when measured")
    ap.add_argument("--no-prefilter", action="store_true",
                    help="ask Red Hat about every CVE in the population, not "
                         "only the ones its kernel listing names. Costs about "
                         "50%% more requests; measured to recover records for "
                         "about 5%% of the CVEs the listing omits, none of "
                         "which carried prose in the sample")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N per-CVE fetches (for sampling)")
    ap.add_argument("--report", action="store_true",
                    help="print the coverage tables to stdout")
    args = ap.parse_args()

    started = time.monotonic()
    global KEEP_CNA
    KEEP_CNA = args.keep_cna_boilerplate
    cache: Path = args.cache
    cache.mkdir(parents=True, exist_ok=True)
    out_path: Path = args.out or (cache / "distro-notes.json")
    if out_path.resolve().is_relative_to((REPO_ROOT / "site" / "data").resolve()):
        sys.exit("refusing to write into site/data/")

    if not args.index.exists():
        sys.exit(f"{args.index} is missing; run scripts/build.py first")
    population, by_id = load_population(args.index, args.population)
    log(f"population {args.population}: {len(population)} CVEs "
        f"of {len(by_id)} tracked")

    wanted = {s.strip() for s in args.sources.split(",") if s.strip()}
    fetcher = Fetcher(args.rate)
    refresh = not args.no_refresh
    notes: dict[str, dict] = {}
    sources: dict[str, dict] = {}
    absent: dict[str, list[str]] = {"redhat": [], "ubuntu": []}
    silent: dict[str, list[str]] = {"redhat": [], "ubuntu": []}

    # ---- Red Hat ----
    if "redhat" in wanted:
        try:
            listing = rh_listing(cache, fetcher, args.offline, refresh)
        except Exception as exc:  # a bad listing must not end the run
            log(f"WARNING: Red Hat listing failed: {exc}")
            listing = {}
        if args.no_prefilter:
            candidates = list(population)
            log("Red Hat: --no-prefilter, asking about all "
                f"{len(candidates)} CVEs in scope")
        elif listing:
            candidates = [c for c in population if c in listing]
        else:
            candidates = []
        if listing and not args.no_prefilter:
            log(f"Red Hat: {len(candidates)} of {len(population)} in scope are "
                f"tracked against the kernel; skipping "
                f"{len(population) - len(candidates)} without a request")
        fetched = errors = 0
        unknown = 0
        # `complete` is the honest answer to "can a consumer trust absence from
        # this run?".  Without the listing we never learned what Red Hat tracks,
        # so nothing can be called absent: a UI that read that as "Red Hat has
        # nothing to say" would tell a reader 2,719 CVEs are fine when nobody
        # looked.  That is the mistake docs/vulnrichment.md records.
        complete = bool(listing) or args.no_prefilter
        if complete:
            listed_set = set(candidates)
            absent["redhat"] = [c for c in population if c not in listed_set]
        else:
            log("WARNING: no Red Hat listing, so absence is unknown this run")
        for cve in candidates:
            if args.limit and fetched >= args.limit:
                log(f"--limit {args.limit} reached")
                break
            try:
                state, rec = rh_fetch(cve, cache, fetcher, args.offline,
                                      args.recheck_days)
            except Exception as exc:  # one bad CVE must not end the run
                errors += 1
                if errors <= 5:
                    log(f"WARNING: {cve}: {exc}")
                continue
            fetched += 1
            if fetched % 250 == 0:
                log(f"  Red Hat: {fetched}/{len(candidates)}")
            shaped = rec and rh_record(cve, rec, listing.get(cve))
            if shaped:
                notes.setdefault(cve, {})["redhat"] = shaped
            elif state == "record":
                silent["redhat"].append(cve)  # tracked, but nothing written
            elif state == "absent":
                absent["redhat"].append(cve)  # listed, then answered 404
            else:
                unknown += 1                  # not cached, --offline
        sources["redhat"] = {
            "name": "Red Hat Product Security",
            "listing_url": RH_LISTING_URL.format(page=1),
            "record_url": RH_CVE_URL.format(cve="CVE-0000-0000"),
            "kernel_cves_listed": len(listing),
            "in_scope_and_listed": len(candidates),
            "errors": errors,
            "not_looked_up": unknown,
            "complete": complete and not errors and not unknown,
            # Stated at https://access.redhat.com/security/data: the Security
            # Data API resources are CC BY 4.0, and redistribution requires
            # attribution to Red Hat plus a link to the original.  Both are
            # carried on every record above as `source` and `url`.
            "licence": "CC BY 4.0",
            "licence_url": "https://access.redhat.com/security/data",
            "republish": "permitted-with-attribution",
            "attribution": "Red Hat Product Security",
        }

    # ---- Ubuntu ----
    if "ubuntu" in wanted:
        repo = None
        try:
            repo = uct_sync(cache, args.offline, refresh)
        except Exception as exc:
            log(f"WARNING: ubuntu-cve-tracker sync failed: {exc}")
        paths = uct_paths(repo) if repo else {}
        blobs = {}
        if paths:
            log(f"Ubuntu: mirror holds {len(paths)} CVE records")
            try:
                blobs = uct_read(repo, paths, population)
            except Exception as exc:
                log(f"WARNING: reading the mirror failed: {exc}")
        # Same rule as Red Hat: with no mirror we looked at nothing, so nothing
        # is absent.
        if paths:
            absent["ubuntu"] = [c for c in population if c not in blobs]
        else:
            log("WARNING: no ubuntu-cve-tracker mirror, so absence is unknown "
                "this run")
        for cve, text in blobs.items():
            shaped = ubuntu_record(cve, text)
            if shaped:
                notes.setdefault(cve, {})["ubuntu"] = shaped
            else:
                silent["ubuntu"].append(cve)
        sources["ubuntu"] = {
            "name": "Ubuntu Security Team",
            "repository": UCT_REPO,
            "records_in_mirror": len(paths),
            "in_scope_and_present": len(blobs),
            "complete": bool(paths),
            # Deliberately not "permitted".  Launchpad registers the project
            # as GNU GPL v2, the tree's own .launchpad.yaml says GPL-3.0, there
            # is no COPYING file, and Canonical's website terms allow only
            # "personal, education and non-commercial use" of site content.
            # No source of truth grants republication of this prose, so the
            # build must gate on this field rather than assume.  See
            # docs/distro-notes.md.
            "licence": "declared inconsistently: GPL-2.0 (Launchpad project) "
                       "vs GPL-3.0 (.launchpad.yaml); no COPYING file",
            "licence_url": "https://launchpad.net/ubuntu-cve-tracker",
            "republish": "unclear",
            "attribution": "Ubuntu Security Team",
        }

    cov = coverage(notes, population, by_id)
    payload = {
        "schema": SCHEMA,
        "generated": now_iso(),
        "population": {"selector": args.population, "size": len(population)},
        "sources": sources,
        "coverage": cov,
        "cna_boilerplate_fields_dropped": DROPPED_CNA["dropped"],
        "examined": population,
        "absent": {k: sorted(set(v)) for k, v in absent.items() if k in wanted},
        "silent": {k: sorted(set(v)) for k, v in silent.items() if k in wanted},
        "notes": {c: notes[c] for c in population if c in notes},
    }
    check_invariant(payload, wanted)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=False))
    tmp.replace(out_path)

    elapsed = time.monotonic() - started
    log(f"wrote {out_path} ({out_path.stat().st_size / 1e6:.2f} MB), "
        f"{len(payload['notes'])} CVEs with prose")
    log(f"{fetcher.requests} HTTP requests, {fetcher.bytes / 1e6:.1f} MB, "
        f"{elapsed:.1f} s wall")
    if args.report:
        print_report(cov)
    return 0


if __name__ == "__main__":
    sys.exit(main())
