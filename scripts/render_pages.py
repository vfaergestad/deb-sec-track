#!/usr/bin/env python3
"""Render one static HTML page per CVE, for readers who arrive from a search
engine rather than from the front page.

The app at site/index.html is a single-page lookup: everything lives behind
`#cve=CVE-2026-80725`, which needs JavaScript and which search engines index
poorly.  Most people hear a CVE id somewhere and type it into a search box, so
the answer has to exist as a plain page at a plain URL.  That is what this
writes: site/cve/<CVE-ID>.html, one self-contained page that renders with
JavaScript switched off, plus a sitemap and robots.txt so crawlers find them.

Every fact on a page is read out of site/data/, the same files the app reads,
and the lifecycle/advice wording below is a direct port of lifecycle() and
advice() in site/app.js, so a static page and the app say the same thing about
the same CVE.  Nothing here infers, estimates or scores anything.

Run from the repository root, after scripts/build.py has written site/data/:

    python3 scripts/render_pages.py [--base-url https://example.github.io/repo/]

Output is idempotent: two runs over the same site/data/ produce byte-identical
files.  Everything that would otherwise vary ("3 months ago", <lastmod>) is
derived from meta.built rather than from the clock.
"""

import argparse
import calendar
import html
import json
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------- inclusion

# Which CVEs get a page.  A page for all 19k CVEs would be several hundred
# megabytes of mostly unvisited HTML; these three rules cover what a reader is
# plausibly searching for.  A CVE outside them is still reachable in the app.
INCLUDE_RECENT_DAYS = 120      # published within this many days of the build
INCLUDE_KEV = True             # everything CISA lists as exploited, at any age
# Anything Debian has not resolved in some release: vulnerable (V), no-dsa (I)
# or still untriaged (U).  These are the pages with something to act on, at any
# age, so they are never dropped for being old.
UNRESOLVED_CODES = "VIU"

# Hard ceiling on the generated HTML.  If a future dataset pushes past this,
# the run fails loudly rather than quietly publishing a huge tree.
#
# Raised from 60 MB when every signal gained a link to the file that published
# it and the CNA's written CVSS reasoning was inlined: 5,768 pages went from
# 47.4 MB to 70.3 MB, of which about 7.4 MB is the reasoning itself and the
# rest is citation markup.  The inclusion rule below is what keeps that
# bounded: the recent window is a fixed 120 days and the KEV set is tiny, so
# the only part that grows with time is the unresolved set.
#
# Raised again from 80 MB when the exposure answer and the other distributions'
# write-ups were added.  Measured on the 2026-09-28 data: 6,017 pages, 95.1 MB
# in total, against 73.5 MB for the same 6,017 pages without the two new
# sections.  Of the 21.6 MB added, 15.6 MB is the exposure panel
# (2.7 KB a page, present on every page) and 6.0 MB the write-ups.
# That leaves under 5 MB of headroom, which is roughly 300 more pages: the
# next thing that grows this tree needs either a tighter inclusion rule above
# or a decision to raise this again.
#
# Folding that panel into "Where it lives" gave 0.5 MB of that headroom back
# (99.65 MB to 99.15 MB on the 2026-09-29 data, the same 6,017 pages): one
# section wrapper and one heading a page, not the prose, which is all still
# there behind the disclosure.
MAX_TOTAL_BYTES = 100 * 1024 * 1024

# Used for <link rel="canonical"> and the sitemap when --base-url is not given.
# GitHub Pages for git@github.com:vfaergestad/deb-sec-track.git.
DEFAULT_BASE_URL = "https://blog.faergestad.com/deb-sec-track/"

DAY = 86400
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# CVSS v3.1 attack vector letters, straight from the spec's own legend.
AV_WORDS = {"N": "network", "A": "adjacent network", "L": "local", "P": "physical"}

# Where each published value comes from.  Mirrors the same block in app.js:
# every number on a page is somebody else's published value, so every number
# carries a link to the file that says so.  Each of these was checked to
# return 200; where a source has no per-CVE page, the closest honest thing is
# linked and described as exactly that.
VULNS_TREE = "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/"
VULNS_LOG = "https://git.kernel.org/pub/scm/linux/security/vulns.git/log/cve/published/"
TRACKER = "https://security-tracker.debian.org/tracker/"
KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_API = "https://api.first.org/data/v1/epss?pretty=true&cve="
CVSS_CALC = "https://www.first.org/cvss/calculator/3.1#"

ADVISORY_RE = re.compile(r"^(DSA|DLA)-(\d+)")

# The eight CVSS v3.1 base metrics in vector order: code, name, the value that
# scores worst for that metric, and the spec's word for each value.  Port of
# CVSS_METRICS in app.js; all of it is copied from the specification.
CVSS_METRICS = [
    ("AV", "Attack vector", "N", AV_WORDS),
    ("AC", "Attack complexity", "L", {"L": "low", "H": "high"}),
    ("PR", "Privileges required", "N", {"N": "none", "L": "low", "H": "high"}),
    ("UI", "User interaction", "N", {"N": "none", "R": "required"}),
    ("S", "Scope", "C", {"U": "unchanged", "C": "changed"}),
    ("C", "Confidentiality impact", "H", {"H": "high", "L": "low", "N": "none"}),
    ("I", "Integrity impact", "H", {"H": "high", "L": "low", "N": "none"}),
    ("A", "Availability impact", "H", {"H": "high", "L": "low", "N": "none"}),
]

# ------------------------------------------------------------------- utils

def esc(value):
    """Escape for both text and attribute context.  Descriptions are raw
    kernel commit messages: they contain <, &, quotes and the occasional
    stray angle bracket pair that looks like a tag."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def fmt_date(ts):
    if not ts:
        return "unknown"
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def age_label(ts, now):
    """Port of ageLabel() in app.js, measured from the build time so that the
    same data always renders the same bytes."""
    if not ts:
        return "unknown"
    d = int((now - ts) // DAY)
    if d <= 0:
        return "today"
    if d == 1:
        return "1 day"
    if d < 45:
        return "%d days" % d
    if d < 730:
        return "%d months" % round(d / 30.44)
    return "%d years" % round(d / 365.25)


def ago_label(ts, now):
    label = age_label(ts, now)
    if label == "unknown":
        return ""
    return label if label == "today" else label + " ago"


def series_of(version):
    """Port of seriesOf() in app.js: the x.y stable series a version belongs
    to, ignoring any epoch."""
    m = re.match(r"^(?:\d+:)?(\d+\.\d+)", version or "")
    return m.group(1) if m else ""


def severity_of(row):
    """Port of severityOf() in app.js.  No published vector means unrated,
    never a guessed number."""
    cvss = row.get("cvss")
    if cvss is None:
        return "unrated"
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    return "low"


def at(row, key, i):
    """Positional field lookup.  st/up are strings and fix/fd/fa are arrays,
    all aligned with meta.columns; any of them may be absent."""
    seq = row.get(key)
    if not seq or i >= len(seq):
        return ""
    return seq[i] or ""

# ------------------------------------------------------------- citations
# Ports of the helpers of the same name in site/app.js.

def vulns_file(cve, suffix):
    """One file per CVE in the kernel CNA's vulns.git: .json is the record,
    .cvss the vector and the written reasoning, .dyad the version pairs."""
    return "%s%s/%s.%s" % (VULNS_TREE, cve.split("-")[1], cve, suffix)


def vulns_log(cve):
    """The commit history of that record, whose first commit is the
    publication date this page shows."""
    return "%s%s/%s.json" % (VULNS_LOG, cve.split("-")[1], cve)


def advisory_url(aid, date):
    """The published text of a DSA or DLA.  Debian files both by year and
    number, and the advisory's own date supplies the year."""
    m = ADVISORY_RE.match(aid or "")
    year = str(date or "")[:4]
    if not m or not re.match(r"^\d{4}$", year):
        return ""
    if m.group(1) == "DSA":
        return "https://www.debian.org/security/%s/dsa-%s" % (year, m.group(2))
    return "https://www.debian.org/lts/security/%s/dla-%s" % (year, m.group(2))


def ext_link(url, text, label=""):
    """Anything off this site opens in a new tab and carries rel=noopener.

    `label` is given only where the visible text is too generic to stand on its
    own in a list of links; where the text is an advisory id or a heading it is
    the accessible name already, and a repeated aria-label would only be noise
    on a page carrying thirty of them."""
    aria = ' aria-label="%s"' % esc(label) if label else ""
    return ('<a href="%s" target="_blank" rel="noopener"%s>%s</a>'
            % (esc(url), aria, esc(text)))


def src(url, label, text="source"):
    """The small "source" link that sits beside a value.  Its visible text is
    the same word every time, so the label always names what it points at.
    `text` overrides that word where the link does not go to a per-CVE page
    and saying "source" would promise more than it delivers."""
    return ('<a class="src" href="%s" target="_blank" rel="noopener" '
            'aria-label="%s">%s</a>' % (esc(url), esc(label), esc(text)))


def vector_parts(vector):
    out = {}
    for part in str(vector or "").split("/"):
        bits = part.split(":")
        if len(bits) == 2 and bits[0] and bits[1]:
            out[bits[0]] = bits[1]
    return out

# --------------------------------------------------- lifecycle and advice
# Both are ports of the functions of the same name in site/app.js.  They are
# the wording a reader sees, so they must not drift from the app.

def lifecycle(row, i, meta):
    code = row["st"][i]
    if code == "-":
        return {"code": "-", "word": "not in this release"}
    if code == "F":
        return {
            "code": "F",
            "word": "fixed",
            "version": at(row, "fix", i),
            "when": at(row, "fd", i),
            "advisory": at(row, "fa", i),
        }
    if code == "N":
        return {"code": "N", "word": "not affected"}
    if code == "U":
        return {"code": "U", "word": "undetermined"}
    if code == "I":
        reason = (row.get("nodsa") or {}).get(meta["columns"][i]["id"]) or ""
        return {"code": "I", "word": "won't fix", "reason": reason}
    if at(row, "up", i) == "P":
        return {"code": "P", "word": "fix ready upstream"}
    return {"code": "V", "word": "vulnerable"}


def advice(row, i, detail, meta):
    col = meta["columns"][i]
    s = lifecycle(row, i, meta)
    lag = (meta.get("fix_lag") or {}).get(col["id"])
    lag_note = ""
    if lag and lag.get("n"):
        lag_note = (" Advisories for %s have historically landed a median of %s "
                    "days after publication." % (col["suite"], lag["median"]))

    code = s["code"]
    if code == "F":
        if s["advisory"]:
            what = "%s shipped the fix on %s, in %s." % (
                s["advisory"], s["when"], s["version"] or "an update")
        else:
            what = "Fixed in %s." % (s["version"] or "a later version")
        return ("Update the kernel and reboot. " + what +
                " A running kernel keeps the old code until the machine restarts.")
    if code == "P":
        series = series_of(col.get("version"))
        upstream = (detail.get("upstream") or {}).get(series) if series else None
        return ("Nothing to install yet. Upstream fixed this in %s, which is the "
                "series %s tracks, so it should arrive in a future kernel update.%s"
                % (upstream if upstream else "the %s series" % (series or "?"),
                   col["suite"], lag_note))
    if code == "V":
        return ("No fix published anywhere yet, neither in Debian nor upstream for "
                "the series %s tracks. Watch the Debian tracker page for this CVE.%s"
                % (col["suite"], lag_note))
    if code == "I":
        return ("Debian has decided against an update for %s%s Moving to a newer "
                "release is the way to get the fix."
                % (col["suite"], (": " + s["reason"] + ".") if s["reason"] else "."))
    if code == "N":
        return "Nothing to do. %s never shipped the vulnerable code." % col["suite"]
    if code == "U":
        return "Debian has not finished triaging this one for %s." % col["suite"]
    return "This package is not part of %s." % col["suite"]

# ------------------------------------------------------------------ pieces

def triage_badges(row):
    """Port of triageBadges() in app.js."""
    out = []
    if row.get("kev"):
        out.append('<span class="badge kev" title="Listed in CISA&#x27;s Known '
                   'Exploited Vulnerabilities catalogue">KEV</span>')
    if row.get("ransom"):
        out.append('<span class="badge ransom" title="KEV records known ransomware '
                   'campaign use">ransomware</span>')
    if row.get("cvss") is not None:
        out.append('<span class="badge cvss %s" title="CVSS v3.1 base score from the '
                   'kernel CNA vector">%.1f</span>' % (severity_of(row), row["cvss"]))
    if row.get("epss") is not None:
        out.append('<span class="badge epss" title="EPSS %.2f%% probability of '
                   'exploitation in the next 30 days, higher than %.0f%% of all '
                   'scored CVEs">EPSS %.1f%%</span>'
                   % (row["epss"] * 100, row["epct"] * 100, row["epss"] * 100))
    if row.get("av"):
        out.append('<span class="badge av%s" title="CVSS attack vector">AV:%s</span>'
                   % (" net" if row["av"] in ("N", "A") else "", esc(row["av"])))
    return " ".join(out)


def answer_rows(row, detail, meta):
    """The per-release table: the whole point of the page."""
    out = []
    for i, col in enumerate(meta["columns"]):
        if row["st"][i] == "-":
            continue
        s = lifecycle(row, i, meta)
        sub = ""
        if s.get("advisory"):
            adv_url = advisory_url(s["advisory"], s.get("when"))
            text = ""
            if adv_url:
                text = " · " + ext_link(adv_url, "text",
                                        s["advisory"] + " announcement")
            sub = ('<span class="sub">%s · %s%s</span>'
                   % (ext_link(TRACKER + s["advisory"], s["advisory"]),
                      esc(s["when"]), text))
        out.append(
            "<tr>"
            '<td><strong>%s</strong><span class="sub">%s</span></td>'
            '<td><span class="state-chip s-%s">%s</span>%s</td>'
            '<td class="mono">%s</td>'
            '<td class="action">%s</td>'
            "</tr>"
            % (esc(col.get("release") or col["suite"]), esc(col["label"]),
               s["code"], esc(s["word"]), sub,
               esc(s.get("version") or col.get("version") or ""),
               esc(advice(row, i, detail, meta))))
    return "".join(out)


def upstream_rows(detail):
    out = []
    for pair in detail.get("pairs") or []:
        intro, fixed, sha = (list(pair) + ["", "", ""])[:3]
        out.append('<tr><td class="mono">%s</td><td class="mono">%s</td>'
                   '<td class="mono">%s</td></tr>'
                   % (esc(intro), esc(fixed),
                      ext_link("https://git.kernel.org/stable/c/" + str(sha), sha)))
    return "".join(out)


def kev_box(detail):
    kev = detail.get("kev")
    if not kev:
        return ""
    action = ""
    if kev.get("action"):
        action = "<dt>Required action</dt><dd>%s</dd>" % esc(kev["action"])
    return ('<div class="kevbox"><h3>Known to be exploited in the wild</h3>'
            '<dl class="kv">'
            "<dt>Added to KEV</dt><dd>%s</dd>"
            "<dt>Federal due date</dt><dd>%s</dd>"
            '<dt>Ransomware use</dt><dd>%s</dd>%s</dl>'
            '<p class="srcline">%s</p></div>'
            % (esc(kev.get("added") or ""), esc(kev.get("due") or ""),
               "known" if kev.get("ransomware") else "unknown", action,
               src(KEV_CATALOG, "KEV source: the CISA catalogue, which has no "
                                "per-CVE page", "the KEV catalogue")))


def advisory_rows(detail):
    out = []
    for adv in detail.get("advisories") or []:
        suites = ", ".join("%s %s" % (k, v)
                           for k, v in sorted((adv.get("releases") or {}).items()))
        aid = adv.get("id") or ""
        url = advisory_url(aid, adv.get("date"))
        first = ext_link(url, aid, aid + " announcement") if url else esc(aid)
        out.append('<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td>'
                   "<td>%s</td></tr>"
                   % (first, esc(adv.get("date") or ""),
                      esc(suites or adv.get("package") or ""),
                      ext_link(TRACKER + aid, "tracker",
                               aid + " in the Debian tracker")))
    return "".join(out)


def reasons_block(row, detail, reasons, meta):
    """The kernel CNA writes a paragraph per CVSS metric saying why it scored
    that metric the way it did.  The app fetches it on request; a static page
    cannot, so it is inlined.  Port of reasonsHtml()/reasonsBlock() in app.js.

    Two thirds of the CVEs here have no vector at all, so the absent case is
    the common one and says so plainly rather than looking broken."""
    cve = row["id"]
    if not reasons:
        if detail.get("vector"):
            note = ("The kernel CNA published a vector for %s but no written "
                    "reasoning for the individual metrics, so there is nothing to "
                    "quote. %s"
                    % (esc(cve), src(vulns_file(cve, "cvss"),
                                     "Vector source: the kernel CNA scoring file")))
        else:
            note = ("The kernel CNA published no CVSS vector and no reasoning for "
                    "%s, which is why it is shown as unrated rather than given an "
                    "invented score. %s of the %s CVEs here carry reasoning; this "
                    "is not one of them."
                    % (esc(cve), "{:,}".format(meta.get("rationale_count") or 0),
                       "{:,}".format(meta.get("total") or 0)))
        return '<p class="panel-note">%s</p>' % note

    v = vector_parts(detail.get("vector"))
    items = []
    for code, name, worst, words in CVSS_METRICS:
        val = v.get(code, "")
        word = words.get(val, "")
        top = bool(val) and val == worst
        items.append('<div class="reason%s"><dt><span class="metric">%s</span>'
                     '<span class="metric-name">%s</span></dt><dd>%s</dd></div>'
                     % (" top" if top else "",
                        esc("%s:%s" % (code, val or "?")),
                        esc(name + (", " + word if word else "")),
                        esc(reasons.get(code)
                            or "The CNA published no note for this metric.")))
    return ('<p class="panel-note">Quoted from the kernel CNA&#x27;s own scoring '
            "file, word for word. A highlighted metric carries the most severe "
            "value CVSS v3.1 defines for it, which is what pushes the score up. "
            '%s</p><dl class="reasons">%s</dl>'
            % (src(vulns_file(cve, "cvss"),
                   "Reasoning source: the kernel CNA scoring file"), "".join(items)))


# ------------------------------------------ exposure, and the checks
# Ports of the functions of the same name in site/app.js.  The wording is the
# same on a static page as in the app, for the same CVE.

def cfg_word(letter, meta):
    """The legend meta.json publishes for a build-state letter.  Read out of
    the data rather than written here, so the page and the file it renders
    cannot disagree about what a letter means.  The case carries meaning:
    lower case means every kernel flavour Debian builds for that release
    agrees, upper case means the flavours disagree.  Nothing here folds the
    two together, and `?` ("not established") is never treated as `n`."""
    return (meta.get("config_codes") or {}).get(letter) or "not established"


def cfg_tone(letter):
    """Tone only: which of the four shapes a single letter belongs to, used
    for the chip colour and for nothing else."""
    if letter == "n":
        return "none"
    if letter == "?" or not letter:
        return "unknown"
    return "all" if letter == letter.lower() else "some"


def exposure_shape(row, meta):
    """Which releases this CVE applies to, what letter the build reported for
    each, and which shape the row as a whole is in.  The shape is a count of
    letters, not a judgement.  "none" is deliberately the strictest of the
    four: every release this CVE applies to has to say `n`, so one release
    whose build rule could not be established is enough to make it "partial"
    instead.  A `?` never helps a row qualify as not built."""
    seen = []
    cfg = row.get("cfg") or ""
    for i, col in enumerate(meta["columns"]):
        if row["st"][i] == "-":
            continue
        letter = cfg[i] if i < len(cfg) else "?"
        seen.append({"col": col, "i": i, "letter": letter or "?"})
    known = [s for s in seen if s["letter"] != "?"]
    none = [s for s in known if s["letter"] == "n"]
    if not known:
        shape = "unknown"
    elif len(none) == len(seen):
        shape = "none"
    elif none:
        shape = "partial"
    else:
        shape = "built"
    return {"seen": seen, "known": known, "none": none, "shape": shape,
            "unresolved": len(seen) - len(known)}


# The sentence that answers the whole question when Debian compiles the code
# into nothing it ships.  Written once and used twice: in the lead, and on its
# own above the per-release table, which is the only place an exposure answer
# is allowed to outrank that table.
NOT_BUILT_HEAD = "Debian does not build this code."

# The label on the disclosure that holds the per-release build detail.  Same
# words as the app's button, so a reader who has seen one recognises the other.
BUILT_SHOW = "Show whether Debian builds this, per release"


def rel_count(n):
    return "%d release%s" % (n, "" if n == 1 else "s")


def exposure_lead(sh):
    """The one sentence at the top of the panel.  Every clause in it is read
    off the letters above; where a release could not be established it says so
    rather than counting it either way."""
    gap = ""
    if sh["unresolved"]:
        gap = (" The build rule could not be established for %s, so nothing is "
               "claimed about those." % rel_count(sh["unresolved"]))
    if sh["shape"] == "unknown":
        return ("<b>Not established.</b> This site could not find the build rule "
                "for the affected file in the kernel trees Debian ships, so it "
                "has no answer about whether Debian compiles this code. Read "
                "that as unknown, never as absent.")
    if sh["shape"] == "none":
        return ("<b>%s</b> In %s below, every "
                "kernel flavour Debian publishes has the switch off, so the "
                "vulnerable file is compiled into no kernel binary Debian "
                "ships.%s" % (NOT_BUILT_HEAD, rel_count(len(sh["none"])), gap))
    if sh["shape"] == "partial":
        rest = len(sh["known"]) - len(sh["none"])
        return ("<b>Debian does not build this code in %s.</b>%s%s"
                % (rel_count(len(sh["none"])),
                   (" It does build it in %s, so the answer depends on which "
                    "release the machine runs." % rel_count(rest)) if rest else "",
                   gap))
    if any(s["letter"] != s["letter"].lower() for s in sh["known"]):
        return ("<b>Debian builds this, but not on every flavour.</b> At least "
                "one release below builds the code on some of its kernel "
                "flavours and not on others, so the answer depends on the "
                "architecture and flavour installed.%s" % gap)
    # With a release unaccounted for, "every release below" would be a claim
    # about a release this lookup has no answer for.
    every = ("Every release with an answer below" if sh["unresolved"]
             else "Every release below")
    if all(s["letter"] == "m" for s in sh["known"]):
        return ("<b>Debian builds this as a loadable module.</b> %s compiles it "
                "as a module on every flavour, so whether the code is in the "
                "running kernel depends on whether that module is loaded.%s"
                % (every, gap))
    return ("<b>Debian builds this code.</b> %s compiles the affected file into "
            "the kernels it ships.%s" % (every, gap))


def off_flavours(col, flav):
    """The flavours of one release that do not build the code at all.  The
    string is one letter per flavour, in the order meta.json lists them for
    that column, and is present only where that release's flavours disagree."""
    string = (flav or {}).get(col["id"]) or ""
    names = col.get("config_flavours") or []
    return [names[k] for k in range(min(len(string), len(names)))
            if string[k] == "n"]


def exposure_releases(detail, meta, sh):
    """One line per answer, not per release: releases that agree are named
    together, because five copies of one sentence is not five pieces of
    information.  The legend for each letter used is printed once underneath,
    so the meaning is on the page without being repeated per row."""
    flav = ((detail.get("exposure") or {}).get("flav")) or {}
    groups = []
    for s in sh["seen"]:
        off = off_flavours(s["col"], flav)
        key = (s["letter"], tuple(off))
        if groups and groups[-1]["key"] == key:
            groups[-1]["names"].append(s["col"]["label"])
        else:
            groups.append({"key": key, "letter": s["letter"], "off": off,
                           "names": [s["col"]["label"]]})
    rows = []
    for g in groups:
        rows.append(
            '<li class="cfg-row"><span class="cfg-rel">%s</span>'
            '<span class="cfg-chip t-%s">%s</span>%s</li>'
            % (esc(", ".join(g["names"])), cfg_tone(g["letter"]),
               esc(g["letter"]),
               ('<span class="cfg-word">not built on %s</span>'
                % esc(", ".join(g["off"]))) if g["off"] else ""))
    letters = []
    for g in groups:
        if g["letter"] not in letters:
            letters.append(g["letter"])
    key = "".join('<dt><span class="cfg-chip t-%s">%s</span></dt><dd>%s</dd>'
                  % (cfg_tone(l), esc(l), esc(cfg_word(l, meta)))
                  for l in letters)
    return ('<ul class="cfg-list">%s</ul><dl class="cfg-key">%s</dl>'
            % ("".join(rows), key))


def exposure_symbols(detail):
    """Every Kconfig symbol that has to be on for the file to be compiled,
    taken over all releases.  Where the releases resolved to different symbol
    lists the union is what a reader should grep for, because they are looking
    at one machine and do not yet know which list applies to it."""
    e = detail.get("exposure") or {}
    out = set(e.get("sym") or [])
    for entry in (e.get("by") or {}).values():
        out.update(entry.get("sym") or [])
    return sorted(out)


def config_command(syms):
    """The command a reader would actually type.  Generic and standard: one
    grep of the booted kernel's own configuration.  Nothing here knows
    anything about the machine, and nothing is invented: `-w` is what keeps
    CONFIG_BRIDGE from matching CONFIG_BRIDGE_CFM."""
    if not syms:
        return ""
    if len(syms) == 1:
        head = "grep -w CONFIG_" + syms[0]
    else:
        head = "grep -wE '%s'" % "|".join("CONFIG_" + s for s in syms)
    return head + " /boot/config-$(uname -r)"


def lsmod_name(mod):
    """lsmod and modprobe both render a module's dashes as underscores, so this
    is the string an admin types rather than the object name kbuild used."""
    return str(mod or "").replace("-", "_")


def not_built_line(row, meta):
    """The one exposure state that ends the question rather than informing it,
    so the only one allowed above the per-release table.  Everything else about
    how Debian builds the code is supporting detail and sits in "Where it
    lives" below.  Port of notBuiltLine() in app.js."""
    if exposure_shape(row, meta)["shape"] != "none":
        return ""
    return ('<p class="not-built"><b>%s</b> <span class="dim">The per-release '
            'build detail is under "Where it lives" below.</span></p>'
            % NOT_BUILT_HEAD)


def where_block(row, detail, meta):
    """Where the vulnerable code lives and whether Debian compiles it are one
    subject, so they are one section.  What stays visible is what a reader acts
    on: the files, the subsystem, the module name and the commands to type.
    The per-release letters, the Kconfig chain and the prose behind them are
    true but not decisive, so they start closed.

    Port of whereBlock() in app.js.  The app hides the detail behind a button
    it toggles in JavaScript; a static page has no script, so the same closed
    by default disclosure is a native <details>, which is keyboard operable
    and reports its own expanded state without one."""
    sh = exposure_shape(row, meta)
    e = detail.get("exposure") or {}
    m = detail.get("maintainers")
    if not m and row.get("sub") is not None and meta.get("subsystems"):
        entry = meta["subsystems"][row["sub"]]
        m = {"name": entry[0], "list": entry[1], "status": entry[2]}
    syms = exposure_symbols(detail)
    # meta.modules carries a module name only where some flavour really does
    # build it as a module.  Where the code is built in or not built at all, a
    # module name would send the reader looking for something that is not
    # there, so the index row is the gate and not detail["exposure"]["mod"].
    mod = ""
    if row.get("mod") is not None and meta.get("modules"):
        mod = meta["modules"][row["mod"]]
    cmd = config_command(syms)

    facts = []
    if m:
        trail = []
        if m.get("pattern"):
            trail.append("MAINTAINERS section matched on " + m["pattern"])
        if m.get("list"):
            trail.append(m["list"])
        if m.get("status"):
            trail.append(m["status"])
        facts.append("<dt>What this is</dt><dd>%s%s</dd>"
                     % (esc(m.get("name") or ""),
                        ('<span class="sub">%s</span>' % esc(" · ".join(trail)))
                        if trail else ""))
    if mod:
        facts.append('<dt>Kernel module</dt><dd class="mono">%s</dd>'
                     % esc(lsmod_name(mod)))
    elif e.get("mod") and sh["shape"] == "none":
        facts.append('<dt>Kernel module</dt><dd><span class="dim">none to look '
                     "for. The file would have gone into %s, and Debian does "
                     "not compile it into that module, so finding %s in lsmod "
                     "would say nothing about this CVE.</span></dd>"
                     % (esc(lsmod_name(e["mod"])), esc(lsmod_name(e["mod"]))))

    # The switch names are what the grep above already spells out, so the chain
    # itself is a re-reading of the command rather than a second instruction.
    deep_facts = []
    if syms:
        deep_facts.append('<dt>Build switch%s</dt><dd class="mono">%s</dd>%s'
                          % ("" if len(syms) == 1 else "es",
                             ", ".join(esc("CONFIG_" + s) for s in syms),
                             "" if len(syms) == 1 else
                             "<dt>Reads as</dt><dd>all on means the file is "
                             "compiled; any one off means it is not.</dd>"))

    checks = []
    if cmd:
        checks.append('<pre class="cmd"><code>%s</code></pre>'
                      '<p class="cmd-note">Reads the booted kernel\'s own '
                      "configuration, on the machine and nowhere else. "
                      '<span class="mono">=y</span> is built in, '
                      '<span class="mono">=m</span> is a module, and an '
                      '<span class="mono">is not set</span> line means the code '
                      "is not there.</p>" % esc(cmd))
    if mod:
        checks.append('<pre class="cmd"><code>%s</code></pre>'
                      '<p class="cmd-note">Prints a line if that module is '
                      "loaded right now, and nothing if it is not. One that is "
                      "not loaded can still be loaded later by anything that "
                      "needs it.</p>" % esc("lsmod | grep -w " + lsmod_name(mod)))

    sources = meta.get("sources") or {}
    cites = []
    if m and sources.get("maintainers"):
        cites.append(src(sources["maintainers"],
                         "Subsystem source: the kernel MAINTAINERS file",
                         "MAINTAINERS"))
    if syms and sources.get("kernel_tree"):
        cites.append(src(sources["kernel_tree"],
                         "Build switch source: the kernel kbuild Makefiles",
                         "kbuild Makefiles"))
    if sh["known"] and sources.get("debian_config"):
        cites.append(src(sources["debian_config"],
                         "Configuration source: Debian's linux-config packages",
                         "Debian linux-config packages"))

    gap_note = ""
    if sh["unresolved"]:
        gap_note = ('<p class="cmd-note">Where a release above reads "not '
                    'established", no build rule for the affected file was found '
                    "in that release's kernel tree. That is a gap in this "
                    "lookup, not a finding that the code is absent.</p>")

    inner = ('<p class="exposure-lead">%s</p>%s%s%s'
             '<p class="panel-note">From the configuration Debian publishes for '
             "every kernel flavour it builds. It covers only the architectures "
             'Debian ships a <span class="mono">linux-config</span> package '
             "for, and nothing about a kernel you built yourself. Debian's own "
             "status above stays authoritative about the source package.%s</p>"
             % (exposure_lead(sh),
                exposure_releases(detail, meta, sh), gap_note,
                ('<dl class="kv exposure-kv">%s</dl>' % "".join(deep_facts))
                if deep_facts else "",
                ('<span class="srcline">%s</span>' % " ".join(cites)) if cites else ""))

    files = ""
    if detail.get("files"):
        files = ('<p class="panel-note">The fix touches these files. If the '
                 "subsystem is one you do not use, the practical exposure is "
                 'lower, though the package is still the vulnerable one.</p>'
                 '<p class="files">%s</p>'
                 % "<br />".join(esc(f) for f in detail["files"]))

    if not files and not facts and not checks and not sh["seen"]:
        return ""

    return ("<h3>Where it lives</h3>%s%s%s"
            '<details class="built-out"><summary class="ghost built-btn">%s'
            "</summary>%s</details>"
            % (files,
               ('<dl class="kv exposure-kv">%s</dl>' % "".join(facts)) if facts else "",
               ("<h4>Check it on the machine</h4>%s" % "".join(checks))
               if checks else "",
               BUILT_SHOW, inner))


# --------------------------------- what other distributions wrote
# Ports of the functions of the same name in site/app.js.

CC_BY_URL = "https://creativecommons.org/licenses/by/4.0/"


def prose_attribution(info, rec, cve):
    """The licence line that has to sit with the text wherever it is shown.
    Red Hat's material is CC BY 4.0, which requires naming the source and
    linking the original; both come out of meta.prose_sources rather than
    being written into the page."""
    licence = info.get("licence") or ""
    deed = CC_BY_URL if licence.upper().startswith("CC BY") else (info.get("licence_url") or "")
    parts = ["Written by %s and quoted here unchanged"
             % esc(info.get("attribution") or info.get("name") or "")]
    if licence:
        parts.append("under %s" % (ext_link(deed, licence, licence + " licence")
                                   if deed else esc(licence)))
    out = ('<p class="prose-attr">%s. %s.'
           % (" ".join(parts),
              ext_link(rec.get("url") or "", "The original record for " + cve)))
    if info.get("licence_url") and deed != info["licence_url"]:
        out += " " + ext_link(info["licence_url"], "the publisher's terms",
                              (info.get("name") or "") + " data licence terms")
    return out + "</p>"


def prose_fields(rec):
    """Labels arrive ready to render, in the order the source wrote them, so
    the list is walked rather than picked over by key."""
    out = []
    for f in rec.get("fields") or []:
        out.append(
            '<div class="prose-field"><h5>%s%s</h5>%s'
            '<p class="prose-text">%s</p></div>'
            % (esc(f.get("label") or f.get("key") or ""),
               (' <span class="dim">by %s</span>' % esc(f["author"]))
               if f.get("author") else "",
               ('<p class="cmd-note">This is the source\'s standard wording '
                'for "no workaround available", not a workaround.</p>')
               if f.get("template") else "",
               esc(f.get("text") or "")))
    return "".join(out)


def prose_card(key, info, detail, cve):
    """Four answers that are genuinely different and must not collapse into
    one: the source wrote something; the source has no record of this CVE; the
    source has a record and wrote nothing; and nobody looked."""
    name = info.get("name") or key
    rec = (detail.get("notes") or {}).get(key)
    head = '<h4 class="prose-name">%s</h4>' % esc(name)

    # quoted is the licence gate.  A source that does not carry it gets its
    # name and its link and nothing else, whatever a data file may hold.
    if rec and rec.get("quoted") is True and (rec.get("fields") or []):
        bits = []
        if rec.get("severity"):
            bits.append("rated " + esc(rec["severity"]))
        if rec.get("date"):
            bits.append("dated " + esc(rec["date"]))
        return ('<article class="prose-src has-text">%s%s%s%s</article>'
                % (head,
                   ('<p class="prose-meta">%s</p>' % " · ".join(bits)) if bits else "",
                   prose_fields(rec), prose_attribution(info, rec, cve)))
    if rec:
        return ('<article class="prose-src">%s<p class="prose-none">%s has '
                "written about this CVE. This project has no licence to "
                "reproduce their wording, so only the link is here. %s</p>"
                "</article>"
                % (head, esc(name),
                   ext_link(rec.get("url") or "", "Read it at " + name,
                            name + " on " + cve)))
    state = (detail.get("notes_state") or {}).get(key)
    if state == "absent":
        body = ("%s does not track this CVE. Their published record was looked "
                "up and there is none." % esc(name))
    elif state == "silent":
        body = ("%s tracks this CVE but published no write-up of their own for "
                "it." % esc(name))
    else:
        body = "Not checked, so nothing was established either way."
    return ('<article class="prose-src">%s<p class="prose-none">%s</p>'
            "</article>" % (head, body))


def prose_unchecked(sources, keys):
    """Nobody looked at any source for this CVE, which is the honest answer
    for everything outside the population the write-ups were collected over.
    Said once, naming the sources, rather than repeated per source."""
    names = [(sources.get(k) or {}).get("name") or k for k in keys]
    return ('<p class="prose-none">Not checked. Write-ups are looked up only '
            "for the CVEs unfixed in some Debian release, plus everything in "
            "the CISA KEV catalogue, and this one falls outside that set, so "
            "neither %s was consulted. That is not the same as their having "
            "nothing to say.</p>" % esc(" nor ".join(names)))


def notes_block(row, detail, meta, tag="h3", tag_attr=""):
    sources = meta.get("prose_sources") or {}
    if not sources:
        return ""
    return ('<section class="prose-block">'
            "<%s%s>What other distributions have written</%s>"
            '<p class="panel-note">Other security teams write about the same CVE '
            "ids in plain language, and sometimes publish a workaround for the "
            "time before a fixed package exists. None of it is Debian's "
            "position.</p>%s</section>"
            % (tag, tag_attr, tag,
               ('<div class="prose-list">%s</div>'
                % "".join(prose_card(k, sources[k] or {}, detail, row["id"])
                          for k in sources))
               if detail.get("notes_examined")
               else prose_unchecked(sources, list(sources))))


def meta_description(row, meta):
    """A one-line answer for the search result snippet, built only from the
    published status of each release."""
    parts = []
    for i, col in enumerate(meta["columns"]):
        if row["st"][i] == "-":
            continue
        s = lifecycle(row, i, meta)
        version = s.get("version")
        parts.append("%s %s%s" % (col["suite"], s["word"],
                                  (" in " + version) if version else ""))
    tail = []
    if row.get("kev"):
        tail.append("Listed in CISA KEV")
    if row.get("cvss") is not None:
        tail.append("CVSS %.1f" % row["cvss"])
    else:
        tail.append("no CVSS vector published")
    text = "%s: %s. Debian status: %s. %s." % (
        row["id"], row["sum"], "; ".join(parts), "; ".join(tail))
    if len(text) > 320:
        text = text[:317].rstrip() + "…"
    return text

# -------------------------------------------------------------------- page

# Kept deliberately small: app.css does the work, and this is repeated in
# every one of several thousand pages.
EXTRA_CSS = (
    ".crumbs{font-size:13px;margin:0 0 14px;color:var(--ink-dim)}"
    ".crumbs a{margin-right:4px}"
    ".cve-id{font:700 clamp(21px,3.6vw,28px)/1.25 var(--mono);margin:0;letter-spacing:-.01em}"
    ".cve-sum{margin:6px 0 12px;font-size:16px;max-width:80ch}"
    ".panel>.detail>h3:first-child,.panel>.detail-grid h3:first-child{margin-top:0}"
    ".lookup{margin:0;font-size:13px;color:var(--ink-dim)}"
)

# The theme toggle needs JavaScript, but the page must not: without it the
# stylesheet falls back to prefers-color-scheme, which is already correct.
# This only carries over a choice the reader made in the app.
THEME_JS = ("try{var t=localStorage.getItem('theme');"
            "if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}"
            "catch(e){}")


def render_page(row, detail, reasons, meta, base_url, now):
    cve = row["id"]
    links = [
        ("Debian tracker", TRACKER + cve),
        ("CVE record", "https://www.cve.org/CVERecord?id=" + cve),
        ("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
    ]
    # The CNA record exists only for the CVEs vulns.git itself published, and
    # the publication date is read out of the commit that added it, so row.pub
    # is exactly the test for whether that file is there to link to.
    if row.get("pub"):
        links.append(("kernel CNA record", vulns_file(cve, "json")))
    if detail.get("debianbug"):
        links.append(("Debian bug #%s" % detail["debianbug"],
                      "https://bugs.debian.org/%s" % detail["debianbug"]))

    summary = row["sum"]
    title_sum = summary if len(summary) <= 80 else summary[:79].rstrip() + "…"

    cvss_src = vulns_file(cve, "cvss")
    cvss_label = "CVSS source: the kernel CNA scoring file"
    av_label = "Attack vector source: the kernel CNA scoring file"
    tracker_label = "Debian urgency source: the Debian Security Tracker"
    kev_label = "KEV source: the CISA catalogue, which has no per-CVE page"

    cvss_dd = ('<span class="dim">no vector published, unrated</span>'
               if row.get("cvss") is None else
               '%.1f %s<br /><span class="mono dim">%s</span>'
               % (row["cvss"], severity_of(row), esc(detail.get("vector") or "")))
    if detail.get("vector"):
        cvss_dd += ('<span class="srcline">%s %s</span>'
                    % (src(cvss_src, cvss_label),
                       ext_link(CVSS_CALC + detail["vector"], "recompute it",
                                "Recompute this score in the FIRST CVSS v3.1 "
                                "calculator")))
    epss_dd = ('<span class="dim">not scored</span>' if row.get("epss") is None else
               '%.2f%%, higher than %.1f%% of all CVEs<span class="srcline">%s</span>'
               % (row["epss"] * 100, row["epct"] * 100,
                  src(EPSS_API + cve, "EPSS source: the FIRST EPSS record")))
    kev_dd = ("listed" + (", known ransomware use" if row.get("ransom") else "")
              if row.get("kev") else '<span class="dim">not listed</span>')
    kev_dd += ('<span class="srcline">%s</span>'
               % src(KEV_CATALOG, kev_label, "the KEV catalogue"))
    av_dd = ('<span class="dim">not published</span>' if not row.get("av") else
             '%s (AV:%s)<span class="srcline">%s</span>'
             % (AV_WORDS.get(row["av"], "unrecognised"), esc(row["av"]),
                src(cvss_src, av_label)))
    urgency_dd = ('%s<span class="srcline">%s</span>'
                  % (esc(row.get("urg") or "not yet assigned"),
                     src(TRACKER + cve, tracker_label)))
    published_dd = esc(fmt_date(row.get("pub")))
    if row.get("pub"):
        published_dd += (' <span class="dim">(%s)</span><span class="srcline">%s</span>'
                         % (esc(ago_label(row["pub"], now)),
                            src(vulns_log(cve),
                                "Published date source: the vulns.git commit")))

    up_rows = upstream_rows(detail)
    upstream_block = ""
    if up_rows:
        dyad_src = (src(vulns_file(cve, "dyad"),
                        "Upstream version source: the CNA version-pair file")
                    if row.get("pub") else "")
        upstream_block = ("<h3>Upstream fixes</h3>"
                          '<p class="panel-note">The versions the CNA records as '
                          "introducing and fixing this, and the commit for each. "
                          "%s</p>"
                          '<table class="mini"><thead><tr><th>Introduced</th>'
                          "<th>Fixed in</th><th>Commit</th></tr></thead><tbody>"
                          "%s</tbody></table>" % (dyad_src, up_rows))

    adv_rows = advisory_rows(detail)
    advisory_block = ""
    if adv_rows:
        advisory_block = ("<h3>Debian advisories</h3>"
                          '<div class="tablewrap"><table class="mini"><thead><tr>'
                          "<th>Advisory</th><th>Date</th><th>Shipped to</th>"
                          "<th>Debian</th></tr></thead><tbody>"
                          "%s</tbody></table></div>" % adv_rows)

    canonical = base_url + "cve/" + cve + ".html"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{cve}: {title_sum} | Debian kernel CVE tracker</title>
<meta name="description" content="{description}" />
<link rel="canonical" href="{canonical}" />
<link rel="stylesheet" href="../app.css" />
<style>{extra_css}</style>
<script>{theme_js}</script>
</head>
<body>
<a class="skip" href="#status">Skip to the per-release answer</a>

<header class="page-head">
  <div class="wrap">
    <div class="titleblock">
      <p class="tagline" style="margin:0"><a href="../">Debian Kernel CVE Tracker</a></p>
    </div>
    <div class="headmeta"><span class="built">data built {built}</span></div>
  </div>
</header>

<main class="wrap">
  <p class="crumbs"><a href="../">Look up another CVE</a> ·
    <a href="../#cve={cve}">open {cve} in the interactive tracker</a></p>

  <section class="panel">
    <h1 class="cve-id">{cve}</h1>
    <p class="cve-sum">{summary}</p>
    <div class="triage-cell">{badges}</div>
    <p class="lookup">{published_line} Subsystem <span class="mono">{subsystem}</span>.
      Debian urgency: {urgency}.</p>
  </section>

  <section class="panel" id="status">
    {not_built_line}
    <h2 class="panel-h">What to do, per Debian release</h2>
    <p class="panel-note">Debian's own status for {cve} in every release this site
      tracks, and what each one means in practice. Every status below is the one the
      Debian Security Team publishes for this CVE. {tracker_src}</p>
    <div class="detail"><div class="tablewrap"><table class="answer"><thead><tr>
      <th scope="col">Release</th><th scope="col">Status</th>
      <th scope="col">Version</th><th scope="col">What this means</th>
    </tr></thead><tbody>{answer_rows}</tbody></table></div></div>
  </section>

  <section class="panel" id="elsewhere">
    <div class="detail">{notes_block}</div>
  </section>

  <section class="panel">
    <h2 class="panel-h">The vulnerability</h2>
    <div class="detail detail-grid">
      <div>
        <h3>What the bug is</h3>
        <p class="desc">{description_text}</p>
        {where_block}
        <div class="linkrow">{links}</div>
      </div>
      <div>
        {kev_box}
        <h3>Signals</h3>
        <dl class="kv">
          <dt>Published</dt><dd>{published_dd}</dd>
          <dt>CVSS</dt><dd>{cvss_dd}</dd>
          <dt>Attack vector</dt><dd>{av_dd}</dd>
          <dt>EPSS</dt><dd>{epss_dd}</dd>
          <dt>CISA KEV</dt><dd>{kev_dd}</dd>
          <dt>Debian urgency</dt><dd>{urgency_dd}</dd>
          <dt>Subsystem</dt><dd class="mono">{subsystem}</dd>
        </dl>
        {upstream_block}
        {advisory_block}
      </div>
    </div>
  </section>

  <section class="panel">
    <h2 class="panel-h">Why the CNA scored it this way</h2>
    <div class="detail reasons-block">{reasons_block}</div>
  </section>

  <footer class="page-foot">
    <p>Data from the <a href="https://security-tracker.debian.org/tracker/source-package/linux">Debian Security Tracker</a>,
      the <a href="https://git.kernel.org/pub/scm/linux/security/vulns.git">Linux kernel CNA</a>,
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a> and
      <a href="https://www.first.org/epss/">FIRST EPSS</a>. Not affiliated with the Debian project.
      Debian's own status is authoritative; the upstream comparison is computed from
      version numbers, and a backport can fix a CVE without changing the version Debian
      ships. A fixed package is not a fixed machine until the system reboots.</p>
  </footer>
</main>
</body>
</html>
""".format(
        cve=esc(cve),
        title_sum=esc(title_sum),
        description=esc(meta_description(row, meta)),
        canonical=esc(canonical),
        extra_css=EXTRA_CSS,
        theme_js=THEME_JS,
        built=esc(meta["built"]),
        summary=esc(summary),
        badges=triage_badges(row),
        published_dd=published_dd,
        tracker_src=src(TRACKER + cve,
                        "Status source: the Debian Security Tracker entry"),
        reasons_block=reasons_block(row, detail, reasons, meta),
        published_line=(
            "Published %s (%s) by the Linux kernel CNA."
            % (esc(fmt_date(row["pub"])), esc(ago_label(row["pub"], now)))
            if row.get("pub") else
            "The kernel CNA record carries no publication date."),
        subsystem=esc(detail.get("subsystem") or row.get("area") or "unknown"),
        urgency=esc(row.get("urg") or "not yet assigned"),
        urgency_dd=urgency_dd,
        answer_rows=answer_rows(row, detail, meta),
        not_built_line=not_built_line(row, meta),
        where_block=where_block(row, detail, meta),
        notes_block=notes_block(row, detail, meta, "h2", ' class="panel-h"'),
        description_text=esc(detail.get("desc") or "No description published."),
        links="".join(ext_link(u, t) for t, u in links),
        kev_box=kev_box(detail),
        cvss_dd=cvss_dd,
        epss_dd=epss_dd,
        kev_dd=kev_dd,
        av_dd=av_dd,
        upstream_block=upstream_block,
        advisory_block=advisory_block,
    )

# ------------------------------------------------------------------ driver

def selected(rows, now):
    """The inclusion rule, applied in a stable order (index order, which
    build.py writes newest-first)."""
    cutoff = now - INCLUDE_RECENT_DAYS * DAY
    out = []
    for r in rows:
        # The Debian tracker carries a few TEMP-0000000-XXXXXX placeholders for
        # issues with no CVE id yet.  They have no cve.org, NVD or CNA record to
        # link to, so they stay app-only.
        if not CVE_RE.match(r["id"]):
            continue
        recent = bool(r.get("pub")) and r["pub"] >= cutoff
        kev = INCLUDE_KEV and bool(r.get("kev"))
        unresolved = any(c in UNRESOLVED_CODES for c in r["st"])
        if recent or kev or unresolved:
            out.append(r)
    return out


def sitemap(ids, base_url, lastmod):
    body = "".join("<url><loc>%scve/%s.html</loc><lastmod>%s</lastmod></url>\n"
                   % (esc(base_url), esc(cve), esc(lastmod)) for cve in ids)
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + body + "</urlset>\n")


def robots(base_url):
    return ("# Every page here is public reference data; crawl all of it.\n"
            "User-agent: *\n"
            "Allow: /\n"
            "\n"
            "Sitemap: %ssitemap.xml\n" % base_url)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--site", default="site", help="site directory (default: site)")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL,
                    help="public URL of the site root, used for canonical links "
                         "and the sitemap")
    args = ap.parse_args(argv)

    site = Path(args.site)
    data = site / "data"
    if not (data / "meta.json").exists():
        sys.exit("%s not found, run scripts/build.py first" % (data / "meta.json"))

    base_url = args.base_url
    if base_url.startswith("http://"):
        base_url = "https://" + base_url[len("http://"):]
    if not base_url.endswith("/"):
        base_url += "/"

    meta = json.loads((data / "meta.json").read_text(encoding="utf-8"))
    rows = json.loads((data / "index.json").read_text(encoding="utf-8"))["rows"]

    # "Now" is the moment the data was built, not the moment this runs, so the
    # output is a pure function of site/data/.
    now = calendar.timegm(time.strptime(meta["built"], "%Y-%m-%dT%H:%M:%SZ"))
    lastmod = meta["built"][:10]

    chosen = selected(rows, now)
    out_dir = site / "cve"
    out_dir.mkdir(parents=True, exist_ok=True)

    # One chunk of details at a time: 28 MB of JSON does not need to be
    # resident all at once.
    by_chunk = {}
    for r in chosen:
        by_chunk.setdefault(r["c"], []).append(r)

    written = {}
    total = 0
    for chunk in sorted(by_chunk):
        details = json.loads((data / "details" / ("%d.json" % chunk)).read_text(
            encoding="utf-8"))
        # Only chunks holding at least one scored CVE get a rationale file.
        rationale_path = data / "rationale" / ("%d.json" % chunk)
        rationale = (json.loads(rationale_path.read_text(encoding="utf-8"))
                     if rationale_path.exists() else {})
        for r in by_chunk[chunk]:
            page = render_page(r, details.get(r["id"]) or {},
                               rationale.get(r["id"]) or {}, meta, base_url, now)
            blob = page.encode("utf-8")
            (out_dir / (r["id"] + ".html")).write_bytes(blob)
            written[r["id"]] = len(blob)
            total += len(blob)

    ids = sorted(written)

    # Drop pages from an earlier run whose CVE no longer qualifies, so the
    # tree matches the rule rather than accumulating.
    stale = 0
    for existing in sorted(out_dir.iterdir()):
        if existing.suffix == ".html" and existing.stem not in written:
            existing.unlink()
            stale += 1

    (site / "sitemap.xml").write_text(sitemap(ids, base_url, lastmod), encoding="utf-8")
    (site / "robots.txt").write_text(robots(base_url), encoding="utf-8")

    sm = (site / "sitemap.xml").stat().st_size
    rb = (site / "robots.txt").stat().st_size
    print("wrote %d pages to %s (%s)" % (len(ids), out_dir, human(total)))
    print("     rule: published within %d days of the build, or in CISA KEV, or "
          "unresolved (%s) in any release"
          % (INCLUDE_RECENT_DAYS, "/".join(UNRESOLVED_CODES)))
    print("     sitemap.xml %s · robots.txt %s · base URL %s"
          % (human(sm), human(rb), base_url))
    if stale:
        print("     removed %d stale page(s) from a previous run" % stale)
    print("     total generated bytes: %d (%s of the %s budget)"
          % (total + sm + rb, human(total + sm + rb), human(MAX_TOTAL_BYTES)))
    if total + sm + rb > MAX_TOTAL_BYTES:
        sys.exit("generated HTML exceeds the %s budget, tighten the inclusion "
                 "rule at the top of this file" % human(MAX_TOTAL_BYTES))
    return 0


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


if __name__ == "__main__":
    sys.exit(main())
