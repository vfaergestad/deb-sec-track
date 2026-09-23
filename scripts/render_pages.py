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
MAX_TOTAL_BYTES = 80 * 1024 * 1024

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

    files_block = ""
    if detail.get("files"):
        files_block = ("<h3>Where it lives</h3>"
                       '<p class="panel-note">The fix touches these files. If the '
                       "subsystem is one you do not use, the practical exposure is "
                       "lower, though the package is still the vulnerable one.</p>"
                       '<p class="files">%s</p>'
                       % "<br />".join(esc(f) for f in detail["files"]))

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
    <h2 class="panel-h">What to do, per Debian release</h2>
    <p class="panel-note">Debian's own status for {cve} in every release this site
      tracks, and what each one means in practice. Every status below is the one the
      Debian Security Team publishes for this CVE. {tracker_src}</p>
    <div class="detail"><div class="tablewrap"><table class="answer"><thead><tr>
      <th scope="col">Release</th><th scope="col">Status</th>
      <th scope="col">Version</th><th scope="col">What this means</th>
    </tr></thead><tbody>{answer_rows}</tbody></table></div></div>
  </section>

  <section class="panel">
    <h2 class="panel-h">The vulnerability</h2>
    <div class="detail detail-grid">
      <div>
        <h3>What the bug is</h3>
        <p class="desc">{description_text}</p>
        {files_block}
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
        description_text=esc(detail.get("desc") or "No description published."),
        files_block=files_block,
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
