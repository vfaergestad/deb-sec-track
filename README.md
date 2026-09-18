# Debian Linux Kernel CVE Tracker

A static site that tracks every Linux kernel CVE, shows which Debian suites
are still vulnerable to each one, and attaches the published signals you need
to decide what to look at first.

Everything on the page is a lookup in a public dataset, keyed by CVE id.
Nothing is inferred, estimated by a model, or scored by hand.

## What it shows

For each CVE:

| Field | Source |
| --- | --- |
| Status per Debian suite | Debian Security Tracker — vulnerable, fixed (with the fixed version), not affected, no-dsa, or undetermined |
| Publication date | The commit in the kernel CNA's `vulns.git` that first published the record |
| Summary, description, touched files | Linux kernel CNA record |
| CVSS v3.1 base score | Computed with the standard formula from the CNA's published vector |
| Attack vector (`AV:N` / `AV:L` / …) | The same vector |
| CISA KEV membership | [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Known ransomware use | `knownRansomwareCampaignUse` in the same KEV record |
| EPSS score and percentile | [FIRST EPSS](https://www.first.org/epss/) daily CSV |
| Debian advisory (DSA / DLA) | The security team's own advisory lists |
| "Fix already released upstream" | Version arithmetic: Debian calls the suite vulnerable, and the stable series that suite tracks already has a release containing the fix |
| Upstream introduced/fixed versions | The CNA's `.dyad` files, with links to each fixing commit |

The last one is worth calling out, because it is the difference between
*nobody has fixed this yet* and *the fix exists and Debian has not pulled it
in*. It is computed purely by comparing the version Debian ships against the
CNA's list of fixed versions for that series.

### Triage order

The "triage order" sort is a fixed rule, applied in this sequence:

1. Listed in CISA KEV
2. Known ransomware campaign use
3. EPSS score, descending
4. CVSS base score, descending
5. Publication date, newest first

Every input is a published value, so the same data always produces the same
ordering. It is a way to bring the sharpest signals to the top, not a risk
verdict for your systems — only you know which subsystems you actually run.

## Suites covered

The Debian Security Tracker's machine-readable data covers the suites its
security team currently tracks: `bookworm`, `trixie`, `forky` and `sid`, plus
the `linux-6.12` backport offered to bookworm. Columns are built from
whatever the data contains, so when Debian adds or retires a suite the site
follows without a code change.

Debian LTS suites older than `bookworm` are **not** in that dataset and so do
not get a column. DLA advisories covering them still show up on individual
CVEs.

## Running it

Requires Python 3.9+ and `git`. No third-party packages.

```sh
python3 scripts/build.py          # fetch sources, write site/data/
cd site && python3 -m http.server # then open http://localhost:8000
```

The first build clones the kernel CNA's `vulns.git` (about 160 MB) into
`.cache/` and takes a few minutes. Later builds reuse it and take well under
a minute — publication dates are computed only for commits added since the
last run.

`--offline` rebuilds from whatever is already in `.cache/`, which is useful
when iterating on the site itself.

## Deploying

`.github/workflows/update.yml` rebuilds every six hours and publishes to
GitHub Pages. To turn it on: **Settings → Pages → Source → GitHub Actions**,
then run the workflow once from the Actions tab.

Generated data is not committed. CI builds it fresh and uploads it as a Pages
artifact, which keeps tens of megabytes per run out of the git history.

## Feeds

Each suite gets an Atom feed of newly published CVEs that are still open in
it, at `data/feeds/<suite>.xml` — for example `data/feeds/trixie.xml`.

## Data files

`site/data/` is plain JSON and reusable on its own.

- `meta.json` — suite definitions, shipped kernel versions, counts, and the
  legend for every code used below.
- `index.json` — one compact row per CVE, newest first. `st` is a string of
  per-suite status codes positionally aligned with `meta.columns`
  (`V` vulnerable, `F` fixed, `N` not affected, `I` no-dsa, `U` undetermined,
  `-` not applicable). `up` uses the same alignment for the upstream check
  (`P` fix released upstream, `W` no upstream fix yet, `.` not applicable).
  `c` is the detail chunk holding the rest of that CVE's data.
- `details/<n>.json` — descriptions, CVSS vectors, upstream version pairs,
  KEV records and advisories, fetched by the page on demand.

## Caveats

- Debian's own status is authoritative for whether a suite is fixed. The
  upstream comparison is a convenience built from version numbers, and a
  targeted backport can fix a CVE without changing the version Debian ships.
- The kernel CNA publishes a CVSS vector for only some CVEs. Those without
  one are shown as unrated rather than given an invented score.
- EPSS is a model of exploitation likelihood across the whole CVE corpus. It
  is a published, reproducible number, but it says nothing about your
  configuration.
- CVEs predating the kernel becoming its own CNA (early 2024) often have no
  publication date and a thinner record.

This project is not affiliated with the Debian project, kernel.org, CISA or
FIRST.
