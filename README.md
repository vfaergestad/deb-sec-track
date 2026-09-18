# Debian Kernel CVE Tracker

Heard about a Linux kernel vulnerability? Look up whether Debian is affected,
which releases, and what to do about it.

That is the whole site. It is a public reference, not a dashboard: it knows
nothing about you or your machines, asks you to configure nothing, and shows
every Debian release side by side on every CVE.

Every signal is a lookup in a published dataset keyed by CVE id, or arithmetic
over published values. Nothing is inferred, estimated by a model, or scored by
hand.

## How you use it

Paste a CVE id into the box at the top. The site jumps straight to it and
answers, for each Debian release:

- what status the Debian Security Team gives it,
- which package version fixes it, and which DSA or DLA shipped that fix on
  what date,
- and what that means in practice — from "update the kernel and reboot" to
  "no fix exists anywhere yet".

If you do not have a CVE id, search by subsystem (`ksmbd`, `nftables`,
`io_uring`) or work through the views:

| View | Answers |
| --- | --- |
| **Latest** | What has the kernel CNA published in the last 30 days? |
| **Exploited in the wild** | Which kernel CVEs are in CISA's KEV catalogue, and is Debian still exposed to any of them? |
| **Unfixed in Debian** | What is still open in at least one release, most serious first? |
| **Recently fixed** | What did Debian's advisories fix lately? |
| **Everything** | The full archive. |

## Fix lifecycle

Each CVE sits in one of these states per release:

- **vulnerable** — Debian lists it unfixed, and upstream has published no fix
  for the stable series that release tracks either. There is nothing to
  install yet.
- **fix ready upstream** — Debian still lists it unfixed, but the stable
  series that release tracks already has a version containing the fix, so it
  should arrive in a future kernel update. This is the difference between
  *nobody has fixed this* and *the fix exists and is waiting*, and it is
  computed by comparing the version Debian ships against the CNA's
  fixed-version list.
- **fixed** — a fixed version is available, with the advisory and date where
  one shipped it.
- **won't fix** — Debian triaged it and decided against an update for that
  release, with their stated reason.
- **not affected** — that release never shipped the vulnerable code.

### How long Debian takes

Debian's advisory lists record which advisory shipped to which suite on which
date, so the turnaround is measured, not guessed:

| Release | Median | 90% within | Sample |
| --- | --- | --- | --- |
| trixie (stable) | 9 days | 41 days | 1,319 advisories |
| bookworm (oldstable) | 17 days | 65 days | 2,962 advisories |
| bookworm · linux-6.12 | 7 days | 13 days | 587 advisories |

Measured from CVE publication to the advisory that fixed it. `forky` and
`sid` get fixes through ordinary uploads rather than advisories, so there is
no advisory turnaround to measure. These are historical distributions, not a
promise about any particular CVE.

## Signals

| Signal | Source |
| --- | --- |
| Status per Debian release | Debian Security Tracker, for the `linux` and `linux-6.12` source packages |
| Publication date | The commit in the kernel CNA's `vulns.git` that first published the record |
| Summary, description, touched files | Linux kernel CNA record |
| CVSS v3.1 base score | Computed with the standard formula from the CNA's published vector |
| Attack vector | The same vector |
| CISA KEV, ransomware use | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| EPSS score and percentile | [FIRST EPSS](https://www.first.org/epss/) daily CSV |
| Advisory and fix date, per release | Debian's own DSA and DLA lists, including the per-suite lines |
| Upstream introduced/fixed versions | The CNA's `.dyad` files, with links to each fixing commit |

CVEs with no published CVSS vector are shown as unrated rather than given an
invented score.

## Releases covered

Columns are built from whatever the tracker data contains — currently
`bookworm`, `trixie`, `forky`, `sid`, plus the `linux-6.12` backport for
bookworm — so a new Debian release appears without a code change. LTS suites
older than `bookworm` are not in that dataset and get no column; DLA
advisories covering them still show up on individual CVEs.

## Running it

Requires Python 3.9+ and `git`. No third-party packages.

```sh
python3 scripts/build.py          # fetch sources, write site/data/
cd site && python3 -m http.server # then open http://localhost:8000
```

The first build clones the kernel CNA's `vulns.git` (about 160 MB) into
`.cache/` and takes a few minutes. Later builds reuse it and take well under
a minute — publication dates are computed only for commits added since the
last run. `--offline` rebuilds from whatever is already cached.

## Deploying

`.github/workflows/update.yml` rebuilds every six hours and publishes to
GitHub Pages. To turn it on: **Settings → Pages → Source → GitHub Actions**.
Generated data is not committed; CI builds it fresh and uploads it as a Pages
artifact, which keeps tens of megabytes per run out of the git history.

## Feeds

Each release has an Atom feed of newly published CVEs still unfixed in it, at
`data/feeds/<release>.xml`.

## Data files

`site/data/` is plain JSON and reusable on its own.

- `meta.json` — release definitions, shipped kernel versions, counts, fix-lag
  statistics, and the legend for every code below.
- `index.json` — one compact row per CVE. Arrays and code strings are
  positionally aligned with `meta.columns`: `st` holds status (`V` vulnerable,
  `F` fixed, `N` not affected, `I` no-dsa, `U` undetermined, `-` n/a), `up`
  holds the upstream check (`P` fix released upstream, `W` none yet, `.` n/a),
  `fix` the fixed version, `fd` the advisory date, `fa` the advisory id. `c`
  is the detail chunk holding the rest.
- `details/<n>.json` — descriptions, CVSS vectors, upstream version pairs,
  KEV records and advisories, fetched on demand.

## Caveats

- Debian's own status is authoritative. The upstream comparison is a
  convenience built from version numbers, and a targeted backport can fix a
  CVE without changing the version Debian ships.
- A fixed package is not the same as a fixed machine: a running kernel keeps
  the old code until the system reboots.
- Fix-lag figures cover CVEs fixed through an advisory. Many are fixed by a
  routine stable rebase instead, which carries no per-CVE date.
- EPSS models exploitation likelihood across the whole CVE corpus. It is
  reproducible, but it says nothing about any particular deployment.
- CVEs predating the kernel becoming its own CNA (early 2024) often have no
  publication date and a thinner record.

Not affiliated with the Debian project, kernel.org, CISA or FIRST.
