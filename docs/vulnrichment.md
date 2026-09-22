# CISA Vulnrichment as an enrichment source

Measured on 2026-09-22 against 19,103 kernel CVEs tracked by Debian.

**Recommendation: do not ship this to the site.** The fetch works, the data is
accurate, and the build integration is complete — but the signal it adds to the
CVEs this site is actually about is five rows. The reasoning is at the bottom;
read it before wiring any of these fields into the UI.

## What the source is

[cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) is CISA's public
repository of its ADP (Authorized Data Publisher) containers for CVE records.
CISA does not overwrite the CNA's data; it adds a container of its own to the
record. For each CVE it analyses, that container carries:

- **SSVC decision points** — the three answers a CISA analyst recorded:
  - `Exploitation`: `none` / `poc` / `active`
  - `Automatable`: `yes` / `no`
  - `Technical Impact`: `partial` / `total`
- **CVSS**, but only where the originating CNA published none.
- **CWE**, likewise only where the CNA published none.

Every field this build takes is a value CISA published against that CVE id. The
build performs a lookup and a character-for-character transcription. Nothing is
inferred, scored, interpolated or filled in.

## How we fetch it

`sync_vulnrichment()` keeps a **bare, shallow, single-branch clone** of the
`develop` branch under `.cache/vulnrichment`, and `load_vulnrichment()` reads
the records we want out of it with a single `git cat-file --batch`.

Bare and shallow is the point. The repo is ~187,000 small JSON files, and the
obvious approaches are all worse:

| approach | cold cost | notes |
|---|---|---|
| normal shallow clone | 101 s, 184 MB transfer, **1.5 GB working tree** | checks out 187k files to use 6k of them; overflowed a 2 GB `/tmp` during testing |
| **bare shallow clone** | **70 s, 167 MB transfer, 167 MB on disk** | **chosen** — one packfile, no checkout |
| blobless partial clone (`--filter=blob:none`) | 1.3 s, 4.7 MB | cheap to clone, but each record is a separate lazy round trip: 0.55 s × 6,053 ≈ 55 min. Batch prefetch by OID is not available to us. |
| per-CVE raw.githubusercontent fetches | — | 6,053 HTTPS requests per build against an unauthenticated endpoint |
| release asset | — | the repo publishes no releases |

Reads are cheap because we never enumerate the repo. We ask `cat-file` for the
19,103 paths we care about; a path that is not in the tree costs one `missing`
line and nothing else. No directory walk, no per-file process, no network.

Path layout is `YYYY/NNxxx/CVE-YYYY-NNNNN.json` — see `vulnrichment_path()`.
CISA's container is picked out by `orgId` (`CISA_ADP_ORG`), not by position or
title, because a record often carries several ADP containers (the CVE Program's
own, a supplier's such as Siemens').

### Cost, measured

| | cost |
|---|---|
| cold (no mirror cached) | **+70 s**, 167 MB transferred, 167 MB on disk |
| warm (mirror present, incremental `git fetch --depth 1`) | **+1.1 s** fetch (churn is ~100 commits/week, so the delta is small) |
| reading + parsing 6,053 records each build | **+4.9 s** (9.5-10.4 s → 14.1-15.6 s on an otherwise fully cached `--offline` build, two runs each) |

The 4.9 s is `json.loads` over ~60 MB, because the repo stores whole CVE records
and we want one container out of each. It is the dominant recurring cost, and it
is a ~50% increase on a warm build — noticeable, though small in absolute terms
next to the 115 s a full online build takes.

**Caveat for CI:** `.github/workflows/update.yml` caches only `kev.json`,
`epss.csv.gz` and the two advisory lists. `.cache/vulnrichment` is not in that
list, so every CI run would pay the full 70 s / 167 MB cold cost unless the
workflow is changed. (That file is owned by someone else; this is a report, not
a change.)

### Failure behaviour

Enrichment is optional and every failure degrades to "no Vulnrichment data"
rather than failing the build: clone or fetch failure keeps a stale mirror if
one exists, a `cat-file` failure returns nothing, `--offline` with no mirror
logs a warning and continues. All four paths were exercised; the build produces
a complete site in each.

## The fields

### `index.json`, per row

| field | meaning |
|---|---|
| `ssvc` | three characters, one per decision point, in the order `exploitation`, `automatable`, `technical_impact`. `n`/`p`/`a`, `y`/`n`, `p`/`t`. `?` means CISA published a container but not that decision point. Absent entirely = no CISA record for this CVE. |
| `cwe` | the first CWE id CISA assigned, e.g. `CWE-416`. |
| `vcvss`, `vsev` | a CVSS base score and severity band from CISA, **emitted only when the kernel CNA published no vector at all**. |

`meta.json` carries `ssvc_codes` so the codes are self-describing to anyone
consuming the raw data, plus `vulnrichment_count`,
`vulnrichment_exploitation`, `vulnrichment_cwe_count` and
`vulnrichment_cvss_count`.

`vcvss` is deliberately *not* merged into the existing `cvss` column. Where both
authorities scored the same CVE (728 cases), **470 disagree**, sometimes by a
lot — CVE-2025-39919 is 8.8 from the CNA and 5.5 from CISA. Blending them into
one number would misrepresent both.

### `details/<n>.json`, per CVE

A `vulnrichment` object with the full record: `exploitation`, `automatable`,
`technical_impact`, `scored` (the SSVC timestamp), `cvss_vector`, `cvss_score`,
`cwe` (all ids with their names), and `updated` (the ADP container's
`dateUpdated`).

### Size delta

| | before | after | delta |
|---|---|---|---|
| `index.json` | 5.183 MB | 5.337 MB | +151 KB (+2.98%) |
| `index.json`, gzipped | 826 KB | 839 KB | **+12.8 KB (+1.54%)** |
| `details/` tree | 28.92 MB | 29.92 MB | +1.00 MB (+3.46%) |

Over the wire — which is what the critical path actually costs — index.json
grows by 12.8 KB. Size is not the problem with this feature.

## Coverage, measured

**6,053 of 19,103 tracked CVEs (31.7%) have a CISA record at all.**

Exploitation across those 6,053: **none 5,953 · poc 65 · active 35.**
Automatable: yes 72, no 5,981. Technical Impact: partial 5,247, total 806.
1,835 records carry a CWE; 1,690 supply a CVSS the CNA never published.

Coverage by CVE year, which is where this falls apart:

| year | enriched / tracked | |
|---|---|---|
| 2021 | 728 / 953 | 76.4% |
| 2022 | 1,027 / 2,424 | 42.4% |
| 2023 | 909 / 1,921 | 47.3% |
| 2024 | 2,769 / 3,114 | 88.9% |
| 2025 | 462 / 2,672 | **17.3%** |
| 2026 | 92 / 6,304 | **1.5%** |

Pre-2021 years are all below 5%.

### KEV cross-check

Every one of the 35 tracked CVEs in CISA KEV has a Vulnrichment record, and all
35 are scored `Exploitation: active`. There are no counterexamples.

The check holds — and it tells us something unwelcome. There are exactly 35
CVEs scored `active`, and they are **exactly** the 35 KEV entries. `active` is
not an independent signal here; on this corpus it is a restatement of KEV
membership. The entire incremental signal over KEV is the **65 CVEs scored
`poc`**, which is 0.34% of the corpus.

### Coverage where it would matter

2,684 of the tracked CVEs are still open (`V` or `I`) in at least one suite.
That set is what the site's workflow is about. Of those:

- **301 (11.2%)** have a Vulnrichment record at all.
- Exploitation: 296 `none`, **5 `poc`**, **0 `active`**.
- Automatable `yes`: **1**.
- Technical Impact `total`: 47.
- 95 gain a CWE; 78 gain a CVSS (out of 1,547 open rows that have no CVSS at all).

The five open CVEs with a `poc` score, in full:

| CVE | status | ssvc |
|---|---|---|
| CVE-2020-36694 | VVVV- | poc / no / total |
| CVE-2023-0597 | VFFF- | poc / no / partial |
| CVE-2023-37454 | VVVV- | poc / no / partial |
| CVE-2023-6240 | VVVV- | poc / no / partial |
| CVE-2024-25740 | VVFF- | poc / no / total |

## Verification

Three records, checked by hand against
`raw.githubusercontent.com/cisagov/vulnrichment/develop/...` fetched fresh,
independently of the local mirror. All three matched exactly.

- **CVE-2023-37454** (`2023/37xxx/`) — built `ssvc: "pnp"`; upstream
  `[{"Exploitation":"poc"},{"Automatable":"no"},{"Technical Impact":"partial"}]`,
  timestamp 2024-11-20. No CVSS, no CWE upstream; none emitted.
- **CVE-2026-53362** (`2026/53xxx/`) — built `ssvc: "ant"`, `cwe: "CWE-122"`;
  upstream `active` / `no` / `total`, `CWE-122 Heap-based Buffer Overflow`,
  scored 2026-08-28. In KEV, and `active`, as the cross-check requires. No
  `vcvss` emitted because the CNA already published 7.8.
- **CVE-2024-57951** (`2024/57xxx/`) — built `ssvc: "nnt"`, `cwe: "CWE-416"`,
  `vcvss: 7.8`; upstream `none` / `no` / `total`,
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.8, `CWE-416 Use After
  Free`. The CNA published no vector for this one, which is why `vcvss` appears.

## Caveats

1. **The data is a point-in-time analyst judgement, not a live feed.** `scored`
   is when CISA looked. A `none` from 2024-09 means nobody had seen exploit code
   *then*. It is not a statement about today.
2. **Absence is not "none".** A CVE with no `ssvc` field was never analysed.
   Any UI must distinguish "CISA says none" from "CISA never looked", or it will
   read 68% of the corpus as safe.
3. **`active` is redundant with KEV** on this corpus (see above).
4. **CISA and the kernel CNA disagree on CVSS** in 470 of the 728 cases where
   both scored, hence the separate `vcvss` field.
5. **Coverage is collapsing for new CVEs** — 17.3% for 2025, 1.5% for 2026 —
   while the kernel CNA's output grows (6,304 CVEs in 2026 alone). CISA is still
   scoring (5 kernel CVEs in September 2026), but as a trickle, and mostly
   backfilling older records rather than keeping up.
6. **`develop` is the default branch**, not `main`.
7. The field is `Technical Impact` with a space upstream; it is normalised to
   `technical_impact`.

## Recommendation: DO NOT SHIP

The integration is finished and correct, and the cost is defensible: +12.8 KB
gzipped on the critical path, +4.9 s warm, +70 s and 167 MB cold. Cost is not
the reason.

The reason is that the premise does not survive contact with the data. The
argument for adding this was that `Exploitation` is a more granular signal than
KEV's 35-CVE binary. It is not, on this corpus:

- `active` selects **exactly** the same 35 CVEs as KEV. Zero new information.
- The whole incremental gain is 65 CVEs scored `poc` — and **60 of those 65 are
  already fixed in every Debian suite.**
- Filtering the 2,684 still-open CVEs — the ones a person on this site is trying
  to make a decision about — by Vulnrichment exploitation surfaces **five rows**,
  all `poc`, none `active`, the newest from 2024.
- On the freshest CVEs, where the "respond to a new CVE" workflow lives,
  coverage is 1.5% for 2026 and 17.3% for 2025, and falling.

A filter that matches 5 of 2,684 open rows is not a triage tool; it is a footgun
that invites people to read "no CISA exploitation signal" as "not exploited"
when the honest answer for 89% of open CVEs is "CISA never looked at this one."

The genuinely useful parts are the secondary ones — 1,690 CVSS scores for CVEs
the kernel CNA never rated, and 1,835 CWE classifications that `vulns.git` does
not carry at all. But those land on open rows only 78 and 95 times respectively,
against 1,547 open rows with no severity at all. That is a 5% dent in the gap it
would be sold as filling, for a 167 MB mirror.

If this is revisited, the case to make is the CWE/CVSS backfill, not
exploitation — and it should be re-measured first, because the trend line on
CISA's kernel coverage is pointing down.

## Where the code is

The integration was finished and measured, not abandoned half-built. It is
preserved on the `spike/vulnrichment` branch rather than on `master`, so that
if CISA's coverage of recent kernel CVEs improves, the work can be revisited by
re-reading the numbers above and rebasing that branch, instead of being redone
from scratch.

Re-run the measurement before trusting it again: the figures here are a snapshot
of 2026-09-22, and the whole argument against shipping rests on coverage numbers
that CISA can change at any time.
