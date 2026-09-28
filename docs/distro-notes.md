# Other distributions' writing as an enrichment source

Measured on 2026-09-28 against the 19,103 kernel CVEs this site tracks.

**Recommendation: ship Red Hat. Do not ship Ubuntu. Do not attempt Openwall.**
The three verdicts have different reasons, and the reasons are at the bottom.
Read them before wiring anything into the UI.

## The problem this is for

A person running Debian machines reads a kernel CVE on this site and gets the
CNA's record, which is a commit message:

> `smc: Fix use-after-free in tcp_write_timer_handler().`

That says what the patch changes. It does not say whether the flaw reaches their
machine, and it does not say what to do while bookworm still has no fixed
package. Other distributions' security teams write that second thing down, for
the same CVE ids, in the register a sysadmin needs. Red Hat, on CVE-2024-1086:

> This flaw can be mitigated by preventing the affected netfilter (nf_tables)
> kernel module from being loaded. [...] on non-containerized deployments of Red
> Hat Enterprise Linux, the mitigation is to disable user namespaces:
> `echo "user.max_user_namespaces=0" > /etc/sysctl.d/userns.conf`

Fetching that writing and putting it next to the CVE is the whole feature.

## What this is and is not

`scripts/distro_notes.py` retrieves prose by CVE id and stores it **verbatim**,
with the name of the team that wrote it, a URL a reader can open, and the date
the source publishes. It is a lookup and a byte-for-byte transcription.

Nothing in the output is summarised, paraphrased, condensed, rewritten or
scored. There are exactly two derived flags, both exact string comparisons
against fixed lists in the script, both documented below: `template` and
`cna_boilerplate`. Neither changes the stored text.

## The sources, and what they actually publish

### Red Hat Product Security

Per-CVE record at
`https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json`, about 14 KB.
Four fields matter:

| field | what it is | example (CVE-2024-1086) |
|---|---|---|
| `statement` | Red Hat's impact assessment, in sentences | "There is the limitation that it can only be exploited by a local user with access to Netfilter, but can still allow privilege escalation if user namespaces are enabled" |
| `mitigation` | what to do before a fixed package exists | the sysctl above |
| `details` | a list. For a 2024-or-later kernel CVE, entry 0 is the CNA's commit message and the last entry is **Red Hat's own rewrite** | "A flaw was found in the Netfilter subsystem in the Linux kernel. [...] The nf_tables component can be exploited to achieve local privilege escalation." |
| `threat_severity` | Critical / Important / Moderate / Low | Important |

The `details` rewrite turned out to be the most widely available prose of the
four, by a wide margin, and it is the field that most often contains the
"a local user could" sentence. It is not the field the brief for this work
expected to matter.

`mitigation` arrives as `{"value": ..., "lang": ...}`, not a string.

### Ubuntu Security Team

The same data that backs `ubuntu.com/security/cves/<CVE>.json`, taken from the
`ubuntu-cve-tracker` repository. Five fields matter:

| field | what it is |
|---|---|
| `Ubuntu-Description` | Ubuntu's own plain-language impact statement, written for a reader, e.g. "A local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code." |
| `Mitigation` | concrete steps, e.g. `sudo sysctl -w kernel.unprivileged_userns_clone=0` |
| `Notes` | free text from a named triager, `author> line` per line |
| `Priority` | the priority, then the reason for it in prose |
| `Description` | usually the CNA's text |

The brief for this work named only `notes`. `Ubuntu-Description` and
`Mitigation` are better, and both are measured separately below.

## Licensing and attribution, checked

This matters more than the coverage numbers, because it is the difference
between a feature and a copyright problem. The two sources are not in the same
position.

### Red Hat: clear permission, CC BY 4.0

`https://access.redhat.com/security/data` states it without ambiguity:

> The data resources linked on this page as well as their alternative
> representations available through the Security Data API are licensed under the
> Creative Commons Attribution 4.0 International License. If you distribute this
> content or a modified version of it, you must provide attribution to Red Hat
> and provide a link to the original.

Both obligations are discharged by data the output file already carries on every
record: `source` is `"Red Hat Product Security"` and `url` is the Red Hat page
for that CVE. The UI must render both next to the quoted text. CC BY 4.0 also
requires that the licence be identified, so the page carrying this prose needs a
visible statement along the lines of "Red Hat's text, CC BY 4.0", linking to the
licence. That is a UI obligation, not a fetcher obligation, and it is the one
thing the coordinator must not drop on integration.

### Ubuntu: no grant anyone can point to

There is no licence file in the `ubuntu-cve-tracker` tree. What exists instead
is three statements that do not agree:

1. The Launchpad project registration for `ubuntu-cve-tracker` says
   **Licence: GNU GPL v2**.
2. The tree's own `.launchpad.yaml` says `license: spdx: GPL-3.0`.
3. Canonical's website terms at `https://ubuntu.com/legal/terms`, which govern
   the `ubuntu.com/security` pages a reader would be sent to, say:

   > You are welcome to display on your computer, download and print pages from
   > this website for **personal, education and non-commercial use only**. You
   > must retain copyright, trademark and other notices unaltered on any copies
   > or printouts you make.

So: two contradictory GPL versions, neither of which is a content licence and
both of which would drag notice-and-source obligations onto prose excerpts in a
web page, plus a site-terms grant that explicitly stops short of republication.

Republishing Ubuntu's prose is therefore **not covered by any grant this
investigation could find**. Linking to `ubuntu.com/security/<CVE>` is
unaffected; linking always is. The output file records this as
`sources.ubuntu.republish = "unclear"` so that `scripts/build.py` can gate on a
field rather than on somebody remembering this document.

This is a licensing conclusion from published terms, not legal advice. If
Canonical clarifies, or someone asks the Ubuntu Security Team and gets a written
answer, the fetcher already works and the gate is one field.

## Fetch strategy, and why this shape

### The population: 2,719 of 19,103

Default `--population open+kev`: every CVE with status `V` (vulnerable) or `I`
(no-dsa) in at least one Debian column, plus every CVE in CISA KEV.
**2,719 CVEs, 14.2% of the corpus.**

The reasoning is the user's own: this prose is read by somebody who has no fixed
package yet and needs to know whether to care and what to do in the meantime. A
CVE that is `F` in every suite does not need a workaround, it needs
`apt upgrade`. KEV entries are included regardless of fix state because those
get read no matter what the status column says.

`--population all` works and costs about seven times as much; the coverage
tables below are by year, so the shape of what `all` would add is visible
without paying for it.

### Red Hat: learn membership in bulk, then spend per-CVE requests

Fetching 19,100 CVEs one at a time against two services is the wrong shape, and
so is fetching 2,719 of them blind. Red Hat publishes a bulk listing filtered by
package:

`https://access.redhat.com/hydra/rest/securitydata/cve.json?package=kernel&per_page=1000&page=N`

**20 requests, 10 MB, 17 seconds** return all **19,045** kernel CVEs Red Hat
tracks, with severity, public date and the one-line bugzilla summary, but not
`statement` or `mitigation`. Intersecting that with the population leaves
**1,769 candidates**, so 950 per-CVE requests are never made. On the 2026 slice
it is the difference between 2,029 requests and 1,099.

The prefilter is not free. Spot-checked on 20 population CVEs absent from the
listing, **1 of 20 did have a per-CVE record** (the listing lags for very fresh
CVEs), and that one carried neither a statement nor a mitigation, so no prose
was lost in the sample. `--no-prefilter` exists to re-measure that gap.

Rejected:

| approach | cost | why not |
|---|---|---|
| per-CVE for all 19,103 tracked | 19,103 requests | most would 404 |
| per-CVE for the population, no prefilter | 2,719 requests, 950 of them 404 | 54% more requests for a measured 5% recall gain that carried no prose |
| CSAF VEX bulk archive | 341 MB zstd for every CVE Red Hat has ever tracked; a single per-CVE VEX file is 2.2 MB | carries the same statement and mitigation at roughly 150 times the bytes |
| **bulk listing, then per-CVE (chosen)** | **20 + 1,769 requests, 17.9 MB** | |

### Ubuntu: a bare shallow mirror, because the HTTP shapes are all wrong

Ubuntu's per-CVE JSON is **961 KB**, because it inlines every USN and every
package status across every release and flavour; `notices` and `packages` alone
are 724 KB and 285 KB of that. We keep about 2 KB of it.

| approach | cold cost | why not |
|---|---|---|
| `ubuntu.com/security/cves/<CVE>.json` per CVE | ~2.6 GB for 2,719 CVEs | 961 KB each; one of my first three requests returned 504 after 50 s |
| `ubuntu.com/security/cves.json?package=linux` paged | ~2.9 GB for 21,233 rows | same objects, no field selection |
| `git.launchpad.net/.../plain/active/<CVE>` per file | 337 MB, ~3 s each, about 2.3 hours | and you must know whether the CVE is in `active/`, `retired/` or `ignored/` before you ask |
| cgit snapshot tarball | unavailable, HTTP 400 | not enabled on git.launchpad.net |
| **bare shallow single-branch clone (chosen)** | **334 s, 196 MB on disk, 80,851 records**, then ~11 s incremental | every read after that is local and free |

Bare and shallow for the reason `docs/vulnrichment.md` already establishes: one
packfile, and no checkout of 80,000 files to read 2,719 of them. Reads go
through one `git cat-file --batch` per 400 records, batched because these files
average 120 KB and asking for all 19,103 at once would buffer over 2 GB before
parsing the first one.

Launchpad is the weak point. It served the clone at roughly 600 KB/s, and during
this session's testing an incremental fetch came back **HTTP 503** once, which
is throttling from repeated clones. The failure path handled it correctly and is
described below.

## Coverage, measured

Over the chosen population of **2,719 CVEs**, on 2026-09-28.
Reproduce with `scripts/distro_notes.py --offline --report`.

"At least one piece of prose" means somebody wrote a sentence for a person to
read: a Red Hat statement, mitigation or description, or an Ubuntu impact
statement, mitigation, note or priority reason. It deliberately **excludes** Red
Hat's one-line bugzilla summary, which is a subsystem and a function name
("kernel: nf_tables: use-after-free vulnerability in the nft_verdict_init()
function"), the same register as the CNA title this site already shows. That
tier is counted separately so the judgement is visible rather than buried.

| | overall | unfixed in a Debian release | in CISA KEV |
|---|---|---|---|
| CVEs in scope | 2,719 | 2,684 | 35 |
| **at least one piece of prose** | **1,506 (55.4%)** | **1,471 (54.8%)** | **35 (100%)** |
| a concrete mitigation from either | 220 (8.1%) | 197 (7.3%) | 23 (65.7%) |
| Red Hat tracks it | 1,769 (65.1%) | 1,736 (64.7%) | 33 (94.3%) |
| Red Hat's own description | 1,343 (49.4%) | 1,311 (48.8%) | 32 (91.4%) |
| Red Hat impact statement | 290 (10.7%) | 269 (10.0%) | 21 (60.0%) |
| Red Hat mitigation | 215 (7.9%) | 192 (7.2%) | 23 (65.7%) |
| of which boilerplate non-mitigations | 31 | 26 | 5 |
| Red Hat one-line summary | 1,768 (65.0%) | 1,735 (64.6%) | 33 (94.3%) |
| Ubuntu prose of any kind | 430 (15.8%) | 396 (14.8%) | 34 (97.1%) |
| Ubuntu impact statement | 40 (1.5%) | 19 (0.7%) | 21 (60.0%) |
| Ubuntu mitigation | 12 (0.4%) | 8 (0.3%) | 4 (11.4%) |
| Ubuntu notes | 117 (4.3%) | 98 (3.7%) | 19 (54.3%) |
| Ubuntu priority reason | 304 (11.2%) | 289 (10.8%) | 15 (42.9%) |
| Ubuntu's own description | 112 (4.1%) | 88 (3.3%) | 24 (68.6%) |

The unfixed-in-Debian column is the one that matters, because those are the rows
the user is stuck on. All 35 KEV entries are currently fixed in every Debian
suite, which is why the KEV column and the unfixed column barely overlap.

### By CVE year

The age skew was expected to be the whole story. It is not, and that is the
single most useful finding here. `pop` is the population in that year; the rest
are counts, not percentages.

| year | pop | any prose | any miti | rh tracks | rh desc | rh stmt | rh miti | ub impact | ub miti | ub note | ub prio |
|---|---|---|---|---|---|---|---|---|---|---|---|
| pre-2019 (14 years) | 32 | 31 | 5 | 18 | 18 | 12 | 3 | 7 | 2 | 27 | 0 |
| 2019 | 23 | 23 | 6 | 23 | 23 | 7 | 5 | 12 | 1 | 16 | 2 |
| 2020 | 5 | 5 | 3 | 4 | 4 | 2 | 3 | 0 | 1 | 3 | 0 |
| 2021 | 9 | 9 | 6 | 8 | 8 | 4 | 5 | 4 | 2 | 6 | 1 |
| 2022 | 17 | 17 | 7 | 17 | 17 | 10 | 7 | 6 | 1 | 16 | 1 |
| 2023 | 68 | 43 | 8 | 65 | 34 | 26 | 8 | 7 | 0 | 14 | 9 |
| 2024 | 247 | 132 | 77 | 246 | 95 | 45 | 76 | 2 | 4 | 24 | 35 |
| 2025 | 289 | 160 | 31 | 289 | 71 | 70 | 31 | 0 | 0 | 7 | 67 |
| **2026** | **2,029** | **1,086** | **77** | **1,099** | **1,073** | **114** | **77** | **2** | **1** | **4** | **189** |

**2026 is 2,029 of the 2,684 unfixed CVEs, and 53.5% of them get prose.** That
is the opposite of what `docs/vulnrichment.md` found about CISA, where 2026
coverage was 1.5% and falling. Red Hat is keeping up with the kernel CNA's
output: it tracks 1,099 of the 2,029 open 2026 CVEs and has written its own
description for 1,073 of them.

What does not scale is mitigations. A mitigation is a human sitting down and
working out a workaround, and nobody does that 6,000 times a year. 77 of the
2,029 open 2026 CVEs have one, and the rate is 65.7% on KEV entries and 7.3%
across the unfixed set. That ratio is the real shape of this feature: **broad
coverage of "what is this and does it reach me", narrow coverage of "what do I do
about it".**

Ubuntu collapses on recent CVEs in a way Red Hat does not: 2 impact statements
and 4 notes across 2,029 open 2026 CVEs. Ubuntu's records exist (its tracker
opens a file for everything MITRE publishes) but 2,288 of the 2,719 carry nothing
but the CNA's copied description, which is why `silent.ubuntu` is 2,288.

### A note on `silent` per source

`silent.redhat` is **0** and will normally stay 0, because every record Red Hat
tracks carries at least the bugzilla one-liner. Do not read an empty
`silent.redhat` as "Red Hat always writes prose". The meaningful Red Hat
distinction is between a record with only a `summary` field and one with a
`statement`, `mitigation` or `details`, and that has to be read off the `fields`
list. `silent.ubuntu` is 2,288 and is meaningful.

## The output contract

One file, `.cache/distro-notes.json` by default, `--out` to move it. The script
refuses to write anywhere under `site/data/`. `.cache/` is already gitignored,
which is correct: this is a build input, rebuilt from the sources, not an
artefact to commit.

```
{
  "schema": "distro-notes/1",
  "generated": "2026-09-28T17:35:02Z",      ISO 8601 UTC, when this file was written
  "population": {"selector": "open+kev", "size": 2719},
  "sources": { "<source key>": { ... see below ... } },
  "coverage": { ... see "Coverage measured" ... },
  "cna_boilerplate_fields_dropped": 4296,
  "examined": ["CVE-2026-93204", ...],      every CVE looked up, in site order
  "absent":  {"redhat": [...], "ubuntu": [...]},
  "silent":  {"redhat": [...], "ubuntu": [...]},
  "notes":   {"<CVE id>": {"redhat": <record>, "ubuntu": <record>}, ...}
}
```

`schema` is the thing to check before parsing. Bump it on any breaking change.

### The three-way absence distinction, which is not optional

`docs/vulnrichment.md` records the exact mistake this avoids: a UI that renders
"no data" as "nothing to worry about" lies to the reader about most of the
corpus. So for **each source**, every CVE in `examined` appears in exactly one
of three places, and the script asserts this invariant on every run and logs a
warning if it is ever violated:

| where | what it means | what the UI must say |
|---|---|---|
| `notes[cve][source]` | this team wrote something | render it, attributed |
| `silent[source]` | this team has a record for the CVE and wrote no prose | "Red Hat tracks this CVE but has not written an impact statement" |
| `absent[source]` | this team has no record for the CVE at all | "Red Hat has not assessed this CVE" |

A CVE that is not in `examined` was never looked up, which is a fourth state and
must not be rendered as any of the three.

One trap in reading these lists: **`silent.redhat` is 0 and will normally stay
0**, because every record Red Hat tracks carries at least the bugzilla one-line
summary, so it always has one field and is never "silent". Do not conclude from
an empty `silent.redhat` that Red Hat always writes prose. For Red Hat the
meaningful line is between a record whose only field is `summary` and one that
also has a `statement`, `mitigation` or `details`, and that has to be read off
the `fields` list. `silent.ubuntu`, at 2,288, is meaningful as it stands.

### A source record

```
{
  "source":   "Red Hat Product Security",     the attribution string to display
  "url":      "https://access.redhat.com/security/cve/CVE-2024-1086",
  "severity": "Important",                    optional, the source's own band
  "date":     "2024-01-31",                   optional, YYYY-MM-DD
  "bug_url":  "https://bugzilla.redhat.com/...",   optional, Red Hat only
  "credit":   "Notselwyn",                    optional, Ubuntu only
  "fields":   [ ... ordered, see below ... ]
}
```

`source` and `url` together are the attribution CC BY 4.0 requires. Both are
always present. `fields` is never empty; a source with nothing to say is in
`silent` instead.

`url` is a page for a human, not the API endpoint: Red Hat's is
`https://access.redhat.com/security/cve/<CVE>` and Ubuntu's is
`https://ubuntu.com/security/<CVE>`. The Ubuntu one carries the CVE id in upper
case, which is the form that site serves; it is not a bug to fix.

### A field

```
{
  "key":   "mitigation",
  "label": "Red Hat's mitigation",     a ready-to-render heading
  "text":  "1. This flaw can be ...",  VERBATIM, newlines preserved, never reflowed
  "template": true,                    optional, see below
  "cna_boilerplate": true,             optional, see below
  "author": "rodrigo-zaiden",          optional, Ubuntu notes only
  "index": 1                           optional, position in Red Hat's own details list
}
```

`fields` is a **list, in reading order**: impact before mitigation before
description. Render it in the order given. It is a list rather than an object
because a source can publish several notes and several `details` entries.

Field keys, per source:

| source | key | from |
|---|---|---|
| redhat | `summary` | the bugzilla one-liner. A subsystem and a function name, the same register as the CNA title this site already shows. Counted separately and deliberately excluded from "has prose". |
| redhat | `statement` | `statement` |
| redhat | `mitigation` | `mitigation.value` |
| redhat | `details` | one field per entry in `details`, `index` preserved |
| ubuntu | `impact` | `Ubuntu-Description` |
| ubuntu | `mitigation` | `Mitigation` |
| ubuntu | `priority_reason` | the prose after the priority word in `Priority` |
| ubuntu | `note` | one field per author run in `Notes`, with `author` |
| ubuntu | `details` | `Description` |

### The two derived flags

Both are exact string comparisons, not judgements.

**`template`** means the text matched a known published boilerplate opener,
after collapsing whitespace and lowercasing. The list is `TEMPLATE_PREFIXES` in
the script; the important one is Red Hat's

> "Mitigation for this issue is either not available or the currently available
> options don't meet the Red Hat Product Security criteria..."

which occupies the `mitigation` field while saying there is no mitigation. The
text is still stored verbatim. The flag exists so that "has a mitigation" can be
counted honestly, and so the UI does not promise a workaround and then show
that. **31 of the 246 Red Hat mitigation fields in the population are
templates.** Treat a `template` field as absent when deciding whether to show a
"mitigation available" affordance.

**`cna_boilerplate`** means the text begins with
`In the Linux kernel, the following vulnerability has been resolved:`, which is
the kernel CNA's own description that both distributions copy into a field of
their own. `scripts/build.py` already has that text from `vulns.git`, so these
fields are **dropped by default** and counted in
`cna_boilerplate_fields_dropped`. Measured, they were 5.06 MB of the 5.99 MB of
prose in the file, and dropping them took the output from 8.21 MB to 2.15 MB,
a 74% cut.
`--keep-cna-boilerplate` keeps them, flagged rather than dropped, if the
coordinator would rather diff the two copies.

Because dropping happens per entry, Red Hat `details` indices are the positions
in Red Hat's published list, not in the emitted array. A record whose only
`details` field has `index: 1` is one where entry 0 was the CNA's text.

### Source metadata

```
"redhat": {
  "name": "Red Hat Product Security",
  "listing_url": "...", "record_url": "...",
  "kernel_cves_listed": 19045,
  "in_scope_and_listed": 1769,
  "errors": 0,
  "not_looked_up": 0,
  "complete": true,
  "licence": "CC BY 4.0",
  "licence_url": "https://access.redhat.com/security/data",
  "republish": "permitted-with-attribution",
  "attribution": "Red Hat Product Security"
}
```

**`complete` is the second field to gate on.** It is `true` only when this run
actually established, for every CVE in `examined`, whether that source has
something. It is `false` when the Red Hat listing could not be fetched, when the
mirror is missing, when per-CVE fetches errored, or when `--offline` was given
with an incomplete cache. **When `complete` is `false`, `absent` for that source
proves nothing** and the UI must fall back to "not checked" rather than to
"nothing found". `not_looked_up` counts the CVEs in that third state.

**`republish` is the field to gate on.** It is
`"permitted-with-attribution"` for Red Hat and `"unclear"` for Ubuntu. A build
that renders prose from a source whose `republish` is not
`"permitted-with-attribution"` is doing something this document says not to do.
`errors` is how many per-CVE fetches failed after retries; it should be 0 and a
non-zero value means the run is incomplete, not that the sources are empty.

## Three worked examples, end to end

Retrieved by `scripts/distro_notes.py`, quoted from
`.cache/distro-notes.json` exactly as stored.

### 1. A KEV CVE: CVE-2024-1086

Debian status `FFFF-`, fixed in every suite. In CISA KEV. No CVSS from the
kernel CNA, which is itself part of the problem; the 7.8 this CVE is usually
quoted at comes from Red Hat and Ubuntu, not from the CNA. The CNA summary this
site shows is `A use-after-free vulnerability in the Linux kernel's netfilter:
nf_tables component can be exploited to achieve local privilege escalation`.

Red Hat, severity Important, dated 2024-01-31,
`https://access.redhat.com/security/cve/CVE-2024-1086`:

> **Red Hat's impact statement.** This flaw is rated as having an Important
> impact. There is the limitation that it can only be exploited by a local user
> with access to Netfilter, but can still allow privilege escalation if user
> namespaces are enabled and Netfilter is being used.
>
> **Red Hat's mitigation.** 1. This flaw can be mitigated by preventing the
> affected netfilter (nf_tables) kernel module from being loaded. For
> instructions on how to blacklist a kernel module, please see
> https://access.redhat.com/solutions/41278.
> 2. If the module cannot be disabled, on non-containerized deployments of Red
> Hat Enterprise Linux, the mitigation is to disable user namespaces:
> ```
> # echo "user.max_user_namespaces=0" > /etc/sysctl.d/userns.conf
> # sysctl -p /etc/sysctl.d/userns.conf
> ```
> On containerized deployments, such as Red Hat OpenShift Container Platform, do
> not use the second mitigation (disabling user namespaces) as the functionality
> is needed to be enabled. The first mitigation (blacklisting nf_tables) is still
> viable for containerized deployments, providing the environment is not using
> netfilter.
>
> **Red Hat's description.** A flaw was found in the Netfilter subsystem in the
> Linux kernel. This issue occurs in the nft_verdict_init() function, allowing
> positive values as a drop error within the hook verdict, therefore, the
> nf_hook_slow() function can cause a double-free vulnerability when NF_DROP is
> issued with a drop error that resembles NF_ACCEPT. The nf_tables component can
> be exploited to achieve local privilege escalation.

Ubuntu, priority high, dated 2024-01-31, credit Notselwyn,
`https://ubuntu.com/security/CVE-2024-1086`:

> **Ubuntu's impact statement.** Notselwyn discovered that the netfilter
> subsystem in the Linux kernel did not properly handle verdict parameters in
> certain cases, leading to a use-after-free vulnerability. A local attacker
> could use this to cause a denial of service (system crash) or possibly execute
> arbitrary code.
>
> **Ubuntu's mitigation.** If not needed, disable the ability for unprivileged
> users to create namespaces. To do this temporarily, do:
> `sudo sysctl -w kernel.unprivileged_userns_clone=0`
>
> **Ubuntu's reason for this priority.** By passing a positive value such as
> NF_ACCEPT, a local attacker can elevate privileges due to a use-after-free
> error.
>
> **Note from the Ubuntu security team**, by `rodrigo-zaiden`. from Google kCTF.
> the fix commit reverts the break commit.

Note the caveat about applicability in action: `kernel.unprivileged_userns_clone`
is an Ubuntu kernel patch and **does not exist on a Debian kernel**. Red Hat's
`user.max_user_namespaces` does. A reader who pastes the first one gets
`sysctl: cannot stat /proc/sys/kernel/unprivileged_userns_clone: No such file or
directory`, and if they miss that, a false sense of having mitigated something.

### 2. An older unfixed CVE: CVE-2022-45885

Debian status `VVVV-`: **vulnerable in bookworm, trixie, forky and sid.** No
CVSS from the CNA, not in KEV. The CNA record is
`An issue was discovered in the Linux kernel through 6.0.9`, which tells a
sysadmin nothing at all. This is precisely the row the user is complaining about.

Red Hat, severity Moderate, dated 2022-11-15:

> **Red Hat's impact statement.** Because exploitation of this flaw requires
> that an attacker has either: local privileges on and physical access to the
> system, or administrative privileges sufficient to virtually attach or detach
> harware devices, Red Hat assesses that the impact of this vulnerability as
> Moderate.
>
> **Red Hat's mitigation.** To mitigate this issue, it is possible to prevent
> the affected code from being loaded by blacklisting the `dvb-core` kernel
> module. For instructions on how to blacklist a kernel module, please see
> https://access.redhat.com/solutions/41278.
>
> **Red Hat's description.** A race condition flaw leading to a use-after-free
> issue was found in the Linux kernel media subsystem in the DVB core device
> driver. It could occur in the dvb_frontend() function when closing the device
> node of dvb_frontend if the device is disconnected. A local user could use
> this flaw to crash the system or potentially escalate their privileges on the
> system.

Ubuntu, priority low, dated 2022-11-25:

> **Note from the Ubuntu security team**, by `sbeattie`. unfixed upstream as of
> 2023.09.01
> exploiting this vulnerability requires disconnecting a DVB
> device, which is why this has been prioritized as low.
> SUSE bug report claims 4172385b0c9a ("media: dvb-core: Fix
> use-after-free due on race condition at dvb_net") is applied for
> this and reverted, but actually 6769a0b7ee0c ("media: dvb-core:
> Fix use-after-free on race condition at dvb_frontend") is meant
> and was reverted in ec21a38df77a.

A reader goes from "an issue was discovered in the Linux kernel through 6.0.9"
to knowing it needs a DVB tuner card and physical access, that it is still
unfixed upstream, that the affected module is `dvb-core`, and that if they have
no DVB hardware they can blacklist it and stop caring. That is the feature
working.

### 3. A recent CVE, where nothing is expected: CVE-2026-93204

Debian status `VVVF-`, vulnerable in bookworm, trixie and forky. Published
2026-09-17. CNA title `batman-adv: dat: atomically update mac addresses`.

```
CVE-2026-93204
  redhat: absent  (Red Hat's kernel listing does not name this CVE)
  ubuntu: silent  (a record exists, and nobody has written prose in it)
```

There is no `notes["CVE-2026-93204"]` key at all. The CVE is in `examined`, in
`absent.redhat`, and in `silent.ubuntu`. Those are three different facts and the
UI has to render them as three different sentences:

- Red Hat: "Red Hat has not assessed this CVE." Not "Red Hat says it is fine."
- Ubuntu: "The Ubuntu security team is tracking this CVE and has not written an
  assessment." Not "Ubuntu has nothing on this."

This is the common case for a fresh CVE, and it is 943 of the 2,029 open 2026
CVEs. A design that only looks good when there is prose will look dishonest on
nearly half the rows a reader actually visits.

## Cost, measured

Population `open+kev`, 2,719 CVEs, on this machine on 2026-09-28.

| | wall | requests | transferred |
|---|---|---|---|
| Ubuntu mirror, first clone | **334 s** | git | **196 MB** |
| everything else, cold (empty Red Hat cache) | **497 s** | 1,790 | 17.9 MB |
| warm (all caches present, listing and mirror refreshed) | **62 s** | 21 | 10.8 MB |
| `--offline` (no network at all) | **39 s** | 0 | 0 |

A first run on a clean machine is therefore about **14 minutes**, and a daily run
after that is about **1 minute**. The 62 s warm figure is dominated by two things
that are not per-CVE work: re-paging the Red Hat listing (20 requests, 10.8 MB,
17 s) and reading plus parsing 2,719 Ubuntu records out of the mirror. The 39 s
offline figure is that parsing alone.

Cold wall time is set by the rate limiter, not by the servers: 1,769 per-CVE
requests at `--rate 4` is 442 s of deliberate sleeping. `--rate` can raise it;
it is set low on purpose, because these are other people's free services.

On disk:

| | size |
|---|---|
| `.cache/ubuntu-cve-tracker.git` | 197 MB |
| `.cache/redhat/` (1,769 trimmed records) | 7.4 MB |
| `.cache/redhat-listing.json` | 3.0 MB |
| **total cache** | **207 MB** |
| **`.cache/distro-notes.json`** | **2.15 MB** (0.33 MB gzipped) |

The output is 2.15 MB because CNA-boilerplate copies are dropped; 4,296 such
fields were dropped on this run, and keeping them takes the file to 8.21 MB. What
this adds to the published site depends entirely on how `build.py` folds it in,
which is the coordinator's call, not a measurement I can make from here. For
scale: `docs/vulnrichment.md` records `index.json` at 5.18 MB and the `details/`
tree at 28.9 MB, so 2.15 MB of prose is a modest addition to `details/` and far
too much for `index.json`.

## Failure behaviour

Every failure degrades to "less prose", never to a failed run. The right-hand
column says whether I actually made it happen, because a documented failure path
that has never fired is a guess.

| failure | behaviour | exercised |
|---|---|---|
| launchpad fetch returns 503 | warning, existing mirror kept and used, run completes | **yes, three times, unprompted** |
| per-CVE 404 | cached as `{"absent": true}`, never asked again, CVE lands in `absent.redhat` | yes, 950 times per run |
| `--offline` with a completely empty cache | both sources skipped, `complete: false` for each, **nothing claimed absent**, exit 0, valid output with 0 notes | yes |
| one source unavailable, the other fine | dead source `complete: false` and empty `absent`, live source `complete: true` and fully populated | yes |
| interrupted mid-run | per-CVE cache files are the resume unit. Deleting 5 of 1,769 cached records and re-running made **exactly 5 requests** | yes |
| Red Hat bulk listing fails with the network up | same code path as the cached-listing-missing case above: warning, Red Hat skipped, `complete: false`, Ubuntu still runs | by equivalence, not directly |
| one per-CVE fetch fails after 3 retries | warning for the first five, counted in `sources.redhat.errors`, run continues, `complete` goes false | no |
| 429 / 5xx on a per-CVE fetch | up to 3 attempts, 2 s / 4 s / 6 s backoff | no |
| clone fails on a first run | warning, Ubuntu skipped, Red Hat still runs | no |

The two that matter most are the two the fix in this script exists for: with no
listing and with no mirror, **`absent` stays empty and `complete` is `false`**.
An earlier version of this script filled `absent` with the whole population in
that case, which would have told a reader that Red Hat had nothing to say about
2,719 CVEs it had never been asked about. That is the exact failure
`docs/vulnrichment.md` warns about, and it is why `complete` exists.

Writes are atomic: every output and cache file is written to a `.tmp` name and
renamed. An interrupted run cannot leave a half-written `distro-notes.json` for
`build.py` to read.

## Refresh strategy

| thing | when | cost |
|---|---|---|
| Red Hat bulk listing | every run | 20 requests, 10 MB, 17 s |
| Red Hat per-CVE record | once, then cached | 0 |
| Red Hat records older than `--recheck-days` | on request | proportional |
| Ubuntu mirror | every run, `git fetch --depth 1` | ~11 s |
| new CVEs entering the population | automatically, the day Debian marks them open | one request each |

The per-CVE cache is permanent by default, and **Red Hat edits these fields
after publication**: a mitigation often appears weeks after the CVE does, which
is exactly the case where a cached "no mitigation" would be wrong and stay
wrong. `--recheck-days N` refetches any cached record whose cache file is older
than N days. For a daily CI build, `--recheck-days 30` re-checks roughly a
thirtieth of the cache per run at a cost of a few dozen extra requests, which is
the setting to use. Deleting `.cache/redhat/` forces a full refetch.

**For CI:** `.github/workflows/update.yml` caches `kev.json`, `epss.csv.gz` and
the two advisory lists. It does not cache `.cache/redhat/` or
`.cache/ubuntu-cve-tracker.git`. Without adding both, every CI run pays the full
cold cost, which for the Ubuntu mirror means a 196 MB clone from launchpad, from
a host that has already been observed throttling. That workflow file is owned by
someone else; this is a note, not a change. If only one can be cached, cache the
mirror.

## Caveats

1. **Another distribution's mitigation may not apply to Debian verbatim.** This
   is the most important caveat and it belongs in the UI, not only here. Red
   Hat's advice is written for RHEL, whose kernel config, default sysctls,
   SELinux policy and backport set are not Debian's. Ubuntu's
   `kernel.unprivileged_userns_clone` sysctl **does not exist on a mainline
   Debian kernel at all**; it is an Ubuntu patch. Debian's equivalent lever for
   the same CVE is `user.max_user_namespaces`, which is what Red Hat names. A
   reader who pastes a mitigation without reading it can get a command that
   silently does nothing. Whatever renders this must say whose system the advice
   was written for, next to the advice.
2. **"Not affected" is about their kernel, not ours.** Red Hat's
   `package_state` and Ubuntu's per-release status describe their trees. This
   script does not emit them, deliberately: Debian's status columns are already
   on the page and a second, differently-scoped set of statuses would be read as
   contradicting them.
3. **The prose is a point-in-time assessment.** `date` is the publication date,
   not a last-reviewed date, and neither source exposes one. A statement written
   in 2024 describes what was known in 2024.
4. **`template` fields are not mitigations.** See above. 31 of 246.
5. **The Red Hat prefilter has a measured 5% false-negative rate** on CVEs the
   kernel listing omits. Re-measure with `--no-prefilter` before trusting it on
   a different population.
6. **Ubuntu has a record for essentially every CVE** (2,718 of 2,719), because
   `ubuntu-cve-tracker` opens a file for everything MITRE publishes. "Ubuntu
   tracks it" is therefore not a signal and must not be shown as one. The prose
   counts are the only Ubuntu numbers that mean anything.
7. **Launchpad throttles.** Observed 503 on an incremental fetch after repeated
   clones in one session.
8. **Both sources copy the CNA's description.** Dropped by default; see
   `cna_boilerplate`.

## Openwall / oss-security: investigated, cannot be done

The user named Openwall specifically, so this was measured rather than waved
away. The answer is no, on three independent grounds.

**There is no index, no search and no bulk export.** The archive at
`https://www.openwall.com/lists/oss-security/` is the `blists` web interface:
year pages linking month pages linking day pages linking one HTML page per
message. There is no CVE index, no search endpoint (`/cgi/search` and
`/search` both 404, and `robots.txt` disallows `/cgi/` anyway), no mbox download,
and oss-security is not on a public-inbox instance (`lore.kernel.org/oss-security`
404s). Building a CVE index means crawling the whole archive and regexing the
text.

**The crawl is disproportionate.** The archive runs 2008 to 2026, about 6,850
days. Measured: January 2024 carried 80 messages across 31 day pages; day pages
are about 5 KB and message pages about 7.5 KB. A full index is therefore roughly
**6,850 day-page requests plus about 20,000 message requests, about 185 MB**, to
a volunteer-run server, and the recent tail has to be re-crawled on every
refresh.

**The yield, measured, is nearly zero.** I crawled January and February 2024 in
full: 60 day pages, 156 messages, 216 requests.

| measured over 2024-01 and 2024-02 | |
|---|---|
| messages mentioning at least one CVE id | 133 |
| distinct CVE ids mentioned | 161 |
| of those, among the 19,103 kernel CVEs this site tracks | **4** |
| of those, in the 2,719-CVE population the user is stuck on | **0** |

The four were CVE-2021-33630, CVE-2021-33631, CVE-2023-46838 and CVE-2023-6040.
Twelve messages touched them, and nine of those twelve were replies in a single
thread. Everything else on the list in those two months was Exim, Apache,
OpenSSL, X.Org, GRUB: oss-security is a cross-project discussion list, not a
kernel advisory database. Extrapolated, the whole archive holds a few hundred
mentions of tracked kernel CVEs, most predating the kernel CNA and long fixed
everywhere.

**And it would fail this project's own rule anyway.** A regex match is not an
authoritative statement that a post is *about* that CVE; a message saying "unlike
CVE-2024-1086, this one needs no namespaces" matches identically. That is a
heuristic mapping, not a deterministic lookup, which is the line this project
does not cross. Mailing list posts are also the copyright of their individual
authors, and Openwall publishes no reuse licence, so there is no grant to
republish them even where the mapping is right.

Not attempted further. No code was written for it.

## Verification

The mechanism, not just the totals.

- **CVE-2024-1086**, fetched fresh with `curl` from
  `access.redhat.com/hydra/.../CVE-2024-1086.json` and from
  `ubuntu.com/security/cves/CVE-2024-1086.json`, independently of the script's
  caches. Every field in the output matches the upstream text character for
  character, including the fenced `sysctl` block and the line breaks inside
  Ubuntu's mitigation.
- **The Ubuntu parser** was checked against the JSON API for the same CVE. The
  API groups consecutive `author> line` lines into one note per author, and
  splits `Priority:` into a priority plus a reason. The parser reproduces both:
  the API returns the same two notes and the same priority reason that
  `uct_parse` and `uct_notes` produce from the flat file.
- **The absence invariant** holds exactly. For Red Hat, 1,769 in `notes` plus 0
  in `silent` plus 950 in `absent` is 2,719. For Ubuntu, 430 plus 2,288 plus 1
  is 2,719. The script asserts this on every run.
- **`--offline` is byte-identical to the online run.** `notes`, `absent`,
  `silent` and `coverage` all compare equal, with 0 HTTP requests.
- **The Red Hat prefilter** was probed with 20 population CVEs the kernel
  listing omits. 19 were 404 on the per-CVE endpoint; the one that was not
  carried no statement and no mitigation.
- **The launchpad 503 path** was not simulated. It fired on its own three times
  during this session, and each time the run logged a warning, kept the existing
  mirror and produced a complete output file.
- **The failure table above** says which paths were actually exercised and which
  are reasoned rather than observed. Three of the ten were not triggered.

## Recommendation

### Red Hat: SHIP

- **55%** of the population and **54.8%** of the CVEs unfixed in a Debian
  release get prose, almost all of it Red Hat's. That is not a footnote feature;
  it is the majority of the rows a reader lands on.
- It **holds up on the newest CVEs**, which is where `docs/vulnrichment.md`
  found CISA collapsing: Red Hat tracks 1,099 of the 2,029 open 2026 CVEs and
  has written a description for 1,073 of them.
- On the CVEs a person is most likely to be scared by, it is near total: 33 of 35
  KEV entries tracked, 23 with a real mitigation, 32 with a plain-language
  description.
- The licence is **explicit**: CC BY 4.0, attribution plus a link, both already
  in the output on every record.
- The cost is defensible: 1,790 requests and 17.9 MB cold, 21 requests warm,
  10.4 MB of cache, and no third-party service is asked anything twice.

Ship it with three conditions, all of which the output file supports:

1. Render `source` and `url` next to every quote, and put the CC BY 4.0 notice on
   the page. This is a licence obligation, not a nicety.
2. Say whose system the advice was written for. "Red Hat's mitigation, for RHEL"
   is honest; presenting it as "the mitigation" is not, and the
   `unprivileged_userns_clone` case shows why.
3. Treat `template` fields as absent when deciding whether to advertise that a
   mitigation exists, and render `absent` and `silent` as distinct sentences.
   Break condition 3 and this becomes the footgun `docs/vulnrichment.md`
   describes, where "no data" reads as "no problem" on 943 of the 2,029 open 2026
   rows.

The honest sales pitch is narrower than the brief hoped for and still worth
shipping: this mostly answers **"what is this and does it reach me"** (48.8% of
unfixed rows get a plain-language description, 10.0% an impact assessment) and
only sometimes answers **"what do I do right now"** (7.3% a real mitigation,
rising to 65.7% on KEV). Both are things the CNA's commit message does not say.

### Ubuntu: DO NOT SHIP

Not because the writing is bad. Ubuntu's `Ubuntu-Description` is the best-written
prose of either source, and its triager notes ("unfixed upstream as of
2023.09.01") say things nobody else records. Two reasons, either sufficient:

1. **There is no licence to republish it.** Launchpad says GPL v2, the tree says
   GPL-3.0, there is no COPYING file, and Canonical's site terms grant
   "personal, education and non-commercial use only". A verbatim republication of
   someone else's prose needs a grant, and this investigation could not find one.
   This is the blocking reason and it is not a numbers question.
2. **The coverage is thin where it is needed.** 396 of 2,684 unfixed CVEs get any
   Ubuntu prose, and on the 2,029 open 2026 CVEs it is 2 impact statements, 1
   mitigation and 4 notes. Its strength is old, famous CVEs: 21 of 35 KEV entries
   have an impact statement. That is a real but small set, and all 35 of them are
   already fixed in every Debian suite, so they are not what a reader is stuck on.

Reason 2 alone would be a marginal call. Reason 1 settles it.

**What to do instead**, which costs nothing and has no licence problem: link to
`https://ubuntu.com/security/<CVE>` on rows where `absent.ubuntu` does not
contain the CVE, labelled as Ubuntu's own page. Linking is always permitted. The
reader who wants Ubuntu's wording gets one click to it, attributed to Canonical,
served by Canonical.

The fetcher keeps working and keeps measuring Ubuntu, so this can be revisited
the moment somebody gets a written answer from the Ubuntu Security Team or
Canonical publishes a content licence. `sources.ubuntu.republish` is the single
field to flip.

### Openwall / oss-security: DO NOT ATTEMPT

Measured above. No index, no search, no export; a full index is roughly 27,000
requests and 185 MB against a volunteer-run server; two months of real crawling
yielded 4 of the 19,103 tracked kernel CVEs and **0** of the 2,719 the user is
stuck on; the CVE-to-post mapping would be a regex heuristic rather than a
lookup, which is the line this project does not cross; and list posts are their
authors' copyright with no reuse licence.

The user was right that reports like Openwall's are what they want to read. They
are just not in Openwall, for kernel CVEs, at a rate that would ever put one on
the page they are looking at. Red Hat is where that writing actually is.

## Where the code is

`scripts/distro_notes.py`, standalone, standard library only, no third-party
packages. It targets Python 3.9+: that floor is checked statically (every
annotation is deferred by `from __future__ import annotations`, and no PEP 604
union is evaluated at runtime), not by executing it on 3.9, because only 3.13 was
available here. It reads `site/data/index.json` and never writes to
`site/data/`; it refuses to, explicitly. Nothing in `scripts/build.py`,
`scripts/render_pages.py` or `site/` was touched, and the integration against the
contract above is a separate piece of work.

Re-measure before trusting any number here. The coverage figures are a snapshot
of 2026-09-28 and Red Hat can change them at any time, in either direction. The
argument for shipping rests on the 2026 row of the year table, which is the one
most likely to move.
