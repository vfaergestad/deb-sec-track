# Kernel exposure data: subsystem, Kconfig symbol, Debian's config

Measured on 2026-09-28 against 19,710 kernel CVEs tracked by Debian.

**Recommendation: ship all four fields.** The reasoning is at the bottom; the
short version is that 96.6% of the CVEs still open in some Debian release get a
subsystem name, 88.8% get a per-release "does this release build it" answer,
and 268 of them get the answer *no, not on any flavour Debian ships* — which is
the one answer that ends the conversation.

The problem this solves: the site could already tell you CVE-2026-97615 is
unfixed in Debian 12 and 13, and could show you a commit message about
`br_cfm.c`. It could not tell you that the thing is called the **Ethernet
bridge**, that the code lives in the **`bridge`** module, or that Debian
compiles that module **without** the affected file, because `CONFIG_BRIDGE_CFM`
is off in every configuration Debian publishes. That is now three lookups, not
a research project.

Everything below is a lookup or a textual match in a published file. No value
here is inferred, scored, or estimated. Where a mapping cannot be made the
field is absent, and "absent" is kept distinguishable from "not enabled"
everywhere it matters.

## The sources

### 1. `MAINTAINERS` — what the thing is called

The kernel's own file-pattern-to-subsystem table. A section names a subsystem,
lists `F:` file patterns it claims, `X:` patterns it disclaims, `L:` its
mailing list and `S:` its maintenance status.

Read out of the kernel tree we already fetch (below), so it costs nothing
extra. `https://git.kernel.org/.../stable/linux.git/plain/MAINTAINERS`
(928 KB) is the fallback if no tree could be fetched, so the highest-coverage
field survives a git outage.

### 2. kbuild Makefiles — which `CONFIG_` symbol controls the code

`net/batman-adv/Makefile` contains

```
obj-$(CONFIG_BATMAN_ADV) += batman-adv.o
batman-adv-$(CONFIG_BATMAN_ADV_DAT) += distributed-arp-table.o
```

which says both that `distributed-arp-table.c` is only compiled when
`CONFIG_BATMAN_ADV_DAT` is on, and that when it is compiled it goes into
`batman-adv.ko`. That is the whole mapping: the symbol to grep for in a
config, and the string to type into `lsmod`.

Fetched from **`https://github.com/gregkh/linux.git`**, the linux-stable
mirror, as a blobless partial clone pinned to the exact upstream tag each
Debian release ships, with a sparse checkout of nothing but `Makefile`,
`Kbuild` and `MAINTAINERS`.

### 3. `linux-config-<series>` binary packages — what Debian actually builds

Debian publishes a `linux-config-6.12`, `linux-config-7.2`, … binary package
per architecture, containing the final, fully expanded `.config` for every
flavour it builds — the same file that lands in `/boot/config-*`. Fetched
from `deb.debian.org`, main pool first and the security pool second, because a
release moves to the security archive when it stops being stable.

**The obvious wrong source, for the record:** `debian/config/` inside the
`.debian.tar.xz` looks like the configuration and is not. Those files are
*fragments* — they record what Debian overrides, and the rest of the config
comes from Kconfig defaults at build time. `CONFIG_HID=m` is in the fragment;
`CONFIG_HID_SUPPORT=y`, which `drivers/Makefile` also requires, is not in it at
all. An earlier revision of this work read the fragments and reported "HID is
not built in Debian 13", which is nonsense. Reading the fragments overstated
"not enabled" by roughly 2x: 6,496 rows with an `n` somewhere, against 3,198
from the real configs.

The `.debian.tar.xz` is still downloaded, for one thing only: the list of
architectures the release is built for, taken from the `ARCH='…'` assignments
in Debian's own generated `debian/rules.gen`.

## How they are fetched, and what it costs

### Choosing a source for the Makefiles

Four ways to get ~3,200 Makefiles for a given kernel version, all measured on
2026-09-28 from this machine:

| approach | cost per kernel version | notes |
|---|---|---|
| `git.kernel.org` shallow clone | **63.8 s, 286 MB** | kernel.org refuses partial clones: `warning: filtering not recognized by server, ignoring`. A full shallow clone of one branch. |
| `git.kernel.org` + `git fetch --depth 1 origin tag vX.Y.Z` | **+56.2 s, +245 MB** each | the cost above, again, for every additional version. Four Debian releases would be ~4 min and ~1.2 GB. |
| Debian orig source tarball | **151 MB**, 6.7 s just to walk the xz stream | the most authoritative tree (it is literally what Debian built), but 604 MB for four releases. |
| **`github.com/gregkh/linux`, blobless + sparse** | **3.4 s, 14.1 MB, 3.5 MB kept** | **chosen.** 1.4 s for the blobless clone, 2.0 s for the Makefile-only checkout. |

The mirror is the deciding factor. Because a version costs 3.4 s instead of
a minute, every Debian release can be resolved against **its own kernel tree**
rather than against one tree standing in for all of them — which matters more
than it sounds (see "Why per-release trees" below). Tag objects were checked
against kernel.org: `v6.12.107` is `d9e5f417…` in both.

`.git` is deleted after the checkout — it holds a second copy of every blob and
nothing here needs git again. A tag is immutable, so a cached tree is never
refreshed.

### Cost, measured

| | cost |
|---|---|
| cold, kernel trees (4 distinct versions for 5 columns) | **+13.6 s, 56 MB transferred**, 14 MB kept |
| cold, Debian packaging + configs (4 tarballs, 31 `.deb`) | **37.6 MB transferred and kept** |
| cold, total added to a build with everything else cached | **+46 s** (60.0 s vs ~12 s), ~94 MB |
| warm (both caches present) | **+4 to +6 s** (10.6–14.1 s → 16.2–17.4 s, two runs each) |

The warm cost is parsing: ~2,300 Makefiles per tree (parsed lazily, only the
directories the CNA's file lists actually mention), 62 xz-compressed configs,
and ~9,000 distinct file paths resolved against 4 trees. `MAINTAINERS` is
compiled lazily for the same reason — compiling all 9,870 `F:` patterns costs
~3 s and only one tree's table is ever used.

Disk: `.cache/trees` is 14.4 MB of content but **108 MB of allocated blocks**,
because it is 12,800 very small files. `.cache/debian-config` is 37.6 MB.

**Caveat for CI:** `.github/workflows/update.yml` caches only `kev.json`,
`epss.csv.gz` and the two advisory lists. Neither `.cache/trees` nor
`.cache/debian-config` is in that list, so every CI run pays the full cold
cost unless the workflow is changed. (That file is owned by someone else; this
is a report, not a change.)

### Failure behaviour

Every source here is optional and every failure degrades to "no exposure data"
rather than failing the build:

- a git clone that fails leaves no tree, and that release simply reports no
  symbol and no config state;
- a 404 in the pool is expected, not an error — not every architecture the
  source builds for is a release architecture — so those are not logged;
- `--offline` with nothing cached logs one warning per missing artefact and
  continues;
- if no tree at all came back, `MAINTAINERS` is fetched from kernel.org so the
  subsystem field still works.

All four paths were exercised; `python3 scripts/build.py --offline` produces a
complete site in each.

## How each mapping is derived

### a. Subsystem, from `MAINTAINERS`

For the CNA's file list, in order, the first file that a section other than the
catch-all `THE REST` claims wins. A section claims a path when one of its `F:`
patterns matches and none of its `X:` patterns do; `*` stops at a `/` and a
trailing `/` means the whole subtree, as the file documents. Where several
sections claim the same path, the longest pattern wins, then the one with more
path components. Patterns are bucketed by their wildcard-free directory prefix,
so a lookup compares against a handful of patterns rather than all 9,870.

Emitted: the subsystem name, its mailing list, and its `S:` status.

### b. The Kconfig symbols, from kbuild

For a source file, the object name is the file name with its suffix replaced by
`.o`. In that directory's `Makefile`/`Kbuild`:

- if the object is on an `obj-$(CONFIG_X)` line, `X` guards it and the object
  on that line is the module base name;
- if it is a member of a composite (`batman-adv-$(CONFIG_Y) += …`), `Y` guards
  it and resolution continues with the composite target;
- every directory between the file and the top of the tree contributes the
  symbol on the `obj-$(CONFIG_Z) += subdir/` line that descends into it.

The result is **the list of symbols that must all be on** for the file to be
compiled. That is what makes the list the right thing to look up in a config:
`min(states)` over the list is the state of the code.

An empty list is an answer, not a gap: 735 rows resolve to a file that is
compiled unconditionally (`net/core/gro.c` is `obj-y`), which means "built into
every kernel, nothing to disable".

Reading is textual, not an evaluation of make. `ifdef CONFIG_X` and
`ifeq ($(CONFIG_X),y|m)` contribute their symbol; an `else` branch drops the
guard rather than pretending the negation can be expressed; anything else
contributes nothing. This is conservative by construction — it can miss a
guard, never invent one.

### c. The per-release config state

For each column, each symbol is looked up in every `.config` in that release's
`linux-config` packages. A symbol missing from a finished `.config` is one
whose dependencies were not met, so absent means off — which is true of a real
`.config` and would have been meaningless in a fragment.

Per flavour: `n` if any symbol is off, else `m` if any is `m`, else `y`.

### d. The module name

The object on the `obj-*` line the resolution ended at: `batman-adv.o` →
`batman-adv.ko`. `lsmod` and `modprobe` render `-` as `_`, so the string an
admin types is `batman_adv`. Emitted on an index row only where some flavour
really does build it as a module; where the code is built in or not built, a
module name would be an invitation to look for something that is not there.

### Why per-release trees

654 rows get a *different* symbol list depending on the release, and the reason
is usually that the kernel moved a guard. `drivers/Makefile` in 6.1 says

```
obj-$(CONFIG_HID)          += hid/
```

and in 6.12 and later says

```
obj-$(CONFIG_HID_SUPPORT)  += hid/
```

so `drivers/hid/hid-core.c` needs `{HID}` in Debian 12 and `{HID, HID_SUPPORT}`
in Debian 13 and later. One tree standing in for all releases would report one
of those two answers for both. A further 2,597 − 255 rows resolve in a newer
tree but not in 6.1's, because the file did not exist yet.

## The architecture caveat

Debian does not build "a kernel". For Debian 13 it builds 15 configurations —
`amd64/amd64`, `amd64/cloud-amd64`, `amd64/rt/amd64`, `arm64/arm64`,
`arm64/arm64-16k`, `arm64/cloud-arm64`, `arm64/rt/arm64`, `armel/rpi`,
`armhf/armmp`, `armhf/armmp-lpae`, `armhf/rt/armmp`, `ppc64el/powerpc64le`,
`ppc64el/powerpc64le-64k`, `riscv64/riscv64`, `s390x/s390x` — and they
disagree. `CONFIG_HID` is `m` on `amd64/amd64`, `y` on `armel/rpi` and off
entirely on `arm64/cloud-arm64`.

**What was chosen.** Every flavour is evaluated. The index row carries one
letter per release that summarises them, and the detail chunk carries the full
per-flavour answer as one letter per flavour, in the order `meta.json` lists
them for that column. Nothing is reported as amd64's answer, and amd64 is not
reported as everyone's answer.

The summary letter is lower case when every flavour agrees and upper case when
some flavours do not build the code at all:

| | meaning |
|---|---|
| `y` | built into the kernel image on every flavour — only a patch removes it |
| `Y` | built in where it is built at all; some flavours do not build it |
| `m` | a loadable module on every flavour |
| `M` | a module where it is built at all; some flavours do not build it |
| `b` | built in on some flavours, a module on others |
| `B` | built in on some, a module on others, absent on the rest |
| `n` | **not enabled on any flavour — this release does not build the code** |
| `?` | not established — no Makefile entry for the affected file |

7,950 rows have at least one release where the flavours disagree, so this is
not a rare corner: an interface that showed a single state per release would be
wrong about a third of the time.

**What is not covered.** Only the architectures for which Debian publishes a
`linux-config` package. Debian 13 builds kernels for `alpha`, `hppa`, `m68k`,
`powerpc`, `sh4`, `sparc64` and others in the ports archive, and those publish
no such package, so they are absent from the flavour list rather than guessed
at. A reader on `sparc64` gets no answer, not a wrong one. Debian 12 covers 13
flavours (including `i386`), Debian 14/unstable 14, the `linux-6.12` backport
in Debian 12 twelve.

## The fields

### `index.json`, per row

| field | meaning |
|---|---|
| `sub` | offset into `meta.subsystems`, which is `[name, mailing list, status]` |
| `cfg` | one letter per column, same order as `st`, from the table above |
| `mod` | offset into `meta.modules` — the `.ko` base name, only where some flavour builds it as a module |

`sub` and `mod` are offsets rather than strings because the names repeat across
thousands of rows: 1,526 distinct subsystems and 1,823 distinct modules over
19,710 rows.

`meta.json` also gains `config_codes` so the letters are self-describing to
anyone consuming the raw data, and each column gains `kernel_tree` (the tag its
symbols were resolved against) and `config_flavours` (the ordered flavour list
its detail strings are indexed by).

### `details/<n>.json`, per CVE

- `maintainers`: `{name, pattern, list, status}` — including the `F:` pattern
  that matched, so the claim is checkable.
- `exposure`:
  - `sym`: the symbols that must all be on. Present when every release agrees.
  - `mod`: the module base name.
  - `by`: `{column: {sym, mod}}` instead of `sym`/`mod`, for the 654 rows where
    the releases disagree.
  - `state`: `{column: letter}`.
  - `flav`: `{column: "mnmm…"}`, one letter per flavour, **only** where that
    release's flavours disagree. Where they agree the summary letter already
    says it, and storing the string would have cost 5.9 MB for nothing.

### Size delta

| | before | after | delta |
|---|---|---|---|
| `index.json` | 5.331 MB | 5.810 MB | +479 KB (+9.0%) |
| `index.json`, gzipped | 842.4 KB | 939.8 KB | **+97.3 KB (+11.6%)** |
| `meta.json` | 2.4 KB | 134.5 KB | +132 KB |
| `meta.json`, gzipped | 1.0 KB | 34.5 KB | **+33.5 KB** |
| `details/` tree (50 chunks) | 29.73 MB | 35.71 MB | +5.98 MB (+20.1%), ~+120 KB per chunk |

On the critical path that is **+131 KB gzipped**, split between `index.json`
and the subsystem/module/flavour tables in `meta.json`. The detail growth is
lazy — a reader pays ~120 KB extra only for the chunk they open.

If that is judged too much, the cheapest thing to drop is `mod` from the index
row (~85 KB raw, it is also in the detail), then `sub` (~170 KB raw) at the
cost of the subsystem filter.

## Coverage, measured

**19,710 tracked CVEs. 17,113 have a kernel.org CNA record with a file list at
all** — that is the ceiling for everything here, and it is the same ceiling the
site's existing CNA-derived fields have.

| field | rows | of all tracked |
|---|---|---|
| subsystem name | 17,021 | 86.4% |
| Kconfig symbol | 14,849 | 75.3% |
| per-release config state | 15,584 | 79.1% |
| module name | 9,651 | 49.0% |
| `n` in at least one release | 3,198 | 16.2% |
| **`n` in every release** | **1,519** | **7.7%** |

92 rows matched only the `THE REST` catch-all in `MAINTAINERS`, and are treated
as having no subsystem rather than being labelled "the rest".

### Where the workflow actually is: the 2,986 rows still open

These are the CVEs unfixed (`V`) or explicitly not-going-to-be-fixed (`I`) in at
least one Debian release — the rows someone is on this site to make a decision
about.

| field | rows | of open |
|---|---|---|
| subsystem name | 2,885 | **96.6%** |
| Kconfig symbol | 2,564 | 85.9% |
| per-release config state | 2,652 | **88.8%** |
| module name | 1,693 | 56.7% |
| `n` in at least one release | 497 | 16.6% |
| **`n` in every release** | **268** | **9.0%** |

### By CVE year

| year | tracked | subsystem | config state |
|---|---|---|---|
| 2026 | 6,911 | 99.4% | 92.4% |
| 2025 | 2,672 | 99.4% | 91.5% |
| 2024 | 3,114 | 98.0% | 87.7% |
| 2023 | 1,921 | 83.6% | 76.1% |
| 2022 | 2,424 | 86.5% | 78.7% |
| 2021 | 953 | 75.9% | 66.8% |
| ≤2020 | 1,627 | ~1% | ~1% |

Unlike the Vulnrichment spike, coverage here is **highest on the newest CVEs**,
because it is derived from the kernel CNA's own output rather than from a
third party's backlog. Pre-2021 CVEs predate the kernel becoming a CNA and have
no file list to work from; nothing in this feature can change that.

### Where the 2,597 + 1,529 gaps are

2,597 rows have no kernel.org record at all. Of the 17,113 that do, 1,529 get no
config state: 1,172 are `.c` files with no Makefile entry in any release's tree
(renamed or deleted since, or `#include`d into another object), 301 are headers
(`.h` has no object, so no symbol), and the rest are device trees, Rust files
and assembly stubs. Per column, the "no Makefile entry" count is 1,758 for
Debian 12's 6.1 tree, 701 for the 6.12 trees and 255 for the 7.2 ones — older
trees lose more, exactly as expected.

## Verification

Five CVEs checked by hand against the raw sources, chosen to cover networking,
a filesystem, a driver, an `=m` symbol, and code Debian does not build at all.
In each case the Makefile lines are quoted from the cached tree and the config
lines from an independent reader that does not import `build.py`.

### 1. Networking, and a module — CVE-2026-93204

Built: `sub: BATMAN ADVANCED`, `cfg: MMMMM`, `mod: batman-adv`,
`sym: [BATMAN_ADV, BATMAN_ADV_DAT]`.

- CNA `programFiles`: `net/batman-adv/distributed-arp-table.c`,
  `net/batman-adv/types.h`.
- `MAINTAINERS` section `BATMAN ADVANCED`, matched on `F: net/batman-adv/`,
  `L: b.a.t.m.a.n@lists.open-mesh.org`, `S: Maintained`. ✔
- `net/batman-adv/Makefile`:
  `obj-$(CONFIG_BATMAN_ADV) += batman-adv.o` and
  `batman-adv-$(CONFIG_BATMAN_ADV_DAT) += distributed-arp-table.o` → both
  symbols, module base `batman-adv`. ✔
- `linux-config-7.2_7.2.8-1_amd64.deb`, `config.amd64_none_amd64`:
  `CONFIG_BATMAN_ADV=m`, `CONFIG_BATMAN_ADV_DAT=y` → `m`. ✔
- same package, `config.amd64_none_cloud-amd64`:
  `# CONFIG_BATMAN_ADV is not set` → `n`. The emitted flavour string for `sid`
  is `mnmmmnmmmmmmmm`, position 0 (`amd64/amd64`) `m`, position 1
  (`amd64/cloud-amd64`) `n`. ✔ Hence the summary `M`, not `m`.
- `lsmod` string: `batman_adv`.

### 2. A filesystem, and `=m` — CVE-2026-90048

Built: `sub: NTFS3 FILESYSTEM`, `cfg: nmnnm`, `mod: ntfs3`, `sym: [NTFS3_FS]`.

- `fs/ntfs3/Makefile`: `obj-$(CONFIG_NTFS3_FS) += ntfs3.o`, with `frecord.o` in
  the `ntfs3-y` member list. ✔
- `linux-config-6.1_6.1.187-1_amd64.deb`: `# CONFIG_NTFS3_FS is not set` → `n`
  for Debian 12. ✔
- `linux-config-6.12_6.12.107-1_amd64.deb`: `CONFIG_NTFS3_FS=m` → `m` for
  Debian 13, and lower case because all 15 flavours agree. ✔
- `linux-config-7.2_7.2.8-1_amd64.deb`: `# CONFIG_NTFS3_FS is not set` → `n`
  for Debian 14 and unstable. ✔

Debian turned `ntfs3` on for Debian 13 and off again for 7.2. The site now says
so per release, from Debian's own configs, rather than implying that "unfixed
in Debian 12" means "your Debian 12 box mounts NTFS with vulnerable code".

### 3. A driver, and flavours that disagree — CVE-2026-43048

Built: `sub: HID CORE LAYER`, `cfg: MBMMM`, `mod: hid`, and a `by` map because
the releases disagree on the symbol list.

- `drivers/hid/Makefile`: `hid-y := hid-core.o hid-input.o hid-quirks.o` and
  `obj-$(CONFIG_HID) += hid.o` → `hid-core.c` is a member of the `hid.ko`
  composite, guarded by `CONFIG_HID`. ✔
- `drivers/Makefile` in `v6.1.187`: `obj-$(CONFIG_HID) += hid/`;
  in `v7.2.8`: `obj-$(CONFIG_HID_SUPPORT) += hid/`. Hence `sym: [HID]` for
  Debian 12 and `[HID, HID_SUPPORT]` for the rest. ✔
- `linux-config-6.12_6.12.107-1_amd64.deb`, `config.amd64_none_amd64`:
  `CONFIG_HID=m`, `CONFIG_HID_SUPPORT=y` → `m`.
- `linux-config-6.12_6.12.107-1_armel.deb`, `config.armel_none_rpi`:
  `CONFIG_HID=y` → `y`.
- `linux-config-6.12_6.12.107-1_arm64.deb`, `config.arm64_none_cloud-arm64`:
  `# CONFIG_HID is not set` → `n`.
- emitted flavour string for `trixie`: `mmmmmnmymmmmmmm`. Position 0
  (`amd64/amd64`) `m`, position 5 (`arm64/cloud-arm64`) `n`, position 7
  (`armel/rpi`) `y`. ✔ Summary `B`: built in on some, a module on others,
  absent on the rest.

### 4. Code Debian does not build at all — CVE-2026-97615

**This is the case the whole feature exists for.** Built: `sub: ETHERNET
BRIDGE`, `cfg: nnnnn`, `sym: [BRIDGE, BRIDGE_CFM]`, and deliberately **no
module name on the index row**.

- CNA `programFiles`: `net/bridge/br_cfm.c`, `br_device.c`, `br_input.c`,
  `br_mrp.c`, `br_private.h`.
- `net/bridge/Makefile`: `obj-$(CONFIG_BRIDGE) += bridge.o` and
  `bridge-$(CONFIG_BRIDGE_CFM) += br_cfm.o br_cfm_netlink.o` → `{BRIDGE,
  BRIDGE_CFM}`, module base `bridge`. ✔
- every configuration checked — 6.1 amd64, 6.12 amd64, 6.12 armel/rpi, 7.2
  amd64, 7.2 cloud-amd64 — has `CONFIG_BRIDGE=m` and
  `# CONFIG_BRIDGE_CFM is not set`. ✔

So: the `bridge` module is built, and is loaded on any Debian box with a
bridge — and the vulnerable file is **not in it**. A naive "which module is
this in, go check `lsmod`" answer would have sent the reader to a module that
is loaded and told them nothing. The state is `n` in all five columns and no
module name is offered, which is the correct and useful answer.

Debian still lists this CVE as unfixed in Debian 12 and 13, and rightly so —
the source package carries the vulnerable source. The exposure field is the
missing second half of that sentence.

### 5. A second not-built case, this time a driver — CVE-2026-98148

Built: `sub: DRM DRIVER FOR GENERIC USB DISPLAY`, `cfg: nnnnn`,
`sym: [DRM_GUD]`, module base `gud`, no module name on the row.

`# CONFIG_DRM_GUD is not set` in the 6.1, 6.12 and 7.2 amd64 configs, and
absent entirely from `cloud-amd64` (its dependencies are unmet there). ✔
Debian never built this driver, in any release this site tracks.

## Where the mapping can be wrong

1. **Debian patches some Makefiles, and the tree does not know.** The symbols
   come from the upstream tag; Debian applies `debian/patches` on top. 13–20
   Makefiles per release are patched, and **35 of 19,710 rows sit on one**.
   The one that produces a wrong answer:
   `debian/patches/debian/android-enable-building-ashmem-and-binder-as-modules.patch`
   rewrites `obj-$(CONFIG_ANDROID_BINDER_IPC) += binder.o binder_alloc.o` to
   `+= binder_linux.o`, so the **32 `drivers/android/` rows report the module
   as `binder` when Debian ships `binder_linux.ko`.** The other 3
   (`drivers/video/fbdev/nvidia`, `…/riva`, removed by a DFSG patch) are
   reported as not built, which the removal makes true anyway.
2. **One file speaks for the CVE.** The CNA's list is taken in order and the
   first file that resolves wins. A CVE spanning two subsystems gets one
   subsystem, one symbol list and one module. 2,352 records list more than one
   file.
3. **Makefile reading is textual.** An `else` branch loses its guard, `ifeq` on
   anything but a bare `CONFIG_` symbol contributes nothing, and make variables
   are not expanded. The bias is one-directional: a missed guard makes the code
   look *more* built than it is, never less. A row that says `n` is therefore
   stronger evidence than a row that says `m`.
4. **kbuild corners are not modelled**, notably a directory pulled in with
   `obj-m` whose contents use `obj-y`, and the `arch/` Makefiles, which have
   conventions of their own. These show up as "no Makefile entry" (`?`), not
   as a wrong answer.
5. **"Built" is not "running".** `m` means Debian compiles a module. It does
   not mean the module is loaded, that the hardware exists, or that the code
   path is reachable. `y` means it is in the image and cannot be unloaded.
   Only `n` is a statement about your exposure, and only for the flavours
   listed.
6. **This does not contradict, and cannot override, Debian's own status.** `V`
   means the source package carries unfixed code; `n` means this release's
   binary kernels do not compile it. Both can be true at once — that is
   CVE-2026-97615 — and the security team's status stays authoritative.
7. **`MAINTAINERS` comes from one tree**, the newest of the ones fetched. A
   subsystem renamed or split since then is labelled by its current name. The
   table is also the kernel's aspiration, not a guarantee: `S: Orphan` sections
   exist and are reported as such.
8. **Ports architectures are absent, not "not built".** See the architecture
   caveat. A flavour that has no `linux-config` package contributes nothing to
   the summary letter, so a symbol enabled only on `m68k` reads as `n`.
9. **The kernel tree is pinned to the version the release ships today.** When
   Debian updates its kernel the tag changes, a new tree is fetched, and
   symbols are re-derived. Old trees are not pruned from `.cache`.

## Recommendation

### a. Subsystem name, mailing list, status — **SHIP**

86.4% of all rows, **96.6% of open rows**, 99.4% of everything from 2025
onward. It is a pure transcription of the kernel's own table, it degrades to a
928 KB HTTP fetch if git is unreachable, and it directly answers the
complaint that started this: "it is not clear from the name". This is the
field that turns `skb_gro_receive()` into "NETWORKING [GENERAL], netdev@".

### b. Kconfig symbol — **SHIP, in the detail only**

75.3% of all rows, 85.9% of open rows. It is the evidence behind (c) and (d)
rather than a thing anyone filters on — the sysadmin action it enables is
`grep CONFIG_BRIDGE_CFM /boot/config-$(uname -r)`, which is a detail-page
action. Keeping it off the index row costs nothing and saves ~150 KB.

### c. Per-release config state — **SHIP**

79.1% of all rows, **88.8% of open rows**, and it is the payoff. 497 open rows
are not built in at least one release and **268 are not built in any of
them** — that is 9% of the open set where the honest answer is "this one
cannot affect the kernel you are running", from Debian's own published
`.config`, with the per-flavour breakdown to back it up.

Compare the Vulnrichment spike, which was rejected for surfacing 5 open rows
out of 2,684. This surfaces 268, on a corpus where coverage is 92% for the
current year and rising rather than 1.5% and falling.

One condition on shipping it: **the interface must not flatten the letters.**
7,950 rows have a release whose flavours disagree. An upper-case letter has to
read as "on some of the kernels this release ships" and `?` has to read as "not
established", never as "no". Collapsing those into "not affected" would be a
worse footgun than the field is a help.

### d. Module name — **SHIP**

9,651 rows (49.0%), 1,693 open rows (56.7%). The 51% that get none is not a
coverage gap: those rows are built-in, not built, or unresolved, and in each
case a module name would be wrong to show. Where it is emitted, it is the
exact string for `lsmod`, and it is the only field that tells a reader what to
*do* next.

The one known defect is the 32 `drivers/android/` rows, above. That is 0.3% of
the rows carrying this field, it is named and bounded, and it does not
generalise — Debian patches very few Makefiles. Worth shipping; worth
revisiting if Debian's patch set grows.

### Re-measure before trusting these numbers

Everything above is a snapshot of 2026-09-28 with Debian 12 on 6.1.187-1,
Debian 13 on 6.12.107-1, Debian 14 on 7.2.6-1 and unstable on 7.2.8-1. Coverage
moves with the kernel CNA's output and with Debian's configuration choices —
`ntfs3` alone changed state twice across the four releases tracked here.
