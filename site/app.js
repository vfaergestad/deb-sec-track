/* Debian Linux kernel CVE tracker.
 *
 * A public lookup, not a personal dashboard: someone hears about a kernel
 * vulnerability and wants to know whether Debian is affected, which releases,
 * and what to do about it.  Every release is shown side by side, always.
 *
 * All data comes out of site/data/, which scripts/build.py regenerates from
 * the Debian Security Tracker, the kernel CNA's vulns.git, CISA KEV and FIRST
 * EPSS.  No scoring happens here; the page filters, sorts and renders
 * published values.
 */
'use strict';

const BATCH = 60;
const DAY = 86400;
const NEW_WINDOW = 30;    // days that count as "latest"
const FIXED_WINDOW = 90;  // days back that "recently fixed" covers

const STAR_KEY = 'starred';
const HISTORY_KEY = 'searches';
const STAR_MAX = 500;     // stars kept in storage
const SHARE_MAX = 50;     // ids a shared link will carry
const HISTORY_MAX = 8;    // recent lookups kept
const QUERY_MAX = 64;     // characters kept per recorded lookup
const QUERY_MIN = 3;      // shorter than this is still being typed
const SETTLE_MS = 1200;   // pause in typing that counts as a committed search

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const $ = (sel) => document.querySelector(sel);

/* Where each published value comes from.  The whole claim this site makes is
 * that every number on it is a lookup in somebody else's published file, so
 * every number carries a link to that file.  Each of these was checked to
 * return 200; where a source has no per-CVE page, the closest honest thing is
 * linked instead and said to be exactly that. */
const VULNS_TREE = 'https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/';
const VULNS_LOG = 'https://git.kernel.org/pub/scm/linux/security/vulns.git/log/cve/published/';
const TRACKER = 'https://security-tracker.debian.org/tracker/';
const KEV_CATALOG = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const EPSS_API = 'https://api.first.org/data/v1/epss?pretty=true&cve=';
const CVSS_CALC = 'https://www.first.org/cvss/calculator/3.1#';

/* CVSS v3.1 attack vector letters, straight from the spec's own legend. */
const AV_WORDS = { N: 'network', A: 'adjacent network', L: 'local', P: 'physical' };

/* The eight base metrics in vector order: code, name, the value that scores
 * worst for that metric, and the spec's word for each value.  All of it is
 * copied from the CVSS v3.1 specification; nothing here is a judgement. */
const CVSS_METRICS = [
  ['AV', 'Attack vector', 'N', AV_WORDS],
  ['AC', 'Attack complexity', 'L', { L: 'low', H: 'high' }],
  ['PR', 'Privileges required', 'N', { N: 'none', L: 'low', H: 'high' }],
  ['UI', 'User interaction', 'N', { N: 'none', R: 'required' }],
  ['S', 'Scope', 'C', { U: 'unchanged', C: 'changed' }],
  ['C', 'Confidentiality impact', 'H', { H: 'high', L: 'low', N: 'none' }],
  ['I', 'Integrity impact', 'H', { H: 'high', L: 'low', N: 'none' }],
  ['A', 'Availability impact', 'H', { H: 'high', L: 'low', N: 'none' }],
];

const VIEWS = [
  {
    id: 'latest',
    label: 'Latest',
    sort: 'new',
    title: 'Published in the last ' + NEW_WINDOW + ' days',
    note: 'Everything the Linux kernel CNA has published recently, and where ' +
      'each Debian release stands on it.',
    match: (r) => r.pub && r.pub >= Date.now() / 1000 - NEW_WINDOW * DAY,
  },
  {
    id: 'exploited',
    label: 'Exploited in the wild',
    sort: 'triage',
    title: 'Kernel CVEs in the CISA KEV catalogue',
    note: 'CISA has evidence these are being exploited. If any release below ' +
      'still shows as unfixed, that is the most urgent thing on this site.',
    match: (r) => !!r.kev,
  },
  {
    id: 'unfixed',
    label: 'Unfixed in Debian',
    sort: 'triage',
    title: 'Unfixed in at least one Debian release',
    note: 'Ordered by CISA KEV listing, then known ransomware use, then EPSS, ' +
      'then CVSS, then publication date. This is a fixed rule over published values.',
    match: (r) => anyUnfixed(r),
  },
  {
    id: 'fixed',
    label: 'Recently fixed',
    sort: 'fixed',
    title: 'Fixed by a Debian advisory in the last ' + FIXED_WINDOW + ' days',
    note: 'The date shown is the date of the advisory that shipped the fix.',
    match: (r) => {
      if (!r.fd) return false;
      const cutoff = Date.now() / 1000 - FIXED_WINDOW * DAY;
      return r.fd.some((w) => w && Date.parse(w + 'T00:00:00Z') / 1000 >= cutoff);
    },
  },
  {
    id: 'all',
    label: 'Everything',
    sort: 'new',
    title: 'Every Linux kernel CVE Debian tracks',
    note: 'The full archive, back to CVEs Debian carries from before the kernel ' +
      'became its own CNA in 2024.',
    match: () => true,
  },
  {
    id: 'starred',
    label: 'Starred',
    sort: 'triage',
    title: 'Starred CVEs',
    note: 'The CVEs starred in this browser. A star is a bookmark and nothing ' +
      'more: it changes nothing about what Debian reports, and the site still ' +
      'knows nothing about any machine.',
    match: (r) => (shared ? shared.has(r.id) : starred.has(r.id)),
  },
];

const state = {
  view: 'latest', q: '', rel: 'any', status: 'any',
  sev: 'any', av: 'any', area: 'any', sort: '', deep: false,
};

let meta = null;
let rows = [];
let filtered = [];
let rendered = 0;
let openCve = null;
const detailCache = new Map();
const rationaleCache = new Map();
const deepText = new Map();

/* Bookmarks the reader chose, most recently starred first, and the recent
 * lookups offered back under the search box.  Both live only in this browser.
 * `shared` is the set carried by a #stars= link, which stands in for the
 * reader's own stars while such a link is open and is never written to
 * storage. */
let starred = new Set();
let recent = [];
let shared = null;
let settleTimer = 0;

/* ---------------------------------------------------------------- utils */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const fmtDate = (ts) => (ts ? new Date(ts * 1000).toISOString().slice(0, 10) : 'unknown');

/* ------------------------------------------------------------- citations */

/* One file per CVE in the kernel CNA's vulns.git: .json is the record, .cvss
 * the vector and the written reasoning, .dyad the introduced/fixed version
 * pairs.  They exist only for CVEs the CNA itself published, which is exactly
 * the set that has a publication date, so r.pub is the test for the .json. */
const vulnsFile = (cve, suffix) => VULNS_TREE + cve.split('-')[1] + '/' + cve + '.' + suffix;
const vulnsLog = (cve) => VULNS_LOG + cve.split('-')[1] + '/' + cve + '.json';

/* The published text of a DSA or DLA. Debian files both by year and number,
 * and the advisory's own date supplies the year. */
function advisoryUrl(id, date) {
  const m = /^(DSA|DLA)-(\d+)/.exec(id || '');
  const year = String(date || '').slice(0, 4);
  if (!m || !/^\d{4}$/.test(year)) return '';
  return m[1] === 'DSA'
    ? 'https://www.debian.org/security/' + year + '/dsa-' + m[2]
    : 'https://www.debian.org/lts/security/' + year + '/dla-' + m[2];
}

/* Anything off this site opens in a new tab, so the reader keeps their place,
 * and carries rel="noopener".  `label` is given only where the visible text is
 * too generic to stand on its own in a list of links; where the text is an
 * advisory id or a heading it is the accessible name already, and a repeated
 * aria-label would only be noise on a page carrying thirty of them. */
function ext(url, text, label) {
  return '<a href="' + esc(url) + '" target="_blank" rel="noopener"' +
    (label ? ' aria-label="' + esc(label) + '"' : '') + '>' + esc(text) + '</a>';
}

/* The small "source" link that sits beside a value.  Its visible text is the
 * same word every time, so the label always names what it points at.  `text`
 * overrides that word where the link does not go to a per-CVE page and saying
 * "source" would promise more than it delivers. */
function src(url, label, text) {
  return '<a class="src" href="' + esc(url) + '" target="_blank" rel="noopener" ' +
    'aria-label="' + esc(label) + '">' + esc(text || 'source') + '</a>';
}

function vectorParts(vector) {
  const out = {};
  for (const part of String(vector || '').split('/')) {
    const [k, v] = part.split(':');
    if (k && v) out[k] = v;
  }
  return out;
}

function ageLabel(ts) {
  if (!ts) return 'unknown';
  const d = Math.floor((Date.now() / 1000 - ts) / DAY);
  if (d <= 0) return 'today';
  if (d === 1) return '1 day';
  if (d < 45) return d + ' days';
  if (d < 730) return Math.round(d / 30.44) + ' months';
  return Math.round(d / 365.25) + ' years';
}

function agoLabel(ts) {
  const label = ageLabel(ts);
  if (label === 'unknown') return '';
  return label === 'today' ? 'today' : label + ' ago';
}

const unfixedAt = (r, i) => r.st[i] === 'V' || r.st[i] === 'I';
const anyUnfixed = (r) => [...r.st].some((c) => c === 'V' || c === 'I');
const view = () => VIEWS.find((v) => v.id === state.view) || VIEWS[0];

/* Which lifecycle state a CVE is in for one release. */
function lifecycle(r, i) {
  const code = r.st[i];
  if (code === '-') return { code: '-', word: 'not in this release' };
  if (code === 'F') {
    return {
      code: 'F',
      word: 'fixed',
      version: r.fix && r.fix[i],
      when: r.fd && r.fd[i],
      advisory: r.fa && r.fa[i],
    };
  }
  if (code === 'N') return { code: 'N', word: 'not affected' };
  if (code === 'U') return { code: 'U', word: 'undetermined' };
  if (code === 'I') {
    return { code: 'I', word: "won't fix", reason: r.nodsa && r.nodsa[meta.columns[i].id] };
  }
  if (r.up && r.up[i] === 'P') return { code: 'P', word: 'fix ready upstream' };
  return { code: 'V', word: 'vulnerable' };
}

/* The point of the page: what a reader should actually do about it, stated
 * from the published status rather than from any guess about their setup. */
function advice(r, i, d) {
  const col = meta.columns[i];
  const s = lifecycle(r, i);
  const lag = meta.fix_lag && meta.fix_lag[col.id];
  const lagNote = lag && lag.n
    ? ' Advisories for ' + col.suite + ' have historically landed a median of ' +
      lag.median + ' days after publication.'
    : '';

  switch (s.code) {
    case 'F':
      return 'Update the kernel and reboot. ' +
        (s.advisory
          ? s.advisory + ' shipped the fix on ' + s.when + ', in ' + (s.version || 'an update') + '.'
          : 'Fixed in ' + (s.version || 'a later version') + '.') +
        ' A running kernel keeps the old code until the machine restarts.';
    case 'P': {
      const series = seriesOf(col.version);
      const upstream = d && d.upstream && series ? d.upstream[series] : null;
      return 'Nothing to install yet. Upstream fixed this in ' +
        (upstream ? upstream : 'the ' + (series || '?') + ' series') +
        ', which is the series ' + col.suite + ' tracks, so it should arrive in a ' +
        'future kernel update.' + lagNote;
    }
    case 'V':
      return 'No fix published anywhere yet, neither in Debian nor upstream ' +
        'for the series ' + col.suite + ' tracks. Watch the Debian tracker page ' +
        'for this CVE.' + lagNote;
    case 'I':
      return 'Debian has decided against an update for ' + col.suite +
        (s.reason ? ': ' + s.reason + '.' : '.') +
        ' Moving to a newer release is the way to get the fix.';
    case 'N':
      return 'Nothing to do. ' + col.suite + ' never shipped the vulnerable code.';
    case 'U':
      return 'Debian has not finished triaging this one for ' + col.suite + '.';
    default:
      return 'This package is not part of ' + col.suite + '.';
  }
}

/* ------------------------------------------------------------- storage */

/* localStorage throws outright in some private windows and whenever site data
 * is blocked, so every read and every write is wrapped, the same way the theme
 * toggle has always done it.  A failure costs the reader persistence and
 * nothing else: the page carries on with whatever is in memory. */
function storeGet(key) {
  try {
    return localStorage.getItem(key);
  } catch (e) {
    return null;
  }
}

function storeSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    /* Private window, blocked site data, or a full quota. Nothing to do. */
  }
}

/* Whatever comes back out of storage was written by an older version of this
 * page, or by hand, or truncated halfway.  Treat it as untrusted text: parse
 * defensively, keep only values that still validate, and fall back to an
 * empty list rather than letting a bad value reach the rest of the page. */
function parseList(raw, limit, clean, keyOf) {
  let list = null;
  try {
    list = JSON.parse(raw);
  } catch (e) {
    return [];
  }
  if (!Array.isArray(list)) return [];
  const out = [];
  const seen = new Set();
  for (const item of list) {
    if (typeof item !== 'string') continue;
    const value = clean(item);
    if (!value) continue;
    const key = keyOf(value);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
    if (out.length >= limit) break;
  }
  return out;
}

const cleanCve = (s) => (CVE_RE.test(s.trim()) ? s.trim().toUpperCase() : '');
const cleanQuery = (s) => s.replace(/\s+/g, ' ').trim().slice(0, QUERY_MAX);
const lower = (s) => s.toLowerCase();

/* ---------------------------------------------------------------- stars */

function loadStars() {
  starred = new Set(parseList(storeGet(STAR_KEY), STAR_MAX, cleanCve, (s) => s));
}

function saveStars() {
  storeSet(STAR_KEY, JSON.stringify([...starred]));
}

function toggleStar(id) {
  if (starred.has(id)) {
    starred.delete(id);
  } else {
    // Newest first, so a shared link that has to truncate carries the stars
    // the reader added most recently.
    starred = new Set([id, ...starred]);
    if (starred.size > STAR_MAX) starred = new Set([...starred].slice(0, STAR_MAX));
  }
  saveStars();
  syncStarControls(id);
  renderViewCounts();
  renderStarBar();
}

const starLabel = (id, on) => (on ? 'Unstar ' : 'Star ') + id;

/* The row control and the one in the open detail panel are the same star and
 * must agree, so a toggle updates every control for that CVE on the page. */
function syncStarControls(id) {
  const on = starred.has(id);
  document.querySelectorAll('button.star[data-cve="' + id + '"]').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(on));
    btn.setAttribute('aria-label', starLabel(id, on));
    btn.title = starLabel(id, on);
    const glyph = btn.querySelector('.star-glyph');
    if (glyph) glyph.textContent = on ? '★' : '☆';
    const text = btn.querySelector('.star-text');
    if (text) text.textContent = on ? 'Starred' : 'Star';
  });
}

/* `wide` is the labelled version used inside the detail panel; rows get the
 * bare glyph. */
function starHtml(id, wide) {
  const on = starred.has(id);
  const label = esc(starLabel(id, on));
  return '<button type="button" class="star' + (wide ? ' star-wide' : '') +
    '" data-cve="' + esc(id) + '" aria-pressed="' + (on ? 'true' : 'false') +
    '" aria-label="' + label + '" title="' + label + '">' +
    '<span class="star-glyph" aria-hidden="true">' + (on ? '★' : '☆') + '</span>' +
    (wide ? '<span class="star-text">' + (on ? 'Starred' : 'Star') + '</span>' : '') +
    '</button>';
}

/* ------------------------------------------------------- recent lookups */

function loadHistory() {
  recent = parseList(storeGet(HISTORY_KEY), HISTORY_MAX, cleanQuery, lower);
}

function saveHistory() {
  storeSet(HISTORY_KEY, JSON.stringify(recent));
}

/* The box filters on every keystroke, so recording on input would fill this
 * list with the prefixes of one word.  A lookup counts as committed only when
 * the reader signals they meant it: Enter, opening a result, or leaving the
 * box alone for SETTLE_MS. */
function recordSearch(raw) {
  const q = cleanQuery(String(raw || ''));
  if (q.length < QUERY_MIN) return;
  const key = lower(q);
  recent = recent.filter((h) => lower(h) !== key);
  // Typing "ksm", pausing, then finishing "ksmbd" is one lookup, not two.
  if (recent.length) {
    const prev = lower(recent[0]);
    if (prev.startsWith(key) || key.startsWith(prev)) recent.shift();
  }
  recent.unshift(q);
  recent = recent.slice(0, HISTORY_MAX);
  saveHistory();
  renderHistory();
}

function renderHistory() {
  const host = $('#history');
  if (!host) return;
  host.hidden = recent.length === 0;
  $('#history-chips').innerHTML = recent.map((q) =>
    '<button type="button" class="histchip" data-q="' + esc(q) +
    '" title="Search again for ' + esc(q) + '">' + esc(q) + '</button>').join('');
}

function clearHistory() {
  recent = [];
  saveHistory();
  renderHistory();
}

/* Re-running a recorded lookup behaves exactly like typing it and committing
 * it, which also moves it back to the front of the list. */
function runQuery(q) {
  clearTimeout(settleTimer);
  const typed = cleanQuery(String(q || ''));
  state.q = typed;
  state.view = 'all';
  apply();
  recordSearch(typed);
  if (CVE_RE.test(typed)) {
    focusCve(typed.toUpperCase());
    return;
  }
  $('#q').focus({ preventScroll: true });
}

/* ------------------------------------------------------- shared star set */

/* A starred set travels in the address bar, so sharing needs no server and
 * stores nothing anywhere.  The ids arrive from someone else's browser, so
 * validate every one and cap the count. */
function setShared(raw) {
  const ids = [];
  const seen = new Set();
  for (const part of String(raw || '').split(',')) {
    const id = ('CVE-' + part.trim()).toUpperCase();
    if (!CVE_RE.test(id) || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= SHARE_MAX) break;
  }
  shared = ids.length ? new Set(ids) : null;
}

function shareLink() {
  const ids = [...starred].slice(0, SHARE_MAX).map((id) => id.slice(4));
  return location.origin + location.pathname + location.search +
    '#view=starred&stars=' + ids.join(',');
}

function legacyCopy(text) {
  try {
    const box = document.createElement('textarea');
    box.value = text;
    box.setAttribute('readonly', '');
    box.style.position = 'fixed';
    box.style.top = '-1000px';
    document.body.appendChild(box);
    box.select();
    const ok = document.execCommand('copy');
    box.remove();
    return ok;
  } catch (e) {
    return false;
  }
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text)
      .then(() => true, () => legacyCopy(text));
  }
  return Promise.resolve(legacyCopy(text));
}

/* ------------------------------------------------------------- loading */

async function boot() {
  applyStoredTheme();
  loadStars();
  loadHistory();
  const [m, idx] = await Promise.all([
    fetch('data/meta.json').then((r) => r.json()),
    fetch('data/index.json').then((r) => r.json()),
  ]);
  meta = m;
  rows = idx.rows;

  $('#built-at').textContent = 'updated ' + meta.built.replace('T', ' ').replace('Z', ' UTC');
  renderOverview();
  renderFeedList();
  buildViewTabs();
  buildReleaseOptions();
  buildAreaOptions();
  $('#deep-size').textContent = '(~' + Math.round(meta.total * 1.4 / 1000) + ' MB)';
  wireControls();
  renderHistory();
  readHash();
  apply();
}

async function loadChunk(n) {
  if (detailCache.has(n)) return detailCache.get(n);
  const data = await fetch('data/details/' + n + '.json').then((r) => r.json());
  detailCache.set(n, data);
  return data;
}

/* The CNA's written justification for each CVSS metric, cached per chunk the
 * same way details are.  About 250 KB a chunk, which is why nothing fetches it
 * on load or on opening a CVE: it waits until the reader presses the button. */
async function loadRationale(n) {
  if (rationaleCache.has(n)) return rationaleCache.get(n);
  const data = await fetch('data/rationale/' + n + '.json').then((r) => r.json());
  rationaleCache.set(n, data);
  return data;
}

/* ------------------------------------------------------------ overview */

function renderOverview() {
  const body = $('#overview-body');
  body.innerHTML = meta.columns.map((col, i) => {
    let open = 0, ready = 0, kev = 0;
    for (const r of rows) {
      if (!unfixedAt(r, i)) continue;
      open++;
      if (r.up && r.up[i] === 'P') ready++;
      if (r.kev) kev++;
    }
    const lag = meta.fix_lag && meta.fix_lag[col.id];
    const lagText = lag && lag.n
      ? 'median ' + lag.median + ' days, 90% within ' + lag.p90
      : '<span class="dim">no advisory path</span>';
    return '<tr>' +
      '<td><strong>' + esc(col.release || col.suite) + '</strong>' +
        '<span class="sub">' + esc(col.label) +
        (col.role ? ' · ' + esc(col.role) : '') + '</span></td>' +
      '<td class="mono">' + esc(col.version || 'unknown') + '</td>' +
      '<td class="num' + (open ? '' : ' good') + '">' + open.toLocaleString() + '</td>' +
      '<td class="num">' + ready.toLocaleString() + '</td>' +
      '<td class="num' + (kev ? ' bad' : ' good') + '">' + kev.toLocaleString() + '</td>' +
      '<td class="lagcell">' + lagText + '</td>' +
      '</tr>';
  }).join('');
}

function renderFeedList() {
  $('#feedlist').innerHTML = meta.columns.map((col) =>
    '<a class="feedchip" href="data/feeds/' + esc(col.id) + '.xml">' +
    esc(col.label) + '</a>').join('');
}

function buildViewTabs() {
  const host = $('#views');
  host.innerHTML = '';
  VIEWS.forEach((v) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'view-tab';
    btn.dataset.view = v.id;
    btn.innerHTML = '<span class="vt-label">' + esc(v.label) + '</span>' +
      '<span class="vt-count" data-count="' + v.id + '">–</span>';
    btn.addEventListener('click', () => {
      state.view = v.id;
      state.sort = '';
      apply();
    });
    host.appendChild(btn);
  });
}

function buildReleaseOptions() {
  const select = $('#rel');
  meta.columns.forEach((col, i) => {
    const opt = document.createElement('option');
    opt.value = String(i);
    opt.textContent = col.label;
    select.appendChild(opt);
  });
}

function buildAreaOptions() {
  const areas = new Map();
  for (const r of rows) if (r.area) areas.set(r.area, (areas.get(r.area) || 0) + 1);
  const select = $('#area');
  for (const [name, n] of [...areas.entries()].sort((a, b) => b[1] - a[1])) {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name + '/ (' + n.toLocaleString() + ')';
    select.appendChild(opt);
  }
}

function renderViewCounts() {
  for (const v of VIEWS) {
    const el = document.querySelector('[data-count="' + v.id + '"]');
    if (!el) continue;
    el.textContent = v.id === 'all'
      ? rows.length.toLocaleString()
      : rows.reduce((n, r) => n + (v.match(r) ? 1 : 0), 0).toLocaleString();
  }
}

/* ------------------------------------------------------------ controls */

function wireControls() {
  const bind = (sel, key, transform = (v) => v) => {
    const el = $(sel);
    const evt = el.type === 'checkbox' || el.tagName === 'SELECT' ? 'change' : 'input';
    el.addEventListener(evt, () => {
      state[key] = transform(el.type === 'checkbox' ? el.checked : el.value);
      apply();
    });
  };
  bind('#rel', 'rel');
  bind('#status', 'status');
  bind('#sev', 'sev');
  bind('#av', 'av');
  bind('#area', 'area');
  bind('#sort', 'sort');

  // A pasted CVE id is a lookup, not a search: go straight to the answer.
  $('#q').addEventListener('input', (e) => {
    state.q = e.target.value;
    const typed = state.q.trim();
    clearTimeout(settleTimer);
    if (typed) settleTimer = setTimeout(() => recordSearch(typed), SETTLE_MS);
    if (CVE_RE.test(typed)) {
      state.view = 'all';
      apply();
      focusCve(typed.toUpperCase());
      return;
    }
    if (typed && state.view !== 'all') state.view = 'all';
    apply();
  });

  // Enter is the reader saying they meant this one, so it commits at once.
  $('#q').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    clearTimeout(settleTimer);
    recordSearch(state.q);
  });

  $('#clear-q').addEventListener('click', () => {
    clearTimeout(settleTimer);
    state.q = '';
    state.view = 'latest';
    apply();
    $('#q').focus();
  });

  $('#history-chips').addEventListener('click', (e) => {
    const btn = e.target.closest('button.histchip');
    if (btn) runQuery(btn.dataset.q);
  });

  $('#clear-history').addEventListener('click', () => {
    clearHistory();
    $('#q').focus({ preventScroll: true });
  });

  // A row is a click target of its own, so the star has to claim the event
  // before the row sees it.  Capture phase does that for mouse and keyboard
  // alike, since a keyboard activation on a button fires an ordinary click.
  $('#tbody').addEventListener('click', (e) => {
    const btn = e.target.closest('button.star');
    if (!btn) return;
    e.stopPropagation();
    e.preventDefault();
    toggleStar(btn.dataset.cve);
  }, true);

  // The reasoning button lives inside the open detail row, which is a sibling
  // of the result row rather than part of it, so pressing it never reaches the
  // row's own click handler and never closes the panel.
  $('#tbody').addEventListener('click', (e) => {
    const btn = e.target.closest('button.reasons-btn');
    if (btn) toggleReasons(btn);
  });

  $('#copy-stars').addEventListener('click', onCopyStars);

  $('#exit-shared').addEventListener('click', () => {
    shared = null;
    apply();
  });

  $('#deep').addEventListener('change', async (e) => {
    state.deep = e.target.checked;
    if (state.deep) await loadAllDetails();
    apply();
  });

  $('#reset').addEventListener('click', () => {
    Object.assign(state, {
      rel: 'any', status: 'any', sev: 'any', av: 'any', area: 'any', sort: '',
    });
    apply();
  });

  $('#theme-toggle').addEventListener('click', toggleTheme);

  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) renderMore();
  }, { rootMargin: '600px' });
  io.observe($('#sentinel'));

  window.addEventListener('hashchange', () => {
    const raw = location.hash.slice(1);
    if (CVE_RE.test(raw) && raw !== openCve) { focusCve(raw.toUpperCase()); return; }
    // A starred-set link pasted into a tab that is already on this page
    // changes the hash without reloading, so readHash never runs again.
    const part = raw.split('&').find((p) => p.startsWith('stars='));
    const next = part ? decodeURIComponent(part.slice(6)) : '';
    const now = shared ? [...shared].map((id) => id.slice(4)).join(',') : '';
    if (next === now) return;
    setShared(next);
    if (shared) state.view = 'starred';
    apply();
  });
}

function syncControls() {
  $('#q').value = state.q;
  $('#rel').value = state.rel;
  $('#status').value = state.status;
  $('#sev').value = state.sev;
  $('#av').value = state.av;
  $('#area').value = state.area;
  $('#sort').value = state.sort || view().sort;
  $('#clear-q').hidden = !state.q;
  document.querySelectorAll('.view-tab').forEach((b) => {
    b.setAttribute('aria-pressed', String(b.dataset.view === state.view));
  });
}

/* The bar above the Starred view: what this set is, and how to hand it to
 * someone else.  Hidden everywhere else, so no other view changes. */
function renderStarBar() {
  const bar = $('#starbar');
  if (!bar) return;
  const n = shared ? shared.size : starred.size;

  if (shared && state.view === 'starred' && !state.q.trim()) {
    $('#view-title').textContent = 'Starred CVEs from a shared link';
    $('#view-note').textContent = 'Exactly the CVEs the link carries. The ids ' +
      'travel in the address, so nothing was uploaded and nothing was read ' +
      'about the machine at either end.';
  }

  // With nothing on screen there is nothing to say about it, and the empty
  // state below explains the view on its own.
  bar.hidden = state.view !== 'starred' || n === 0 || filtered.length === 0;
  if (bar.hidden) return;

  $('#exit-shared').hidden = !shared;
  $('#copy-stars').hidden = !!shared;
  $('#starbar-note').textContent = shared
    ? 'Showing the ' + n + ' CVE' + (n === 1 ? '' : 's') + ' this link carries, ' +
      'and nothing else. Star any of them to keep it in this browser as well.'
    : n > SHARE_MAX
      ? 'A shared link carries at most ' + SHARE_MAX + ' CVEs, so a link copied ' +
        'now covers the ' + SHARE_MAX + ' most recently starred of these ' +
        n.toLocaleString() + '.'
      : 'Copy a link that opens this exact set for someone else. The ids ' +
        'travel in the address, so nothing is uploaded anywhere.';
}

async function onCopyStars() {
  const btn = $('#copy-stars');
  const link = shareLink();
  if (await copyText(link)) {
    btn.textContent = 'Link copied';
    setTimeout(() => {
      btn.textContent = 'Copy link to these';
      renderStarBar();
    }, 2500);
    return;
  }
  // A browser can refuse clipboard access outright. Leave the link on screen
  // to be selected by hand rather than leaving the reader with nothing.
  $('#starbar-note').textContent = 'Copying was blocked by the browser. ' +
    'The link is ' + link;
}

async function loadAllDetails() {
  const bar = document.createElement('div');
  bar.className = 'loadbar';
  bar.style.width = '0%';
  $('#deep').parentElement.appendChild(bar);
  for (let n = 0; n < meta.chunks; n++) {
    const chunk = await loadChunk(n);
    for (const [cve, d] of Object.entries(chunk)) {
      deepText.set(cve, (d.desc || '').toLowerCase());
    }
    bar.style.width = Math.round(((n + 1) / meta.chunks) * 100) + '%';
  }
  bar.remove();
}

/* -------------------------------------------------------------- filter */

function apply() {
  const v = view();
  const terms = state.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const relIdx = state.rel === 'any' ? -1 : Number(state.rel);

  filtered = rows.filter((r) => {
    if (!v.match(r)) return false;
    if (relIdx >= 0 && state.status !== 'any' && !state.status.includes(r.st[relIdx])) return false;
    if (relIdx < 0 && state.status !== 'any' &&
        ![...r.st].some((c) => state.status.includes(c))) return false;
    if (state.av !== 'any' && r.av !== state.av) return false;
    if (state.area !== 'any' && r.area !== state.area) return false;
    if (state.sev !== 'any' && severityOf(r) !== state.sev) return false;
    if (terms.length) {
      const hay = (r.id + ' ' + r.sum + ' ' + (r.area || '')).toLowerCase() +
        (state.deep ? ' ' + (deepText.get(r.id) || '') : '');
      for (const t of terms) if (!hay.includes(t)) return false;
    }
    return true;
  });

  sortRows();
  writeHash();
  renderViewCounts();
  syncControls();

  $('#view-title').textContent = state.q.trim()
    ? 'Results for “' + state.q.trim() + '”'
    : v.title;
  $('#view-note').textContent = state.q.trim()
    ? 'Searching every CVE Debian tracks. Clear the box to go back to ' + v.label + '.'
    : v.note;
  $('#when-head').textContent = state.view === 'fixed' ? 'Fixed' : 'Published';
  $('#result-count').textContent =
    filtered.length.toLocaleString() + ' shown · ' +
    rows.length.toLocaleString() + ' kernel CVEs tracked in total';
  $('#empty').hidden = filtered.length > 0;
  $('#empty').textContent = emptyMessage();
  $('#hero-hint').textContent = heroHint();
  renderStarBar();

  $('#tbody').innerHTML = '';
  rendered = 0;
  renderMore();
}

function heroHint() {
  const typed = state.q.trim();
  if (!typed) {
    return 'Paste a CVE id to jump straight to it, or search by subsystem to ' +
      'see what has been found there.';
  }
  if (CVE_RE.test(typed)) {
    return filtered.length
      ? 'Found it. The answer for every Debian release is below.'
      : typed.toUpperCase() + ' is not a Linux kernel CVE that Debian tracks. It ' +
        'may affect a different package, or not apply to Debian at all.';
  }
  return filtered.length.toLocaleString() + ' kernel CVEs mention “' + typed + '”.';
}

function emptyMessage() {
  const typed = state.q.trim();
  if (CVE_RE.test(typed)) {
    return typed.toUpperCase() + ' is not in the Linux kernel CVE data Debian ' +
      'tracks. Check the Debian Security Tracker directly, since it may belong to ' +
      'another package.';
  }
  if (typed) return 'No kernel CVE matches that. Try a subsystem name, like ksmbd or nftables.';
  if (state.view === 'starred') {
    if (shared) {
      return 'That link carries no CVE this site tracks. It may have been cut ' +
        'short in transit, or point at CVEs in another package.';
    }
    return 'Nothing starred yet. Every result row starts with a star button, ' +
      'and so does each CVE once you open it. Star one and it stays here, in ' +
      'this browser, the next time you come back.';
  }
  if (state.view === 'exploited') {
    return 'No kernel CVE in the CISA KEV catalogue matches these filters.';
  }
  return 'Nothing matches these filters.';
}

function severityOf(r) {
  if (r.cvss === undefined) return 'unrated';
  if (r.cvss >= 9) return 'critical';
  if (r.cvss >= 7) return 'high';
  if (r.cvss >= 4) return 'medium';
  return 'low';
}

function sortRows() {
  const newestFix = (r) => (r.fd || []).reduce((best, w) =>
    w ? Math.max(best, Date.parse(w + 'T00:00:00Z')) : best, 0);
  const cmp = {
    new: (a, b) => (b.pub || 0) - (a.pub || 0) || (a.id < b.id ? 1 : -1),
    oldest: (a, b) => (a.pub || Infinity) - (b.pub || Infinity),
    fixed: (a, b) => newestFix(b) - newestFix(a),
    epss: (a, b) => (b.epss || 0) - (a.epss || 0),
    cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1),
    triage: (a, b) =>
      (b.kev || 0) - (a.kev || 0) ||
      (b.ransom || 0) - (a.ransom || 0) ||
      (b.epss || 0) - (a.epss || 0) ||
      (b.cvss ?? -1) - (a.cvss ?? -1) ||
      (b.pub || 0) - (a.pub || 0),
  }[state.sort || view().sort];
  filtered.sort(cmp);
}

/* -------------------------------------------------------------- render */

function renderMore() {
  if (!filtered.length || rendered >= filtered.length) return;
  const frag = document.createDocumentFragment();
  const end = Math.min(rendered + BATCH, filtered.length);
  for (let n = rendered; n < end; n++) frag.appendChild(rowEl(filtered[n]));
  $('#tbody').appendChild(frag);
  rendered = end;
}

function triageBadges(r) {
  const out = [];
  if (r.kev) out.push('<span class="badge kev" title="Listed in CISA\'s Known Exploited Vulnerabilities catalogue">KEV</span>');
  if (r.ransom) out.push('<span class="badge ransom" title="KEV records known ransomware campaign use">ransomware</span>');
  if (r.cvss !== undefined) {
    out.push('<span class="badge cvss ' + severityOf(r) +
      '" title="CVSS v3.1 base score from the kernel CNA vector">' + r.cvss.toFixed(1) + '</span>');
  }
  if (r.epss !== undefined) {
    out.push('<span class="badge epss" title="EPSS ' + (r.epss * 100).toFixed(2) +
      '% probability of exploitation in the next 30 days, higher than ' +
      (r.epct * 100).toFixed(0) + '% of all scored CVEs">EPSS ' +
      (r.epss * 100).toFixed(1) + '%</span>');
  }
  if (r.av) {
    out.push('<span class="badge av' + (r.av === 'N' || r.av === 'A' ? ' net' : '') +
      '" title="CVSS attack vector">AV:' + r.av + '</span>');
  }
  return out.join(' ');
}

function releasePills(r) {
  return meta.columns.map((col, i) => {
    if (r.st[i] === '-') return '';
    const s = lifecycle(r, i);
    const extra = s.version ? ' in ' + s.version : '';
    return '<span class="pill ' + s.code + '" title="' +
      esc(col.label + ': ' + s.word + extra) + '">' +
      esc(col.suite) + '</span>';
  }).join('');
}

function rowEl(r) {
  const tr = document.createElement('tr');
  tr.className = 'row';
  tr.dataset.cve = r.id;
  tr.innerHTML =
    '<td class="starcell">' + starHtml(r.id, false) + '</td>' +
    '<td class="cve">' + esc(r.id) + '</td>' +
    '<td class="when">' + fmtDate(r.pub) +
      (r.pub ? '<span class="sub">' + agoLabel(r.pub) + '</span>' : '') + '</td>' +
    '<td class="sum">' + esc(r.sum) +
      (r.area ? '<span class="sub mono">' + esc(r.area) + '/</span>' : '') + '</td>' +
    '<td><div class="triage-cell">' + triageBadges(r) + '</div></td>' +
    '<td class="pills-cell"><div class="pills">' + releasePills(r) + '</div></td>';
  tr.addEventListener('click', () => toggleDetail(tr, r));
  return tr;
}

/* -------------------------------------------------------------- detail */

async function toggleDetail(tr, r) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('detail')) {
    next.remove();
    tr.classList.remove('open');
    if (openCve === r.id) { openCve = null; writeHash(); }
    return;
  }
  document.querySelectorAll('tr.detail').forEach((el) => el.remove());
  document.querySelectorAll('tr.row.open').forEach((el) => el.classList.remove('open'));
  tr.classList.add('open');
  openCve = r.id;
  writeHash();

  // Opening a result is the reader saying the query in the box worked.
  if (state.q.trim()) {
    clearTimeout(settleTimer);
    recordSearch(state.q);
  }

  const holder = document.createElement('tr');
  holder.className = 'detail';
  holder.innerHTML = '<td colspan="6"><div class="detail dim">Loading…</div></td>';
  tr.after(holder);

  const chunk = await loadChunk(r.c);
  holder.querySelector('td').innerHTML = detailHtml(r, chunk[r.id] || {});
}

/* ------------------------------------------------- CVSS reasoning (lazy) */

/* The kernel CNA writes a paragraph per CVSS metric saying why it scored that
 * metric the way it did.  It is the only published account of what a score is
 * based on, and it is the difference between "9.8" and a reason to believe
 * it, so the expanded CVE offers it whenever the CNA wrote one. */
function reasonsHtml(cve, vector, reasons) {
  const v = vectorParts(vector);
  const items = CVSS_METRICS.map(([code, name, worst, words]) => {
    const val = v[code] || '';
    const word = words[val] || '';
    const top = !!val && val === worst;
    return '<div class="reason' + (top ? ' top' : '') + '">' +
      '<dt><span class="metric">' + esc(code + ':' + (val || '?')) + '</span>' +
      '<span class="metric-name">' + esc(name + (word ? ', ' + word : '')) + '</span></dt>' +
      '<dd>' + esc(reasons[code] ||
        'The CNA published no note for this metric.') + '</dd>' +
      '</div>';
  }).join('');
  return '<p class="panel-note">Quoted from the kernel CNA\'s own scoring file, ' +
    'word for word. A highlighted metric carries the most severe value CVSS v3.1 ' +
    'defines for it, which is what pushes the score up. ' +
    src(vulnsFile(cve, 'cvss'), 'Reasoning source: the kernel CNA scoring file') + '</p>' +
    '<dl class="reasons">' + items + '</dl>';
}

/* Two thirds of the CVEs here have no vector at all, so the absent case is the
 * common one and says so plainly rather than offering a control with nothing
 * behind it. */
function reasonsBlock(r, d) {
  const head = '<h3>Why the CNA scored it this way</h3>';
  if (d.has_reasons) {
    const id = 'reasons-' + r.id;
    return '<div class="reasons-block">' + head +
      '<p class="panel-note">The Linux kernel CNA published a written ' +
      'justification for each of the eight CVSS metrics. It is fetched only ' +
      'when you ask for it.</p>' +
      '<button type="button" class="ghost reasons-btn" data-cve="' + esc(r.id) +
        '" data-chunk="' + esc(String(r.c)) +
        '" data-vector="' + esc(d.vector || '') +
        '" aria-expanded="false" aria-controls="' + esc(id) + '">' +
        'Show the reasoning for each metric</button>' +
      '<div class="reasons-out" id="' + esc(id) + '" hidden></div></div>';
  }
  const note = d.vector
    ? 'The kernel CNA published a vector for ' + esc(r.id) + ' but no written ' +
      'reasoning for the individual metrics, so there is nothing to quote. ' +
      src(vulnsFile(r.id, 'cvss'), 'Vector source: the kernel CNA scoring file')
    : 'The kernel CNA published no CVSS vector and no reasoning for ' + esc(r.id) +
      ', which is why it is shown as unrated rather than given an invented score. ' +
      (meta.rationale_count
        ? meta.rationale_count.toLocaleString() + ' of the ' + meta.total.toLocaleString() +
          ' CVEs here carry reasoning; this is not one of them.'
        : '');
  return '<div class="reasons-block">' + head +
    '<p class="panel-note">' + note + '</p></div>';
}

async function toggleReasons(btn) {
  const out = document.getElementById(btn.getAttribute('aria-controls'));
  if (!out) return;
  if (!out.hidden) {
    out.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = 'Show the reasoning for each metric';
    return;
  }
  if (!out.dataset.filled) {
    // A second press while the fetch is in flight would start a second one.
    // A busy flag stops that without disabling the button, which would take
    // the focus off it and leave a keyboard reader nowhere.
    if (btn.dataset.busy) return;
    btn.dataset.busy = '1';
    btn.textContent = 'Loading the reasoning';
    try {
      const chunk = await loadRationale(Number(btn.dataset.chunk));
      out.innerHTML = reasonsHtml(btn.dataset.cve, btn.dataset.vector,
        chunk[btn.dataset.cve] || {});
    } catch (e) {
      out.innerHTML = '<p class="panel-note">The reasoning file could not be ' +
        'loaded. ' + src(vulnsFile(btn.dataset.cve, 'cvss'),
          'Reasoning source: the kernel CNA scoring file') + '</p>';
    }
    out.dataset.filled = '1';
    delete btn.dataset.busy;
  }
  out.hidden = false;
  btn.setAttribute('aria-expanded', 'true');
  btn.textContent = 'Hide the reasoning';
}

function detailHtml(r, d) {
  const isCve = CVE_RE.test(r.id);
  const links = [['Permalink for this CVE', 'cve/' + r.id + '.html', false],
    ['Debian tracker', TRACKER + r.id, true]];
  // cve.org and NVD key on a real CVE id; the Debian tracker also carries a
  // few TEMP-... placeholders for issues that have not been assigned one.
  if (isCve) {
    links.push(['CVE record', 'https://www.cve.org/CVERecord?id=' + r.id, true]);
    links.push(['NVD', 'https://nvd.nist.gov/vuln/detail/' + r.id, true]);
  }
  // The CNA record exists only for the CVEs vulns.git itself published, and
  // the publication date is read out of the commit that added it, so r.pub is
  // exactly the test for whether that file is there to link to.
  if (isCve && r.pub) links.push(['kernel CNA record', vulnsFile(r.id, 'json'), true]);
  if (d.debianbug) {
    links.push(['Debian bug #' + d.debianbug, 'https://bugs.debian.org/' + d.debianbug, true]);
  }

  // The answer table: one row per release, ending in what to do about it.
  const actionRows = meta.columns.map((col, i) => {
    if (r.st[i] === '-') return '';
    const s = lifecycle(r, i);
    const advUrl = s.advisory ? advisoryUrl(s.advisory, s.when) : '';
    return '<tr>' +
      '<td><strong>' + esc(col.release || col.suite) + '</strong>' +
        '<span class="sub">' + esc(col.label) + '</span></td>' +
      '<td><span class="state-chip s-' + s.code + '">' + esc(s.word) + '</span>' +
        (s.advisory
          ? '<span class="sub">' +
            ext(TRACKER + s.advisory, s.advisory, '') +
            ' · ' + esc(s.when) +
            (advUrl ? ' · ' + ext(advUrl, 'text', s.advisory + ' announcement') : '') +
            '</span>'
          : '') + '</td>' +
      '<td class="mono">' + esc(s.version || col.version || '') + '</td>' +
      '<td class="action">' + esc(advice(r, i, d)) + '</td>' +
      '</tr>';
  }).join('');

  const upstreamRows = (d.pairs || []).map(([intro, fixed, sha]) =>
    '<tr><td class="mono">' + esc(intro) + '</td><td class="mono">' + esc(fixed) + '</td>' +
    '<td>' + ext('https://git.kernel.org/stable/c/' + sha, sha, '') + '</td></tr>').join('');

  const advisoryRows = (d.advisories || []).map((adv) => {
    const url = advisoryUrl(adv.id, adv.date);
    const suites = Object.keys(adv.releases || {}).sort()
      .map((k) => k + ' ' + adv.releases[k]).join(', ');
    return '<tr><td class="mono">' +
      (url ? ext(url, adv.id, adv.id + ' announcement') : esc(adv.id)) +
      '</td><td class="mono">' + esc(adv.date || '') + '</td>' +
      '<td>' + esc(suites || adv.package || '') + '</td>' +
      '<td>' + ext(TRACKER + adv.id, 'tracker', adv.id + ' in the Debian tracker') +
      '</td></tr>';
  }).join('');

  const kevBox = d.kev ? (
    '<div class="kevbox"><h3>Known to be exploited in the wild</h3><dl class="kv">' +
    '<dt>Added to KEV</dt><dd>' + esc(d.kev.added || '') + '</dd>' +
    '<dt>Federal due date</dt><dd>' + esc(d.kev.due || '') + '</dd>' +
    '<dt>Ransomware use</dt><dd>' + (d.kev.ransomware ? 'known' : 'unknown') + '</dd>' +
    (d.kev.action ? '<dt>Required action</dt><dd>' + esc(d.kev.action) + '</dd>' : '') +
    '</dl><p class="srcline">' + src(KEV_CATALOG,
      'KEV source: the CISA catalogue, which has no per-CVE page',
      'the KEV catalogue') +
    '</p></div>') : '';

  return '<div class="detail">' +
    '<div class="detail-tools">' + starHtml(r.id, true) + '</div>' +
    '<h3>What to do, per Debian release</h3>' +
    '<p class="panel-note">Every status below is the one the Debian Security Team ' +
      'publishes for this CVE. ' +
      src(TRACKER + r.id, 'Status source: the Debian Security Tracker entry') + '</p>' +
    '<div class="tablewrap"><table class="answer"><thead><tr>' +
      '<th>Release</th><th>Status</th><th>Version</th><th>What this means</th>' +
    '</tr></thead><tbody>' + actionRows + '</tbody></table></div>' +
    '<div class="detail-grid"><div>' +
      '<h3>What the bug is</h3>' +
      '<p class="desc">' + esc(d.desc || 'No description published.') + '</p>' +
      (d.files && d.files.length
        ? '<h3>Where it lives</h3>' +
          '<p class="panel-note">The fix touches these files. If the subsystem ' +
          'is one you do not use, the practical exposure is lower, though the ' +
          'package is still the vulnerable one.</p>' +
          '<p class="files">' + d.files.map(esc).join('<br>') + '</p>'
        : '') +
      '<div class="linkrow">' +
        links.map(([t, u, external]) => (external
          ? ext(u, t, '')
          : '<a href="' + esc(u) + '">' + esc(t) + '</a>')).join('') +
      '</div>' +
    '</div><div>' +
      kevBox +
      '<h3>Signals</h3><dl class="kv">' +
        '<dt>Published</dt><dd>' + fmtDate(r.pub) +
          (r.pub
            ? ' <span class="dim">(' + agoLabel(r.pub) + ')</span>' +
              '<span class="srcline">' + src(vulnsLog(r.id), 'Published date source: the vulns.git commit') + '</span>'
            : '') + '</dd>' +
        '<dt>CVSS</dt><dd>' + (r.cvss !== undefined
          ? r.cvss.toFixed(1) + ' ' + severityOf(r) +
            '<br><span class="mono dim">' + esc(d.vector || '') + '</span>'
          : '<span class="dim">no vector published</span>') +
          (d.vector
            ? '<span class="srcline">' +
              src(vulnsFile(r.id, 'cvss'), 'CVSS source: the kernel CNA scoring file') +
              ' ' + ext(CVSS_CALC + d.vector, 'recompute it',
                'Recompute this score in the FIRST CVSS v3.1 calculator') +
              '</span>'
            : '') + '</dd>' +
        '<dt>Attack vector</dt><dd>' + (r.av
          ? esc((AV_WORDS[r.av] || 'unrecognised') + ' (AV:' + r.av + ')') +
            '<span class="srcline">' +
            src(vulnsFile(r.id, 'cvss'), 'Attack vector source: the kernel CNA scoring file') +
            '</span>'
          : '<span class="dim">not published</span>') + '</dd>' +
        '<dt>EPSS</dt><dd>' + (r.epss !== undefined
          ? (r.epss * 100).toFixed(2) + '%, higher than ' + (r.epct * 100).toFixed(1) +
            '% of all CVEs' +
            '<span class="srcline">' + src(EPSS_API + r.id, 'EPSS source: the FIRST EPSS record') + '</span>'
          : '<span class="dim">not scored</span>') + '</dd>' +
        '<dt>CISA KEV</dt><dd>' + (r.kev ? 'listed' : '<span class="dim">not listed</span>') +
          '<span class="srcline">' + src(KEV_CATALOG,
            'KEV source: the CISA catalogue, which has no per-CVE page',
            'the KEV catalogue') + '</span></dd>' +
        '<dt>Debian urgency</dt><dd>' + esc(r.urg || 'not yet assigned') +
          '<span class="srcline">' + src(TRACKER + r.id, 'Debian urgency source: the Debian Security Tracker') + '</span></dd>' +
        '<dt>Subsystem</dt><dd class="mono">' + esc(d.subsystem || 'unknown') + '</dd>' +
      '</dl>' +
      (upstreamRows
        ? '<h3>Upstream fixes</h3>' +
          '<p class="panel-note">The versions the CNA records as introducing and ' +
          'fixing this, and the commit for each. ' +
          (isCve && r.pub
            ? src(vulnsFile(r.id, 'dyad'), 'Upstream version source: the CNA version-pair file')
            : '') + '</p>' +
          '<table class="mini"><thead><tr><th>Introduced</th>' +
          '<th>Fixed in</th><th>Commit</th></tr></thead><tbody>' + upstreamRows +
          '</tbody></table>'
        : '') +
      (advisoryRows
        ? '<h3>Debian advisories</h3>' +
          '<div class="tablewrap"><table class="mini"><thead><tr><th>Advisory</th>' +
          '<th>Date</th><th>Shipped to</th><th>Debian</th></tr></thead><tbody>' +
          advisoryRows + '</tbody></table></div>'
        : '') +
    '</div></div>' +
    reasonsBlock(r, d) +
    '</div>';
}

function seriesOf(version) {
  const m = /^(?:\d+:)?(\d+\.\d+)/.exec(version || '');
  return m ? m[1] : '';
}

async function focusCve(cve) {
  let idx = filtered.findIndex((r) => r.id === cve);
  if (idx === -1) {
    // A shared or pasted link must resolve wherever the reader landed.
    state.view = 'all';
    state.q = cve;
    apply();
    idx = filtered.findIndex((r) => r.id === cve);
    if (idx === -1) return;
  }
  while (rendered <= idx) renderMore();
  const tr = document.querySelector('tr.row[data-cve="' + cve + '"]');
  if (!tr) return;
  if (typeof tr.scrollIntoView === 'function') tr.scrollIntoView({ block: 'center' });
  if (!tr.classList.contains('open')) toggleDetail(tr, filtered[idx]);
}

/* ---------------------------------------------------------------- hash */

function writeHash() {
  const parts = [];
  const def = {
    view: 'latest', q: '', rel: 'any', status: 'any',
    sev: 'any', av: 'any', area: 'any', sort: '',
  };
  for (const [k, v] of Object.entries(def)) {
    if (state[k] !== v) parts.push(k + '=' + encodeURIComponent(state[k]));
  }
  // Ids only, with the constant CVE- prefix dropped: a fifty-CVE set is a few
  // hundred characters, which every browser and chat client carries intact.
  if (shared) parts.push('stars=' + [...shared].map((id) => id.slice(4)).join(','));
  if (openCve) parts.push('cve=' + openCve);
  history.replaceState(null, '', location.pathname + location.search +
    (parts.length ? '#' + parts.join('&') : ''));
}

function readHash() {
  const raw = location.hash.slice(1);
  if (!raw) return;
  if (CVE_RE.test(raw)) { openCve = raw.toUpperCase(); return; }
  let sawView = false;
  for (const part of raw.split('&')) {
    const [k, v] = part.split('=');
    const value = decodeURIComponent(v ?? '');
    if (k === 'cve') { openCve = value.toUpperCase(); continue; }
    if (k === 'stars') { setShared(value); continue; }
    if (!(k in state)) continue;
    if (k === 'view') sawView = true;
    if (typeof state[k] === 'boolean') state[k] = value === '1';
    else state[k] = value;
  }
  // A bare #stars= link is a starred set, so land on it rather than on Latest.
  if (shared && !sawView) state.view = 'starred';
  if (state.rel !== 'any' || state.status !== 'any' || state.area !== 'any') {
    $('#refine').open = true;
  }
}

/* --------------------------------------------------------------- theme */

function applyStoredTheme() {
  let stored = null;
  try { stored = localStorage.getItem('theme'); } catch (e) { /* private mode */ }
  if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
}

function toggleTheme() {
  const root = document.documentElement;
  const dark = root.dataset.theme
    ? root.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
  try { localStorage.setItem('theme', root.dataset.theme); } catch (e) { /* ignore */ }
}

boot().then(() => {
  if (openCve) focusCve(openCve);
}).catch((err) => {
  $('#view-title').textContent = 'Failed to load data';
  console.error(err);
});
