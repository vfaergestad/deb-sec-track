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

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const $ = (sel) => document.querySelector(sel);

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
const deepText = new Map();

/* ---------------------------------------------------------------- utils */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const fmtDate = (ts) => (ts ? new Date(ts * 1000).toISOString().slice(0, 10) : 'unknown');

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

/* ------------------------------------------------------------- loading */

async function boot() {
  applyStoredTheme();
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
  readHash();
  apply();
}

async function loadChunk(n) {
  if (detailCache.has(n)) return detailCache.get(n);
  const data = await fetch('data/details/' + n + '.json').then((r) => r.json());
  detailCache.set(n, data);
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
    if (CVE_RE.test(typed)) {
      state.view = 'all';
      apply();
      focusCve(typed.toUpperCase());
      return;
    }
    if (typed && state.view !== 'all') state.view = 'all';
    apply();
  });

  $('#clear-q').addEventListener('click', () => {
    state.q = '';
    state.view = 'latest';
    apply();
    $('#q').focus();
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
    const cve = location.hash.slice(1);
    if (CVE_RE.test(cve) && cve !== openCve) focusCve(cve.toUpperCase());
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

  const holder = document.createElement('tr');
  holder.className = 'detail';
  holder.innerHTML = '<td colspan="5"><div class="detail dim">Loading…</div></td>';
  tr.after(holder);

  const chunk = await loadChunk(r.c);
  holder.querySelector('td').innerHTML = detailHtml(r, chunk[r.id] || {});
}

function detailHtml(r, d) {
  const year = r.id.split('-')[1];
  const links = [
    ['Debian tracker', 'https://security-tracker.debian.org/tracker/' + r.id],
    ['CVE record', 'https://www.cve.org/CVERecord?id=' + r.id],
    ['NVD', 'https://nvd.nist.gov/vuln/detail/' + r.id],
    ['kernel CNA record',
      'https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/published/' +
      year + '/' + r.id + '.json'],
  ];
  if (d.debianbug) links.push(['Debian bug #' + d.debianbug, 'https://bugs.debian.org/' + d.debianbug]);
  // A shareable address that renders without JavaScript, for people who land
  // here from a search engine or paste the link into a ticket.
  links.unshift(['Permalink for this CVE', 'cve/' + r.id + '.html']);

  // The answer table: one row per release, ending in what to do about it.
  const actionRows = meta.columns.map((col, i) => {
    if (r.st[i] === '-') return '';
    const s = lifecycle(r, i);
    return '<tr>' +
      '<td><strong>' + esc(col.release || col.suite) + '</strong>' +
        '<span class="sub">' + esc(col.label) + '</span></td>' +
      '<td><span class="state-chip s-' + s.code + '">' + esc(s.word) + '</span>' +
        (s.advisory
          ? '<span class="sub"><a href="https://security-tracker.debian.org/tracker/' +
            esc(s.advisory) + '">' + esc(s.advisory) + '</a> · ' + esc(s.when) + '</span>'
          : '') + '</td>' +
      '<td class="mono">' + esc(s.version || col.version || '') + '</td>' +
      '<td class="action">' + esc(advice(r, i, d)) + '</td>' +
      '</tr>';
  }).join('');

  const upstreamRows = (d.pairs || []).map(([intro, fixed, sha]) =>
    '<tr><td class="mono">' + esc(intro) + '</td><td class="mono">' + esc(fixed) + '</td>' +
    '<td><a class="mono" href="https://git.kernel.org/stable/c/' + esc(sha) + '">' +
    esc(sha) + '</a></td></tr>').join('');

  const kevBox = d.kev ? (
    '<div class="kevbox"><h3>Known to be exploited in the wild</h3><dl class="kv">' +
    '<dt>Added to KEV</dt><dd>' + esc(d.kev.added || '') + '</dd>' +
    '<dt>Federal due date</dt><dd>' + esc(d.kev.due || '') + '</dd>' +
    '<dt>Ransomware use</dt><dd>' + (d.kev.ransomware ? 'known' : 'unknown') + '</dd>' +
    (d.kev.action ? '<dt>Required action</dt><dd>' + esc(d.kev.action) + '</dd>' : '') +
    '</dl></div>') : '';

  return '<div class="detail">' +
    '<h3>What to do, per Debian release</h3>' +
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
        links.map(([t, u]) => '<a href="' + esc(u) + '">' + esc(t) + '</a>').join('') +
      '</div>' +
    '</div><div>' +
      kevBox +
      '<h3>Signals</h3><dl class="kv">' +
        '<dt>Published</dt><dd>' + fmtDate(r.pub) +
          (r.pub ? ' <span class="dim">(' + agoLabel(r.pub) + ')</span>' : '') + '</dd>' +
        '<dt>CVSS</dt><dd>' + (r.cvss !== undefined
          ? r.cvss.toFixed(1) + ' ' + severityOf(r) +
            '<br><span class="mono dim">' + esc(d.vector || '') + '</span>'
          : '<span class="dim">no vector published</span>') + '</dd>' +
        '<dt>EPSS</dt><dd>' + (r.epss !== undefined
          ? (r.epss * 100).toFixed(2) + '%, higher than ' + (r.epct * 100).toFixed(1) + '% of all CVEs'
          : '<span class="dim">not scored</span>') + '</dd>' +
        '<dt>KEV</dt><dd>' + (r.kev ? 'listed' : '<span class="dim">not listed</span>') + '</dd>' +
        '<dt>Debian urgency</dt><dd>' + esc(r.urg || 'not yet assigned') + '</dd>' +
        '<dt>Subsystem</dt><dd class="mono">' + esc(d.subsystem || 'unknown') + '</dd>' +
      '</dl>' +
      (upstreamRows
        ? '<h3>Upstream fixes</h3><table class="mini"><thead><tr><th>Introduced</th>' +
          '<th>Fixed in</th><th>Commit</th></tr></thead><tbody>' + upstreamRows + '</tbody></table>'
        : '') +
    '</div></div></div>';
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
  if (openCve) parts.push('cve=' + openCve);
  history.replaceState(null, '', location.pathname + location.search +
    (parts.length ? '#' + parts.join('&') : ''));
}

function readHash() {
  const raw = location.hash.slice(1);
  if (!raw) return;
  if (CVE_RE.test(raw)) { openCve = raw.toUpperCase(); return; }
  for (const part of raw.split('&')) {
    const [k, v] = part.split('=');
    const value = decodeURIComponent(v ?? '');
    if (k === 'cve') { openCve = value.toUpperCase(); continue; }
    if (!(k in state)) continue;
    if (typeof state[k] === 'boolean') state[k] = value === '1';
    else state[k] = value;
  }
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
