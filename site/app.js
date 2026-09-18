/* Debian Linux kernel CVE tracker.
 *
 * Everything the page shows comes out of site/data/, which scripts/build.py
 * regenerates from the Debian Security Tracker, the kernel CNA's vulns.git,
 * CISA KEV and FIRST EPSS.  No scoring or guessing happens here: the page
 * filters, sorts and renders published values.
 */
'use strict';

const BATCH = 60;           // rows rendered per scroll batch
const $ = (sel) => document.querySelector(sel);

const state = {
  q: '', col: 0, status: 'any', sev: 'any', av: 'any', area: 'any',
  since: 0, sort: 'new', kev: false, adv: false, pending: false, deep: false,
};

let meta = null;
let rows = [];
let filtered = [];
let rendered = 0;
let openCve = null;
const detailCache = new Map();   // chunk id -> {cve: detail}
const deepText = new Map();      // cve -> lowercased description

/* ---------------------------------------------------------------- utils */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const fmtDate = (ts) => ts
  ? new Date(ts * 1000).toISOString().slice(0, 10)
  : '—';

const DAY = 86400;

function relative(ts) {
  if (!ts) return '';
  const days = Math.floor((Date.now() / 1000 - ts) / DAY);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 30) return days + ' days ago';
  if (days < 365) return Math.floor(days / 30) + ' months ago';
  return Math.floor(days / 365) + ' years ago';
}

const STATUS_WORD = {
  V: 'vulnerable', I: 'no-dsa', F: 'fixed',
  N: 'not affected', U: 'undetermined', '-': 'n/a',
};

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
  buildSuiteControls();
  buildAreaOptions();
  $('#deep-size').textContent = '(~' + Math.round(meta.total * 1.4 / 1000) + ' MB)';
  wireControls();
  readHash();
  apply();
}

function chunkUrl(n) { return 'data/details/' + n + '.json'; }

async function loadChunk(n) {
  if (detailCache.has(n)) return detailCache.get(n);
  const data = await fetch(chunkUrl(n)).then((r) => r.json());
  detailCache.set(n, data);
  return data;
}

/* --------------------------------------------------------- suite cards */

function buildSuiteControls() {
  const cards = $('#suite-cards');
  const select = $('#col');
  cards.innerHTML = '';
  select.innerHTML = '';

  meta.columns.forEach((col, i) => {
    const tally = meta.counts[col.id];
    const open = tally.V + tally.I;
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'suite-card';
    card.setAttribute('aria-pressed', String(i === state.col));
    card.dataset.col = String(i);
    card.innerHTML =
      '<div class="sc-name">' + esc(col.release || col.suite) + '</div>' +
      '<div class="sc-role">' + esc(col.label) +
        (col.role ? ' · ' + esc(col.role) : '') + '</div>' +
      '<div class="sc-ver">' + esc(col.version || 'unknown version') + '</div>' +
      '<div class="sc-open' + (open ? '' : ' zero') + '">' + open.toLocaleString() +
        ' <span>unfixed' + (tally.I ? ' (' + tally.I + ' no-dsa)' : '') + '</span></div>';
    card.addEventListener('click', () => {
      state.col = i;
      syncControls();
      apply();
    });
    cards.appendChild(card);

    const opt = document.createElement('option');
    opt.value = String(i);
    opt.textContent = col.label + (col.version ? ' — ' + col.version : '');
    select.appendChild(opt);
  });

  renderTriageSummary();
}

function renderTriageSummary() {
  const i = state.col;
  const col = meta.columns[i];
  let open = 0, kev = 0, pending = 0, network = 0, highSev = 0;
  for (const r of rows) {
    const code = r.st[i];
    if (code !== 'V' && code !== 'I') continue;
    open++;
    if (r.kev) kev++;
    if (r.up && r.up[i] === 'P') pending++;
    if (r.av === 'N' || r.av === 'A') network++;
    if (r.cvss >= 7) highSev++;
  }
  $('#triage-summary').innerHTML = [
    ['unfixed in ' + esc(col.label), open, false],
    ['in CISA KEV', kev, kev > 0],
    ['CVSS 7.0 or higher', highSev, false],
    ['network or adjacent reachable', network, false],
    ['fix already released upstream', pending, false],
  ].map(([label, n, alarm]) =>
    '<div class="tstat' + (alarm ? ' alarm' : '') + '"><b>' +
    n.toLocaleString() + '</b>' + label + '</div>'
  ).join('');
}

function buildAreaOptions() {
  const areas = new Map();
  for (const r of rows) if (r.area) areas.set(r.area, (areas.get(r.area) || 0) + 1);
  const sorted = [...areas.entries()].sort((a, b) => b[1] - a[1]);
  const select = $('#area');
  for (const [name, n] of sorted) {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name + '/ (' + n.toLocaleString() + ')';
    select.appendChild(opt);
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
  bind('#q', 'q');
  bind('#col', 'col', Number);
  bind('#status', 'status');
  bind('#sev', 'sev');
  bind('#av', 'av');
  bind('#area', 'area');
  bind('#since', 'since', Number);
  bind('#sort', 'sort');
  bind('#kev', 'kev');
  bind('#adv', 'adv');
  bind('#pending', 'pending');

  $('#deep').addEventListener('change', async (e) => {
    state.deep = e.target.checked;
    if (state.deep) await loadAllDetails();
    apply();
  });

  $('#reset').addEventListener('click', () => {
    Object.assign(state, {
      q: '', status: 'any', sev: 'any', av: 'any', area: 'any',
      since: 0, sort: 'new', kev: false, adv: false, pending: false,
    });
    syncControls();
    apply();
  });

  $('#theme-toggle').addEventListener('click', toggleTheme);

  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) renderMore();
  }, { rootMargin: '600px' });
  io.observe($('#sentinel'));

  window.addEventListener('hashchange', () => {
    const cve = location.hash.slice(1);
    if (cve && cve !== openCve && /^CVE-/.test(cve)) focusCve(cve);
  });
}

function syncControls() {
  $('#q').value = state.q;
  $('#col').value = String(state.col);
  $('#status').value = state.status;
  $('#sev').value = state.sev;
  $('#av').value = state.av;
  $('#area').value = state.area;
  $('#since').value = String(state.since);
  $('#sort').value = state.sort;
  $('#kev').checked = state.kev;
  $('#adv').checked = state.adv;
  $('#pending').checked = state.pending;
  document.querySelectorAll('.suite-card').forEach((card) => {
    card.setAttribute('aria-pressed', String(Number(card.dataset.col) === state.col));
  });
}

/* ------------------------------------------------------------ deep search */

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
  const i = state.col;
  const q = state.q.trim().toLowerCase();
  const terms = q ? q.split(/\s+/) : [];
  const cutoff = state.since ? Date.now() / 1000 - state.since * DAY : 0;

  filtered = rows.filter((r) => {
    const code = r.st[i];
    if (state.status !== 'any' && !state.status.includes(code)) return false;
    if (state.kev && !r.kev) return false;
    if (state.adv && !r.adv) return false;
    if (state.pending && !(r.up && r.up[i] === 'P')) return false;
    if (state.av !== 'any' && r.av !== state.av) return false;
    if (state.area !== 'any' && r.area !== state.area) return false;
    if (cutoff && !(r.pub && r.pub >= cutoff)) return false;
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
  renderTriageSummary();
  syncFeedLink();

  $('#result-count').textContent =
    filtered.length.toLocaleString() + ' of ' + rows.length.toLocaleString() + ' CVEs';
  $('#sort-note').textContent = sortNote();
  $('#empty').hidden = filtered.length > 0;

  $('#tbody').innerHTML = '';
  rendered = 0;
  renderMore();
}

function severityOf(r) {
  if (r.cvss === undefined) return 'unrated';
  if (r.cvss >= 9) return 'critical';
  if (r.cvss >= 7) return 'high';
  if (r.cvss >= 4) return 'medium';
  return 'low';
}

function sortRows() {
  const cmp = {
    // Newest first; undated CVEs (pre-2024, before the kernel was its own
    // CNA) fall to the end, ordered by id.
    new: (a, b) => (b.pub || 0) - (a.pub || 0) || (a.id < b.id ? 1 : -1),
    id: (a, b) => (a.id < b.id ? 1 : -1),
    epss: (a, b) => (b.epss || 0) - (a.epss || 0),
    cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1),
    // A fixed, documented rule - see sortNote().
    triage: (a, b) =>
      (b.kev || 0) - (a.kev || 0) ||
      (b.ransom || 0) - (a.ransom || 0) ||
      (b.epss || 0) - (a.epss || 0) ||
      (b.cvss ?? -1) - (a.cvss ?? -1) ||
      (b.pub || 0) - (a.pub || 0),
  }[state.sort];
  filtered.sort(cmp);
}

function sortNote() {
  if (state.sort !== 'triage') return '';
  return 'Triage order is a fixed rule, applied in this sequence: CISA KEV ' +
    'membership, then known ransomware use, then EPSS score, then CVSS base ' +
    'score, then publication date. Every input is a published value.';
}

/* -------------------------------------------------------------- render */

function renderMore() {
  if (rendered >= filtered.length) return;
  const tbody = $('#tbody');
  const frag = document.createDocumentFragment();
  const end = Math.min(rendered + BATCH, filtered.length);
  for (let n = rendered; n < end; n++) frag.appendChild(rowEl(filtered[n]));
  tbody.appendChild(frag);
  rendered = end;
}

function triageBadges(r, col) {
  const out = [];
  if (r.kev) out.push('<span class="badge kev" title="Listed in CISA\'s Known Exploited Vulnerabilities catalogue">KEV</span>');
  if (r.ransom) out.push('<span class="badge ransom" title="KEV records known ransomware campaign use">ransomware</span>');
  if (r.cvss !== undefined) {
    out.push('<span class="badge cvss ' + severityOf(r) + '" title="CVSS v3.1 base score from the kernel CNA vector">' +
      r.cvss.toFixed(1) + '</span>');
  }
  if (r.epss !== undefined) {
    const pct = (r.epct * 100).toFixed(0);
    out.push('<span class="badge epss" title="EPSS ' + (r.epss * 100).toFixed(2) +
      '% probability of exploitation in the next 30 days — higher than ' + pct +
      '% of all scored CVEs">EPSS ' + (r.epss * 100).toFixed(1) + '%</span>');
  }
  if (r.av) {
    out.push('<span class="badge av' + (r.av === 'N' || r.av === 'A' ? ' net' : '') +
      '" title="CVSS attack vector">AV:' + r.av + '</span>');
  }
  if (r.adv) out.push('<span class="badge adv" title="Fixed by a Debian security advisory">' + esc(r.adv) + '</span>');
  // Whether a fix is already sitting upstream depends on which suite you are
  // looking at, so this badge follows the suite selector.
  if (r.up && r.up[col] === 'P') {
    out.push('<span class="badge pending" title="Debian lists this suite as vulnerable, but the stable series it tracks already has the fix">fix upstream</span>');
  }
  return out.join(' ');
}

function suitePills(r) {
  return meta.columns.map((col, i) => {
    const code = r.st[i];
    if (code === '-') return '';
    const fix = r.fix && r.fix[i];
    const pendingCode = r.up ? r.up[i] : '.';
    let tip = col.label + ': ' + STATUS_WORD[code];
    if (fix) tip += ' in ' + fix;
    if (pendingCode === 'P') tip += ' — fix already released upstream';
    if (pendingCode === 'W') tip += ' — no upstream fix for this series yet';
    return '<span class="pill ' + code + '" title="' + esc(tip) + '">' +
      esc(col.suite) + (pendingCode === 'P' ? ' ↑' : '') + '</span>';
  }).join('');
}

function rowEl(r) {
  const tr = document.createElement('tr');
  tr.className = 'row';
  tr.dataset.cve = r.id;
  tr.innerHTML =
    '<td class="cve">' + esc(r.id) + '</td>' +
    '<td class="pub" title="' + esc(relative(r.pub)) + '">' + fmtDate(r.pub) + '</td>' +
    '<td><div class="triage-cell">' + triageBadges(r, state.col) + '</div></td>' +
    '<td class="sum">' + esc(r.sum) + '</td>' +
    '<td><div class="pills">' + suitePills(r) + '</div></td>';
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

  const row = document.createElement('tr');
  row.className = 'detail';
  row.innerHTML = '<td colspan="5"><div class="detail dim">Loading…</div></td>';
  tr.after(row);

  const chunk = await loadChunk(r.c);
  row.querySelector('td').innerHTML = detailHtml(r, chunk[r.id] || {});
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
  if (d.debianbug) {
    links.push(['Debian bug #' + d.debianbug, 'https://bugs.debian.org/' + d.debianbug]);
  }

  const statusRows = meta.columns.map((col, i) => {
    const code = r.st[i];
    if (code === '-') return '';
    const fix = (r.fix && r.fix[i]) || '';
    const pendingCode = r.up ? r.up[i] : '.';
    let note = '';
    if (pendingCode === 'P') {
      const series = seriesOf(col.version);
      const up = d.upstream && d.upstream[series];
      note = '<span class="badge pending">fix in ' + esc(up || 'upstream') + '</span>';
    } else if (pendingCode === 'W') {
      note = '<span class="badge waiting">no upstream fix yet</span>';
    }
    if (code === 'I' && r.nodsa && r.nodsa[col.id]) {
      note = '<span class="badge waiting">' + esc(r.nodsa[col.id]) + '</span>';
    }
    return '<tr><td><span class="pill ' + code + '">' + esc(col.suite) + '</span></td>' +
      '<td>' + STATUS_WORD[code] + '</td>' +
      '<td class="mono">' + esc(fix || col.version || '') + '</td>' +
      '<td>' + note + '</td></tr>';
  }).join('');

  const upstreamRows = (d.pairs || []).map(([intro, fixed, sha]) =>
    '<tr><td class="mono">' + esc(intro) + '</td><td class="mono">' + esc(fixed) + '</td>' +
    '<td><a class="mono" href="https://git.kernel.org/stable/c/' + esc(sha) + '">' +
    esc(sha) + '</a></td></tr>'
  ).join('');

  const kevBox = d.kev ? (
    '<div class="kevbox"><h3>Known exploited</h3>' +
    '<dl class="kv">' +
    '<dt>Added to KEV</dt><dd>' + esc(d.kev.added || '') + '</dd>' +
    '<dt>Federal due date</dt><dd>' + esc(d.kev.due || '') + '</dd>' +
    '<dt>Ransomware use</dt><dd>' + (d.kev.ransomware ? 'known' : 'unknown') + '</dd>' +
    (d.kev.action ? '<dt>Required action</dt><dd>' + esc(d.kev.action) + '</dd>' : '') +
    '</dl></div>'
  ) : '';

  return '<div class="detail"><div class="detail-grid"><div>' +
    '<h3>Description</h3>' +
    '<p class="desc">' + esc(d.desc || 'No description published.') + '</p>' +
    (d.files && d.files.length
      ? '<h3>Files touched by the fix</h3><p class="files">' +
        d.files.map(esc).join('<br>') + '</p>'
      : '') +
    '<div class="linkrow">' +
      links.map(([t, u]) => '<a href="' + esc(u) + '">' + esc(t) + '</a>').join('') +
    '</div>' +
  '</div><div>' +
    kevBox +
    '<h3>Triage</h3><dl class="kv">' +
      '<dt>CVSS</dt><dd>' + (r.cvss !== undefined
        ? r.cvss.toFixed(1) + ' ' + severityOf(r) + '<br><span class="mono dim">' + esc(d.vector || '') + '</span>'
        : '<span class="dim">no vector published</span>') + '</dd>' +
      '<dt>EPSS</dt><dd>' + (r.epss !== undefined
        ? (r.epss * 100).toFixed(2) + '% — higher than ' + (r.epct * 100).toFixed(1) + '% of all CVEs'
        : '<span class="dim">not scored</span>') + '</dd>' +
      '<dt>KEV</dt><dd>' + (r.kev ? 'listed' : '<span class="dim">not listed</span>') + '</dd>' +
      '<dt>Debian urgency</dt><dd>' + esc(r.urg || 'not yet assigned') + '</dd>' +
      '<dt>Scope</dt><dd>' + esc(d.scope || 'unknown') + '</dd>' +
      '<dt>Subsystem</dt><dd class="mono">' + esc(d.subsystem || 'unknown') + '</dd>' +
      (d.advisories && d.advisories.length
        ? '<dt>Advisories</dt><dd>' + d.advisories.map((a) =>
            '<a href="https://security-tracker.debian.org/tracker/' + esc(a.id) + '">' +
            esc(a.id) + '</a> <span class="dim">' + esc(a.date) + '</span>').join('<br>') + '</dd>'
        : '') +
    '</dl>' +
    '<h3>Debian status</h3>' +
    '<table class="mini"><thead><tr><th>Suite</th><th>Status</th><th>Version</th><th></th></tr></thead>' +
    '<tbody>' + statusRows + '</tbody></table>' +
    (upstreamRows
      ? '<h3>Upstream fixes</h3><table class="mini">' +
        '<thead><tr><th>Introduced</th><th>Fixed in</th><th>Commit</th></tr></thead>' +
        '<tbody>' + upstreamRows + '</tbody></table>'
      : '') +
  '</div></div></div>';
}

function seriesOf(version) {
  const m = /^(?:\d+:)?(\d+\.\d+)/.exec(version || '');
  return m ? m[1] : '';
}

async function focusCve(cve) {
  const idx = filtered.findIndex((r) => r.id === cve);
  if (idx === -1) return;
  while (rendered <= idx) renderMore();
  const tr = document.querySelector('tr.row[data-cve="' + cve + '"]');
  if (tr) {
    tr.scrollIntoView({ block: 'center' });
    if (!tr.classList.contains('open')) toggleDetail(tr, filtered[idx]);
  }
}

/* ---------------------------------------------------------------- hash */

function writeHash() {
  const parts = [];
  const def = { q: '', col: 0, status: 'any', sev: 'any', av: 'any', area: 'any', since: 0, sort: 'new' };
  for (const [k, v] of Object.entries(def)) {
    if (state[k] !== v) parts.push(k + '=' + encodeURIComponent(state[k]));
  }
  for (const k of ['kev', 'adv', 'pending']) if (state[k]) parts.push(k + '=1');
  if (openCve) parts.push('cve=' + openCve);
  const hash = parts.length ? '#' + parts.join('&') : '';
  history.replaceState(null, '', location.pathname + location.search + hash);
}

function readHash() {
  const raw = location.hash.slice(1);
  if (!raw) return;
  if (/^CVE-/.test(raw)) { openCve = raw; return; }
  for (const part of raw.split('&')) {
    const [k, v] = part.split('=');
    const value = decodeURIComponent(v ?? '');
    if (k === 'cve') { openCve = value; continue; }
    if (!(k in state)) continue;
    if (typeof state[k] === 'boolean') state[k] = value === '1';
    else if (typeof state[k] === 'number') state[k] = Number(value);
    else state[k] = value;
  }
  syncControls();
}

function syncFeedLink() {
  const col = meta.columns[state.col];
  const link = $('#feed-link');
  link.href = 'data/feeds/' + col.id + '.xml';
  link.textContent = 'Atom feed: new CVEs open in ' + col.label;
}

/* --------------------------------------------------------------- theme */

function applyStoredTheme() {
  let stored = null;
  try { stored = localStorage.getItem('theme'); } catch (e) { /* private mode */ }
  if (stored === 'light' || stored === 'dark') {
    document.documentElement.dataset.theme = stored;
  }
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
  $('#result-count').textContent = 'Failed to load data';
  console.error(err);
});
