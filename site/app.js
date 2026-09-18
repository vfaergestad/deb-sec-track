/* Debian Linux kernel CVE tracker.
 *
 * The page answers one workflow: a kernel CVE landed - is the release I run
 * exposed, how urgent is it, and when does the fix arrive?  Everything it
 * shows comes out of site/data/, which scripts/build.py regenerates from the
 * Debian Security Tracker, the kernel CNA's vulns.git, CISA KEV and FIRST
 * EPSS.  No scoring happens here; the page filters, sorts and renders
 * published values.
 */
'use strict';

const BATCH = 60;
const DAY = 86400;
const NEW_WINDOW = 30;    // days that count as "new"
const FIXED_WINDOW = 90;  // days back that "recently fixed" covers

// The bar for "needs attention": in CISA KEV, or an EPSS score in the top
// few percent, or a high CVSS score that is reachable from the network.
// Deliberately a fixed rule so the same CVE always lands the same way.
const ATTENTION_EPSS = 0.05;
const ATTENTION_CVSS = 7;

const $ = (sel) => document.querySelector(sel);

const VIEWS = [
  {
    id: 'attention',
    label: 'Needs attention',
    sort: 'triage',
    title: (c) => 'Unfixed in ' + c.label + ' and carrying a signal',
    note: () =>
      'Unfixed in this release and matching at least one of: listed in CISA KEV, ' +
      'EPSS at or above ' + (ATTENTION_EPSS * 100) + '%, or CVSS ' + ATTENTION_CVSS +
      '+ reachable over the network. Ordered by CISA KEV, then ransomware use, ' +
      'then EPSS, then CVSS, then publication date.',
    match: (r, i) => unfixed(r, i) && (
      r.kev ||
      (r.epss !== undefined && r.epss >= ATTENTION_EPSS) ||
      (r.cvss >= ATTENTION_CVSS && (r.av === 'N' || r.av === 'A'))
    ),
  },
  {
    id: 'new',
    label: 'New',
    sort: 'new',
    title: (c) => 'Published in the last ' + NEW_WINDOW + ' days',
    note: (c) => 'Everything the kernel CNA published in the last ' + NEW_WINDOW +
      ' days, with where ' + c.label + ' stands on each one.',
    match: (r) => r.pub && r.pub >= Date.now() / 1000 - NEW_WINDOW * DAY,
  },
  {
    id: 'waiting',
    label: 'Waiting on Debian',
    sort: 'oldest',
    title: (c) => 'Fixed upstream, not yet in ' + c.label,
    note: (c) => 'The stable series ' + c.label + ' tracks already has a release ' +
      'containing the fix, but Debian still lists the CVE as unfixed here. ' +
      'Longest waiting first.',
    match: (r, i) => r.st[i] === 'V' && r.up && r.up[i] === 'P',
  },
  {
    id: 'fixed',
    label: 'Recently fixed',
    sort: 'fixed',
    title: (c) => 'Fixed in ' + c.label + ' in the last ' + FIXED_WINDOW + ' days',
    note: () => 'CVEs where a Debian security advisory shipped the fix to this ' +
      'release recently, newest first. The date is the advisory date.',
    match: (r, i) => {
      const when = r.fd && r.fd[i];
      if (!when) return false;
      return Date.parse(when + 'T00:00:00Z') / 1000 >= Date.now() / 1000 - FIXED_WINDOW * DAY;
    },
  },
  {
    id: 'all',
    label: 'Search everything',
    sort: 'new',
    title: () => 'Every kernel CVE Debian tracks',
    note: () => 'The full archive, back to the CVEs Debian carries from before ' +
      'the kernel became its own CNA. Use the search box to narrow it.',
    match: () => true,
  },
];

const state = {
  view: 'attention', col: 0,
  q: '', status: 'any', sev: 'any', av: 'any', area: 'any',
  since: 0, sort: '', kev: false, adv: false, deep: false,
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

const fmtDate = (ts) => (ts ? new Date(ts * 1000).toISOString().slice(0, 10) : '—');

function ageDays(ts) {
  if (!ts) return null;
  return Math.floor((Date.now() / 1000 - ts) / DAY);
}

function ageLabel(ts) {
  const d = ageDays(ts);
  if (d === null) return '—';
  if (d <= 0) return 'today';
  if (d === 1) return '1 day';
  if (d < 45) return d + ' days';
  if (d < 730) return Math.round(d / 30.44) + ' months';
  return Math.round(d / 365.25) + ' years';
}

function agoLabel(ts) {
  const label = ageLabel(ts);
  if (label === '—') return '';
  return label === 'today' ? 'today' : label + ' ago';
}

const unfixed = (r, i) => r.st[i] === 'V' || r.st[i] === 'I';

const view = () => VIEWS.find((v) => v.id === state.view) || VIEWS[0];
const column = () => meta.columns[state.col];

/* Which of the five lifecycle states a CVE is in for one release. */
function lifecycle(r, i) {
  const code = r.st[i];
  if (code === '-') return { code: '-', word: 'n/a' };
  if (code === 'F') {
    const when = r.fd && r.fd[i];
    return {
      code: 'F',
      word: 'fixed',
      detail: when ? 'in an advisory on ' + when : (r.fix && r.fix[i] ? 'in ' + r.fix[i] : ''),
      advisory: r.fa && r.fa[i],
      when,
    };
  }
  if (code === 'N') return { code: 'N', word: 'not affected' };
  if (code === 'U') return { code: 'U', word: 'undetermined' };
  if (code === 'I') {
    return { code: 'I', word: "won't fix", detail: r.nodsa && r.nodsa[meta.columns[i].id] };
  }
  if (r.up && r.up[i] === 'P') {
    return { code: 'P', word: 'fix ready upstream', detail: 'waiting on Debian' };
  }
  return { code: 'V', word: 'vulnerable', detail: 'no fix published yet' };
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
  restoreSuite();
  buildSuitePicker();
  buildViewTabs();
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

/* --------------------------------------------------------- suite picker */

function restoreSuite() {
  let saved = null;
  try { saved = localStorage.getItem('suite'); } catch (e) { /* private mode */ }
  const idx = meta.columns.findIndex((c) => c.id === saved);
  if (idx >= 0) state.col = idx;
  else state.col = Math.max(0, meta.columns.findIndex((c) => c.role === 'stable'));
}

function buildSuitePicker() {
  const host = $('#suite-picker');
  host.innerHTML = '';
  meta.columns.forEach((col, i) => {
    const tally = meta.counts[col.id];
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'suite-btn';
    btn.dataset.col = String(i);
    btn.setAttribute('aria-pressed', String(i === state.col));
    btn.innerHTML =
      '<span class="sb-name">' + esc(col.release || col.suite) + '</span>' +
      '<span class="sb-suite">' + esc(col.label) + '</span>' +
      '<span class="sb-ver">' + esc(col.version || '') + '</span>' +
      '<span class="sb-open">' + (tally.V + tally.I).toLocaleString() + ' unfixed</span>';
    btn.addEventListener('click', () => {
      state.col = i;
      try { localStorage.setItem('suite', col.id); } catch (e) { /* ignore */ }
      syncControls();
      apply();
    });
    host.appendChild(btn);
  });
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
      if (v.id !== 'all') { state.q = ''; state.status = 'any'; state.since = 0; }
      syncControls();
      apply();
    });
    host.appendChild(btn);
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

/* ------------------------------------------------------------ exposure */

function renderExposure() {
  const i = state.col;
  const col = column();
  let open = 0, kev = 0, waiting = 0, stuck = 0, wontfix = 0, attention = 0;
  for (const r of rows) {
    if (!unfixed(r, i)) continue;
    open++;
    if (r.kev) kev++;
    if (r.st[i] === 'I') wontfix++;
    else if (r.up && r.up[i] === 'P') waiting++;
    else stuck++;
    if (VIEWS[0].match(r, i)) attention++;
  }

  const lag = meta.fix_lag ? meta.fix_lag[col.id] : null;
  const lagText = lag && lag.n
    ? 'Debian shipped an advisory a median of <b>' + lag.median + ' days</b> after ' +
      'publication, and within <b>' + lag.p90 + ' days</b> 90% of the time ' +
      '<span class="dim">(' + lag.n.toLocaleString() + ' advisories)</span>.'
    : 'This release gets fixes through ordinary uploads rather than security ' +
      'advisories, so there is no advisory turnaround to measure.';

  const tile = (id, n, label, cls, status) =>
    '<button type="button" class="tile ' + cls + '" data-goto="' + id + '"' +
    (status ? ' data-status="' + status + '"' : '') + '>' +
    '<b>' + n.toLocaleString() + '</b><span>' + label + '</span></button>';

  $('#exposure-body').innerHTML =
    '<p class="exposure-lead">' +
      '<b>' + open.toLocaleString() + '</b> kernel CVEs are unfixed in ' +
      '<strong>' + esc(col.release || col.suite) + '</strong> ' +
      '<span class="dim">(' + esc(col.label) + ', running ' + esc(col.version || 'unknown') + ')</span>' +
      (kev ? ' — <span class="alarm">' + kev + ' of them are in CISA KEV</span>.' : '.') +
    '</p>' +
    '<div class="tiles">' +
      tile('attention', attention, 'need attention', 'warn') +
      tile('waiting', waiting, 'fix ready upstream', 'pend') +
      tile('all', stuck, 'no fix anywhere yet', 'plain', 'V') +
      tile('all', wontfix, "Debian won't fix", 'plain', 'I') +
    '</div>' +
    '<p class="lag">' + lagText + '</p>';

  $('#exposure-body').querySelectorAll('[data-goto]').forEach((el) => {
    el.addEventListener('click', () => {
      state.view = el.dataset.goto;
      state.sort = '';
      state.status = el.dataset.status || 'any';
      syncControls();
      apply();
    });
  });
}

function renderViewCounts() {
  const i = state.col;
  for (const v of VIEWS) {
    const el = document.querySelector('[data-count="' + v.id + '"]');
    if (!el) continue;
    el.textContent = v.id === 'all'
      ? rows.length.toLocaleString()
      : rows.reduce((n, r) => n + (v.match(r, i) ? 1 : 0), 0).toLocaleString();
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
  bind('#status', 'status');
  bind('#sev', 'sev');
  bind('#av', 'av');
  bind('#area', 'area');
  bind('#since', 'since', Number);
  bind('#sort', 'sort');
  bind('#kev', 'kev');
  bind('#adv', 'adv');

  $('#deep').addEventListener('change', async (e) => {
    state.deep = e.target.checked;
    if (state.deep) await loadAllDetails();
    apply();
  });

  $('#reset').addEventListener('click', () => {
    Object.assign(state, {
      q: '', status: 'any', sev: 'any', av: 'any', area: 'any',
      since: 0, sort: '', kev: false, adv: false,
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
    if (/^CVE-/.test(cve) && cve !== openCve) focusCve(cve);
  });
}

function syncControls() {
  $('#q').value = state.q;
  $('#status').value = state.status;
  $('#sev').value = state.sev;
  $('#av').value = state.av;
  $('#area').value = state.area;
  $('#since').value = String(state.since);
  $('#sort').value = state.sort || view().sort;
  $('#kev').checked = state.kev;
  $('#adv').checked = state.adv;
  document.querySelectorAll('.suite-btn').forEach((b) => {
    b.setAttribute('aria-pressed', String(Number(b.dataset.col) === state.col));
  });
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
  const i = state.col;
  const v = view();
  const terms = state.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const cutoff = state.since ? Date.now() / 1000 - state.since * DAY : 0;

  filtered = rows.filter((r) => {
    if (!v.match(r, i)) return false;
    const code = r.st[i];
    if (state.status !== 'any' && !state.status.includes(code)) return false;
    if (state.kev && !r.kev) return false;
    if (state.adv && !r.adv) return false;
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
  renderExposure();
  renderViewCounts();
  syncControls();

  const col = column();
  $('#view-title').textContent = v.title(col);
  $('#view-note').textContent = v.note(col);
  $('#when-head').textContent = state.view === 'fixed' ? 'Fixed' : 'Published';
  $('#state-head').textContent = 'In ' + col.suite;
  $('#result-count').textContent =
    filtered.length.toLocaleString() + ' shown · ' + rows.length.toLocaleString() +
    ' CVEs tracked in total';
  $('#empty').hidden = filtered.length > 0;
  $('#empty').textContent = emptyMessage(v, col);

  const link = $('#feed-link');
  link.href = 'data/feeds/' + col.id + '.xml';
  link.textContent = 'Atom feed for ' + col.label;

  $('#tbody').innerHTML = '';
  rendered = 0;
  renderMore();
}

function emptyMessage(v, col) {
  if (v.id === 'attention') {
    return 'Nothing unfixed in ' + col.label + ' carries a KEV listing, a high ' +
      'EPSS score or a network-reachable high CVSS score. That is the good case.';
  }
  return 'Nothing matches here.';
}

function severityOf(r) {
  if (r.cvss === undefined) return 'unrated';
  if (r.cvss >= 9) return 'critical';
  if (r.cvss >= 7) return 'high';
  if (r.cvss >= 4) return 'medium';
  return 'low';
}

function sortRows() {
  const i = state.col;
  const fixTime = (r) => {
    const w = r.fd && r.fd[i];
    return w ? Date.parse(w + 'T00:00:00Z') : 0;
  };
  const cmp = {
    new: (a, b) => (b.pub || 0) - (a.pub || 0) || (a.id < b.id ? 1 : -1),
    oldest: (a, b) => (a.pub || Infinity) - (b.pub || Infinity),
    fixed: (a, b) => fixTime(b) - fixTime(a),
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
      '% probability of exploitation in the next 30 days — higher than ' +
      (r.epct * 100).toFixed(0) + '% of all scored CVEs">EPSS ' + (r.epss * 100).toFixed(1) + '%</span>');
  }
  if (r.av) {
    out.push('<span class="badge av' + (r.av === 'N' || r.av === 'A' ? ' net' : '') +
      '" title="CVSS attack vector">AV:' + r.av + '</span>');
  }
  return out.join(' ');
}

function otherSuites(r) {
  return meta.columns.map((col, i) => {
    if (i === state.col || r.st[i] === '-') return '';
    const s = lifecycle(r, i);
    return '<span class="pill ' + s.code + '" title="' + esc(col.label + ': ' + s.word) + '">' +
      esc(col.suite) + '</span>';
  }).join('');
}

function rowEl(r) {
  const i = state.col;
  const s = lifecycle(r, i);
  const tr = document.createElement('tr');
  tr.className = 'row';
  tr.dataset.cve = r.id;

  const whenCell = state.view === 'fixed' && s.when
    ? '<td class="when">' + esc(s.when) + '<span class="sub">' +
      agoLabel(Date.parse(s.when + 'T00:00:00Z') / 1000) + '</span></td>'
    : '<td class="when">' + fmtDate(r.pub) +
      (r.pub ? '<span class="sub">' + agoLabel(r.pub) + '</span>' : '') + '</td>';

  const stateCell = '<td class="state"><span class="state-chip s-' + s.code + '">' +
    esc(s.word) + '</span>' +
    (s.advisory ? '<span class="sub">' + esc(s.advisory) + '</span>'
      : s.detail ? '<span class="sub">' + esc(s.detail) + '</span>' : '') +
    ((s.code === 'V' || s.code === 'P') && r.pub
      ? '<span class="sub dim">open ' + ageLabel(r.pub) + '</span>' : '') +
    '</td>';

  tr.innerHTML =
    '<td class="cve">' + esc(r.id) + '</td>' +
    whenCell +
    stateCell +
    '<td><div class="triage-cell">' + triageBadges(r) + '</div></td>' +
    '<td class="sum">' + esc(r.sum) + '</td>' +
    '<td class="pills-cell"><div class="pills">' + otherSuites(r) + '</div></td>';
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
  holder.innerHTML = '<td colspan="6"><div class="detail dim">Loading…</div></td>';
  tr.after(holder);

  const chunk = await loadChunk(r.c);
  holder.querySelector('td').innerHTML = detailHtml(r, chunk[r.id] || {});
}

/* The question the detail panel exists to answer: what happened to this CVE,
 * in order, and where does my release sit in that sequence? */
function timelineHtml(r, d) {
  const i = state.col;
  const col = column();
  const s = lifecycle(r, i);
  const steps = [];

  steps.push({
    done: true,
    label: r.pub ? 'Published by the kernel CNA' : 'Published before the kernel became a CNA',
    when: r.pub ? fmtDate(r.pub) : 'date unknown',
    note: r.pub ? agoLabel(r.pub) : 'Debian has carried it since before 2024',
  });

  const series = seriesOf(col.version);
  const upstreamFix = d.upstream && series ? d.upstream[series] : null;
  if (upstreamFix) {
    steps.push({
      done: true,
      label: 'Fixed upstream in the ' + series + ' series',
      when: upstreamFix,
      note: col.label + ' ships ' + (col.version || '?'),
    });
  } else if (s.code === 'V') {
    steps.push({
      done: false,
      label: 'No upstream fix for the ' + (series || '?') + ' series yet',
      when: '—',
      note: 'nothing to backport so far',
    });
  }

  if (s.code === 'F') {
    steps.push({
      done: true,
      label: 'Fixed in ' + col.label,
      when: s.when || (r.fix && r.fix[i]) || 'released',
      note: s.advisory ? 'shipped in ' + s.advisory : 'shipped in ' + (r.fix[i] || 'an update'),
    });
  } else if (s.code === 'N') {
    steps.push({ done: true, label: col.label + ' was never affected', when: '—', note: '' });
  } else if (s.code === 'I') {
    steps.push({
      done: false,
      label: 'Debian will not fix this in ' + col.label,
      when: '—',
      note: s.detail || '',
    });
  } else {
    const lag = meta.fix_lag && meta.fix_lag[col.id];
    steps.push({
      done: false,
      label: 'Not yet fixed in ' + col.label,
      when: '—',
      note: lag && lag.n
        ? 'advisories for this release land a median of ' + lag.median + ' days after publication'
        : 'this release is fixed by ordinary uploads, not advisories',
    });
  }

  return '<ol class="timeline">' + steps.map((st) =>
    '<li class="' + (st.done ? 'done' : 'pending') + '">' +
    '<span class="tl-label">' + esc(st.label) + '</span>' +
    '<span class="tl-when mono">' + esc(st.when) + '</span>' +
    (st.note ? '<span class="tl-note dim">' + esc(st.note) + '</span>' : '') +
    '</li>').join('') + '</ol>';
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

  const statusRows = meta.columns.map((col, i) => {
    if (r.st[i] === '-') return '';
    const s = lifecycle(r, i);
    return '<tr><td><span class="pill ' + s.code + '">' + esc(col.suite) + '</span></td>' +
      '<td>' + esc(s.word) + '</td>' +
      '<td class="mono">' + esc((r.fix && r.fix[i]) || col.version || '') + '</td>' +
      '<td class="mono dim">' + esc(s.when || '') + '</td>' +
      '<td>' + (s.advisory
        ? '<a href="https://security-tracker.debian.org/tracker/' + esc(s.advisory) + '">' +
          esc(s.advisory) + '</a>'
        : esc(s.detail || '')) + '</td></tr>';
  }).join('');

  const upstreamRows = (d.pairs || []).map(([intro, fixed, sha]) =>
    '<tr><td class="mono">' + esc(intro) + '</td><td class="mono">' + esc(fixed) + '</td>' +
    '<td><a class="mono" href="https://git.kernel.org/stable/c/' + esc(sha) + '">' +
    esc(sha) + '</a></td></tr>').join('');

  const kevBox = d.kev ? (
    '<div class="kevbox"><h3>Known to be exploited</h3><dl class="kv">' +
    '<dt>Added to KEV</dt><dd>' + esc(d.kev.added || '') + '</dd>' +
    '<dt>Federal due date</dt><dd>' + esc(d.kev.due || '') + '</dd>' +
    '<dt>Ransomware use</dt><dd>' + (d.kev.ransomware ? 'known' : 'unknown') + '</dd>' +
    (d.kev.action ? '<dt>Required action</dt><dd>' + esc(d.kev.action) + '</dd>' : '') +
    '</dl></div>') : '';

  return '<div class="detail">' +
    '<h3>What happened, and where ' + esc(column().label) + ' stands</h3>' +
    timelineHtml(r, d) +
    '<div class="detail-grid"><div>' +
      '<h3>Description</h3>' +
      '<p class="desc">' + esc(d.desc || 'No description published.') + '</p>' +
      (d.files && d.files.length
        ? '<h3>Files touched by the fix</h3><p class="files">' + d.files.map(esc).join('<br>') + '</p>'
        : '') +
      '<div class="linkrow">' +
        links.map(([t, u]) => '<a href="' + esc(u) + '">' + esc(t) + '</a>').join('') +
      '</div>' +
    '</div><div>' +
      kevBox +
      '<h3>Triage</h3><dl class="kv">' +
        '<dt>CVSS</dt><dd>' + (r.cvss !== undefined
          ? r.cvss.toFixed(1) + ' ' + severityOf(r) +
            '<br><span class="mono dim">' + esc(d.vector || '') + '</span>'
          : '<span class="dim">no vector published</span>') + '</dd>' +
        '<dt>EPSS</dt><dd>' + (r.epss !== undefined
          ? (r.epss * 100).toFixed(2) + '% — higher than ' + (r.epct * 100).toFixed(1) + '% of all CVEs'
          : '<span class="dim">not scored</span>') + '</dd>' +
        '<dt>KEV</dt><dd>' + (r.kev ? 'listed' : '<span class="dim">not listed</span>') + '</dd>' +
        '<dt>Debian urgency</dt><dd>' + esc(r.urg || 'not yet assigned') + '</dd>' +
        '<dt>Subsystem</dt><dd class="mono">' + esc(d.subsystem || 'unknown') + '</dd>' +
      '</dl>' +
      '<h3>Every release</h3>' +
      '<table class="mini"><thead><tr><th>Release</th><th>Status</th><th>Version</th>' +
      '<th>Fixed</th><th>Advisory</th></tr></thead><tbody>' + statusRows + '</tbody></table>' +
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
    // Fall back to the full archive so a shared link always resolves.
    state.view = 'all';
    state.q = cve;
    syncControls();
    apply();
    idx = filtered.findIndex((r) => r.id === cve);
    if (idx === -1) return;
  }
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
  const def = {
    view: 'attention', q: '', status: 'any', sev: 'any',
    av: 'any', area: 'any', since: 0, sort: '',
  };
  for (const [k, v] of Object.entries(def)) {
    if (state[k] !== v) parts.push(k + '=' + encodeURIComponent(state[k]));
  }
  if (meta && meta.columns[state.col]) parts.push('rel=' + meta.columns[state.col].id);
  for (const k of ['kev', 'adv']) if (state[k]) parts.push(k + '=1');
  if (openCve) parts.push('cve=' + openCve);
  history.replaceState(null, '', location.pathname + location.search +
    (parts.length ? '#' + parts.join('&') : ''));
}

function readHash() {
  const raw = location.hash.slice(1);
  if (!raw) return;
  if (/^CVE-/.test(raw)) { openCve = raw; return; }
  for (const part of raw.split('&')) {
    const [k, v] = part.split('=');
    const value = decodeURIComponent(v ?? '');
    if (k === 'cve') { openCve = value; continue; }
    if (k === 'rel') {
      const idx = meta.columns.findIndex((c) => c.id === value);
      if (idx >= 0) state.col = idx;
      continue;
    }
    if (!(k in state)) continue;
    if (typeof state[k] === 'boolean') state[k] = value === '1';
    else if (typeof state[k] === 'number') state[k] = Number(value);
    else state[k] = value;
  }
  if (state.q || state.status !== 'any') $('#refine').open = true;
  syncControls();
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
