package report

const stylesheet = `
:root {
  --bg: #f7f8fa;
  --panel: #ffffff;
  --ink: #1a1f2c;
  --muted: #5b6478;
  --line: #e3e6ec;
  --accent: #2461d9;
  --accent-soft: #e8effb;
  --code-bg: #f1f3f8;
  --badge-yaml: #2563eb;
  --badge-json: #0891b2;
  --badge-text: #4b5563;
  --badge-binary: #9a3412;
  --badge-unknown: #6b7280;
}

* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.55;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

header.site {
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  gap: 24px;
  position: sticky;
  top: 0;
  z-index: 10;
}
header.site h1 {
  margin: 0;
  font-size: 17px;
  letter-spacing: 0.2px;
}
header.site nav {
  display: flex;
  gap: 16px;
  font-size: 14px;
}
header.site nav a {
  color: var(--muted);
}
header.site nav a.active { color: var(--ink); font-weight: 600; }

main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 24px;
}

h2 { margin-top: 0; font-size: 22px; }
h3 { font-size: 16px; color: var(--muted); margin-bottom: 8px; }

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 28px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px 16px;
}
.card .label {
  text-transform: uppercase;
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.6px;
}
.card .value {
  font-size: 22px;
  font-weight: 600;
  margin-top: 4px;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: hidden;
}
th, td {
  text-align: left;
  padding: 9px 12px;
  font-size: 14px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
th {
  background: #fafbfd;
  color: var(--muted);
  font-weight: 600;
  font-size: 12px;
  letter-spacing: 0.4px;
  text-transform: uppercase;
}
tr:last-child td { border-bottom: none; }
td.path, td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }

.badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
  color: white;
  background: var(--badge-unknown);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.badge.yaml { background: var(--badge-yaml); }
.badge.json { background: var(--badge-json); }
.badge.text { background: var(--badge-text); }
.badge.binary { background: var(--badge-binary); }
.badge.unknown { background: var(--badge-unknown); }

.toolbar {
  display: flex;
  gap: 12px;
  margin-bottom: 14px;
  align-items: center;
  flex-wrap: wrap;
}
.toolbar input[type=search], .toolbar select {
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  font-size: 14px;
  background: var(--panel);
}
.toolbar input[type=search] { min-width: 280px; }
.toolbar .count { color: var(--muted); font-size: 13px; }

.breadcrumbs {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 10px;
}
.breadcrumbs a { color: var(--muted); }

dl.meta {
  display: grid;
  grid-template-columns: 180px 1fr;
  gap: 6px 16px;
  margin: 0 0 22px;
  font-size: 14px;
}
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; word-break: break-all; }

pre.code {
  background: var(--code-bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 14px 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  margin: 0;
}
.code-wrap { position: relative; }
.code-wrap button.copy {
  position: absolute; top: 8px; right: 8px;
  border: 1px solid var(--line);
  background: var(--panel);
  border-radius: 4px;
  padding: 4px 10px;
  font-size: 12px;
  cursor: pointer;
}
.code-wrap button.copy:hover { background: var(--accent-soft); }

.notice {
  background: var(--accent-soft);
  border: 1px solid #bcd0f4;
  color: #1e3a8a;
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 14px;
  margin-bottom: 16px;
}

footer.site {
  color: var(--muted);
  font-size: 12px;
  padding: 18px 24px 30px;
  text-align: center;
}

/* Severity badges + cards */
.sev {
  display: inline-block;
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 999px;
  color: white;
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.sev-critical { background: #b91c1c; }
.sev-warning  { background: #b45309; }
.sev-info     { background: #1e40af; }

.sev-card.critical { border-color: #fecaca; background: #fef2f2; }
.sev-card.critical .value { color: #991b1b; }
.sev-card.warning { border-color: #fed7aa; background: #fff7ed; }
.sev-card.warning .value { color: #9a3412; }
.sev-card.info { border-color: #bfdbfe; background: #eff6ff; }
.sev-card.info .value { color: #1e3a8a; }

/* Summary line on a file detail page */
.summary-line {
  background: var(--accent-soft);
  border: 1px solid #bcd0f4;
  border-radius: 6px;
  padding: 10px 14px;
  margin: 0 0 18px;
  font-size: 14px;
}

/* Findings list */
.findings { display: flex; flex-direction: column; gap: 10px; margin-bottom: 22px; }
.finding {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px 14px;
}
.finding-head {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 4px;
}
.finding-rule { background: var(--code-bg); padding: 1px 6px; border-radius: 4px; font-size: 12px; }
.finding-target { color: var(--ink); }
.finding-title { font-size: 15px; font-weight: 600; }
.finding-detail {
  margin-top: 4px;
  font-size: 13px;
  color: var(--muted);
  background: var(--code-bg);
  border-radius: 4px;
  padding: 8px 10px;
  white-space: pre-wrap;
  word-break: break-word;
}

/* Investigate (collapsible) panel */
.investigate { margin-top: 10px; }
.investigate > summary {
  cursor: pointer;
  color: var(--accent);
  font-size: 13px;
  user-select: none;
}
.investigate > summary:hover { text-decoration: underline; }
.investigate[open] > summary { margin-bottom: 8px; }
.investigate-actions { margin-bottom: 8px; }
.btn {
  display: inline-block;
  padding: 4px 12px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel);
  color: var(--accent);
  font-size: 12px;
  text-decoration: none;
}
.btn:hover { background: var(--accent-soft); text-decoration: none; }

.toolbar select.filter-sev { padding: 7px 10px; border: 1px solid var(--line); border-radius: 6px; font-size: 14px; }
`

const scriptJS = `
function attachSearch(formId, tableId) {
  var input = document.querySelector(formId + ' input[type=search]');
  var kindSel = document.querySelector(formId + ' select.filter-kind');
  var rows = Array.from(document.querySelectorAll(tableId + ' tbody tr'));
  var countEl = document.querySelector(formId + ' .count');
  function apply() {
    var q = (input ? input.value : '').toLowerCase();
    var kind = kindSel ? kindSel.value : '';
    var shown = 0;
    rows.forEach(function (row) {
      var text = row.getAttribute('data-search') || row.textContent.toLowerCase();
      var rowKind = row.getAttribute('data-kind') || '';
      var match = (!q || text.toLowerCase().indexOf(q) !== -1) && (!kind || rowKind === kind);
      row.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    if (countEl) countEl.textContent = shown + ' / ' + rows.length;
  }
  if (input) input.addEventListener('input', apply);
  if (kindSel) kindSel.addEventListener('change', apply);
  apply();
}

function attachCopy() {
  document.querySelectorAll('button.copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.getElementById(btn.getAttribute('data-target'));
      if (!target) return;
      var text = target.innerText;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () { flash(btn, 'Copied'); });
      } else {
        var ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); flash(btn, 'Copied'); } catch (e) {}
        document.body.removeChild(ta);
      }
    });
  });
}
function flash(btn, msg) {
  var prev = btn.textContent;
  btn.textContent = msg;
  setTimeout(function () { btn.textContent = prev; }, 1200);
}
function attachConcernsFilter() {
  var form = document.getElementById('concerns-form');
  var list = document.getElementById('concerns-list');
  if (!form || !list) return;
  var input = form.querySelector('input[type=search]');
  var sevSel = form.querySelector('select.filter-sev');
  var countEl = form.querySelector('.count');
  var findings = Array.from(list.querySelectorAll('.finding'));
  function apply() {
    var q = (input ? input.value : '').toLowerCase();
    var sev = sevSel ? sevSel.value : '';
    var shown = 0;
    findings.forEach(function (el) {
      var sevBadge = el.querySelector('.sev');
      var rowSev = sevBadge ? sevBadge.textContent.trim().toLowerCase() : '';
      var text = el.textContent.toLowerCase();
      var match = (!q || text.indexOf(q) !== -1) && (!sev || rowSev === sev);
      el.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    if (countEl) countEl.textContent = shown + ' / ' + findings.length;
  }
  if (input) input.addEventListener('input', apply);
  if (sevSel) sevSel.addEventListener('change', apply);
  apply();
}

document.addEventListener('DOMContentLoaded', function () {
  if (document.getElementById('files-form')) attachSearch('#files-form', '#files-table');
  if (document.getElementById('objects-form')) attachSearch('#objects-form', '#objects-table');
  attachConcernsFilter();
  attachCopy();
});
`
