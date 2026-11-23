export const list = value => Array.isArray(value) ? value : [];
export const hasScore = value => typeof value === 'number' && value >= 0 && value <= 100;
export function csvCell(value) {
  let text = String(value ?? '');
  // Spreadsheet apps interpret these prefixes as formulas, including after
  // whitespace. Quote every cell as well as neutralizing formula evaluation.
  if (/^[\s\u0000-\u001f]*[=+@-]/u.test(text) || /^[\t\r\n]/u.test(text)) text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
export function reportRows(scan) {
  const r = scan.report || {};
  const rows = [['section', 'key', 'value'], ['report', 'target', scan.target], ['report', 'status', scan.status], ['report', 'timestamp_utc', scan.timestamp], ['report', 'header_score', hasScore(r.score) ? r.score : 'unavailable']];
  for (const d of list(r.dns?.records)) rows.push(['dns', d.type + ' ' + d.name, (d.priority==null?'':'priority='+d.priority+' ')+d.value]);
  for (const d of list(r.dns?.insights)) rows.push(['dns_policy',d.label,d.state+': '+d.summary+(d.value?'\n'+d.value:'')]);
  for (const [key, value] of Object.entries(r.http?.headers || {})) rows.push(['http', key, value]);
  for (const c of list(r.http?.checks)) rows.push(['security', c.label, c.state + ': ' + (c.value || c.advice)]);
  for (const e of list(r.http?.resources)) rows.push(['resource', e.path, e.error || e.status]);
  for (const name of list(r.transparency?.names)) rows.push(['transparency', 'hostname', name]);
  for (const e of list(r.registration?.events)) rows.push(['registration', e.action, e.date]);
  for (const e of list(r.errors)) rows.push(['error', 'check', e]);
  if (r.error) rows.push(['error', 'scan', r.error]);
  return rows;
}
export const reportCsv = scan => '\uFEFF' + reportRows(scan).map(row => row.map(csvCell).join(',')).join('\r\n');
export function compareReports(before, after) {
  if (before.target !== after.target) throw new Error('Choose two reports for the same domain.');
  const flatten = scan => {
    const r = scan.report || {};
    const values = new Map();
    const grouped = new Map();
    for (const d of list(r.dns?.records)) {
      const key = 'DNS ' + d.type + ' ' + d.name;
      if (!grouped.has(key)) grouped.set(key, new Set());
      grouped.get(key).add((d.priority == null ? '' : d.priority + ' ') + d.value);
    }
    for (const [key, set] of grouped) values.set(key, [...set].sort().join('\n'));
    for (const [key, value] of Object.entries(r.http?.headers || {})) values.set('HTTP ' + key, String(value));
    if (r.http && !r.http.error) {
      values.set('HTTPS verified', String(!!r.http.tls?.verified));
      values.set('HTTP status', String(r.http.status));
    }
    for (const name of list(r.transparency?.names)) values.set('CT ' + name, 'Observed');
    return values;
  };
  const a = flatten(before), b = flatten(after);
  return [...new Set([...a.keys(), ...b.keys()])].sort().flatMap(key => {
    if (a.get(key) === b.get(key)) return [];
    return [{key, before:a.get(key), after:b.get(key), state:!a.has(key) ? 'added' : !b.has(key) ? 'removed' : 'changed'}];
  });
}
