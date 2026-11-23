import { list, hasScore, reportRows } from './report.js?v=2.1';
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const table = (heads,rows) => '<div class="table-wrap"><table><thead><tr>'+heads.map(h=>'<th>'+escapeHtml(h)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(value=>'<td>'+escapeHtml(value)+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
const note = value => '<p class="note">'+escapeHtml(value)+'</p>';
const section = (title,content) => '<section><h2>'+escapeHtml(title)+'</h2>'+content+'</section>';
const dateUtc = scan => (scan.timestamp || 'Unavailable')+' UTC';
export function reportSummary(scan) {
  const r=scan.report||{};
  const checks=list(r.http?.checks);
  const lines=[`LuaLens${scan.id==='demo'?' example report':''}: ${scan.target}`,`Analyzed: ${dateUtc(scan)}`,`Status: ${scan.status} · ${scan.profile==='deep'?'Deep dive':'Quick look'}`,`HTTP header score: ${hasScore(r.score)?r.score+'/100':'Unavailable'}`,`HTTPS: ${r.http?.tls?.verified?'Certificate chain and hostname verified':'Not verified'}`,`DNS records: ${list(r.dns?.records).length}`,`Header observations: ${checks.filter(c=>c.state==='pass').length}/${checks.length} configured`];
  for(const c of list(r.dns?.insights))lines.push(`${c.label}: ${c.summary}`);
  if(r.error)lines.push('Scan error: '+r.error);
  for(const error of list(r.errors).slice(0,5))lines.push('Unavailable: '+error);
  lines.push('Observed configuration only; this is not a security certification.');
  return lines.join('\n');
}
export function reportMarkdown(scan) {
  const groups=new Map();
  for(const [group,key,value] of reportRows(scan).slice(1)) {
    if(!groups.has(group))groups.set(group,[]);
    groups.get(group).push(key+': '+String(value??''));
  }
  const literal=escapeHtml(scan.target).replace(/[\\`*_{}[\]()#!|]/g,'\\$&');
  let output='# LuaLens '+(scan.id==='demo'?'example ':'')+'report: '+literal+'\n\nObserved configuration only; this is not a security certification.\n';
  for(const [group,lines] of groups){
    const text=lines.join('\n');const runs=text.match(/`+/g)||[];
    const fence='`'.repeat(runs.reduce((longest,run)=>Math.max(longest,run.length+1),3));
    output+='\n## '+group.replaceAll('_',' ')+'\n\n'+fence+'text\n'+text+'\n'+fence+'\n';
  }
  return output;
}
export function reportHtml(scan) {
  const r=scan.report||{},http=r.http||{},dns=r.dns||{};
  const sample=scan.id==='demo';
  let content='<header><div class="brand">λ &nbsp; LuaLens.</div><p class="eyebrow">'+(sample?'ILLUSTRATIVE EXAMPLE REPORT':'DOMAIN INTELLIGENCE REPORT')+'</p><h1>'+escapeHtml(scan.target)+'</h1><p>'+escapeHtml(dateUtc(scan))+' · '+escapeHtml(scan.profile==='deep'?'Deep dive':'Quick look')+' · '+escapeHtml(scan.status)+'</p></header>';
  if(sample)content+=note('Sample data for exploring the product. These are not live findings.');
  content+='<div class="facts">'+[['Header score',hasScore(r.score)?r.score+'/100':'Unavailable'],['HTTPS',http.tls?.verified?'Verified':'Not verified'],['DNS records',list(dns.records).length],['Duration',scan.duration_ms!=null?(scan.duration_ms/1000).toFixed(1)+'s':'Unavailable']].map(([key,value])=>'<div><span>'+escapeHtml(key)+'</span><strong>'+escapeHtml(value)+'</strong></div>').join('')+'</div>';
  content+=note('A snapshot of the observed root response and public DNS. The header score is not a security certification. Redirect destinations are not followed.');
  const warnings=[...(r.error?[r.error]:[]),...list(r.errors)];
  if(warnings.length)content+=section('Unavailable checks','<ul>'+warnings.map(x=>'<li>'+escapeHtml(x)+'</li>').join('')+'</ul>');
  const checks=list(http.checks);
  content+=section('HTTP security observations',checks.length?table(['Control','Observation','Value','Context'],checks.map(c=>[c.label,c.state,c.value??'Not observed',c.advice])):note(http.error||'No HTTP security observations.'));
  const insights=list(dns.insights);
  content+=section('DNS and email policies',insights.length?insights.map(c=>'<article><div class="policy-heading"><h3>'+escapeHtml(c.label)+'</h3><span>'+escapeHtml(c.state)+'</span></div><p>'+escapeHtml(c.summary)+'</p>'+(c.value?'<pre>'+escapeHtml(c.value)+'</pre>':'')+note(c.advice)+'</article>').join(''):note('No DNS policy observations in this report.'));
  const records=list(dns.records);
  content+=section('DNS records',records.length?table(['Type','Name','Value','Priority','TTL (seconds)'],records.map(d=>[d.type,d.name,d.value===''&&d.type==='MX'?'(null MX)':d.value,d.priority??'—',d.ttl??'—'])):note(dns.note||dns.error||'No records returned.'));
  const headers=Object.entries(http.headers||{}).sort(([a],[b])=>a.localeCompare(b));
  content+=section('Observed HTTP headers',headers.length?table(['Header','Value'],headers):note(http.error||'No headers collected.'));
  content+=section('HTTPS verification',note(http.tls?.verified?'The certificate chain and requested hostname passed TLS verification.':http.tls?.error||'HTTPS was not verified.')+note('Certificate expiry, revocation and protocol grading are not collected.'));
  const resources=list(http.resources);
  content+=section('Public resources',resources.length?table(['Path','HEAD response'],resources.map(p=>[p.path,p.error||'HTTP '+p.status]))+note('HEAD responses indicate availability; file contents are not validated.'):note('No public resource observations.'));
  const ct=r.transparency;
  content+=section('Certificate transparency',!ct?note('Not included in this profile.'):ct.error?note(ct.error):note('Historical certificates do not prove a hostname is currently live.')+'<pre>'+escapeHtml(list(ct.names).join('\n')||'No names returned.')+'</pre>'+(ct.truncated?note('Collection truncated at 300 names.'):'')+note('Source: '+(ct.source||'crt.sh')));
  const reg=r.registration;
  content+=section('Registration',!reg?note('Not included in this profile.'):reg.error?note(reg.error):table(['Event','UTC date'],list(reg.events).map(e=>[e.action,e.date]))+note('Status: '+list(reg.status).join(', '))+note('Source: '+(reg.source||'RDAP')));
  content+='<footer>LuaLens · Private report export. Store or share this local copy deliberately.<br>Use your browser’s Print command to print or save as PDF.</footer>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>LuaLens report · '+escapeHtml(scan.target)+'</title><style>'+exportStyles+'</style></head><body><main>'+content+'</main></body></html>';
}
const exportStyles=`:root{font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#19251b;background:#f3f6f1;font-size:16px}*{box-sizing:border-box}body{margin:0;padding:40px 24px;line-height:1.7}main{max-width:1100px;margin:auto;background:#fff;border:1px solid #dbe3d8;border-radius:18px;overflow:hidden}header{padding:40px;background:#162019;color:#f1f5eb}.brand{font-size:26px;font-weight:700;color:#c4f66c}.eyebrow{letter-spacing:2px;font-size:12px;margin:24px 0 8px}h1{font-size:38px;line-height:1.3;margin:0;overflow-wrap:anywhere}header>p:last-child{font-size:14px;color:#becbbd}.facts{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;padding:28px 35px;border-bottom:1px solid #dbe3d8}.facts span{display:block;font-size:13px;color:#53614f}.facts strong{font-size:23px;font-weight:600}section{padding:25px 35px;border-top:1px solid #dbe3d8}h2{font-size:20px;margin:0 0 18px}h3{font-size:16px;margin:0}.note{font-size:13px;color:#53614f;margin:12px 0;overflow-wrap:anywhere}main>.note{margin:22px 35px}table{border-collapse:collapse;width:100%;font-size:13px;table-layout:fixed}th,td{padding:10px;text-align:left;vertical-align:top;border:1px solid #dbe3d8;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#f0f4ed;font-weight:600}article{border:1px solid #dbe3d8;border-radius:10px;padding:17px;margin:12px 0;break-inside:avoid}.policy-heading{display:flex;justify-content:space-between;gap:15px}.policy-heading>span{font-size:12px;color:#53614f}article p{font-size:14px}pre{font:13px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f0f4ed;padding:14px;border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere}li{overflow-wrap:anywhere}footer{padding:24px 35px;background:#f0f4ed;color:#53614f;font-size:13px}@media(max-width:650px){body{padding:15px 10px}header{padding:25px 20px}h1{font-size:28px}section{padding:20px 17px}.facts{padding:20px;grid-template-columns:1fr 1fr}.table-wrap{overflow-x:auto}table{min-width:560px}main>.note{margin:20px}footer{padding:20px}}@media print{@page{margin:14mm}body{background:#fff;padding:0;font-size:11pt}main{border:0;border-radius:0;max-width:none}header{padding:15px 0;background:#fff;color:#19251b}header .brand{color:#315c0b}header>p:last-child{color:#53614f}h1{font-size:26px}.facts{padding:15px 0}section{padding:18px 0}main>.note{margin:15px 0}table{min-width:0;font-size:9pt}th,td{padding:6px}tr{break-inside:avoid}h2,h3{break-after:avoid}footer{background:#fff;padding:15px 0}}`;
