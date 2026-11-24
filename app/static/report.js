export const list = value => Array.isArray(value) ? value : [];
export const hasScore = value => typeof value === 'number' && value >= 0 && value <= 100;
export function utcDate(value){if(typeof value!=='number'||!Number.isFinite(value))return 'Unavailable';const d=new Date(value*1000);return Number.isNaN(d.getTime())?'Unavailable':d.toISOString();}
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
  const certificate=r.http?.tls?.certificate;
  if(certificate)for(const key of ['subject_cn','issuer_cn','protocol','cipher','fingerprint_sha256','not_before','not_after','observed_at']){
    if(certificate[key]!=null)rows.push(['tls',key,key==='not_before'||key==='not_after'||key==='observed_at'?utcDate(certificate[key]):certificate[key]]);
  }
  for (const c of list(r.http?.checks)) rows.push(['security', c.label, c.state + ': ' + (c.value || c.advice)]);
  for (const e of list(r.http?.resources)) rows.push(['resource', e.path, e.error || e.status]);
  for (const name of list(r.transparency?.names)) rows.push(['transparency', 'hostname', name]);
  for (const e of list(r.registration?.events)) rows.push(['registration', e.action, e.date]);
  for (const e of list(r.errors)) rows.push(['error', 'check', e]);
  if (r.error) rows.push(['error', 'scan', r.error]);
  return rows;
}
export const reportCsv = scan => '\uFEFF' + reportRows(scan).map(row => row.map(csvCell).join(',')).join('\r\n');
const requestHeaders=new Set(['date','age','cf-ray','x-request-id','x-correlation-id','request-id','traceparent','tracestate','server-timing','set-cookie']);
const validOutcome=state=>state==='answered'||state==='absent';
function dnsKnown(report,type) {
  const dns=report.dns;
  if(!dns||dns.error)return false;
  if(dns.query_status!=null) {
    if(type==='CNAME')return ['A','AAAA','MX','NS','TXT','CAA','DMARC'].every(t=>validOutcome(dns.query_status[t]));
    return validOutcome(dns.query_status[type]);
  }
  return Array.isArray(dns.records)&&list(dns.errors).length===0;
}
function dnsMap(report,type) {
  const grouped=new Map();
  for(const record of list(report.dns?.records)) {
    if(record.type!==type)continue;
    const key='DNS '+type+' '+record.name;
    if(!grouped.has(key))grouped.set(key,new Set());
    grouped.get(key).add((record.priority==null?'':record.priority+' ')+record.value);
  }
  return new Map([...grouped].map(([key,values])=>[key,[...values].sort().join('\n')]));
}
export function compareReportDetails(before,after) {
  if(before.target!==after.target)throw new Error('Choose two reports for the same domain.');
  const a=before.report||{},b=after.report||{};
  const changes=[],unavailable=[];
  const compare=(left,right,group)=>{
    for(const key of new Set([...left.keys(),...right.keys()])) {
      if(left.get(key)===right.get(key))continue;
      changes.push({key,before:left.get(key),after:right.get(key),group,
        volatile:group==='http'&&requestHeaders.has(key.slice(5).toLowerCase()),
        state:!left.has(key)?'added':!right.has(key)?'removed':'changed'});
    }
  };
  if(a.dns||b.dns) {
    const types=new Set(['A','AAAA','MX','NS','TXT','CAA','DMARC',...list(a.dns?.records).map(r=>r.type),...list(b.dns?.records).map(r=>r.type)]);
    const unknown=[];
    for(const type of types){if(dnsKnown(a,type)&&dnsKnown(b,type))compare(dnsMap(a,type),dnsMap(b,type),'dns');else unknown.push(type);}
    if(unknown.length)unavailable.push('DNS lookups not comparable in both reports: '+unknown.join(', ')+'.');
  }
  const httpKnown=r=>r.http&&!r.http.error&&r.http.headers&&typeof r.http.headers==='object';
  if(httpKnown(a)&&httpKnown(b))compare(new Map(Object.entries(a.http.headers).map(([k,v])=>['HTTP '+k,String(v)])),new Map(Object.entries(b.http.headers).map(([k,v])=>['HTTP '+k,String(v)])),'http');
  else if(a.http||b.http)unavailable.push('HTTP headers were unavailable in at least one report.');
  if(typeof a.http?.tls?.verified==='boolean'&&typeof b.http?.tls?.verified==='boolean')compare(new Map([['HTTPS verified',String(a.http.tls.verified)]]),new Map([['HTTPS verified',String(b.http.tls.verified)]]),'tls');
  if(typeof a.http?.status==='number'&&typeof b.http?.status==='number')compare(new Map([['HTTP status',String(a.http.status)]]),new Map([['HTTP status',String(b.http.status)]]),'http_status');
  const ca=a.http?.tls?.certificate,cb=b.http?.tls?.certificate;
  if(ca||cb){
    if(ca&&cb&&/^[a-f0-9]{64}$/i.test(ca.fingerprint_sha256||'')&&/^[a-f0-9]{64}$/i.test(cb.fingerprint_sha256||'')){
      const fields={fingerprint_sha256:'Certificate SHA-256',not_after:'Certificate expires (UTC)',issuer_cn:'Certificate issuer CN',protocol:'Negotiated TLS protocol',cipher:'Negotiated cipher'};
      const values=c=>new Map(Object.entries(fields).filter(([key])=>c[key]!=null).map(([key,label])=>[label,key==='not_after'?utcDate(c[key]):key==='fingerprint_sha256'?c[key].toLowerCase():String(c[key])]));
      compare(values(ca),values(cb),'tls');
    }else unavailable.push('Certificate details were not collected in both reports.');
  }
  if(a.http?.resources||b.http?.resources){
    const left=new Map(list(a.http?.resources).map(r=>[r.path,r])),right=new Map(list(b.http?.resources).map(r=>[r.path,r]));
    const unknown=[];
    for(const path of new Set([...left.keys(),...right.keys()])){
      const x=left.get(path),y=right.get(path);
      if(x&&!x.error&&typeof x.status==='number'&&y&&!y.error&&typeof y.status==='number')compare(new Map([['Resource '+path,'HTTP '+x.status]]),new Map([['Resource '+path,'HTTP '+y.status]]),'resource');
      else unknown.push(path);
    }
    if(unknown.length)unavailable.push('Resource checks not comparable in both reports: '+unknown.join(', ')+'.');
  }
  const ctA=a.transparency,ctB=b.transparency;
  if(ctA||ctB){
    if(ctA&&ctB&&!ctA.error&&!ctB.error&&!ctA.truncated&&!ctB.truncated){
      compare(new Map(list(ctA.names).map(name=>['CT '+name,'Observed'])),new Map(list(ctB.names).map(name=>['CT '+name,'Observed'])),'transparency');
    }else unavailable.push('Certificate transparency was missing, unavailable or truncated in at least one report.');
  }
  const regA=a.registration,regB=b.registration;
  if(regA||regB){
    if(regA&&regB&&!regA.error&&!regB.error){
      const values=r=>{
        const groups=new Map();for(const e of list(r.events)){if(!groups.has(e.action))groups.set(e.action,new Set());groups.get(e.action).add(String(e.date));}
        return new Map([['Registration status',[...new Set(list(r.status).map(String))].sort().join('\n')],...[...groups].map(([action,dates])=>['Registration '+action,[...dates].sort().join('\n')])]);
      };
      compare(values(regA),values(regB),'registration');
    }else unavailable.push('Registration data was not available in both reports.');
  }
  return {changes:changes.sort((x,y)=>x.key.localeCompare(y.key)),unavailable};
}
export function compareReports(before,after){return compareReportDetails(before,after).changes;}
export function certificateExpiry(notAfter,at=Date.now()/1000) {
  if(typeof notAfter!=='number'||!Number.isFinite(notAfter)||typeof at!=='number'||!Number.isFinite(at))return {state:'unavailable',label:'Expiry not collected',days:null};
  const remaining=notAfter-at,days=Math.floor(remaining/86400);
  if(remaining<=0)return {state:'expired',label:'Recorded certificate expired',days};
  const label=days<1?'Recorded certificate expires in under a day':`Recorded certificate expires in ${days} day${days===1?'':'s'}`;
  return {state:remaining<=7*86400?'urgent':remaining<=30*86400?'soon':'valid',label,days};
}
