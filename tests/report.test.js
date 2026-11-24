import { test } from 'node:test';
import assert from 'node:assert/strict';
import { csvCell, reportCsv, compareReports, compareReportDetails, certificateExpiry, utcDate, hasScore } from '../app/static/report.js';
test('CSV prevents spreadsheet formulas even after leading whitespace',()=>{
  for(const value of ['=CMD()', '+SUM(A1)', '-1+2', '@SUM(A1)', '  =1+1', '\ttext']) assert.ok(csvCell(value).startsWith('"\''));
  assert.equal(csvCell('a,"b"\nc'), '"a,""b""\nc"');
});
test('Exports preserve failed and unavailable observations',()=>{
  const csv=reportCsv({target:'example.com',status:'failed',report:{error:'Timeout',http:{resources:[{path:'/robots.txt',error:'Timeout'}]}}});
  assert.ok(csv.includes('unavailable'));assert.ok(csv.includes('Timeout'));assert.ok(csv.startsWith('\uFEFF'));
});
test('Comparison ignores DNS order and TTL, but detects priority and value changes',()=>{
  const record={type:'MX',name:'example.com',value:'mx.example.com',priority:10,ttl:30};
  const before={target:'example.com',report:{dns:{records:[record]}}};
  const after=structuredClone(before);after.report.dns.records[0].ttl=60;
  assert.deepEqual(compareReports(before,after),[]);
  after.report.dns.records[0].priority=20;
  assert.equal(compareReports(before,after)[0].state,'changed');
});
test('Comparison marks unavailable data as unobserved and prevents cross-domain comparisons',()=>{
  const before={target:'example.com',report:{http:{headers:{server:'Example'}}}};
  const after={target:'example.com',report:{http:{error:'Timeout'}}};
  assert.deepEqual(compareReports(before,after),[]);
  assert.match(compareReportDetails(before,after).unavailable[0],/HTTP headers/);
  assert.throws(()=>compareReports(before,{...after,target:'different.com'}));
});
test('Failed DNS queries do not become removed records, but confirmed empty answers do',()=>{
  const before={target:'example.com',report:{dns:{records:[{type:'A',name:'example.com',value:'93.184.215.14'}],query_status:{A:'answered'}}}};
  const after={target:'example.com',report:{dns:{records:[],query_status:{A:'error'}}}};
  assert.deepEqual(compareReports(before,after),[]);assert.match(compareReportDetails(before,after).unavailable.join(' '),/A/);
  after.report.dns.query_status.A='absent';assert.equal(compareReports(before,after)[0].state,'removed');
});
test('Missing or truncated CT collections cannot establish hostname removals',()=>{
  const before={target:'example.com',report:{transparency:{names:['www.example.com']}}};
  const after={target:'example.com',report:{}};
  assert.deepEqual(compareReports(before,after),[]);assert.match(compareReportDetails(before,after).unavailable.join(' '),/transparency/);
  after.report.transparency={names:[],truncated:true};assert.deepEqual(compareReports(before,after),[]);
  after.report.transparency.truncated=false;assert.equal(compareReports(before,after)[0].state,'removed');
});
test('Request-specific headers are classified separately from configuration changes',()=>{
  const before={target:'example.com',report:{http:{headers:{date:'old',age:'1','set-cookie':'a=1','strict-transport-security':'max-age=0'}}}};
  const after=structuredClone(before);Object.assign(after.report.http.headers,{date:'new',age:'2','set-cookie':'a=2','strict-transport-security':'max-age=31536000'});
  const result=compareReportDetails(before,after);
  assert.equal(result.changes.filter(c=>c.volatile).length,3);assert.equal(result.changes.filter(c=>!c.volatile).length,1);
});
test('TLS details are compared only when both snapshots exist and fingerprints are normalized',()=>{
  const before={target:'example.com',report:{http:{tls:{verified:true,certificate:{fingerprint_sha256:'A'.repeat(64),not_after:1800000000}}}}};
  const after=structuredClone(before);after.report.http.tls.certificate.fingerprint_sha256='a'.repeat(64);
  assert.deepEqual(compareReports(before,after),[]);
  after.report.http.tls.certificate.fingerprint_sha256='b'.repeat(64);
  assert.equal(compareReports(before,after)[0].key,'Certificate SHA-256');
  delete after.report.http.tls.certificate;assert.deepEqual(compareReports(before,after),[]);assert.match(compareReportDetails(before,after).unavailable.join(' '),/Certificate details/);
});
test('Unavailable resource checks do not become HTTP removals',()=>{
  const before={target:'example.com',report:{http:{resources:[{path:'/robots.txt',status:200}]}}};
  const after={target:'example.com',report:{http:{resources:[{path:'/robots.txt',error:'Timeout'}]}}};
  assert.deepEqual(compareReports(before,after),[]);assert.match(compareReportDetails(before,after).unavailable.join(' '),/robots/);
  after.report.http.resources[0]={path:'/robots.txt',status:404};assert.equal(compareReports(before,after)[0].state,'changed');
});
test('RDAP event and status ordering do not invent a registration change',()=>{
  const registration={status:['active','client transfer prohibited'],events:[{action:'expiration',date:'2027-01-01'},{action:'expiration',date:'2028-01-01'}]};
  const before={target:'example.com',report:{registration}},after=structuredClone(before);
  after.report.registration.events.reverse();after.report.registration.status.reverse();assert.deepEqual(compareReports(before,after),[]);
  after.report.registration.events[0].date='2030-01-01';assert.equal(compareReports(before,after)[0].key,'Registration expiration');
});
test('Expiry warnings use recorded dates without turning unavailable data into an expiry',()=>{
  const now=1800000000;
  assert.equal(certificateExpiry(now,now).state,'expired');assert.equal(certificateExpiry(now+3600,now).days,0);
  assert.equal(certificateExpiry(now+7*86400,now).state,'urgent');assert.equal(certificateExpiry(now+30*86400,now).state,'soon');
  assert.equal(certificateExpiry(now+31*86400,now).state,'valid');
  for(const value of [null,undefined,NaN,Infinity,'1800000000'])assert.equal(certificateExpiry(value,now).state,'unavailable');
  assert.equal(utcDate(0),'1970-01-01T00:00:00.000Z');assert.equal(utcDate(Infinity),'Unavailable');
});
test('Unknown scores are never converted into a zero or a pass',()=>{
  for(const value of [null,undefined,'100',-1,101]) assert.equal(hasScore(value),false);
  assert.equal(hasScore(0),true);assert.equal(hasScore(100),true);
});
