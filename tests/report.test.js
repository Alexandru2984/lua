import { test } from 'node:test';
import assert from 'node:assert/strict';
import { csvCell, reportCsv, compareReports, hasScore } from '../app/static/report.js';
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
  assert.equal(compareReports(before,after)[0].state,'removed');
  assert.throws(()=>compareReports(before,{...after,target:'different.com'}));
});
test('Unknown scores are never converted into a zero or a pass',()=>{
  for(const value of [null,undefined,'100',-1,101]) assert.equal(hasScore(value),false);
  assert.equal(hasScore(0),true);assert.equal(hasScore(100),true);
});
