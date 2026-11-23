import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportHtml,reportMarkdown,reportSummary } from '../app/static/report-export.js';
import { reportCsv } from '../app/static/report.js';
const scan={id:1,target:'example.com',timestamp:'2026-11-23 00:00:00',status:'partial',profile:'quick',report:{score:0,errors:['Provider timeout'],dns:{records:[{type:'MX',name:'example.com',priority:0,value:'',ttl:300}],insights:[{key:'spf',label:'SPF policy',state:'unavailable',summary:'Lookup timed out.',advice:'Retry the lookup.'}]},http:{tls:{verified:false},headers:{'x-danger':'<img src="https://attacker.example/" onerror="window.__xss=1">'},checks:[],resources:[]}}};
test('HTML export keeps external text inert in titles, fields and error messages',()=>{
  const value=structuredClone(scan);value.target='</title><script>window.__xss=1</script>';value.report.errors.push('<iframe src="https://attacker.example/">');
  const html=reportHtml(value);
  for(const tag of ['<script','<img','<iframe','<form','<link'])assert.ok(!html.toLowerCase().includes(tag));
  assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes("default-src 'none'"));assert.ok(html.includes("form-action 'none'"));
});
test('HTML export contains the whole snapshot, including missing and unavailable observations',()=>{
  const html=reportHtml(scan);
  for(const phrase of ['DNS and email policies','DNS records','HTTP security observations','Observed HTTP headers','HTTPS verification','Certificate transparency','Registration','0/100','Provider timeout','(null MX)'])assert.ok(html.includes(phrase),phrase);
});
test('Markdown fences cannot be closed by untrusted backtick runs',()=>{
  const value=structuredClone(scan);value.report.http.headers['x-danger']='```\n<script>window.__xss=1</script>\n```';
  const markdown=reportMarkdown(value);
  assert.match(markdown,/````text\n/);assert.match(markdown,/\n````\n/);
  assert.ok(markdown.includes('```\n<script>'));
});
test('Large alternating backtick input stays bounded without a spread-argument failure',()=>{
  const value=structuredClone(scan);value.report.http.headers['x-danger']='`x'.repeat(100000);
  const markdown=reportMarkdown(value);assert.ok(markdown.length<250000);
});
test('Summaries preserve zero scores and explicit failure context',()=>{
  const text=reportSummary(scan);
  assert.match(text,/0\/100/);assert.match(text,/Not verified/);assert.match(text,/Unavailable: Provider timeout/);assert.match(text,/SPF policy: Lookup timed out/);assert.ok(!text.includes('undefined'));
});
test('Samples remain labeled as examples and CSV retains MX priorities',()=>{
  assert.match(reportHtml({...scan,id:'demo'}),/ILLUSTRATIVE EXAMPLE REPORT/);
  assert.match(reportMarkdown({...scan,id:'demo'}),/^# LuaLens example report/);
  assert.match(reportSummary({...scan,id:'demo'}),/^LuaLens example report/);
  assert.ok(reportCsv(scan).includes('priority=0'));
});
