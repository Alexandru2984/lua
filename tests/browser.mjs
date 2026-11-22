import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { readFile, mkdir } from 'node:fs/promises';
let browser, server, base;
let serverOutput='';
before(async()=>{
  const reservation=createServer();await new Promise(resolve=>reservation.listen(0,'127.0.0.1',resolve));
  const port=reservation.address().port;await new Promise(resolve=>reservation.close(resolve));
  base='http://127.0.0.1:'+port;
  server=spawn('python3',['scripts/preview.py','--fixtures','--port',String(port)],{detached:true,stdio:['ignore','pipe','pipe']});
  server.stdout.on('data',data=>serverOutput+=data);server.stderr.on('data',data=>serverOutput+=data);
  let ready=false;
  for(let i=0;i<100;i++) {try {if((await fetch(base+'/api/health')).ok){ready=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,100));}
  assert.ok(ready,'Isolated Nginx failed to start: '+serverOutput);
  browser=await chromium.launch({headless:true});await mkdir('test-results',{recursive:true});
});
after(async()=>{
  await browser?.close();
  if(server && server.exitCode===null) {const ended=new Promise(resolve=>server.once('exit',resolve));process.kill(-server.pid,'SIGINT');await ended;}
});
async function context(ip,viewport={width:1440,height:1000}) {
  const ctx=await browser.newContext({viewport,extraHTTPHeaders:{'X-Real-IP':ip}});
  const page=await ctx.newPage();
  await page.goto(base);await page.waitForFunction(()=>!document.getElementById('scan-submit').disabled);
  return {ctx,page};
}
async function finished(page) {
  await page.waitForFunction(()=>document.getElementById('report-title').textContent && !document.getElementById('scan-submit').disabled && document.querySelector('#report-summary .status-badge'));
}
test('Origin, CSRF, ownership and cookie forgery are rejected',async()=>{
  const {ctx,page}=await context('8.8.4.11');
  const bootstrap=await ctx.request.get(base+'/api/bootstrap');const {csrf}=await bootstrap.json();
  assert.equal((await ctx.request.post(base+'/api/scans',{data:{target:'example.com'}})).status(),403);
  assert.equal((await ctx.request.post(base+'/api/scans',{headers:{'X-CSRF-Token':csrf,Origin:'https://attacker.example'},data:{target:'example.com'}})).status(),403);
  for(const target of [[],true,'127.0.0.1','169.254.169.254','https://example.com:22','-evil.com']) {
    assert.equal((await ctx.request.post(base+'/api/scans',{headers:{'X-CSRF-Token':csrf,Origin:base},data:{target}})).status(),422);
  }
  assert.equal((await ctx.request.post(base+'/api/scans',{headers:{'X-CSRF-Token':csrf,'Content-Type':'application/json'},data:'{broken'})).status(),400);
  const result=await ctx.request.post(base+'/api/scans',{headers:{'X-CSRF-Token':csrf,Origin:base},data:{target:'rebind.example.com'}});
  assert.equal(result.status(),202);const {id}=await result.json();
  await page.waitForTimeout(50);
  const scan=await (await ctx.request.get(base+'/api/scans/'+id)).json();assert.equal(scan.status,'failed');assert.match(scan.report.error,/blocked/);
  const other=await context('8.8.4.12');const otherCsrf=(await (await other.ctx.request.get(base+'/api/bootstrap')).json()).csrf;
  for(const method of ['get','delete','patch']) {
    const response=await other.ctx.request[method](base+'/api/scans/'+id,{headers:{'X-CSRF-Token':otherCsrf},...(method==='patch'?{data:{favorite:true}}:{})});
    assert.equal(response.status(),404);
  }
  const cookie=(await ctx.cookies()).find(c=>c.name==='__Host-lualens');assert.ok(cookie.secure && cookie.httpOnly && cookie.sameSite==='Strict');
  await other.ctx.addCookies([{...cookie,value:cookie.value.slice(0,-1)+(cookie.value.endsWith('a')?'b':'a')}]);
  assert.equal((await other.ctx.request.get(base+'/api/scans')).status(),401);
  for(const path of ['/data/recon.db','/.git/config','/modules/storage.lua']) assert.equal((await ctx.request.get(base+path)).status(),404);
  const headers=(await ctx.request.get(base)).headers();assert.match(headers['content-security-policy'],/frame-ancestors 'none'/);assert.ok(!headers['content-security-policy'].includes('unsafe-inline'));assert.match(headers['cache-control'],/no-store/);
  await ctx.close();await other.ctx.close();
});
test('Real UI supports scans, favorites, comparisons, safe external text, downloads and deletion',async()=>{
  const {ctx,page}=await context('8.8.4.21');const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.locator('#target').fill('example.com');await page.locator('#scan-submit').click();await finished(page);
  assert.equal(await page.locator('#stat-total').textContent(),'1');
  for(let i=0;i<12;i++)assert.equal((await ctx.request.get(base+'/api/scans')).status(),200);
  await page.locator('#rescan-button').click();await page.waitForFunction(()=>document.getElementById('stat-total').textContent==='2');await finished(page);
  await page.locator('.row-actions button').first().click();await page.waitForFunction(()=>document.getElementById('stat-saved').textContent==='1');
  await page.locator('#favorites-filter').click();assert.equal(await page.locator('.history-table tbody tr').count(),1);await page.locator('#favorites-filter').click();
  await page.locator('#compare-button').click();await page.locator('#run-compare').click();await page.waitForFunction(()=>document.getElementById('compare-result').textContent.includes('x-observation'));
  await page.locator('[data-close=compare-dialog]').click();
  await page.locator('#tab-headers').click();assert.ok((await page.locator('#report-content').textContent()).includes('<img src=x onerror='));assert.equal(await page.evaluate(()=>window.__xss),undefined);assert.equal(await page.locator('#report-content img').count(),0);
  const event=page.waitForEvent('download');await page.locator('#export-json').click();const download=await event;const json=JSON.parse(await readFile(await download.path(),'utf8'));assert.equal(json.target,'example.com');
  const csvEvent=page.waitForEvent('download');await page.locator('#export-csv').click();const csvDownload=await csvEvent;const csv=await readFile(await csvDownload.path(),'utf8');assert.ok(csv.includes("'=HYPERLINK"));
  await page.locator('#tab-dns').click();await page.getByRole('searchbox',{name:'Filter DNS records'}).fill('MX');assert.equal(await page.locator('#report-content .data-table tbody tr').count(),1);
  await page.locator('#theme-button').click();const theme=await page.locator('html').getAttribute('data-theme');await page.reload();await page.waitForFunction(()=>!document.getElementById('scan-submit').disabled);assert.equal(await page.locator('html').getAttribute('data-theme'),theme);
  await page.locator('.row-actions button[aria-label^="Delete"]').last().click();await page.locator('#confirm-delete').click();await page.waitForFunction(()=>document.getElementById('stat-total').textContent==='1');
  assert.deepEqual(errors,[]);await page.screenshot({path:'test-results/desktop.png',fullPage:true});await ctx.close();
});
test('Rate limits apply only to new scans and partial results stay explicit',async()=>{
  const {ctx,page}=await context('8.8.4.31');const {csrf}=await (await ctx.request.get(base+'/api/bootstrap')).json();
  const headers={'X-CSRF-Token':csrf,Origin:base};
  for(let i=0;i<3;i++) {
    const response=await ctx.request.post(base+'/api/scans',{headers,data:{target:'timeout.example.com',fresh:true}});assert.equal(response.status(),202);
    const {id}=await response.json();
    let data;
    for(let tries=0;tries<20;tries++) {data=await (await ctx.request.get(base+'/api/scans/'+id)).json();if(data.status!=='pending')break;await page.waitForTimeout(20);}
    assert.equal(data.status,'partial');assert.equal(data.score,undefined);assert.ok(data.report.errors.length);
  }
  const denied=await ctx.request.post(base+'/api/scans',{headers,data:{target:'example.com',fresh:true}});assert.equal(denied.status(),429);assert.equal(denied.headers()['retry-after'],'60');
  const cached=await ctx.request.post(base+'/api/scans',{headers,data:{target:'timeout.example.com'}});assert.equal(cached.status(),200);assert.equal((await cached.json()).cached,true);
  await ctx.close();
});
test('Deep scans return validated CT and registration data',async()=>{
  const {ctx,page}=await context('8.8.4.41');
  await page.locator('#target').fill('example.com');await page.locator('input[value=deep]').check();await page.locator('#scan-submit').click();await finished(page);
  await page.locator('#tab-footprint').click();const text=await page.locator('#report-content').textContent();assert.match(text,/www.example.com/);assert.match(text,/1995-08-14/);assert.ok(!text.includes('<script>'));assert.ok(!text.includes('evil-example.com'));
  await ctx.close();
});
test('Mobile layouts, accessible tabs, dialogs, keyboard and demo need no scan allowance',async()=>{
  const {ctx,page}=await context('8.8.4.51',{width:390,height:844});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.getByRole('button',{name:'Take a look at an example'}).click();assert.equal(await page.locator('#stat-total').textContent(),'0');assert.equal(await page.locator('#demo-notice').isVisible(),true);
  await page.locator('#tab-security').focus();await page.keyboard.press('ArrowRight');assert.equal(await page.locator('#tab-dns').getAttribute('aria-selected'),'true');
  for(const width of [360,390,768,1024,1440]) {
    await page.setViewportSize({width,height:1000});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Horizontal overflow at '+width);
  }
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:'test-results/mobile.png',fullPage:true});
  await page.locator('#close-report').click();await page.keyboard.press('/');assert.equal(await page.evaluate(()=>document.activeElement.id),'target');
  await page.locator('#help-button').click();assert.equal(await page.locator('#guide-dialog').isVisible(),true);await page.keyboard.press('Escape');assert.equal(await page.locator('#guide-dialog').isVisible(),false);
  await page.locator('#theme-button').click();await page.screenshot({path:'test-results/mobile-light.png',fullPage:true});assert.deepEqual(errors,[]);await ctx.close();
});
