import { list, hasScore, reportCsv, compareReports } from './report.js?v=2';
import { demo } from './demo.js?v=2';
const $ = id => document.getElementById(id);
const state = {csrf:null, scans:[], total:0, page:1, selected:null, tab:'security', favorites:false, pending:null, busy:false, deleteId:null, historySeq:0, reportSeq:0};
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [key,value] of Object.entries(attrs)) {
    if (key === 'class') n.className = value;
    else if (key === 'onClick') n.addEventListener('click', value);
    else n.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    n.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return n;
}
function toast(message) {
  $('toast').textContent = message; $('toast').hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => $('toast').hidden = true, 4500);
}
function message(text, cls = 'warning') { return el('div', {class:'notice ' + cls}, text); }
async function api(path, options = {}) {
  const response = await fetch('/api/' + path, {...options, credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json', ...(options.method && options.method !== 'GET' ? {'X-CSRF-Token':state.csrf} : {}), ...options.headers}, signal:AbortSignal.timeout(15000)});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || (response.status === 413 ? 'The request is too large.' : 'The request failed. Please try again.'));
  return data;
}
const statusLabels = {completed:'Complete',partial:'Partial',failed:'Failed',pending:'Running'};
const statusBadge = status => el('span', {class:'status-badge status-' + (statusLabels[status] ? status : 'failed')}, statusLabels[status] || 'Unknown');
function date(value) {
  const d = new Date((value || '').replace(' ', 'T') + (value?.includes('Z') ? '' : 'Z'));
  return Number.isNaN(d.getTime()) ? 'Date unavailable' : d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}
function scoreLabel(value) { return hasScore(value) ? value + '/100' : '—'; }
function renderHistory() {
  const search = $('history-search').value.toLowerCase().trim();
  const status = $('status-filter').value;
  const rows = state.scans.filter(s => (!search || s.target.toLowerCase().includes(search)) && (status==='all' || s.status===status) && (!state.favorites || s.favorite));
  $('stat-total').textContent = state.total;
  $('stat-saved').textContent = state.scans.filter(s => s.favorite).length;
  const latest = state.scans.find(s => hasScore(s.score));
  $('stat-score').textContent = latest ? latest.score : '—';
  $('history-count').textContent = state.total; $('nav-count').textContent = state.total;
  $('history-page-label').textContent = state.total ? `Page ${state.page} of ${Math.ceil(state.total/50)} · ${rows.length} shown · Stored for up to 30 days` : 'Private to this browser · Stored for up to 30 days';
  $('prev-page').disabled = state.page<=1; $('next-page').disabled = state.page*50>=state.total;
  if (!rows.length) {
    const empty = el('div',{class:'empty-state'},el('span',{class:'empty-symbol','aria-hidden':'true'},'◎'),el('h3',{},state.total ? 'No reports match these filters.' : 'Your next discovery starts here.'),el('p',{},state.total ? 'Try another domain, status or history page.' : 'Analyze a domain to bring its DNS, security signals and public footprint into focus.'));
    empty.append(el('button',{class:'text-button',onClick:state.total ? () => { $('history-search').value=''; $('status-filter').value='all'; state.favorites=false; $('favorites-filter').setAttribute('aria-pressed','false'); renderHistory(); } : showDemo},state.total ? 'Clear filters' : 'Take a look at an example'));
    $('history-content').replaceChildren(empty); return;
  }
  const table = el('table',{class:'history-table'},el('thead',{},el('tr',{},...['Domain','Status','Analyzed','Score','Actions'].map(x=>el('th',{scope:'col'},x)))));
  const body = el('tbody');
  for (const scan of rows) {
    const favorite = el('button',{class:'icon-button' + (scan.favorite ? ' is-favorite' : ''),'aria-label':(scan.favorite ? 'Unsave ' : 'Save ') + scan.target,'aria-pressed':!!scan.favorite,onClick:async event => {
      const button=event.currentTarget;
      button.disabled = true;
      try { await api('scans/' + scan.id,{method:'PATCH',body:JSON.stringify({favorite:!scan.favorite})}); scan.favorite=scan.favorite?0:1; renderHistory(); }
      catch(error) {toast(error.message); button.disabled=false;}
    }},scan.favorite?'★':'☆');
    const remove = el('button',{class:'icon-button','aria-label':'Delete report for ' + scan.target,onClick:()=>askDelete(scan)},'×');
    remove.disabled = scan.status==='pending';
    body.append(el('tr',{},
      el('td',{},el('div',{class:'domain-cell'},el('span',{class:'domain-glyph','aria-hidden':'true'},'◎'),el('div',{},el('button',{class:'domain-button',onClick:()=>openReport(scan.id,true)},scan.target),el('span',{class:'domain-profile'},scan.profile==='deep'?'Deep dive':'Quick look')))),
      el('td',{},statusBadge(scan.status)),el('td',{class:'date-cell'},date(scan.timestamp)),el('td',{class:'score-cell'},scoreLabel(scan.score)),el('td',{},el('div',{class:'row-actions'},favorite,remove))));
  }
  table.append(body); $('history-content').replaceChildren(table);
}
async function refreshHistory(silent=false) {
  const sequence=++state.historySeq;
  try {
    const data=await api('scans?page='+state.page);
    if (sequence!==state.historySeq) return;
    state.scans=list(data.scans); state.total=data.total;
    if (state.page>1 && !state.scans.length) {state.page--; return refreshHistory(silent);}
    renderHistory();
    const running=state.scans.find(s=>s.status==='pending');
    if (running && !state.pending) startPolling(running.id,running.target);
  } catch(error) {
    if (!silent) { $('history-content').replaceChildren(message(error.message,'error')); $('history-page-label').textContent='Workspace could not be loaded. Use Refresh to retry.'; }
    else toast(error.message);
  }
}
function setBusy(busy) {
  state.busy=busy; $('scan-submit').disabled=busy;
  $('scan-submit-label').textContent=busy ? 'Analysis in progress' : 'Analyze domain';
}
async function startScan(event) {
  event?.preventDefault(); if (state.busy) return;
  $('form-error').hidden=true; setBusy(true);
  try {
    const data=await api('scans',{method:'POST',body:JSON.stringify({target:$('target').value,profile:document.querySelector('input[name=profile]:checked').value,fresh:$('fresh').checked})});
    state.page=1; await refreshHistory();
    await openReport(data.id,false);
    if (data.cached) { toast('Opened your recent report. Use “Bypass recent cache” for a fresh scan.'); setBusy(false); }
    else startPolling(data.id,$('target').value);
    $('report-section').scrollIntoView({behavior:'smooth',block:'start'});
  } catch(error) { $('form-error').textContent=error.message; $('form-error').hidden=false; setBusy(false); }
}
function startPolling(id,target) {
  if (state.pending?.id===id) return;
  if (state.pending) clearTimeout(state.pending.timer);
  state.pending={id,started:Date.now(),timer:null};
  setBusy(true); $('scan-progress').hidden=false; $('progress-target').textContent='Analyzing '+target;
  const poll=async()=>{
    const job=state.pending; if (!job || job.id!==id) return;
    $('progress-time').textContent=Math.floor((Date.now()-job.started)/1000)+'s';
    try {
      const scan=await api('scans/'+id);
      if (state.pending!==job) return;
      $('progress-stage').textContent=scan.stage;
      if (state.selected?.id===id) {state.selected=scan;renderReport();}
      if (scan.status!=='pending') {
        state.pending=null;setBusy(false);$('scan-progress').hidden=true;
        await refreshHistory(true);
        toast(scan.status==='completed'?'Your report is ready.':scan.status==='partial'?'Report ready. Some checks were unavailable.':'This scan could not finish. See the report for details.');
        return;
      }
      if (Date.now()-job.started>150000) {state.pending=null;setBusy(false);$('scan-progress').hidden=true;toast('This scan is taking longer than expected. Refresh history to check its status.');return;}
      job.timer=setTimeout(poll,document.hidden?6000:2000);
    } catch(error) {
      if (state.pending!==job) return;
      state.pending=null;setBusy(false);$('scan-progress').hidden=true;toast(error.message+' Refresh history to resume.');
    }
  };
  poll();
}
async function openReport(id,scroll=false) {
  const sequence=++state.reportSeq;
  try {
    const scan=await api('scans/'+id);
    if (sequence!==state.reportSeq) return;
    state.selected=scan; renderReport();
    history.replaceState(null,'','#report='+scan.id);
    if (scroll) {$('report-section').scrollIntoView({behavior:'smooth',block:'start'});$('report-title').setAttribute('tabindex','-1');$('report-title').focus({preventScroll:true});}
    if (scan.status==='pending') startPolling(scan.id,scan.target);
  } catch(error) {toast(error.message);}
}
function renderReport() {
  const scan=state.selected; if(!scan) return;
  const sample=scan.id==='demo', r=scan.report||{}, http=r.http||{};
  $('report-section').hidden=false; $('demo-notice').hidden=!sample;
  $('report-title').textContent=scan.target;
  $('report-meta').textContent=(sample?'Illustrative report':date(scan.timestamp))+' · '+(scan.profile==='deep'?'Deep dive':'Quick look')+(scan.duration_ms!=null?' · '+(scan.duration_ms/1000).toFixed(1)+'s':'');
  $('rescan-button').disabled=sample || scan.status==='pending'; $('compare-button').disabled=sample || !scan.report || scan.status==='pending';
  $('export-json').disabled=!scan.report; $('export-csv').disabled=!scan.report;
  if(scan.status==='pending') {
    $('report-summary').replaceChildren(el('div',{class:'report-warning'},message(scan.stage || 'Analysis is running.')));
    $('report-content').replaceChildren(el('p',{class:'muted'},'Your findings will appear here as soon as the analysis finishes.'));
    return;
  }
  const score=hasScore(r.score)?r.score:null;
  const summary=el('div',{class:'report-summary'},el('div',{class:'score-ring'},el('div',{},el('strong',{},score??'—'),el('small',{},'HEADER SCORE'))),el('div',{},el('h3',{},score==null?'Header checks unavailable':score>=80?'A considered configuration.':score>=50?'A few things to look into.':'Room for a stronger configuration.'),el('div',{class:'summary-facts'},statusBadge(scan.status),el('span',{},http.tls?.verified?'HTTPS verified':'HTTPS not verified'),r.ip?el('code',{},r.ip):null,http.status?el('span',{},'HTTP '+http.status):null),el('p',{},'A score for the observed response headers, not a security certification. Redirect destinations are not followed.')));
  const warnings=list(r.errors);
  const warning=r.error || (!scan.report?scan.stage:null) || (warnings.length ? warnings.length+' check'+(warnings.length===1?' was':'s were')+' unavailable. Open the relevant section for details.' : null);
  $('report-summary').replaceChildren(summary,...(warning?[el('div',{class:'report-warning'},message(warning))]:[]));
  renderTab();
}
function renderTab() {
  const scan=state.selected; if(!scan || scan.status==='pending') return;
  const r=scan.report||{}, http=r.http||{};
  const out=$('report-content');
  out.setAttribute('aria-labelledby','tab-'+state.tab);
  if(state.tab==='security') {
    const checks=list(http.checks);
    if(!checks.length) {out.replaceChildren(message(http.error || r.error || 'No HTTP security observations are available for this report.'));return;}
    out.replaceChildren(el('div',{class:'check-grid'},...checks.map(c=>el('article',{class:'check-card'},el('div',{class:'check-heading'},el('h3',{},c.label),el('span',{class:'check-status '+(c.state==='pass'?'pass':'')},c.state==='pass'?'✓ Configured':c.state==='review'?'Review value':'Missing')),c.value?el('code',{},c.value):null,el('p',{},c.advice)))));
    if(http.redirect) out.append(el('p',{class:'notice warning'},'This response redirects to '+http.redirect+'. Headers above belong to the initial response.'));
  } else if(state.tab==='dns') {
    const records=list(r.dns?.records);
    const input=el('input',{type:'search',placeholder:'Filter type, name or value…','aria-label':'Filter DNS records'});
    const content=el('div');
    const render=()=>{
      const query=input.value.toLowerCase();
      const rows=records.filter(d=>[d.type,d.name,d.value].some(v=>String(v).toLowerCase().includes(query)));
      if(!rows.length) {content.replaceChildren(el('p',{class:'muted'},records.length?'No DNS records match.':r.dns?.note||r.dns?.error||'No DNS records returned.'));return;}
      content.replaceChildren(dataTable(['Type','Value','TTL',''],rows.map(d=>[el('span',{class:'record-type'},d.type),el('div',{},el('code',{},d.priority!=null?'Priority '+d.priority+' · '+(d.value||'(null MX)'):d.value),el('div',{class:'domain-profile'},d.name)),el('code',{},d.ttl??'—'),copyButton(d.value)])));
    };
    input.addEventListener('input',render);
    out.replaceChildren(el('div',{class:'data-toolbar'},el('span',{},records.length+' records · TTL in seconds'),input),content);render();
    for(const error of list(r.dns?.errors)) out.append(message(error));
  } else if(state.tab==='headers') {
    const entries=Object.entries(http.headers||{}).sort(([a],[b])=>a.localeCompare(b));
    out.replaceChildren(entries.length?dataTable(['Header','Observed value',''],entries.map(([k,v])=>[el('code',{},k),el('code',{},v),copyButton(v)])):message(http.error||'No HTTP headers were collected.'));
  } else {
    const resources=el('section',{class:'footprint-block'},el('h3',{},'Public resources'));
    for(const resource of list(http.resources)) resources.append(el('div',{class:'resource-row'},el('span',{},resource.path),el('span',{class:'status-badge'},resource.error?'Unavailable':resource.status===200?'Found · 200':'HTTP '+resource.status)));
    if(!list(http.resources).length) resources.append(el('p',{},'No public resource observations.'));
    resources.append(el('p',{},'HEAD responses indicate availability; file content is not validated.'));
    const tls=el('section',{class:'footprint-block'},el('h3',{},'HTTPS verification'),el('p',{},http.tls?.verified?'The certificate chain and requested hostname passed TLS verification.':http.tls?.error||'HTTPS could not be verified.'),el('p',{},'Certificate expiry, revocation and protocol grading are not collected.'));
    const ct=el('section',{class:'footprint-block'},el('h3',{},'Certificate transparency'));
    const reg=el('section',{class:'footprint-block'},el('h3',{},'Domain registration · RDAP'));
    if(scan.profile!=='deep') {ct.append(el('p',{},'Choose Deep dive to discover historical hostnames.'));reg.append(el('p',{},'Choose Deep dive to include registration events.'));}
    else {
      const names=list(r.transparency?.names);
      ct.append(el('p',{},r.transparency?.error||r.transparency?.note||(names.length+' unique hostnames · Source: crt.sh')));
      if(names.length) ct.append(el('div',{class:'names-list'},...names.map(n=>el('div',{},n))));
      if(r.transparency?.truncated) ct.append(el('p',{},'Showing the first 300 unique hostnames.'));
      ct.append(el('p',{},'Historical records do not confirm a currently live host.'));
      const registration=r.registration;
      if(!registration || registration.error) reg.append(el('p',{},registration?.error||'Registration data unavailable.'));
      else {
        const dl=el('dl',{class:'registration-list'});
        for(const e of list(registration.events)) dl.append(el('dt',{},e.action),el('dd',{},e.date));
        for(const status of list(registration.status)) dl.append(el('dt',{},'Status'),el('dd',{},String(status)));
        reg.append(dl,el('p',{},'Source: '+registration.source));
      }
    }
    out.replaceChildren(el('div',{class:'footprint-grid'},resources,tls,ct,reg));
  }
}
function dataTable(headings,rows) {
  const table=el('table',{class:'data-table'},el('thead',{},el('tr',{},...headings.map(h=>el('th',{scope:'col'},h)))));
  table.append(el('tbody',{},...rows.map(row=>el('tr',{},...row.map((v,i)=>el('td',{class:i===1?'value-cell':''},v))))));
  return el('div',{class:'table-scroll'},table);
}
function copyButton(value) {
  return el('button',{class:'copy-button','aria-label':'Copy value',onClick:async()=>{
    try {await navigator.clipboard.writeText(String(value));toast('Copied to clipboard.');}
    catch {toast('Clipboard unavailable. Select and copy the value manually.');}
  }},'Copy');
}
function showDemo() {
  state.reportSeq++;state.selected=structuredClone(demo);state.tab='security';syncTabs();renderReport();
  $('report-section').scrollIntoView({behavior:'smooth',block:'start'});
}
function download(kind) {
  const scan=state.selected;if(!scan?.report) return;
  const text=kind==='json'?JSON.stringify(scan,null,2):reportCsv(scan);
  const url=URL.createObjectURL(new Blob([text],{type:kind==='json'?'application/json':'text/csv;charset=utf-8'}));
  const a=el('a',{href:url,download:`lualens-${scan.target}-${scan.id}${scan.id==='demo'?'-sample':''}.${kind}`});
  document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function syncTabs() {
  for(const tab of document.querySelectorAll('[data-tab]')) {const active=tab.dataset.tab===state.tab;tab.setAttribute('aria-selected',active);tab.tabIndex=active?0:-1;}
}
async function openCompare() {
  const current=state.selected;if(!current||current.id==='demo')return;
  const candidates=state.scans.filter(s=>s.target===current.target&&s.id<current.id&&s.status!=='pending'&&s.status!=='failed');
  $('compare-description').textContent=candidates.length ? 'Compare DNS, headers and historical hostnames. Results are drawn from this history page; unavailable checks can appear as differences.' : 'No earlier finished report for this domain is on the current history page. Run a fresh scan, or select a newer report on the same page.';
  $('compare-select').replaceChildren(...candidates.map(s=>el('option',{value:s.id},date(s.timestamp)+' · '+(s.profile==='deep'?'Deep':'Quick')+' · #'+s.id)));
  $('run-compare').disabled=!candidates.length;$('compare-result').replaceChildren();$('compare-dialog').showModal();
}
async function runCompare() {
  const current=state.selected;if(!current || !$('compare-select').value)return;
  $('run-compare').disabled=true;
  try {
    const before=await api('scans/'+$('compare-select').value);
    const changes=compareReports(before,current);
    $('compare-result').replaceChildren(el('p',{},changes.length+' observed difference'+(changes.length===1?'':'s')+' · Older report compared with selected report'),...(changes.length?[dataTable(['Signal','Before','After'],changes.map(c=>[el('span',{class:'change-'+c.state},c.key),el('code',{},c.before??'Not observed'),el('code',{},c.after??'Not observed')]))]:[el('p',{class:'muted'},'The observed values match. TTL and record order are excluded from this comparison.')]),el('p',{class:'muted'},'Different profiles or unavailable providers can explain missing observations. This view compares observations and cannot confirm a change at the source.'));
  } catch(error) {$('compare-result').replaceChildren(message(error.message,'error'));}
  finally {$('run-compare').disabled=false;}
}
function askDelete(scan) {state.deleteId=scan.id;$('delete-description').textContent=scan.target+' · '+date(scan.timestamp);$('delete-dialog').showModal();}
async function confirmDelete() {
  $('confirm-delete').disabled=true;
  try {
    await api('scans/'+state.deleteId,{method:'DELETE'});
    if(state.selected?.id===state.deleteId){state.reportSeq++;state.selected=null;$('report-section').hidden=true;history.replaceState(null,'',location.pathname);}
    $('delete-dialog').close();toast('Report deleted.');await refreshHistory();
  }catch(error){toast(error.message);}finally{$('confirm-delete').disabled=false;}
}
function setTheme(theme) {
  document.documentElement.dataset.theme=theme;
  $('theme-button').setAttribute('aria-label','Switch to '+(theme==='dark'?'light':'dark')+' theme');
  document.querySelector('meta[name=theme-color]').content=theme==='dark'?'#101411':'#f3f6f1';
}
try {setTheme(localStorage.getItem('lualens-theme')||'dark');} catch {setTheme('dark');}
$('theme-button').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';setTheme(theme);try{localStorage.setItem('lualens-theme',theme);}catch{}});
$('scan-form').addEventListener('submit',startScan);
for(const id of ['guide-button','help-button','privacy-button']) $(id).addEventListener('click',()=>$('guide-dialog').showModal());
$('demo-button').addEventListener('click',showDemo);
for(const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',()=>$(button.dataset.close).close());
$('history-search').addEventListener('input',renderHistory);$('status-filter').addEventListener('change',renderHistory);
$('favorites-filter').addEventListener('click',()=>{state.favorites=!state.favorites;$('favorites-filter').setAttribute('aria-pressed',state.favorites);renderHistory();});
$('refresh-button').addEventListener('click',()=>refreshHistory());
$('prev-page').addEventListener('click',()=>{if(state.page>1){state.page--;refreshHistory();}});
$('next-page').addEventListener('click',()=>{if(state.page*50<state.total){state.page++;refreshHistory();}});
$('close-report').addEventListener('click',()=>{state.reportSeq++;state.selected=null;$('report-section').hidden=true;history.replaceState(null,'',location.pathname);});
$('rescan-button').addEventListener('click',()=>{if(!state.selected)return;$('target').value=state.selected.target;document.querySelector(`input[name=profile][value=${state.selected.profile==='deep'?'deep':'quick'}]`).checked=true;$('fresh').checked=true;startScan();});
$('compare-button').addEventListener('click',openCompare);$('run-compare').addEventListener('click',runCompare);
$('export-json').addEventListener('click',()=>download('json'));$('export-csv').addEventListener('click',()=>download('csv'));
$('confirm-delete').addEventListener('click',confirmDelete);
const tabs=[...document.querySelectorAll('[data-tab]')];
for(const tab of tabs) {
  tab.addEventListener('click',()=>{state.tab=tab.dataset.tab;syncTabs();renderTab();});
  tab.addEventListener('keydown',event=>{
    let i=tabs.indexOf(tab);
    if(event.key==='ArrowRight')i=(i+1)%tabs.length;else if(event.key==='ArrowLeft')i=(i+tabs.length-1)%tabs.length;else if(event.key==='Home')i=0;else if(event.key==='End')i=tabs.length-1;else return;
    event.preventDefault();tabs[i].focus();tabs[i].click();
  });
}
document.addEventListener('keydown',event=>{if(event.key==='/' && !event.ctrlKey && !event.metaKey && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName) && !document.querySelector('dialog[open]')){event.preventDefault();$('target').focus();}});
async function init() {
  $('scan-submit').disabled=true;$('history-content').replaceChildren(el('div',{class:'loading-state'},'Opening your private workspace…'));
  try {
    const bootstrap=await api('bootstrap');state.csrf=bootstrap.csrf;setBusy(false);await refreshHistory();
    const id=location.hash.match(/^#report=(\d+)$/)?.[1];if(id)await openReport(id);
  }catch(error){$('form-error').textContent=error.message+' Reload this page to retry.';$('form-error').hidden=false;$('history-content').replaceChildren(message('Your workspace could not be opened.','error'));}
}
init();
