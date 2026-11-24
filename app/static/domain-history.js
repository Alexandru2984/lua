import { list,hasScore,certificateExpiry } from './report.js?v=2.2';
export function createDomainHistory({api,el,message,formatDate,statusBadge,openReport,now}) {
  const $=id=>document.getElementById(id);
  let target='',selected=null,cursor=null,stack=[],rows=[],more=false,busy=false,generation=0;
  let observer;
  const navigation=disabled=>{for(const button of document.querySelectorAll('#domain-history-dialog [data-history-page]'))button.disabled=disabled||(button.dataset.historyPage==='newer'?stack.length===0:!more);};
  const node=(tag,attrs={},...children)=>{
    const result=document.createElementNS('http://www.w3.org/2000/svg',tag);
    for(const [key,value] of Object.entries(attrs))result.setAttribute(key,String(value));
    for(const child of children.flat())result.append(child instanceof Node?child:document.createTextNode(String(child)));
    return result;
  };
  function chart() {
    const host=$('domain-score-chart');
    const chronological=[...rows].reverse();
    if(!chronological.some(r=>hasScore(r.score))){host.replaceChildren(el('p',{class:'muted'},'No header scores were recorded on this page.'));return;}
    const width=Math.max(280,Math.floor(host.clientWidth)),height=200,left=34,right=16,top=16,bottom=35;
    const x=i=>chronological.length===1?width/2:left+i*(width-left-right)/(chronological.length-1);
    const y=score=>top+(100-score)*(height-top-bottom)/100;
    const svg=node('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'HTTP header configuration scores, oldest to newest. Missing scores leave gaps.'},node('title',{},'Header configuration scores for '+target),node('desc',{},'One point per scan. Scores describe observed headers, not overall security. The accessible report list follows this chart.'));
    for(const tick of [0,25,50,75,100])svg.append(node('line',{x1:left,x2:width-right,y1:y(tick),y2:y(tick),class:'chart-grid'}),node('text',{x:left-8,y:y(tick)+4,'text-anchor':'end',class:'chart-label'},tick));
    let segment=[];
    const flush=()=>{if(segment.length>1)svg.append(node('polyline',{points:segment.join(' '),class:'chart-line'}));segment=[];};
    chronological.forEach((row,i)=>{if(hasScore(row.score))segment.push(x(i)+','+y(row.score));else flush();});flush();
    chronological.forEach((row,i)=>{if(hasScore(row.score))svg.append(node('circle',{cx:x(i),cy:y(row.score),r:4,class:row.status==='partial'?'chart-point chart-partial':'chart-point'},node('title',{},formatDate(row.timestamp)+' · '+row.score+'/100 · '+row.status)));});
    const day=r=>{const d=new Date(r.timestamp.replace(' ','T')+'Z');return Number.isNaN(d.getTime())?'Unknown date':d.toLocaleDateString(undefined,{month:'short',day:'numeric'});};
    if(chronological.length===1)svg.append(node('text',{x:width/2,y:height-5,'text-anchor':'middle',class:'chart-label'},day(chronological[0])));
    else svg.append(node('text',{x:left,y:height-5,class:'chart-label'},day(chronological[0])),node('text',{x:width-right,y:height-5,'text-anchor':'end',class:'chart-label'},day(chronological.at(-1))));
    host.replaceChildren(svg);
  }
  function render() {
    $('domain-history-summary').textContent=`Page ${stack.length+1} · ${rows.length} retained scan${rows.length===1?'':'s'} · Times use your browser timezone.`;
    navigation(false);
    if(!rows.length)$('domain-history-list').replaceChildren(el('p',{class:'muted'},'No retained reports for this domain in your workspace.'));
    else $('domain-history-list').replaceChildren(...rows.map(row=>{
      const info=el('div',{class:'timeline-row-main'},el('strong',{},formatDate(row.timestamp)),el('div',{class:'timeline-row-meta'},statusBadge(row.status),el('span',{},(row.profile==='deep'?'Deep dive':'Quick look')+' · #'+row.id)));
      const details=el('div',{class:'timeline-row-details'},el('span',{},'Header score '+(hasScore(row.score)?row.score+'/100':'unavailable')),el('span',{},typeof row.http_status==='number'?'HTTP '+row.http_status:'HTTP unavailable'));
      if(typeof row.certificate_not_after==='number'){
        const expiry=certificateExpiry(row.certificate_not_after,now());
        details.append(el('span',{class:'recorded-expiry expiry-'+expiry.state},expiry.label));
      }
      const button=el('button',{class:'secondary-button',onClick:()=>{$('domain-history-dialog').close();openReport(row.id,true);}},row.id===selected?.id?'Open selected report':'Open report');
      return el('article',{class:'timeline-row'+(row.id===selected?.id?' timeline-selected':'')},info,details,button);
    }));
    chart();observer?.disconnect();observer=new ResizeObserver(chart);observer.observe($('domain-score-chart'));
  }
  async function load() {
    busy=true;const sequence=++generation;
    navigation(true);
    $('domain-history-summary').textContent='Loading retained scans…';$('domain-score-chart').replaceChildren();$('domain-history-list').replaceChildren(el('p',{class:'muted'},'Loading domain history…'));
    try{
      const result=await api('domain-history?target='+encodeURIComponent(target)+(cursor?'&before='+cursor:''));
      if(sequence!==generation||!$('domain-history-dialog').open)return;
      rows=list(result.scans);more=result.has_more===true;render();
    }catch(error){if(sequence===generation&&$('domain-history-dialog').open){$('domain-history-summary').textContent='History could not be loaded.';$('domain-history-list').replaceChildren(message(error.message,'error'));}}
    finally{if(sequence===generation)busy=false;}
  }
  for(const button of document.querySelectorAll('#domain-history-dialog [data-history-page]'))button.addEventListener('click',()=>{
    if(busy)return;
    if(button.dataset.historyPage==='older'){if(!more||!rows.length)return;stack.push(cursor);cursor=rows.at(-1).id;}
    else {if(!stack.length)return;cursor=stack.pop();}
    load();
  });
  $('domain-history-dialog').addEventListener('close',()=>{generation++;busy=false;observer?.disconnect();});
  return {open(scan){if(!scan||scan.id==='demo')return;target=scan.target;selected=scan;cursor=null;stack=[];$('domain-history-title').textContent=target+' · Scan history';if(!$('domain-history-dialog').open)$('domain-history-dialog').showModal();load();}};
}
