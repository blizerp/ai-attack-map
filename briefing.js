// Evaluate expected publication by New York calendar time, including DST.
// Thirty minutes allows normal generation; a missed dispatch is visible afterward.
function expectedBriefing(now) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date(now)).map(p => [p.type, p.value]));
  let date = `${parts.year}-${parts.month}-${parts.day}`;
  const hour = Number(parts.hour);
  const edition = hour >= 17 || hour < 8 ? 'evening' : 'morning';
  if (hour < 8) date = new Date(Date.parse(date + 'T12:00:00Z') - 86400000).toISOString().slice(0, 10);
  const id = date + '-' + edition;
  return {id, date, edition};
}
function missingBriefing(editions, now = Date.now()) {
  const expected = expectedBriefing(now - 30 * 60000);
  const key = slot => slot.date + '-' + (slot.edition === 'morning' ? '08' : '17');
  const expectedKey = key(expected);
  const covered = editions.some(e => {
    if (e.edition === 'initial' && Number.isFinite(Date.parse(e.window_end)))
      return key(expectedBriefing(Date.parse(e.window_end))) >= expectedKey;
    const match = /^(\d{4}-\d{2}-\d{2})-(morning|evening)$/.exec(e.id || '');
    return match && key({date:match[1], edition:match[2]}) >= expectedKey;
  });
  return covered ? null : expected;
}
if (typeof module !== 'undefined' && module.exports) module.exports = {missingBriefing};

if (typeof document !== 'undefined') (() => {
  const tabs = {overview:'Overview', energy:'Energy & Power', water:'Water', food:'Food & Agriculture', finance:'Finance', healthcare:'Healthcare', internet:'Internet & Telecom', supply_chain:'Supply Chain'};
  const editionNames = {morning:'Morning', evening:'Evening', initial:'Opening brief'};
  const shell = document.getElementById('threat-brief');
  const toggle = document.getElementById('brief-toggle');
  const body = document.getElementById('brief-body');
  const content = document.getElementById('brief-content');
  const date = document.getElementById('brief-date');
  const editions = document.getElementById('brief-editions');
  const tablist = document.getElementById('brief-tabs');
  let data = null, selectedTab = 'overview', selectedEdition = null, loadVersion = 0, refreshFailed = false;
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const link = value => /^https?:\/\//i.test(value || '') ? escape(value) : '#';
  const time = value => new Date(value).toLocaleString('en-US', {timeZone:'America/New_York', month:'short', day:'numeric', hour:'numeric', minute:'2-digit', timeZoneName:'short'});
  const day = value => new Date(value+'T12:00:00Z').toLocaleDateString('en-US', {timeZone:'America/New_York',month:'short',day:'numeric',year:'numeric'});
  tablist.innerHTML = Object.entries(tabs).map(([key,name]) => `<button role="tab" id="brief-tab-${key}" aria-controls="brief-content" aria-selected="${key==='overview'}" tabindex="${key==='overview'?0:-1}" data-tab="${key}">${name}</button>`).join('');
  function chooseTab(key) {
    selectedTab = key;
    tablist.querySelectorAll('button').forEach(b => {b.setAttribute('aria-selected', String(b.dataset.tab===key)); b.tabIndex=b.dataset.tab===key?0:-1;});
    content.setAttribute('aria-labelledby','brief-tab-'+key);
    renderBrief();
  }
  tablist.addEventListener('click', event => {const b=event.target.closest('button[data-tab]'); if(b) chooseTab(b.dataset.tab);});
  tablist.addEventListener('keydown', event => {
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault(); const keys=Object.keys(tabs); let n=keys.indexOf(selectedTab);
    n=event.key==='Home'?0:event.key==='End'?keys.length-1:(n+(event.key==='ArrowRight'?1:-1)+keys.length)%keys.length;
    chooseTab(keys[n]); document.getElementById('brief-tab-'+keys[n]).focus();
  });
  function newestForDate() {return data?.editions.filter(e => e.date===date.value).at(-1);}
  function renderBrief() {
    if(!data) return;
    const all=data.editions || [];
    const overview=all.find(e => e.id===selectedEdition) || newestForDate();
    const missing=missingBriefing(all);
    const refreshWarning=refreshFailed?'<p class="brief-warning">Could not refresh the briefing. Showing the last loaded copy; close and reopen to retry.</p>':'';
    const overdue=refreshWarning+(missing?`<p class="brief-warning">The ${escape(day(missing.date))} ${escape(missing.edition)} briefing is overdue (scheduled for ${missing.edition==='morning'?'8 a.m.':'5 p.m.'} Eastern). Catch-up checks are enabled; publication may still be delayed.</p>`:'');
    if(!overview) {content.innerHTML=overdue+(data.last_attempt?.status==='failed'?'<p class="brief-warning">The first briefing could not be completed. A new edition will appear after a successful update.</p>':'<p>The first briefing has not been published yet.</p>'); return;}
    editions.hidden=selectedTab!=='overview';
    editions.innerHTML=all.filter(e=>e.date===date.value).map(e=>`<button data-edition="${escape(e.id)}" aria-pressed="${e.id===overview.id}">${editionNames[e.edition]||'Briefing'}</button>`).join('');
    const edition=selectedTab==='overview'?overview:all.filter(e=>e.sectors_enabled&&e.date<=date.value).at(-1);
    if(!edition) {content.innerHTML=overdue+'<p>Sector roundups will appear with the first evening briefing at 5 p.m. Eastern.</p>'; return;}
    const section=selectedTab==='overview'?edition.overview:edition.sectors[selectedTab];
    const title=selectedTab==='overview'?(edition.edition==='initial'?'Opening brief':(editionNames[edition.edition]||'Latest')+' briefing'):tabs[selectedTab]+' daily roundup';
    const failed=data.last_attempt?.status==='failed';
    const previousSector=selectedTab!=='overview'&&edition.date!==date.value;
    content.innerHTML=`${overdue}${failed?'<p class="brief-warning">The latest update could not be completed. The previous published briefing is still available below.</p>':''}
      <h2>${escape(title)}</h2><p class="brief-time">Published ${escape(time(edition.published_at))}<br>Reporting window: ${escape(time(selectedTab==='overview'?edition.window_start:edition.sector_window_start))} – ${escape(time(edition.window_end))}</p>
      ${previousSector?'<p class="brief-warning">Showing the previous daily roundup. The next sector update is due at 5 p.m. Eastern.</p>':''}
      ${(edition.warnings||[]).map(w=>`<p class="brief-warning">${escape(w)}</p>`).join('')}
      ${section?.intro?`<p class="brief-intro">${escape(section.intro)}</p>`:''}
      ${section?.items?.length?section.items.map(item=>`<article class="brief-item"><span class="brief-change">${escape(item.change)}</span><h3>${escape(item.headline)}</h3>
        <p>${escape(item.what_happened)}</p><p><strong>Why it matters:</strong> ${escape(item.impact)}</p><p><strong>What to watch:</strong> ${escape(item.what_next)}</p>
        <div class="brief-sources">${item.sources.map(s=>`<a href="${link(s.url)}" target="_blank" rel="noopener noreferrer">${escape(s.name)}</a>`).join('')}</div>
        ${(item.incident_ids||[]).map(id=>{const incident=typeof state!=='undefined'&&state.incidents.find(i=>i.id===id);return incident?`<button class="brief-map" data-brief-incident="${escape(id)}">${mapLocations(incident).length?'Show on map':'Incident details'}${item.incident_ids.length>1?' · '+escape(incident.victim):''}</button>`:'';}).join('')}
      </article>`).join(''):'<p>No significant new developments found in the monitored sources for this briefing.</p>'}`;
  }
  editions.addEventListener('click',event=>{const b=event.target.closest('[data-edition]');if(b){selectedEdition=b.dataset.edition;renderBrief();}});
  date.addEventListener('change',()=>{selectedEdition=newestForDate()?.id;renderBrief();});
  content.addEventListener('click',event=>{
    const b=event.target.closest('[data-brief-incident]'); if(!b||typeof state==='undefined')return;
    const incident=state.incidents.find(i=>i.id===b.dataset.briefIncident);if(!incident)return;
    const locations=mapLocations(incident);
    if(locations.length){
      if(!visible().some(i=>i.id===incident.id)){state.days=0;state.cats.add(incident.category);document.querySelectorAll('.seg button').forEach(x=>x.setAttribute('aria-pressed',x.dataset.days==='0'));document.querySelectorAll('.legend input').forEach(x=>x.checked=state.cats.has(x.dataset.cat));render();}
      map.panTo([locations[0].lat,locations[0].lon]);
    }
    closeBrief();openIncident(incident,locations[0]||null);
  });
  function closeBrief(){shell.classList.remove('open');body.hidden=true;toggle.setAttribute('aria-expanded','false');document.getElementById('brief-toggle-icon').textContent='+';shell.dispatchEvent(new Event('close',{bubbles:true}));}
  async function loadBrief(preserveSelection=false){
    const version=++loadVersion;
    try{
      const response=await fetch('briefings.json?v='+Date.now(),{cache:'no-store'});if(!response.ok)throw Error(response.status);
      const nextData=await response.json();
      if(version!==loadVersion)return;
      const oldDate=date.value, oldEdition=selectedEdition, oldTab=selectedTab;
      const wasLatest=oldEdition===data?.editions.at(-1)?.id;
      data=nextData;refreshFailed=false;
      const dates=[...new Set(data.editions.map(e=>e.date))].sort().reverse();
      date.innerHTML=dates.map(d=>`<option value="${escape(d)}">${escape(day(d))}</option>`).join('');
      selectedEdition=data.editions.at(-1)?.id;
      if(preserveSelection&&!wasLatest&&dates.includes(oldDate)){date.value=oldDate;selectedEdition=oldEdition;}
      chooseTab(preserveSelection?oldTab:'overview');
    }catch(_){
      if(version!==loadVersion)return;
      if(data){refreshFailed=true;renderBrief();}
      else content.innerHTML='<p>The briefing could not be loaded. Close and reopen this panel to try again.</p>';
    }
  }
  toggle.addEventListener('click',()=>{
    if(shell.classList.contains('open')){closeBrief();return;}
    shell.classList.add('open');body.hidden=false;toggle.setAttribute('aria-expanded','true');document.getElementById('brief-toggle-icon').textContent='−';
    loadBrief();
    body.scrollTop=0;
  });
  setInterval(()=>{if(!body.hidden&&data)renderBrief();},60000);
  setInterval(()=>{if(!body.hidden)loadBrief(true);},300000);
  shell.addEventListener('keydown',e=>{if(e.key==='Escape'){closeBrief();toggle.focus();}});
})();
