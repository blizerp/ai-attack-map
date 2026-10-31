// Optional DOM regression harness: npm install --no-save --ignore-scripts jsdom@26.1.0
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {JSDOM}=require('jsdom');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
test('panel refresh, tabs, keyboard dismissal, retries and request ordering',async()=>{
  const dom=new JSDOM(`<div id="threat-brief"><button id="brief-toggle"><span id="brief-toggle-icon"></span></button><div id="brief-body" hidden><select id="brief-date"></select><div id="brief-editions"></div><div id="brief-tabs"></div><div id="brief-content"></div></div></div>`,{runScripts:'outside-only'});
  const w=dom.window, d=w.document;
  w.Date.now=()=>Date.parse('2026-10-28T13:43:00Z');
  const intervals=[];w.setInterval=(fn,ms)=>intervals.push({fn,ms});
  const prior={id:'2026-10-27-evening',date:'2026-10-27',edition:'evening',published_at:'2026-10-28T00:20:00Z',window_start:'2026-10-27T12:00:00Z',window_end:'2026-10-28T00:20:00Z',sector_window_start:'2026-10-27T00:20:00Z',overview:{intro:'Prior briefing',items:[]},sectors_enabled:true,sectors:{},warnings:[]};
  const fixture={editions:[prior],last_attempt:{status:'ok'}};
  const response=()=>({ok:true,json:async()=>structuredClone(fixture)});
  w.fetch=async()=>response();
  w.eval(fs.readFileSync(require.resolve('./briefing.js'),'utf8'));
  const toggle=()=>d.getElementById('brief-toggle').click();
  const content=()=>d.getElementById('brief-content').textContent;
  toggle();await flush();assert.match(content(),/morning briefing is overdue/);assert.match(content(),/Prior briefing/);
  d.querySelector('[data-tab="energy"]').click();assert.match(content(),/morning briefing is overdue/);
  d.getElementById('threat-brief').dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape'}));
  assert.equal(d.getElementById('brief-toggle').getAttribute('aria-expanded'),'false');
  fixture.editions.push({...prior,id:'2026-10-28-morning',date:'2026-10-28',edition:'morning',sectors_enabled:false,overview:{intro:'Recovered morning',items:[]}});
  toggle();await flush();assert.match(content(),/Recovered morning/);assert.doesNotMatch(content(),/briefing is overdue/);
  w.fetch=async()=>{throw Error('offline')};toggle();toggle();await flush();
  assert.match(content(),/Could not refresh/);assert.match(content(),/Recovered morning/);
  intervals.find(i=>i.ms===60000).fn();assert.match(content(),/Could not refresh/);
  let resolveOld,count=0;
  w.fetch=async()=>++count===1?new Promise(resolve=>resolveOld=resolve):response();
  toggle();toggle();toggle();toggle();await flush();
  resolveOld({ok:true,json:async()=>({editions:[]})});await flush();assert.match(content(),/Recovered morning/);
  // Periodic refresh preserves an explicitly selected historic edition and tab.
  d.getElementById('brief-date').value='2026-10-27';d.getElementById('brief-date').dispatchEvent(new w.Event('change'));
  d.querySelector('[data-tab="energy"]').click();
  await intervals.find(i=>i.ms===300000).fn();await flush();
  assert.equal(d.getElementById('brief-date').value,'2026-10-27');
  assert.equal(d.querySelector('[data-tab="energy"]').getAttribute('aria-selected'),'true');
  dom.window.close();
});
