const {test} = require('node:test');
const assert = require('node:assert/strict');
const {missingBriefing} = require('./briefing.js');
const missing = (stamp, editions=[]) => missingBriefing(editions, Date.parse(stamp));

test('morning and evening thirty-minute grace, including exact boundaries', () => {
  const evening=[{id:'2026-10-27-evening'}];
  assert.equal(missing('2026-10-28T12:29:59Z', evening),null);
  assert.equal(missing('2026-10-28T12:30:00Z', evening).id,'2026-10-28-morning');
  const morning=[{id:'2026-10-28-morning'}];
  assert.equal(missing('2026-10-28T21:29:59Z', morning),null);
  assert.equal(missing('2026-10-28T21:30:00Z', morning).id,'2026-10-28-evening');
});
test('missing morning is visible even with a recent evening publication',()=>{
  assert.equal(missing('2026-10-28T13:43:00Z',[{id:'2026-10-27-evening',published_at:'2026-10-28T00:20:00Z'}]).edition,'morning');
});
test('late publication satisfies edition ID and does not warn again',()=>{
  assert.equal(missing('2026-10-28T19:00:00Z',[{id:'2026-10-28-morning',published_at:'2026-10-28T18:00:00Z'}]),null);
});
test('summer, winter, both DST transitions and local midnight',()=>{
  for(const [stamp,id] of [
    ['2026-07-01T12:30:00Z','2026-07-01-morning'],
    ['2026-12-01T13:30:00Z','2026-12-01-morning'],
    ['2026-03-08T12:30:00Z','2026-03-08-morning'],
    ['2026-11-01T13:30:00Z','2026-11-01-morning'],
    ['2026-11-01T05:30:00Z','2026-10-31-evening'],
    ['2026-11-01T06:30:00Z','2026-10-31-evening'],
    ['2026-01-01T05:01:00Z','2025-12-31-evening']]) assert.equal(missing(stamp).id,id);
});
test('opening brief covers its own due slot, not the next',()=>{
  const initial=[{id:'2026-10-28-initial',edition:'initial',window_end:'2026-10-28T14:00:00Z'}];
  assert.equal(missing('2026-10-28T15:00:00Z',initial),null);
  assert.equal(missing('2026-10-28T22:00:00Z',initial).edition,'evening');
});

test('newer publication supersedes previous missing edition during grace',()=>{
  assert.equal(missing('2026-10-28T12:05:00Z',[{id:'2026-10-28-morning'}]),null);
  assert.equal(missing('2026-10-28T21:05:00Z',[{id:'2026-10-28-evening'}]),null);
  assert.equal(missing('2026-10-28T12:05:00Z',[{edition:'initial',window_end:'2026-10-28T12:02:00Z'}]),null);
});
