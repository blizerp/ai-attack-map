const assert = require('node:assert/strict');
const {dailyTrend} = require('./map-trends.js');
const result = dailyTrend([{id:1,date:'2026-08-01',locations:[{},{}]}, {id:1,date:'2026-08-01'}, {id:2,date:'2026-08-01'}, {id:3,date:'August 2026'}, {id:4,date:'2026-11-13'}, {id:5,date:'2026-07-31'}, {id:6,date:'2026-09-31'}], new Date('2026-11-12T00:00:00Z'));
assert.equal(result.days.length,104);
assert.equal(result.days[0].count,2);
assert.equal(result.undated,2);
assert.equal(result.days.reduce((n,d)=>n+d.count,0),2);
assert.equal(dailyTrend([],new Date('2027-01-01')).start,'2026-08-01');
console.log('Trend tests passed');
