/* Recorded incidents, not a census of attacks. UTC calendar days avoid DST gaps. */
(function (root) {
  function dailyTrend(incidents, now = new Date()) {
    const end = new Date(now).toISOString().slice(0, 10);
    const start = '2026-08-01', counts = new Map(), seen = new Set();
    let undated = 0;
    for (const incident of incidents) {
      if (incident.id != null && seen.has(String(incident.id))) continue;
      if (incident.id != null) seen.add(String(incident.id));
      const day = incident.date;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(day || '') || !Number.isFinite(Date.parse(day)) || new Date(day).toISOString().slice(0, 10) !== day) { undated++; continue; }
      if (day >= start && day <= end) counts.set(day, (counts.get(day) || 0) + 1);
    }
    const days = [];
    for (let t = Date.parse(start); t <= Date.parse(end); t += 86400000) {
      const day = new Date(t).toISOString().slice(0, 10);
      days.push({day, count: counts.get(day) || 0});
    }
    return {start, end, days, undated};
  }
  function renderTrend(incidents, updated) {
    const trend = dailyTrend(incidents), max = Math.max(1, ...trend.days.map(d => d.count));
    const width = 700, height = 80, step = width / trend.days.length;
    document.getElementById('trend-chart').innerHTML = `<svg viewBox="0 0 740 110" role="img" aria-label="Daily recorded incidents from ${trend.start} through ${trend.end}; maximum ${max} in one day"><text x="0" y="14" fill="#A7B4C2" font-size="12">${max}</text><text x="0" y="91" fill="#A7B4C2" font-size="12">0</text>${trend.days.map((d,i) => `<rect x="${30+i*step}" y="${90-d.count/max*height}" width="${Math.max(.5,step-.5)}" height="${d.count/max*height}" fill="#8DC4FF"><title>${d.day}: ${d.count} recorded incidents</title></rect>`).join('')}<text x="30" y="108" fill="#A7B4C2" font-size="12">Aug 1, ${trend.start.slice(0,4)}</text><text x="730" y="108" text-anchor="end" fill="#A7B4C2" font-size="12">${trend.end} (partial)</text></svg>`;
    document.getElementById('trend-note').textContent = `All categories, independent of map filters. Incomplete reporting; blank days mean no dated records, not no attacks. ${trend.undated} records with imprecise dates excluded. Data: ${updated ? new Date(updated).toLocaleString() : 'unknown'}.`;
  }
  root.MapTrends = {dailyTrend, renderTrend};
  if (typeof module !== 'undefined') module.exports = root.MapTrends;
})(typeof window === 'undefined' ? globalThis : window);
