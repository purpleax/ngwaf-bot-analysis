// Turns unified-API NGWAF events into the three answers the dashboard asks:
//   1. Top threats (last 7 days)
//   2. Top priority to action
//   3. Attack trends
//
// Structure: fetch+aggregate a single workspace into a mergeable "raw" object,
// then either format one workspace (buildOverview) or merge several and format
// the result (buildAggregate for the customer-wide "All workspaces" view). All
// heavy lifting lives here so the HTTP layer and the frontend stay thin.

import { listEvents } from './fastlyApi.js';

// Signal severity + human labels. Anything not listed defaults to "low".
// High-severity attack classes are the block-rule candidates.
const SIGNALS = {
  SQLI: { label: 'SQL Injection', severity: 'high' },
  CMDEXE: { label: 'Command Execution', severity: 'high' },
  'LOG4J-JNDI': { label: 'Log4j / JNDI', severity: 'high' },
  TRAVERSAL: { label: 'Directory Traversal', severity: 'high' },
  XSS: { label: 'Cross-Site Scripting', severity: 'high' },
  BACKDOOR: { label: 'Backdoor / Webshell', severity: 'high' },
  RCE: { label: 'Remote Code Execution', severity: 'high' },
  XXE: { label: 'XML External Entity', severity: 'high' },
  SSRF: { label: 'Server-Side Request Forgery', severity: 'high' },
  USERAGENT: { label: 'Malicious User-Agent', severity: 'medium' },
  SCANNER: { label: 'Scanner Activity', severity: 'medium' },
  'FORCEFULBROWSING': { label: 'Forceful Browsing', severity: 'medium' },
  NOUA: { label: 'Missing User-Agent', severity: 'medium' },
  NULLBYTE: { label: 'Null Byte Injection', severity: 'medium' },
  'HTTP403': { label: 'HTTP 403 Responses', severity: 'low' },
  'HTTP404': { label: 'HTTP 404 Responses', severity: 'low' },
  LOGINSUCCESS: { label: 'Login Success', severity: 'info' },
  LOGINFAILURE: { label: 'Login Failure', severity: 'low' },
};

const SEVERITY_WEIGHT = { high: 5, medium: 3, low: 1, info: 0 };
const MAX_EXAMPLES = 6;

function signalMeta(name) {
  const m = SIGNALS[name];
  if (m) return m;
  // Heuristic fallback: corp.* / anomaly signals treated as low.
  const severity = /^(corp|site)\./i.test(name) ? 'low' : 'medium';
  return { label: name, severity };
}

// --- window helpers -------------------------------------------------------

const WINDOW_SECONDS = { '24h': 86400, '7d': 604800, '14d': 1209600 };

export function windowRange(windowStr, nowMs = Date.now()) {
  const seconds = WINDOW_SECONDS[windowStr] || WINDOW_SECONDS['7d'];
  const until = Math.floor(nowMs / 1000);
  const from = until - seconds;
  return { from, until, seconds };
}

function dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

// Was the example request actually blocked (vs only flagged)?
function eventWasBlocked(ev) {
  const tags = ev?.exampleRequest?.tags || [];
  if (tags.some((t) => t.type === 'BLOCKED')) return true;
  const code = ev?.exampleRequest?.agentResponseCode;
  return code && code >= 400 && code !== 404;
}

// Pull a drill-down example (path + attack payload) for one signal from an event.
function extractExample(ev, signalName, workspace) {
  const req = ev.exampleRequest || {};
  const tag = (req.tags || []).find((t) => t.type === signalName);
  return {
    workspace: workspace || null,
    timestamp: ev.timestamp || ev.detectedTimestamp || null,
    ip: ev.source || req.remoteIP || null,
    country: ev.remoteCountryCode || req.remoteCountryCode || '',
    method: req.method || '',
    path: req.path || req.uri || '',
    host: req.serverHostname || req.serverName || '',
    userAgent: req.userAgent || (ev.userAgents && ev.userAgents[0]) || '',
    responseCode: req.agentResponseCode || req.responseCode || null,
    blocked: eventWasBlocked(ev),
    attackLocation: tag?.location || '',
    attackValue: tag?.value || '',
  };
}

// --- raw aggregation (mergeable) -----------------------------------------

function emptyRaw() {
  return {
    bySignal: new Map(), // name -> {name, events, requests, blocked, ips:Set, countries:Set, lastSeen}
    byDay: new Map(), // day -> {events, requests}
    byDaySignal: new Map(), // day -> Map(signal -> requests)
    byIP: new Map(), // ip -> {ip, events, requests, blocked, signals:Set, country, lastSeen}
    byPath: new Map(), // path -> requests
    byCountry: new Map(), // cc -> requests
    examplesBySignal: new Map(), // signal -> [example]
    totalRequests: 0, // summed requestCount over sampled events
    blockedEvents: 0,
    totalEventCount: 0, // authoritative event count (events endpoint meta.total)
    sampledEvents: 0, // events actually processed
    flaggedRequestsTotal: null, // dormant; kpis falls back to summed sampled requestCount
    topIPs: [], // [{ip, count}]
    suspicious: [],
    errors: [],
    workspaces: [], // workspace ids contributing to this raw
  };
}

function aggregateEvents(raw, events, workspace) {
  for (const ev of events) {
    const ts = ev.timestamp || ev.detectedTimestamp;
    const day = ts ? dayKey(ts) : 'unknown';
    const rc = ev.requestCount || 1;
    const blocked = eventWasBlocked(ev);
    raw.sampledEvents += 1;
    raw.totalRequests += rc;
    if (blocked) raw.blockedEvents += 1;

    const d = raw.byDay.get(day) || { events: 0, requests: 0 };
    d.events += 1;
    d.requests += rc;
    raw.byDay.set(day, d);

    const path = ev.exampleRequest?.path;
    if (path) raw.byPath.set(path, (raw.byPath.get(path) || 0) + rc);
    if (ev.remoteCountryCode) raw.byCountry.set(ev.remoteCountryCode, (raw.byCountry.get(ev.remoteCountryCode) || 0) + rc);

    if (ev.source) {
      const ip = raw.byIP.get(ev.source) || {
        ip: ev.source, events: 0, requests: 0, blocked: 0,
        signals: new Set(), country: ev.remoteCountryCode || '', lastSeen: ts,
      };
      ip.events += 1;
      ip.requests += rc;
      if (blocked) ip.blocked += 1;
      if (ts && ts > ip.lastSeen) ip.lastSeen = ts;
      raw.byIP.set(ev.source, ip);
    }

    for (const name of Object.keys(ev.reasons || {})) {
      const s = raw.bySignal.get(name) || {
        name, events: 0, requests: 0, blocked: 0,
        ips: new Set(), countries: new Set(), lastSeen: ts,
      };
      s.events += 1;
      s.requests += rc;
      if (blocked) s.blocked += 1;
      if (ev.source) s.ips.add(ev.source);
      if (ev.remoteCountryCode) s.countries.add(ev.remoteCountryCode);
      if (ts && ts > s.lastSeen) s.lastSeen = ts;
      raw.bySignal.set(name, s);

      if (ev.source) raw.byIP.get(ev.source)?.signals.add(name);

      const dm = raw.byDaySignal.get(day) || new Map();
      dm.set(name, (dm.get(name) || 0) + rc);
      raw.byDaySignal.set(day, dm);

      const ex = raw.examplesBySignal.get(name) || [];
      if (ex.length < MAX_EXAMPLES) {
        ex.push(extractExample(ev, name, workspace));
        raw.examplesBySignal.set(name, ex);
      }
    }
  }
}

// Fetch one workspace's events and aggregate them into a raw object.
// The unified events endpoint drives the threat-context panel (top threats are
// derived from event `reasons`). `from`/`until` are unix seconds internally and
// converted to RFC 3339 for the API.
async function fetchWorkspaceRaw({ workspace, customerId, from, until }) {
  const raw = emptyRaw();
  raw.workspaces = workspace ? [workspace] : [];

  try {
    const res = await listEvents(customerId, workspace, {
      from: new Date(from * 1000).toISOString(),
      until: new Date(until * 1000).toISOString(),
    });
    const events = res?.data || [];
    raw.totalEventCount = res?.totalCount ?? events.length;
    aggregateEvents(raw, events, workspace);
  } catch (err) {
    raw.errors.push(`${workspace || 'workspace'}: ${String(err.message || err)}`);
  }
  return raw;
}

// --- merge several raws into one -----------------------------------------

function mergeRaw(list) {
  const out = emptyRaw();
  const ipCount = new Map();

  for (const r of list) {
    out.workspaces.push(...r.workspaces);
    out.totalRequests += r.totalRequests;
    out.blockedEvents += r.blockedEvents;
    out.totalEventCount += r.totalEventCount;
    out.sampledEvents += r.sampledEvents;
    if (r.flaggedRequestsTotal != null) {
      out.flaggedRequestsTotal = (out.flaggedRequestsTotal || 0) + r.flaggedRequestsTotal;
    }
    out.errors.push(...r.errors);
    out.suspicious.push(...r.suspicious);

    for (const [name, s] of r.bySignal) {
      const t = out.bySignal.get(name) || {
        name, events: 0, requests: 0, blocked: 0, ips: new Set(), countries: new Set(), lastSeen: s.lastSeen,
      };
      t.events += s.events;
      t.requests += s.requests;
      t.blocked += s.blocked;
      s.ips.forEach((v) => t.ips.add(v));
      s.countries.forEach((v) => t.countries.add(v));
      if (s.lastSeen > t.lastSeen) t.lastSeen = s.lastSeen;
      out.bySignal.set(name, t);
    }
    for (const [day, d] of r.byDay) {
      const t = out.byDay.get(day) || { events: 0, requests: 0 };
      t.events += d.events;
      t.requests += d.requests;
      out.byDay.set(day, t);
    }
    for (const [day, dm] of r.byDaySignal) {
      const t = out.byDaySignal.get(day) || new Map();
      for (const [sig, v] of dm) t.set(sig, (t.get(sig) || 0) + v);
      out.byDaySignal.set(day, t);
    }
    for (const [ip, info] of r.byIP) {
      const t = out.byIP.get(ip) || {
        ip, events: 0, requests: 0, blocked: 0, signals: new Set(), country: info.country, lastSeen: info.lastSeen,
      };
      t.events += info.events;
      t.requests += info.requests;
      t.blocked += info.blocked;
      info.signals.forEach((v) => t.signals.add(v));
      if (info.lastSeen > t.lastSeen) t.lastSeen = info.lastSeen;
      out.byIP.set(ip, t);
    }
    for (const [p, v] of r.byPath) out.byPath.set(p, (out.byPath.get(p) || 0) + v);
    for (const [c, v] of r.byCountry) out.byCountry.set(c, (out.byCountry.get(c) || 0) + v);
    for (const [sig, exs] of r.examplesBySignal) {
      const cur = out.examplesBySignal.get(sig) || [];
      for (const e of exs) if (cur.length < MAX_EXAMPLES) cur.push(e);
      out.examplesBySignal.set(sig, cur);
    }
    for (const { ip, count } of r.topIPs) ipCount.set(ip, (ipCount.get(ip) || 0) + count);
  }

  out.topIPs = [...ipCount.entries()]
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);
  return out;
}

// --- format a raw aggregate into the API payload -------------------------

function formatOverview(raw, { windowStr, from, until, seconds, scope }) {
  const days = Math.max(1, Math.round(seconds / 86400));

  // Q1: TOP THREATS
  const threats = [...raw.bySignal.values()]
    .map((s) => {
      const meta = signalMeta(s.name);
      return {
        signal: s.name,
        label: meta.label,
        severity: meta.severity,
        events: s.events,
        requests: s.requests,
        blocked: s.blocked,
        sourceIPs: s.ips.size,
        countries: s.countries.size,
        lastSeen: s.lastSeen,
        examples: raw.examplesBySignal.get(s.name) || [],
      };
    })
    .sort((a, b) => b.requests - a.requests || b.events - a.events);

  // Q2: PRIORITY TO ACTION
  const priority = threats
    .filter((t) => t.severity === 'high' || t.severity === 'medium')
    .map((t) => {
      const weight = SEVERITY_WEIGHT[t.severity] || 1;
      const offenders = [...raw.byIP.values()]
        .filter((ip) => ip.signals.has(t.signal))
        .sort((a, b) => b.requests - a.requests);
      const topOffender = offenders[0];
      const score = t.requests * weight + t.blocked * 2 + t.sourceIPs;
      const recommend =
        t.severity === 'high' && (t.requests >= 3 || t.sourceIPs >= 3)
          ? 'Create block rule'
          : t.severity === 'high'
            ? 'Review & block offenders'
            : 'Monitor / tune threshold';
      return {
        signal: t.signal,
        label: t.label,
        severity: t.severity,
        requests: t.requests,
        blocked: t.blocked,
        sourceIPs: t.sourceIPs,
        topOffenderIP: topOffender?.ip || null,
        topOffenderCountry: topOffender?.country || null,
        topOffenderRequests: topOffender?.requests || 0,
        score,
        recommend,
        examples: raw.examplesBySignal.get(t.signal) || [],
      };
    })
    .sort((a, b) => b.score - a.score);

  const offenderIPs = [...raw.byIP.values()]
    .map((ip) => ({
      ip: ip.ip,
      country: ip.country,
      events: ip.events,
      requests: ip.requests,
      blocked: ip.blocked,
      signals: [...ip.signals].map((n) => signalMeta(n).label),
      rawSignals: [...ip.signals],
      severity: [...ip.signals].some((n) => signalMeta(n).severity === 'high') ? 'high' : 'medium',
      lastSeen: ip.lastSeen,
    }))
    .sort((a, b) => b.requests - a.requests || b.events - a.events)
    .slice(0, 15);

  // Q3: TRENDS
  const dayLabels = [];
  const startDay = new Date((until - seconds) * 1000);
  for (let i = 0; i <= days; i++) {
    dayLabels.push(new Date(startDay.getTime() + i * 86400000).toISOString().slice(0, 10));
  }
  const trendTotals = dayLabels.map((d) => raw.byDay.get(d)?.requests || 0);
  const trendEvents = dayLabels.map((d) => raw.byDay.get(d)?.events || 0);

  const top3 = threats.slice(0, 3).map((t) => t.signal);
  const trendSeries = top3.map((sig) => ({
    signal: sig,
    label: signalMeta(sig).label,
    severity: signalMeta(sig).severity,
    data: dayLabels.map((d) => raw.byDaySignal.get(d)?.get(sig) || 0),
  }));

  const mid = Math.floor(trendTotals.length / 2);
  const firstHalf = trendTotals.slice(0, mid).reduce((a, b) => a + b, 0);
  const secondHalf = trendTotals.slice(mid).reduce((a, b) => a + b, 0);
  let direction = 'steady';
  let changePct = 0;
  if (firstHalf === 0 && secondHalf > 0) {
    direction = 'rising';
    changePct = 100;
  } else if (firstHalf > 0) {
    changePct = Math.round(((secondHalf - firstHalf) / firstHalf) * 100);
    if (changePct >= 15) direction = 'rising';
    else if (changePct <= -15) direction = 'falling';
  }
  const peakIdx = trendTotals.indexOf(Math.max(...trendTotals, 0));

  const trends = {
    labels: dayLabels,
    totals: trendTotals,
    events: trendEvents,
    series: trendSeries,
    direction,
    changePct,
    peakDay: trendTotals.some((v) => v > 0) ? dayLabels[peakIdx] : null,
    peakValue: trendTotals[peakIdx] || 0,
    topPaths: [...raw.byPath.entries()].map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 10),
    topCountries: [...raw.byCountry.entries()].map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count).slice(0, 10),
  };

  const kpis = {
    totalEvents: raw.totalEventCount,
    sampledEvents: raw.sampledEvents,
    totalRequests: raw.flaggedRequestsTotal ?? raw.totalRequests,
    sampledRequests: raw.totalRequests,
    blockedEvents: raw.blockedEvents,
    uniqueSignals: raw.bySignal.size,
    uniqueSourceIPs: raw.byIP.size,
    uniqueCountries: raw.byCountry.size,
  };

  return {
    scope,
    window: windowStr,
    from,
    until,
    kpis,
    threats,
    priority: { signals: priority, offenderIPs, suspicious: raw.suspicious.slice(0, 15) },
    trends,
    topIPs: raw.topIPs,
    errors: raw.errors,
    truncated: raw.totalEventCount > raw.sampledEvents,
  };
}

// --- public entry points --------------------------------------------------

export async function buildOverview({ workspace, customerId, window: windowStr = '7d', nowMs }) {
  const { from, until, seconds } = windowRange(windowStr, nowMs);
  const raw = await fetchWorkspaceRaw({ workspace, customerId, from, until });
  return formatOverview(raw, { windowStr, from, until, seconds, scope: { type: 'workspace', workspaces: raw.workspaces } });
}

export async function buildAggregate({ workspaces, customerId, window: windowStr = '7d', nowMs }) {
  const { from, until, seconds } = windowRange(windowStr, nowMs);
  const raws = await Promise.all(workspaces.map((workspace) => fetchWorkspaceRaw({ workspace, customerId, from, until })));
  const merged = mergeRaw(raws);
  return formatOverview(merged, { windowStr, from, until, seconds, scope: { type: 'all', workspaces } });
}
