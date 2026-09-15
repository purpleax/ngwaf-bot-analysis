// Bot visibility & analysis, derived from NGWAF request-level data.
//
// Attack *events* only cover flagged traffic, so bot visibility comes from the
// request store via the unified-API workspace requests endpoint (fastlyApi.js),
// whose query language carries the time range inline
// (e.g. "from:-168h tag:VERIFIED-BOT.AI-CRAWLER").
//
// NGWAF's bot taxonomy (see Fastly system-signals docs):
//   VERIFIED-BOT[.<SUBTYPE>]   confirmed legit bots. Subtypes include
//       SEARCH-ENGINE-CRAWLER, SEARCH-ENGINE-OPTIMIZATION, MONITORING-SITE-TOOLS,
//       ONLINE-MARKETING, PAGE-PREVIEW, PLATFORM-INTEGRATIONS, RESEARCH,
//       SECURITY-TOOLS, ACCESSIBILITY, CONTENT-FETCHER, AI-CRAWLER, AI-FETCHER
//   SUSPECTED-BOT[.HEADLESS|.AI-CRAWLER|.AI-FETCHER]   unverified / suspicious
//   SUSPECTED-BAD-BOT[.HEADLESS]                       malicious automation
//   SCANNER      known scanning services/tools
//   IMPOSTOR     bot spoofing a verified identity (fake Google/Bing)
//   DATACENTER   request originates from a cloud/hosting network
//   CHALLENGED / CHALLENGE-TOKEN-VALID|INVALID   interactive bot challenges
//
// AI-CRAWLER = bulk crawling to train AIs/LLMs (GPTBot, ClaudeBot, CCBot).
// AI-FETCHER = real-time, user-triggered retrieval (OAI-SearchBot, ChatGPT-User).
//
// The three top-level bot *verdicts* — VERIFIED-BOT, SUSPECTED-BOT,
// SUSPECTED-BAD-BOT — are treated as mutually exclusive; their sum is the
// "identified bot" volume, and total traffic minus that is the human estimate.

import { searchRequests } from './fastlyApi.js';

const WINDOW_HOURS = { '24h': 24, '7d': 168, '14d': 336 };
// The Fastly requests API rejects any single search spanning more than 7 days,
// so a full-window query for a longer period is split into <=168h (7-day) chunks
// (older→newer) that are queried separately; their exact totals and sampled data
// are then summed/merged. For windows <=7d this returns a single unchanged chunk.
function windowChunks(hours) {
  const MAX = 168, chunks = [];
  for (let from = hours; from > 0;) { const until = Math.max(0, from - MAX); chunks.push({ from, until }); from = until; }
  return chunks;
}

// The four AI quadrants — verified/suspected × crawler/fetcher.
const AI_CATS = [
  { key: 'aiCrawlerV', tag: 'VERIFIED-BOT.AI-CRAWLER', cls: 'crawler', verified: true, limit: 200 },
  { key: 'aiFetcherV', tag: 'VERIFIED-BOT.AI-FETCHER', cls: 'fetcher', verified: true, limit: 200 },
  { key: 'aiCrawlerS', tag: 'SUSPECTED-BOT.AI-CRAWLER', cls: 'crawler', verified: false, limit: 150 },
  { key: 'aiFetcherS', tag: 'SUSPECTED-BOT.AI-FETCHER', cls: 'fetcher', verified: false, limit: 120 },
];

// Non-AI categories. `verdict` categories (verified/suspected/bad) are mutually
// exclusive and also feed the geo/host/traffic distribution.
const OTHER_CATS = [
  { key: 'verified', tag: 'VERIFIED-BOT', limit: 300, ingest: 'verified', verdict: true },
  { key: 'badBot', tag: 'SUSPECTED-BAD-BOT', limit: 250, ingest: 'bad', verdict: true },
  { key: 'suspected', tag: 'SUSPECTED-BOT', limit: 200, ingest: 'suspected', verdict: true },
  { key: 'scanner', tag: 'SCANNER', limit: 120, ingest: 'scanner' },
  { key: 'impostor', tag: 'IMPOSTOR', limit: 120, ingest: 'impostor' },
  { key: 'challenged', tag: 'CHALLENGED', limit: 1, ingest: null },
  { key: 'datacenter', tag: 'DATACENTER', limit: 1, ingest: null },
];

const VERIFIED_SUBTYPES = {
  'SEARCH-ENGINE-CRAWLER': 'Search engine',
  'SEARCH-ENGINE-OPTIMIZATION': 'SEO tools',
  'MONITORING-SITE-TOOLS': 'Monitoring',
  'ONLINE-MARKETING': 'Online marketing',
  'PAGE-PREVIEW': 'Page preview',
  'PLATFORM-INTEGRATIONS': 'Platform integrations',
  'RESEARCH': 'Research',
  'SECURITY-TOOLS': 'Security tools',
  'ACCESSIBILITY': 'Accessibility',
  'CONTENT-FETCHER': 'Content fetcher',
  'AI-CRAWLER': 'AI crawler',
  'AI-FETCHER': 'AI fetcher',
};

const AI_BOTS = [
  [/GPTBot/i, 'GPTBot'], [/ChatGPT-User/i, 'ChatGPT-User'], [/OAI-SearchBot/i, 'OAI-SearchBot'],
  [/anthropic-ai|ClaudeBot|Claude-Web/i, 'ClaudeBot'], [/PerplexityBot/i, 'PerplexityBot'],
  [/Perplexity-User/i, 'Perplexity-User'], [/CCBot/i, 'CCBot'], [/DuckAssistBot/i, 'DuckAssistBot'],
  [/AI2Bot/i, 'AI2Bot'], [/Diffbot/i, 'Diffbot'], [/Timpibot/i, 'Timpibot'], [/Bytespider/i, 'Bytespider'],
  [/Amazonbot/i, 'Amazonbot'], [/Applebot-Extended/i, 'Applebot-Extended'], [/Applebot/i, 'Applebot'],
  [/Google-Extended/i, 'Google-Extended'], [/Meta-ExternalAgent|FacebookBot/i, 'Meta-ExternalAgent'],
  [/cohere-ai/i, 'Cohere'], [/YouBot/i, 'YouBot'], [/Omgilibot/i, 'Omgilibot'],
];
const SEARCH_BOTS = [
  [/Googlebot/i, 'Googlebot'], [/bingbot/i, 'Bingbot'], [/DuckDuckBot/i, 'DuckDuckBot'],
  [/YandexBot/i, 'YandexBot'], [/Baiduspider/i, 'Baiduspider'], [/AdsBot-Google/i, 'AdsBot-Google'],
  [/APIs-Google/i, 'APIs-Google'], [/FeedFetcher/i, 'FeedFetcher-Google'], [/facebookexternalhit/i, 'facebookexternalhit'],
  [/Google-Read-Aloud/i, 'Google-Read-Aloud'],
];
const TOOL_BOTS = [
  [/Nessus/i, 'Nessus'], [/Scrapy/i, 'Scrapy'], [/Assetnote/i, 'Assetnote'], [/nikto/i, 'Nikto'],
  [/sqlmap/i, 'sqlmap'], [/nuclei/i, 'Nuclei'], [/masscan/i, 'masscan'], [/zgrab/i, 'zgrab'],
  [/Detectify/i, 'Detectify'], [/wpscan/i, 'WPScan'], [/curl\//i, 'curl'], [/python-requests/i, 'python-requests'],
  [/Go-http-client/i, 'Go-http-client'], [/dirbuster|gobuster|feroxbuster/i, 'Dir brute-forcer'],
];

// Group AI bots by the company/operator that runs them, so the section can show
// "who is scraping you" (OpenAI, Anthropic, Google, …) not just individual UAs.
const AI_OPERATORS = {
  GPTBot: 'OpenAI', 'ChatGPT-User': 'OpenAI', 'OAI-SearchBot': 'OpenAI',
  ClaudeBot: 'Anthropic',
  PerplexityBot: 'Perplexity', 'Perplexity-User': 'Perplexity',
  CCBot: 'Common Crawl',
  DuckAssistBot: 'DuckDuckGo',
  AI2Bot: 'Allen Institute for AI',
  Diffbot: 'Diffbot', Timpibot: 'Timpi',
  Bytespider: 'ByteDance',
  Amazonbot: 'Amazon',
  Applebot: 'Apple', 'Applebot-Extended': 'Apple',
  'Google-Extended': 'Google',
  'Meta-ExternalAgent': 'Meta',
  Cohere: 'Cohere', YouBot: 'You.com', Omgilibot: 'Webz.io',
};
export function aiOperator(name) { return AI_OPERATORS[name] || 'Other / unrecognised'; }

function matchUA(ua, table) { for (const [re, name] of table) if (re.test(ua)) return name; return null; }
export function aiBotFromUA(ua) { return matchUA(ua || '', AI_BOTS); }

function tagTypes(req) { return (req.tags || []).map((t) => t.type); }
function tagValue(req, type) { return (req.tags || []).find((t) => t.type === type)?.value || null; }
function hasTag(req, type) { return (req.tags || []).some((t) => t.type === type); }
function isHeadless(req) { return tagTypes(req).some((t) => t.endsWith('.HEADLESS')); }
// Portable network attribution — no CDN header injection required. Prefer
// Fastly's native DATACENTER signal (the hosting/cloud provider name), else fall
// back to the registrable domain of the reverse-DNS remote hostname. Residential
// / ISP IPs (~a fifth of requests) have neither and are left unattributed.
function networkOf(req) {
  const dc = tagValue(req, 'DATACENTER');
  if (dc) return dc;
  const host = req.remoteHostname || '';
  const m = host.match(/([a-z0-9-]+\.[a-z]{2,})$/i);
  return m ? m[1] : (host || null);
}
// Any recognisable bot name for a request (used for new-bot detection).
function resolveAnyName(req) {
  const ua = req.userAgent || '';
  return aiBotFromUA(ua) || matchUA(ua, SEARCH_BOTS) || matchUA(ua, TOOL_BOTS)
    || tagValue(req, 'VERIFIED-BOT') || tagValue(req, 'SUSPECTED-BOT') || null;
}
const GENERIC_NAMES = new Set(['Suspected bot', 'Unclassified bad bot', 'Verified bot', 'Scanner', 'AI bot']);
function requestBlocked(req) {
  if (hasTag(req, 'BLOCKED')) return true;
  const code = req.agentResponseCode || req.responseCode;
  return code && code >= 400 && code !== 404;
}
function verifiedSubtypeOf(req) {
  for (const t of tagTypes(req)) {
    if (t.startsWith('VERIFIED-BOT.')) {
      const child = t.slice('VERIFIED-BOT.'.length);
      if (VERIFIED_SUBTYPES[child]) return VERIFIED_SUBTYPES[child];
    }
  }
  return 'Other verified';
}
// Suspected-bot requests carry the *detection reason* in the SUSPECTED-BOT signal
// value — "Missing header(s)", "User-Agent: Crawler", "User-Agent: Common
// Automation" — emitted by the system BotDetectRule detector. AI bots tagged
// SUSPECTED-BOT instead carry their bot name there ("ClaudeBot"). A single noisy
// reason can dominate the whole category, so the sample is partitioned by reason
// and the caller can exclude one without losing the rest.
const SUSPECTED_REASON_UNKNOWN = 'Unattributed';
function suspectedReasonOf(req) {
  return tagValue(req, 'SUSPECTED-BOT') || SUSPECTED_REASON_UNKNOWN;
}

function dayKey(ts) { return new Date(ts).toISOString().slice(0, 10); }

// --- raw aggregate (mergeable) -------------------------------------------

function emptyBotRaw() {
  return {
    cat: {}, // key -> {total, sampled, blocked}
    totalRequests: 0, // all traffic in window
    aiBots: new Map(), // name -> agg + {cls:Set, verified, unverified}
    aiGeo: new Map(), // country -> sampleCount (AI requests only)
    aiNetworks: new Map(), // hosting network -> sampleCount (AI requests only)
    bots: new Map(), // `${cat}:${name}` -> agg
    verifiedSubtypes: new Map(), // label -> sampleCount
    headless: 0,
    geoByCat: new Map(), // verdict catKey -> Map(country -> sampleCount)
    hostsByCat: new Map(), // verdict catKey -> Map(host -> sampleCount)
    // Suspected bots are stored partitioned by detection reason and materialised
    // into the flat shapes at format time, so an excluded reason can be dropped
    // without re-fetching. See suspectedReasonOf() and materialiseSuspected().
    suspectedParts: new Map(), // reason -> {sampled, blocked, bots, geo, hosts, buckets}
    suspectedReasons: new Map(), // reason -> {total (exact), filterable}
    nBuckets: 0,
    bucketLabels: [], // per time bucket
    bucketTotal: [], // exact total requests per bucket
    bucketBots: [], // {verified,suspected,bad,ai} sampled counts per bucket
    firstHalfNames: new Set(), // bot names seen in the first half of the window
    errors: [],
    workspaces: [],
  };
}

function newBotAgg(name, catKey) {
  return {
    name, catKey, requests: 0, blocked: 0, allowed: 0,
    paths: new Map(), ips: new Set(), countries: new Set(), hosts: new Set(),
    ja3: new Set(), ja4: new Set(), networks: new Map(), methods: new Map(), statuses: new Map(), uas: new Set(),
    examples: [], firstSeen: null, lastSeen: null,
  };
}

function bump(map, key) { if (key != null && key !== '') map.set(key, (map.get(key) || 0) + 1); }

function recordCommon(agg, req, blocked) {
  agg.requests += 1;
  if (blocked) agg.blocked += 1; else agg.allowed += 1;
  const path = req.path || req.uri || '/';
  bump(agg.paths, path);
  if (req.remoteIP) agg.ips.add(req.remoteIP);
  if (req.remoteCountryCode) agg.countries.add(req.remoteCountryCode);
  if (req.serverHostname) agg.hosts.add(req.serverHostname);
  if (req.ja3) agg.ja3.add(req.ja3);
  if (req.ja4) agg.ja4.add(req.ja4);
  bump(agg.networks, networkOf(req));
  bump(agg.methods, req.method);
  bump(agg.statuses, req.agentResponseCode || req.responseCode);
  if (req.userAgent) agg.uas.add(req.userAgent);
  const ts = req.timestamp;
  if (ts) {
    if (!agg.lastSeen || ts > agg.lastSeen) agg.lastSeen = ts;
    if (!agg.firstSeen || ts < agg.firstSeen) agg.firstSeen = ts;
  }
  if (agg.examples.length < 6) {
    agg.examples.push({
      workspace: agg._workspace || null, timestamp: ts, ip: req.remoteIP,
      country: req.remoteCountryCode || '', method: req.method, path,
      host: req.serverHostname || '', userAgent: req.userAgent || '',
      status: req.agentResponseCode || req.responseCode || null, blocked,
    });
  }
}

function ingestAI(raw, cat, req, workspace) {
  const name = aiBotFromUA(req.userAgent) || tagValue(req, cat.verified ? 'VERIFIED-BOT' : 'SUSPECTED-BOT') || 'AI bot';
  let b = raw.aiBots.get(name);
  if (!b) { b = { ...newBotAgg(name, cat.key), cls: new Set(), verified: false, unverified: false }; raw.aiBots.set(name, b); }
  b.cls.add(cat.cls);
  if (cat.verified) b.verified = true; else b.unverified = true;
  b._workspace = workspace;
  recordCommon(b, req, requestBlocked(req));
  if (req.remoteCountryCode) raw.aiGeo.set(req.remoteCountryCode, (raw.aiGeo.get(req.remoteCountryCode) || 0) + 1);
  const net = networkOf(req);
  if (net) raw.aiNetworks.set(net, (raw.aiNetworks.get(net) || 0) + 1);
}

function ingestBot(raw, catKey, name, req, workspace) {
  const key = `${catKey}:${name}`;
  let b = raw.bots.get(key);
  if (!b) { b = newBotAgg(name, catKey); raw.bots.set(key, b); }
  b._workspace = workspace;
  recordCommon(b, req, requestBlocked(req));
  return b;
}

function accumulateGeoHost(raw, catKey, req) {
  if (req.remoteCountryCode) {
    const g = raw.geoByCat.get(catKey) || new Map();
    g.set(req.remoteCountryCode, (g.get(req.remoteCountryCode) || 0) + 1);
    raw.geoByCat.set(catKey, g);
  }
  if (req.serverHostname) {
    const h = raw.hostsByCat.get(catKey) || new Map();
    h.set(req.serverHostname, (h.get(req.serverHostname) || 0) + 1);
    raw.hostsByCat.set(catKey, h);
  }
}

function suspectedPart(raw, reason) {
  let p = raw.suspectedParts.get(reason);
  if (!p) {
    p = { sampled: 0, blocked: 0, bots: new Map(), geo: new Map(), hosts: new Map(), buckets: new Array(raw.nBuckets).fill(0) };
    raw.suspectedParts.set(reason, p);
  }
  return p;
}

// Every sampled SUSPECTED-BOT request lands in exactly one reason partition —
// including the AI-tagged ones, which are kept out of the bot list here (the AI
// jobs own them) but still carry the category's geo/host distribution.
function ingestSuspected(raw, req, workspace, bk) {
  const p = suspectedPart(raw, suspectedReasonOf(req));
  const blocked = requestBlocked(req);
  p.sampled += 1;
  if (blocked) p.blocked += 1;
  if (req.remoteCountryCode) p.geo.set(req.remoteCountryCode, (p.geo.get(req.remoteCountryCode) || 0) + 1);
  if (req.serverHostname) p.hosts.set(req.serverHostname, (p.hosts.get(req.serverHostname) || 0) + 1);
  if (hasTag(req, 'SUSPECTED-BOT.AI-CRAWLER') || hasTag(req, 'SUSPECTED-BOT.AI-FETCHER')) return;
  const ua = req.userAgent || '';
  const name = matchUA(ua, TOOL_BOTS) || matchUA(ua, SEARCH_BOTS) || 'Suspected bot';
  let b = p.bots.get(name);
  if (!b) { b = newBotAgg(name, 'suspected'); p.bots.set(name, b); }
  b._workspace = workspace;
  recordCommon(b, req, blocked);
  if (req.timestamp) { const i = bucketIndex(bk, Date.parse(req.timestamp)); if (i >= 0) p.buckets[i] += 1; }
}

function ingestOther(raw, cat, req, workspace) {
  const ua = req.userAgent || '';
  if (isHeadless(req)) raw.headless += 1;
  // Verdict categories drive the geo/host/traffic distribution. 'suspected' keeps
  // its own per-reason geo/host maps instead, merged in materialiseSuspected().
  if (cat.verdict && cat.ingest !== 'suspected') accumulateGeoHost(raw, cat.key, req);

  if (cat.ingest === 'verified') {
    const subtype = verifiedSubtypeOf(req);
    raw.verifiedSubtypes.set(subtype, (raw.verifiedSubtypes.get(subtype) || 0) + 1);
    if (subtype !== 'AI crawler' && subtype !== 'AI fetcher') {
      const b = ingestBot(raw, 'verified', tagValue(req, 'VERIFIED-BOT') || matchUA(ua, SEARCH_BOTS) || 'Verified bot', req, workspace);
      if (!b.subtype) b.subtype = subtype;
    }
  } else if (cat.ingest === 'bad') {
    ingestBot(raw, 'badBot', matchUA(ua, TOOL_BOTS) || 'Unclassified bad bot', req, workspace);
  } else if (cat.ingest === 'scanner') {
    ingestBot(raw, 'scanner', matchUA(ua, TOOL_BOTS) || tagValue(req, 'VERIFIED-BOT') || tagValue(req, 'SCANNER') || 'Scanner', req, workspace);
  } else if (cat.ingest === 'impostor') {
    ingestBot(raw, 'impostor', `Fake ${matchUA(ua, SEARCH_BOTS) || matchUA(ua, AI_BOTS) || 'bot'}`, req, workspace);
  }
  // 'suspected' is handled by ingestSuspected() — it partitions by detection reason.
}

// Split the window into <=8 time buckets; return {edges(ms), labels}.
function makeBuckets(hours, nowMs) {
  const n = hours <= 24 ? 6 : hours <= 168 ? 7 : 8;
  const spanMs = hours * 3600 * 1000;
  const bucketMs = spanMs / n;
  const start = nowMs - spanMs;
  const edges = [];
  for (let i = 0; i <= n; i++) edges.push(start + i * bucketMs);
  const daily = bucketMs >= 20 * 3600 * 1000;
  const labels = [];
  for (let i = 0; i < n; i++) {
    const d = new Date(edges[i]);
    labels.push(daily ? d.toISOString().slice(5, 10) : `${String(d.getUTCHours()).padStart(2, '0')}:00`);
  }
  return { n, edges, bucketMs, labels };
}
function bucketIndex(bk, tsMs) {
  if (!bk.n) return -1;
  const i = Math.floor((tsMs - bk.edges[0]) / bk.bucketMs);
  return Math.max(0, Math.min(bk.n - 1, i));
}

async function fetchWorkspaceBots({ workspace, customerId, hours, nowMs }) {
  const raw = emptyBotRaw();
  raw.workspaces = workspace ? [workspace] : [];

  const bk = makeBuckets(hours, nowMs);
  raw.nBuckets = bk.n;
  raw.bucketLabels = bk.labels;
  raw.bucketTotal = new Array(bk.n).fill(0);
  raw.bucketBots = Array.from({ length: bk.n }, () => ({ verified: 0, suspected: 0, bad: 0, ai: 0 }));
  const half = Math.round(hours / 2);

  const bumpBucket = (req, kind) => {
    if (!req.timestamp) return;
    const i = bucketIndex(bk, Date.parse(req.timestamp));
    if (i >= 0) raw.bucketBots[i][kind] += 1;
  };

  // Per-bucket exact totals (cheap count queries) for the bot-vs-human trend.
  const bucketJobs = Array.from({ length: bk.n }, (_, i) => {
    const fromH = Math.round(((bk.n - i) * bk.bucketMs) / 3600000);
    const untilH = Math.round(((bk.n - i - 1) * bk.bucketMs) / 3600000);
    return { key: `__bucket_${i}__`, type: 'bucketTotal', idx: i, limit: 1, query: `from:-${fromH}h until:-${untilH}h` };
  });

  // First-half presence per verdict parent — captures verified (incl. AI),
  // suspected (incl. unverified AI) and bad bot names, so "new" detection is
  // reliable rather than sample-biased.
  const firstHalfJobs = ['VERIFIED-BOT', 'SUSPECTED-BOT', 'SUSPECTED-BAD-BOT'].map((tag) =>
    ({ key: `__fh_${tag}__`, query: `from:-${hours}h until:-${half}h tag:${tag}`, limit: 150, type: 'firsthalf' }));

  // Full-window jobs (total + every category) span the whole period and are
  // chunked to <=7 days each; firstHalf/bucket jobs already use bounded sub-ranges.
  const jobs = [
    { key: '__total__', tag: null, limit: 1, type: 'total', full: true },
    ...firstHalfJobs,
    ...bucketJobs,
    ...AI_CATS.map((c) => ({ ...c, type: 'ai', full: true })),
    ...OTHER_CATS.map((c) => ({ ...c, type: 'other', full: true })),
  ];

  await mapPool(jobs, 5, async (j) => {
    let data, total;
    try {
      if (j.full) {
        total = 0; data = [];
        for (const c of windowChunks(hours)) {
          const q = `from:-${c.from}h${c.until > 0 ? ` until:-${c.until}h` : ''}${j.tag ? ` tag:${j.tag}` : ''}`;
          const r = await searchRequests(customerId, workspace, q, j.limit);
          total += r.totalCount ?? r.data.length;
          for (const rec of r.data) data.push(rec);
        }
      } else {
        const r = await searchRequests(customerId, workspace, j.query, j.limit);
        data = r?.data || [];
        total = r?.totalCount ?? data.length;
      }
    } catch (err) { raw.errors.push(`${workspace || 'workspace'}/${j.key}: ${String(err.message || err)}`); return; }
    if (j.type === 'total') { raw.totalRequests = total; return; }
    if (j.type === 'bucketTotal') { raw.bucketTotal[j.idx] = total; return; }
    if (j.type === 'firsthalf') { for (const req of data) { const n = resolveAnyName(req); if (n) raw.firstHalfNames.add(n.toLowerCase()); } return; }
    let blocked = 0;
    for (const req of data) if (requestBlocked(req)) blocked += 1;
    raw.cat[j.key] = { total, sampled: data.length, blocked };
    if (j.type === 'ai') {
      for (const req of data) { ingestAI(raw, j, req, workspace); bumpBucket(req, 'ai'); }
    } else if (j.ingest === 'suspected') {
      for (const req of data) { ingestOther(raw, j, req, workspace); ingestSuspected(raw, req, workspace, bk); }
    } else if (j.ingest) {
      const kind = j.ingest === 'verified' ? 'verified' : 'bad';
      for (const req of data) {
        ingestOther(raw, j, req, workspace);
        // AI requests are counted by the AI jobs; don't double-count them here.
        const isAIreq = hasTag(req, 'VERIFIED-BOT.AI-CRAWLER') || hasTag(req, 'VERIFIED-BOT.AI-FETCHER')
          || hasTag(req, 'SUSPECTED-BOT.AI-CRAWLER') || hasTag(req, 'SUSPECTED-BOT.AI-FETCHER');
        if (!(kind !== 'bad' && isAIreq)) bumpBucket(req, kind);
      }
    }
  });

  await countSuspectedReasons(raw, { customerId, workspace, hours });
  return raw;
}

// Exact volume per detection reason, so excluding one can subtract a real count
// rather than a sampled estimate.
//
// TRAP: `signal:"<value>"` is honoured only for the BotDetectRule reason strings.
// For any other value — a bot name like "ClaudeBot", or a typo — the filter is
// SILENTLY IGNORED and the query returns the entire parent set rather than zero
// or an error. `-signal:"<value>"` negation is likewise silently dropped and
// returns the positive result, so exclusion subtracts a positive count and never
// negates.
//
// Whether the filter was honoured is therefore verified by CONTENT, not by count:
// the probe reads back a sample and every returned row must actually carry the
// reason. A count-only check ("smaller than the parent total") would be a
// heuristic, and on a category dominated by one reason it could pass by luck —
// the totals also drift under live traffic, since parent and reason are measured
// seconds apart. A reason that fails the check is reported filterable:false and
// can never be excluded, so an unverified filter can never move a number.
const REASON_PROBE = 25;
async function countSuspectedReasons(raw, { customerId, workspace, hours }) {
  const reasons = [...raw.suspectedParts.keys()].filter((r) => r && r !== SUSPECTED_REASON_UNKNOWN);
  await mapPool(reasons, 5, async (reason) => {
    if (reason.includes('"')) { raw.suspectedReasons.set(reason, { total: 0, filterable: false }); return; }
    try {
      let total = 0; let honoured = true; let seen = 0;
      for (const c of windowChunks(hours)) {
        const q = `from:-${c.from}h${c.until > 0 ? ` until:-${c.until}h` : ''} tag:SUSPECTED-BOT signal:"${reason}"`;
        const r = await searchRequests(customerId, workspace, q, REASON_PROBE);
        total += r?.totalCount ?? 0;
        for (const req of r?.data || []) { seen += 1; if (suspectedReasonOf(req) !== reason) honoured = false; }
      }
      raw.suspectedReasons.set(reason, { total, filterable: honoured && seen > 0 && total > 0 });
    } catch (err) {
      raw.errors.push(`${workspace || 'workspace'}/reason ${reason}: ${String(err.message || err)}`);
      raw.suspectedReasons.set(reason, { total: 0, filterable: false });
    }
  });
}

async function mapPool(items, size, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (i < items.length) { const idx = i++; await fn(items[idx], idx); }
  });
  await Promise.all(workers);
}

// --- merge ----------------------------------------------------------------

function mergeCountMap(target, src) { for (const [k, n] of src) target.set(k, (target.get(k) || 0) + n); }
function mergeAgg(target, src) {
  target.requests += src.requests; target.blocked += src.blocked; target.allowed += src.allowed;
  mergeCountMap(target.paths, src.paths);
  mergeCountMap(target.networks, src.networks);
  mergeCountMap(target.methods, src.methods);
  mergeCountMap(target.statuses, src.statuses);
  src.ips.forEach((v) => target.ips.add(v));
  src.countries.forEach((v) => target.countries.add(v));
  src.hosts.forEach((v) => target.hosts.add(v));
  src.ja3.forEach((v) => target.ja3.add(v));
  src.ja4.forEach((v) => target.ja4.add(v));
  src.uas.forEach((v) => target.uas.add(v));
  for (const e of src.examples) if (target.examples.length < 6) target.examples.push(e);
  if (src.lastSeen && (!target.lastSeen || src.lastSeen > target.lastSeen)) target.lastSeen = src.lastSeen;
  if (src.firstSeen && (!target.firstSeen || src.firstSeen < target.firstSeen)) target.firstSeen = src.firstSeen;
}

function mergeBotRaw(list) {
  const out = emptyBotRaw();
  for (const r of list) {
    out.workspaces.push(...r.workspaces);
    out.errors.push(...r.errors);
    out.headless += r.headless;
    out.totalRequests += r.totalRequests;
    for (const [k, v] of Object.entries(r.cat)) {
      const t = out.cat[k] || { total: 0, sampled: 0, blocked: 0 };
      t.total += v.total; t.sampled += v.sampled; t.blocked += v.blocked;
      out.cat[k] = t;
    }
    for (const [label, n] of r.verifiedSubtypes) out.verifiedSubtypes.set(label, (out.verifiedSubtypes.get(label) || 0) + n);
    for (const [name, b] of r.aiBots) {
      let t = out.aiBots.get(name);
      if (!t) { t = { ...newBotAgg(name, b.catKey), cls: new Set(), verified: false, unverified: false }; out.aiBots.set(name, t); }
      b.cls.forEach((c) => t.cls.add(c));
      t.verified = t.verified || b.verified; t.unverified = t.unverified || b.unverified;
      mergeAgg(t, b);
    }
    for (const [key, b] of r.bots) {
      let t = out.bots.get(key);
      if (!t) { t = newBotAgg(b.name, b.catKey); out.bots.set(key, t); }
      if (b.subtype && !t.subtype) t.subtype = b.subtype;
      mergeAgg(t, b);
    }
    for (const [reason, sp] of r.suspectedParts) {
      let t = out.suspectedParts.get(reason);
      if (!t) { t = { sampled: 0, blocked: 0, bots: new Map(), geo: new Map(), hosts: new Map(), buckets: [] }; out.suspectedParts.set(reason, t); }
      t.sampled += sp.sampled; t.blocked += sp.blocked;
      mergeCountMap(t.geo, sp.geo); mergeCountMap(t.hosts, sp.hosts);
      for (const [name, b] of sp.bots) {
        let tb = t.bots.get(name);
        if (!tb) { tb = newBotAgg(name, 'suspected'); t.bots.set(name, tb); }
        mergeAgg(tb, b);
      }
      if (!t.buckets.length) t.buckets = sp.buckets.slice();
      else for (let i = 0; i < t.buckets.length; i++) t.buckets[i] += sp.buckets[i] || 0;
    }
    for (const [reason, v] of r.suspectedReasons) {
      const t = out.suspectedReasons.get(reason);
      // A reason is only excludable if every workspace could filter on it.
      out.suspectedReasons.set(reason, t
        ? { total: t.total + v.total, filterable: t.filterable && v.filterable }
        : { ...v });
    }
    mergeCountMap(out.aiGeo, r.aiGeo);
    mergeCountMap(out.aiNetworks, r.aiNetworks);
    for (const [cat, m] of r.geoByCat) { const t = out.geoByCat.get(cat) || new Map(); mergeCountMap(t, m); out.geoByCat.set(cat, t); }
    for (const [cat, m] of r.hostsByCat) { const t = out.hostsByCat.get(cat) || new Map(); mergeCountMap(t, m); out.hostsByCat.set(cat, t); }
    r.firstHalfNames.forEach((n) => out.firstHalfNames.add(n));
    // Buckets align across sites (same window + now); merge by index.
    if (r.nBuckets && !out.nBuckets) {
      out.nBuckets = r.nBuckets; out.bucketLabels = r.bucketLabels;
      out.bucketTotal = r.bucketTotal.slice();
      out.bucketBots = r.bucketBots.map((b) => ({ ...b }));
    } else if (r.nBuckets === out.nBuckets) {
      for (let i = 0; i < out.nBuckets; i++) {
        out.bucketTotal[i] += r.bucketTotal[i] || 0;
        for (const k of ['verified', 'suspected', 'bad', 'ai']) out.bucketBots[i][k] += r.bucketBots[i]?.[k] || 0;
      }
    }
  }
  return out;
}

// --- format ---------------------------------------------------------------

function catOf(raw, key) { return raw.cat[key] || { total: 0, sampled: 0, blocked: 0 }; }
function scaleFactor(c) { return c.sampled && c.sampled < c.total ? c.total / c.sampled : 1; }

const topN = (map, n) => [...map.entries()].sort((a, z) => z[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));

function botRow(raw, b, extra = {}) {
  const c = catOf(raw, b.catKey);
  const f = scaleFactor(c);
  const paths = topN(b.paths, 15);
  const isNew = !!(b.firstSeen && !raw.firstHalfNames.has((b.name || '').toLowerCase()) && !GENERIC_NAMES.has(b.name));
  return {
    name: b.name,
    subtype: b.subtype || null,
    requests: Math.round(b.requests * f),
    blocked: Math.round(b.blocked * f),
    allowed: Math.round(b.allowed * f),
    sourceIPs: b.ips.size,
    countries: [...b.countries],
    hosts: [...b.hosts],
    topPath: paths[0]?.key || null,
    paths,
    ja3: [...b.ja3].slice(0, 4),
    ja4: [...b.ja4].slice(0, 4),
    networks: topN(b.networks, 5),
    methods: topN(b.methods, 6),
    statuses: topN(b.statuses, 6),
    userAgents: [...b.uas].slice(0, 4),
    firstSeen: b.firstSeen,
    lastSeen: b.lastSeen,
    isNew,
    examples: b.examples,
    ...extra,
  };
}
function botsIn(raw, catKey) {
  return [...raw.bots.values()].filter((b) => b.catKey === catKey).map((b) => botRow(raw, b)).sort((a, z) => z.requests - a.requests);
}

function catSummary(raw, key, note) {
  const c = catOf(raw, key);
  const reliable = c.sampled >= c.total || c.sampled >= 20;
  const rate = c.sampled ? c.blocked / c.sampled : 0;
  return {
    total: c.total, sampled: c.sampled,
    blocked: !reliable ? null : Math.round(c.total * rate),
    blockRatePct: reliable ? Math.round(rate * 100) : null,
    truncated: c.total > c.sampled, note,
  };
}

// Merge + scale a set of per-category count maps into a ranked list.
function scaledDistribution(raw, mapByCat, catKeys, n = 12) {
  const merged = new Map();
  for (const key of catKeys) {
    const m = mapByCat.get(key);
    if (!m) continue;
    const f = scaleFactor(catOf(raw, key));
    for (const [k, v] of m) merged.set(k, (merged.get(k) || 0) + v * f);
  }
  return [...merged.entries()].map(([k, v]) => ({ key: k, count: Math.round(v) })).sort((a, z) => z.count - a.count).slice(0, n);
}

// Fold the suspected-bot reason partitions back into the flat shapes the rest of
// formatBots reads, keeping only the reasons the caller did not exclude. Returns
// a shallow clone — `raw` is shared between cached views (see workspaceRaw) and
// must stay read-only.
function materialiseSuspected(raw, excluded) {
  const drop = new Set([...excluded].filter((r) => raw.suspectedReasons.get(r)?.filterable));
  const bots = new Map([...raw.bots].filter(([, b]) => b.catKey !== 'suspected'));
  const geo = new Map(); const hosts = new Map();
  const buckets = new Array(raw.nBuckets).fill(0);
  let sampled = 0; let blocked = 0; let removedExact = 0;

  for (const [reason, p] of raw.suspectedParts) {
    if (drop.has(reason)) { removedExact += raw.suspectedReasons.get(reason)?.total || 0; continue; }
    sampled += p.sampled; blocked += p.blocked;
    mergeCountMap(geo, p.geo); mergeCountMap(hosts, p.hosts);
    for (let i = 0; i < buckets.length; i++) buckets[i] += p.buckets[i] || 0;
    for (const [name, b] of p.bots) {
      const key = `suspected:${name}`;
      let t = bots.get(key);
      if (!t) { t = newBotAgg(name, 'suspected'); bots.set(key, t); }
      mergeAgg(t, b);
    }
  }

  const base = raw.cat.suspected || { total: 0, sampled: 0, blocked: 0 };
  const geoByCat = new Map(raw.geoByCat); geoByCat.set('suspected', geo);
  const hostsByCat = new Map(raw.hostsByCat); hostsByCat.set('suspected', hosts);
  return {
    ...raw,
    bots, geoByCat, hostsByCat,
    cat: { ...raw.cat, suspected: { total: Math.max(0, base.total - removedExact), sampled, blocked } },
    bucketBots: raw.bucketBots.map((b, i) => ({ ...b, suspected: buckets[i] || 0 })),
    excludedReasons: [...drop],
  };
}

function formatBots(rawIn, { windowStr, scope, hours, exclude = [] }) {
  const raw = materialiseSuspected(rawIn, new Set(exclude));
  const S = (k, note) => catSummary(raw, k, note);
  const cat = {
    verified: S('verified', 'Confirmed legitimate crawlers'),
    aiCrawlerV: S('aiCrawlerV', 'Verified AI training crawlers'),
    aiFetcherV: S('aiFetcherV', 'Verified AI real-time fetchers'),
    aiCrawlerS: S('aiCrawlerS', 'Unverified AI crawlers'),
    aiFetcherS: S('aiFetcherS', 'Unverified AI fetchers'),
    bad: S('badBot', 'Attack tooling & malicious automation'),
    suspected: S('suspected', 'Anomalous / unverified bots'),
    scanner: S('scanner', 'Known scanning services'),
    impostor: S('impostor', 'Spoofing a verified bot identity'),
    challenged: S('challenged', 'Issued an interactive bot challenge'),
    datacenter: S('datacenter', 'Origin is a hosting/cloud network'),
  };

  // Identified bots — the three verdict tags are mutually exclusive. We deliberately
  // do NOT derive a "human" figure: the request total comes from the NGWAF requests
  // feed (inspected/logged requests), not true CDN edge volume, so total − bots is
  // not a reliable human count. The dashboard reports absolute bot counts only.
  const identifiedBots = cat.verified.total + cat.suspected.total + cat.bad.total;
  const totalRequests = Math.max(raw.totalRequests, identifiedBots);
  const verdictCatKeys = ['verified', 'suspected', 'badBot'];
  const botsBlocked = (cat.verified.blocked || 0) + (cat.suspected.blocked || 0) + (cat.bad.blocked || 0);

  // AI section
  const aiCrawlerTotal = cat.aiCrawlerV.total + cat.aiCrawlerS.total;
  const aiFetcherTotal = cat.aiFetcherV.total + cat.aiFetcherS.total;
  const aiVerifiedTotal = cat.aiCrawlerV.total + cat.aiFetcherV.total;
  const aiSuspectedTotal = cat.aiCrawlerS.total + cat.aiFetcherS.total;
  const aiTotal = aiVerifiedTotal + aiSuspectedTotal;
  const aiBlocked = ['aiCrawlerV', 'aiFetcherV', 'aiCrawlerS', 'aiFetcherS'].reduce((s, k) => s + (cat[k].blocked || 0), 0);
  // Overall AI sample→total scale factor (per-cat factors differ but the AI
  // geo/network/path maps are pooled, so scale approximately by the AI aggregate).
  const aiSampledAll = ['aiCrawlerV', 'aiFetcherV', 'aiCrawlerS', 'aiFetcherS'].reduce((s, k) => s + catOf(raw, k).sampled, 0);
  const fAI = aiSampledAll ? aiTotal / aiSampledAll : 1;
  const aiBots = [...raw.aiBots.values()].map((b) => botRow(raw, b, { classes: [...b.cls], verified: b.verified, unverified: b.unverified, operator: aiOperator(b.name) })).sort((a, z) => z.requests - a.requests);

  // Paths pooled across AI bots — also a robots.txt/sitemap "good-citizen" signal.
  const aiPaths = new Map();
  let aiPathHits = 0, aiRobotsHits = 0, aiSitemapHits = 0;
  for (const b of raw.aiBots.values()) for (const [p, n] of b.paths) {
    aiPaths.set(p, (aiPaths.get(p) || 0) + n);
    aiPathHits += n;
    if (/robots\.txt/i.test(p)) aiRobotsHits += n;
    if (/sitemap/i.test(p)) aiSitemapHits += n;
  }
  const aiTopPaths = [...aiPaths.entries()].map(([path, count]) => ({ path, count })).sort((a, z) => z.count - a.count).slice(0, 10);

  // Group AI bots by operator/company (who is scraping the site).
  const opMap = new Map();
  for (const b of aiBots) {
    const op = b.operator;
    let o = opMap.get(op);
    if (!o) { o = { operator: op, requests: 0, blocked: 0, bots: [], sourceIPs: 0, verified: false, unverified: false, crawler: false, fetcher: false }; opMap.set(op, o); }
    o.requests += b.requests; o.blocked += b.blocked; o.sourceIPs += b.sourceIPs; o.bots.push(b.name);
    if (b.verified) o.verified = true;
    if (b.unverified) o.unverified = true;
    if (b.classes.includes('crawler')) o.crawler = true;
    if (b.classes.includes('fetcher')) o.fetcher = true;
  }
  const aiOperators = [...opMap.values()].sort((a, z) => z.requests - a.requests);

  // AI geo / networks (pooled sample counts scaled by the AI factor — estimates).
  const aiGeo = [...raw.aiGeo.entries()].map(([k, v]) => ({ key: k, count: Math.round(v * fAI) })).sort((a, z) => z.count - a.count).slice(0, 12);
  const aiNetworks = [...raw.aiNetworks.entries()].map(([k, v]) => ({ key: k, count: Math.round(v * fAI) })).sort((a, z) => z.count - a.count).slice(0, 10);

  const aiNewBots = aiBots.filter((b) => b.isNew);
  const aiVerifiedPct = aiTotal ? Math.round((aiVerifiedTotal / aiTotal) * 100) : 0;
  const aiBlockRatePct = aiTotal ? Math.round((aiBlocked / aiTotal) * 100) : 0;
  const aiCompliancePct = aiPathHits ? Math.round(((aiRobotsHits + aiSitemapHits) / aiPathHits) * 100) : null;

  // Verified subtypes (AI exact, rest scaled)
  const vf = scaleFactor(catOf(raw, 'verified'));
  const verifiedSubtypes = [...raw.verifiedSubtypes.entries()]
    .map(([label, n]) => {
      if (label === 'AI crawler') return { label, count: cat.aiCrawlerV.total, exact: true };
      if (label === 'AI fetcher') return { label, count: cat.aiFetcherV.total, exact: true };
      return { label, count: Math.round(n * vf) };
    })
    .sort((a, z) => z.count - a.count);

  // Top bots within each verified-bot category. Non-AI verified bots carry a
  // `subtype`; AI crawler/fetcher categories draw their bots from the AI list.
  const verifiedRows = botsIn(raw, 'verified');
  const bySubtype = new Map();
  for (const b of verifiedRows) {
    const st = b.subtype || 'Other verified';
    if (!bySubtype.has(st)) bySubtype.set(st, []);
    bySubtype.get(st).push(b);
  }
  const verifiedBreakdown = verifiedSubtypes.map((s) => {
    const isAI = s.label === 'AI crawler' || s.label === 'AI fetcher';
    let bots;
    if (s.label === 'AI crawler') bots = aiBots.filter((b) => b.verified && b.classes.includes('crawler'));
    else if (s.label === 'AI fetcher') bots = aiBots.filter((b) => b.verified && b.classes.includes('fetcher'));
    else bots = bySubtype.get(s.label) || [];
    return { label: s.label, count: s.count, exact: !!s.exact, isAI, bots: bots.slice(0, 6) };
  }).filter((s) => s.count > 0 || s.bots.length);

  // Master bot list across categories.
  const verdictOf = (kind, verified) =>
    kind === 'bad' || kind === 'scanner' || kind === 'impostor' ? 'bad'
      : kind === 'suspected' ? 'suspicious'
        : kind === 'ai' ? (verified ? 'good' : 'suspicious') : 'good';
  const allBots = [];
  for (const b of aiBots) allBots.push({ ...b, category: `AI ${b.classes.join('/')}`, verified: b.verified, verdict: verdictOf('ai', b.verified) });
  for (const b of botsIn(raw, 'verified')) allBots.push({ ...b, category: 'Verified', verified: true, verdict: 'good' });
  for (const b of botsIn(raw, 'badBot')) allBots.push({ ...b, category: 'Bad bot', verified: false, verdict: 'bad' });
  for (const b of botsIn(raw, 'scanner')) allBots.push({ ...b, category: 'Scanner', verified: false, verdict: 'bad' });
  for (const b of botsIn(raw, 'impostor')) allBots.push({ ...b, category: 'Impostor', verified: false, verdict: 'bad' });
  for (const b of botsIn(raw, 'suspected')) allBots.push({ ...b, category: 'Suspected', verified: false, verdict: 'suspicious' });
  allBots.sort((a, z) => z.requests - a.requests);

  // Bots that only appeared in the recent half of the window.
  const newBots = allBots.filter((b) => b.isNew && b.requests >= 5).slice(0, 12);

  // Trend — per-bucket. Bot counts are sampled (scaled by category factor);
  // per-bucket totals are exact, so human = total − bots (clamped).
  const fVer = scaleFactor(catOf(raw, 'verified'));
  const fSus = scaleFactor(catOf(raw, 'suspected'));
  const fBad = scaleFactor(catOf(raw, 'badBot'));
  const bb = raw.bucketBots;
  const tVer = bb.map((x) => Math.round(x.verified * fVer));
  const tSus = bb.map((x) => Math.round(x.suspected * fSus));
  const tBad = bb.map((x) => Math.round(x.bad * fBad));
  const tAI = bb.map((x) => Math.round(x.ai * fAI));
  const trend = {
    labels: raw.bucketLabels,
    total: raw.bucketTotal,
    verified: tVer, suspected: tSus, bad: tBad, ai: tAI,
  };

  // Geo & hosts (scaled distribution across the verdict samples).
  const geo = scaledDistribution(raw, raw.geoByCat, verdictCatKeys, 12);
  const hosts = scaledDistribution(raw, raw.hostsByCat, verdictCatKeys, 10);

  return {
    scope, window: windowStr, hours,
    totals: {
      totalRequests, identifiedBots,
      verified: cat.verified.total, suspected: cat.suspected.total, bad: cat.bad.total,
      botsBlocked, scanner: cat.scanner.total, impostor: cat.impostor.total,
      datacenter: cat.datacenter.total, challenged: cat.challenged.total,
      goodBots: cat.verified.total, badBots: cat.bad.total + cat.scanner.total + cat.impostor.total,
      suspiciousBots: cat.suspected.total,
      headlessSample: raw.headless,
    },
    categories: cat,
    ai: {
      total: aiTotal, blocked: aiBlocked, allowed: aiTotal - aiBlocked,
      pctOfBots: identifiedBots ? Math.round((aiTotal / identifiedBots) * 100) : 0,
      crawlerTotal: aiCrawlerTotal, fetcherTotal: aiFetcherTotal,
      verifiedTotal: aiVerifiedTotal, suspectedTotal: aiSuspectedTotal,
      verifiedPct: aiVerifiedPct, blockRatePct: aiBlockRatePct,
      compliancePct: aiCompliancePct, robotsHits: aiRobotsHits, sitemapHits: aiSitemapHits,
      quadrants: {
        crawlerVerified: cat.aiCrawlerV.total, fetcherVerified: cat.aiFetcherV.total,
        crawlerSuspected: cat.aiCrawlerS.total, fetcherSuspected: cat.aiFetcherS.total,
      },
      distinctBots: aiBots.length, distinctOperators: aiOperators.length,
      bots: aiBots, operators: aiOperators, topPaths: aiTopPaths,
      geo: aiGeo, networks: aiNetworks, newBots: aiNewBots,
      truncated: [cat.aiCrawlerV, cat.aiFetcherV, cat.aiCrawlerS, cat.aiFetcherS].some((q) => q.truncated),
    },
    verified: { total: cat.verified.total, subtypes: verifiedSubtypes, subtypeBreakdown: verifiedBreakdown, bots: verifiedRows.slice(0, 12) },
    bad: { total: cat.bad.total, blocked: cat.bad.blocked, truncated: cat.bad.truncated, bots: botsIn(raw, 'badBot').slice(0, 12) },
    scanner: { total: cat.scanner.total, blocked: cat.scanner.blocked, bots: botsIn(raw, 'scanner').slice(0, 10) },
    impostor: { total: cat.impostor.total, bots: botsIn(raw, 'impostor').slice(0, 10) },
    suspected: {
      total: cat.suspected.total,
      bots: botsIn(raw, 'suspected').slice(0, 10),
      // Detection reasons offered to the exclusion control. `filterable:false`
      // means the API would not honour a signal: filter for that value, so it is
      // listed for context but can never be excluded.
      reasons: [...rawIn.suspectedParts.keys()]
        .map((reason) => {
          const info = rawIn.suspectedReasons.get(reason) || { total: 0, filterable: false };
          return { reason, total: info.total, filterable: !!info.filterable, excluded: raw.excludedReasons.includes(reason) };
        })
        .sort((a, z) => z.total - a.total || a.reason.localeCompare(z.reason)),
      excluded: raw.excludedReasons,
    },
    allBots: allBots.slice(0, 40),
    newBots,
    trend, geo, hosts,
    errors: raw.errors,
  };
}

// --- per-workspace raw cache ----------------------------------------------
// fetchWorkspaceBots() is the expensive part (many API calls, doubled for 14d).
// Cache each workspace's raw aggregate briefly so that switching between a single
// workspace and "All workspaces", refreshing, or concurrent requests reuse one
// fetch instead of re-hitting the API — e.g. loading the default eCommerce view
// then clicking "All workspaces" reuses the eCommerce raw and only fetches the
// rest. The cached promise also dedupes concurrent identical fetches.
// `nowMs` is rounded to the minute so raws fetched close together share identical
// bucket edges and merge cleanly; TTL matches the server's 60s response cache.
const rawCache = new Map(); // `${customerId}:${workspace}:${window}` -> { t, p }
const RAW_TTL_MS = 60_000;
const minuteNow = () => Math.floor(Date.now() / 60_000) * 60_000;

function workspaceRaw({ workspace, customerId, hours, windowStr, nowMs }) {
  const key = `${customerId}:${workspace}:${windowStr}`;
  const hit = rawCache.get(key);
  if (hit && Date.now() - hit.t < RAW_TTL_MS) return hit.p;
  const p = fetchWorkspaceBots({ workspace, customerId, hours, nowMs });
  rawCache.set(key, { t: Date.now(), p });
  p.catch(() => { const e = rawCache.get(key); if (e && e.p === p) rawCache.delete(key); }); // don't cache failures
  return p;
}

// --- public entry points --------------------------------------------------

// `exclude` is applied at format time only, so the cached raw is shared across
// every exclusion choice and toggling a reason costs no API calls.
export async function buildBots({ workspace, customerId, window: windowStr = '7d', exclude = [] }) {
  const hours = WINDOW_HOURS[windowStr] || WINDOW_HOURS['7d'];
  const raw = await workspaceRaw({ workspace, customerId, hours, windowStr, nowMs: minuteNow() });
  return formatBots(raw, { windowStr, hours, exclude, scope: { type: 'workspace', workspaces: raw.workspaces } });
}

export async function buildBotsAggregate({ workspaces, customerId, window: windowStr = '7d', exclude = [] }) {
  const hours = WINDOW_HOURS[windowStr] || WINDOW_HOURS['7d'];
  const nowMs = minuteNow(); // shared so buckets align across workspaces (and with cached single-workspace raws)
  const raws = [];
  await mapPool(workspaces, 3, async (workspace) => { raws.push(await workspaceRaw({ workspace, customerId, hours, windowStr, nowMs })); });
  const merged = mergeBotRaw(raws);
  return formatBots(merged, { windowStr, hours, exclude, scope: { type: 'all', workspaces } });
}
