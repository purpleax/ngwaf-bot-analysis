// Direct client for the Fastly unified API (api.fastly.com), NGWAF workspace model.
// Replaces the old SignalSciences MCP subprocess. Auth is a Fastly API token sent
// as the `Fastly-Key` header. `customer_id` is REQUIRED on every call. The request
// search DSL (e.g. "from:-168h until:-84h tag:VERIFIED-BOT.AI-CRAWLER") is carried
// inline in the `q` param, exactly as the old search_requests tool expected.
//
// This module also NORMALISES unified responses back into the field shapes that
// bots.js / analytics.js already read, so the heavy analysis code is unchanged:
//   request.signals[]{id,value,location}      -> tags[]{type,value,location}
//   request.request_headers[]{name,value}     -> headersIn[] [key,value]
//   snake_case fields                          -> the old camelCase names
//   event.reasons[]{signal_id,count}           -> { <signal>: <count> } object

const BASE = (process.env.FASTLY_API_BASE_URL || 'https://api.fastly.com').replace(/\/+$/, '');
const token = () => process.env.FASTLY_API_TOKEN || '';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// GET a unified-API path with query params. Retries transient 429/5xx with
// exponential backoff (honouring Retry-After when present).
async function apiGet(path, query = {}, { retries = 4 } = {}) {
  const url = new URL(BASE + path);
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
  }
  let attempt = 0;
  for (;;) {
    let res;
    try {
      res = await fetch(url, { headers: { 'Fastly-Key': token(), Accept: 'application/json' } });
    } catch (err) {
      if (attempt < retries) { await sleep(300 * 2 ** attempt); attempt += 1; continue; }
      throw new Error(`Fastly API ${path}: ${String(err.message || err)}`);
    }
    if ((res.status === 429 || (res.status >= 500 && res.status <= 599)) && attempt < retries) {
      const ra = Number(res.headers.get('Retry-After'));
      await sleep(Number.isFinite(ra) && ra > 0 ? ra * 1000 : 300 * 2 ** attempt);
      attempt += 1;
      continue;
    }
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    if (!res.ok) {
      const msg = (body && (body.detail || body.title)) || text || `HTTP ${res.status}`;
      throw new Error(`Fastly API ${path} ${res.status}: ${msg}`);
    }
    return body;
  }
}

const WS = (id) => `/ngwaf/v1/workspaces/${encodeURIComponent(id)}`;

// --- normalisation --------------------------------------------------------

function normReq(r) {
  if (!r) return {};
  return {
    tags: (r.signals || []).map((s) => ({ type: s.id, value: s.value || '', location: s.location || '' })),
    headersIn: (r.request_headers || []).map((h) => [h.name, h.value]),
    userAgent: r.user_agent || '',
    remoteIP: r.remote_ip || '',
    remoteHostname: r.remote_hostname || '',
    remoteCountryCode: r.country || '',
    serverHostname: r.server_hostname || r.server_name || '',
    serverName: r.server_name || r.server_hostname || '',
    ja3: r.ja3 || '',
    ja4: r.ja4 || '',
    method: r.method || '',
    path: r.path || '',
    uri: r.uri || '',
    timestamp: r.timestamp || null,
    responseCode: r.response_code ?? null,
    agentResponseCode: r.agent_response_code ?? null,
  };
}

function normEvent(ev) {
  const reasons = {};
  for (const r of ev.reasons || []) {
    if (r && r.signal_id) reasons[r.signal_id] = (reasons[r.signal_id] || 0) + (r.count || 1);
  }
  const ts = ev.detected_at || ev.created_at || null;
  return {
    timestamp: ts,
    detectedTimestamp: ts,
    requestCount: ev.request_count || 1,
    source: ev.source || null,
    remoteCountryCode: ev.country || '',
    userAgents: ev.user_agents || [],
    action: ev.action || null,
    reasons,
    exampleRequest: ev.sample_request ? normReq(ev.sample_request) : null,
  };
}

// --- public API (old-shaped returns) --------------------------------------

// Human-readable customer name for a customer id (root:read tokens can see any
// customer). Returns null if the account isn't visible to the token / on error.
export async function getCustomerName(customerId) {
  if (!customerId) return null;
  try {
    const body = await apiGet(`/customer/${encodeURIComponent(customerId)}`);
    return (body && body.name) || null;
  } catch { return null; }
}

// [{ name:<workspaceId>, displayName, description, mode }]
export async function listWorkspaces(customerId) {
  const body = await apiGet('/ngwaf/v1/workspaces', { customer_id: customerId });
  return (body?.data || []).map((w) => ({
    name: w.id,
    displayName: w.name || w.id,
    description: w.description || '',
    mode: w.mode || 'unknown',
  }));
}

// { totalCount:<exact>, data:[ normReq ] }. `query` is the inline search DSL;
// `limit` bounds the sample (the API returns up to at least 500 in one page,
// well above every sample size we ask for, so no cursor paging is needed).
export async function searchRequests(customerId, workspace, query, limit = 100) {
  const body = await apiGet(`${WS(workspace)}/requests`, { customer_id: customerId, q: query, limit });
  const data = body?.data || [];
  return { totalCount: body?.meta?.total ?? data.length, data: data.map(normReq) };
}

// { totalCount:<exact>, data:[ normEvent ] }. `from`/`until` are RFC 3339.
export async function listEvents(customerId, workspace, { from, until, limit = 500 } = {}) {
  const body = await apiGet(`${WS(workspace)}/events`, { customer_id: customerId, from, until, limit });
  const data = body?.data || [];
  return { totalCount: body?.meta?.total ?? data.length, data: data.map(normEvent) };
}
