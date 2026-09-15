// NGWAF Bot Analysis — HTTP layer.
// Serves the static frontend and a small JSON API backed by the Fastly unified
// API (fastlyApi.js, workspace model). Every request is scoped by a customer id.
// Endpoints: /api/workspaces (discovery), /api/bots (primary — see bots.js),
// /api/overview (threat context), /api/health.

import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { listWorkspaces, getCustomerName } from './fastlyApi.js';
import { buildOverview, buildAggregate } from './analytics.js';
import { buildBots, buildBotsAggregate } from './bots.js';

// Dual-mode: ESM in dev (`node server.js`), CJS once bundled into the SEA binary.
// In the CJS bundle `require`/`__dirname` are native globals; in ESM they aren't,
// so derive them from import.meta.url (the CJS branch never evaluates it).
const inCJS = typeof require === 'function' && typeof __dirname === 'string';
const nodeRequire = inCJS ? require : createRequire(import.meta.url);
const baseDir = inCJS ? __dirname : dirname(fileURLToPath(import.meta.url));

// Detect running as a packaged Single Executable Application (SEA). When packaged
// the frontend assets are embedded in the binary (there is no ./public on disk)
// and .env lives beside the executable, not in the source tree.
let seaAPI = null;
try { const s = nodeRequire('node:sea'); if (s.isSea()) seaAPI = s; } catch { /* plain `node server.js` */ }

// --- minimal .env loader (no dependency) ---------------------------------
// Prefer a .env next to the executable / in the cwd (for the packaged binary),
// then fall back to the source dir (for `node server.js`).
(function loadEnv() {
  const envPath = [
    join(dirname(process.execPath), '.env'),
    join(process.cwd(), '.env'),
    join(baseDir, '.env'),
  ].find((p) => existsSync(p));
  if (!envPath) return;
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
})();

// Build stamp: esbuild replaces `__BUILD_STAMP__` at bundle time (see
// scripts/build-sea.sh), so a packaged binary reports exactly when it was built.
// Running `node server.js` leaves the token undefined → reports "dev" (live source).
const BUILD_STAMP = typeof __BUILD_STAMP__ !== 'undefined' ? __BUILD_STAMP__ : 'dev';

const PORT = process.env.PORT || 4000;
const DEFAULT_CUSTOMER_ID = process.env.FASTLY_DEFAULT_CUSTOMER_ID || null;
const DEFAULT_WORKSPACE = process.env.FASTLY_DEFAULT_WORKSPACE_ID || null;
const app = express();

// Resolve the target customer id for a request (query overrides the env default).
const customerOf = (req) => req.query.customer_id || DEFAULT_CUSTOMER_ID;

// Tiny in-memory cache so tile clicks / refreshes don't re-hammer the API.
const cache = new Map();
const TTL_MS = 60_000;
function cached(key, producer) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.t < TTL_MS) return hit.p;
  const p = Promise.resolve().then(producer);
  cache.set(key, { t: Date.now(), p });
  p.catch(() => cache.delete(key)); // don't cache failures
  return p;
}

// Serve the frontend — from the embedded SEA assets when packaged, else from
// ./public on disk. Always no-cache so edits to app.js/styles.css aren't masked.
const STATIC = {
  '/': 'index.html', '/index.html': 'index.html',
  '/app.js': 'app.js', '/styles.css': 'styles.css',
  '/chart.umd.min.js': 'chart.umd.min.js',
};
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
function readAsset(name) {
  if (seaAPI) return Buffer.from(seaAPI.getAsset(name));
  return readFileSync(join(baseDir, 'public', name));
}
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  const name = STATIC[req.path];
  if (!name) return next();
  let body;
  try { body = readAsset(name); } catch { return next(); }
  res.setHeader('Cache-Control', 'no-cache');
  res.type(MIME[extname(name)] || 'application/octet-stream');
  res.send(body);
});

// Discover the workspaces for a customer (populates the selector).
app.get('/api/workspaces', async (req, res) => {
  const customerId = customerOf(req);
  if (!customerId) return res.status(400).json({ error: 'customer_id is required' });
  try {
    const [workspaces, customerName] = await Promise.all([
      cached(`ws:${customerId}`, () => listWorkspaces(customerId)),
      cached(`cust:${customerId}`, () => getCustomerName(customerId)),
    ]);
    res.json({
      customerId,
      customerName,
      defaultWorkspace: (DEFAULT_WORKSPACE && workspaces.some((w) => w.name === DEFAULT_WORKSPACE))
        ? DEFAULT_WORKSPACE : (workspaces[0]?.name || null),
      workspaces,
    });
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

async function listWorkspaceNames(customerId) {
  const workspaces = await cached(`ws:${customerId}`, () => listWorkspaces(customerId));
  return workspaces.map((w) => w.name);
}

// Consolidated overview powering all three tiles + detail windows.
// workspace=__all__ aggregates every workspace for the customer.
app.get('/api/overview', async (req, res) => {
  const customerId = customerOf(req);
  if (!customerId) return res.status(400).json({ error: 'customer_id is required' });
  const workspace = req.query.workspace || DEFAULT_WORKSPACE;
  const window = ['24h', '7d', '14d'].includes(req.query.window) ? req.query.window : '7d';
  try {
    if (workspace === '__all__') {
      const key = `overview:${customerId}:__all__:${window}`;
      const data = await cached(key, async () => buildAggregate({ workspaces: await listWorkspaceNames(customerId), customerId, window }));
      return res.json(data);
    }
    const key = `overview:${customerId}:${workspace}:${window}`;
    const data = await cached(key, () => buildOverview({ workspace, customerId, window }));
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

// Bot & AI-crawler intelligence (separate endpoint so the attack overview
// stays fast; the frontend fetches both in parallel).
app.get('/api/bots', async (req, res) => {
  const customerId = customerOf(req);
  if (!customerId) return res.status(400).json({ error: 'customer_id is required' });
  const workspace = req.query.workspace || DEFAULT_WORKSPACE;
  const window = ['24h', '7d', '14d'].includes(req.query.window) ? req.query.window : '7d';
  // Suspected-bot detection reasons to leave out of the report, passed as a
  // repeated param (?exclude=Missing+header(s)&exclude=...) because the values
  // themselves contain commas and colons. Sorted into the cache key so the same
  // set in any order reuses one entry; the underlying raw is shared regardless.
  const exclude = [].concat(req.query.exclude || []).map((r) => String(r).trim()).filter(Boolean).sort();
  const ex = exclude.length ? `:x=${exclude.join('|')}` : '';
  try {
    if (workspace === '__all__') {
      const key = `bots:${customerId}:__all__:${window}${ex}`;
      const data = await cached(key, async () => buildBotsAggregate({ workspaces: await listWorkspaceNames(customerId), customerId, window, exclude }));
      return res.json(data);
    }
    const key = `bots:${customerId}:${workspace}:${window}${ex}`;
    const data = await cached(key, () => buildBots({ workspace, customerId, window, exclude }));
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true, build: BUILD_STAMP }));

// Whether to auto-open the browser. Default: only the packaged binary does
// (an app-like launch); `npm start`/preview don't. OPEN_BROWSER=1/0 forces on/off.
function wantsBrowser() {
  const v = String(process.env.OPEN_BROWSER || '').toLowerCase();
  if (['0', 'false', 'no'].includes(v)) return false;
  if (['1', 'true', 'yes'].includes(v)) return true;
  return !!seaAPI;
}
// Open a URL in the default browser (best-effort, non-fatal). Detached so it
// survives this process exiting (needed for the already-running case below).
function openBrowser(url) {
  try {
    const [cmd, args] = process.platform === 'darwin' ? ['open', [url]]
      : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
        : ['xdg-open', [url]];
    const cp = spawn(cmd, args, { stdio: 'ignore', detached: true });
    cp.on('error', () => { /* browser open is best-effort */ });
    cp.unref();
  } catch { /* non-fatal */ }
}

const server = app.listen(PORT, () => {
  console.log(`\n  NGWAF Bot Analysis → http://localhost:${PORT}\n  (press Ctrl+C to stop)\n`);
  if (wantsBrowser()) openBrowser(`http://localhost:${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  ✗ Port ${PORT} is already in use — the dashboard is probably already running.\n`);
    console.error(`    Open   http://localhost:${PORT}   in your browser, or free the port:\n`);
    console.error(`      lsof -ti:${PORT} | xargs kill\n`);
    console.error(`    …then run "npm start" again. To use a different port instead:\n`);
    console.error(`      PORT=4100 npm start\n`);
    // It's already running — just surface the existing instance.
    if (wantsBrowser()) openBrowser(`http://localhost:${PORT}`);
  } else {
    console.error(`\n  ✗ Server failed to start: ${err.message}\n`);
  }
  process.exit(1);
});

function close() {
  server.close(() => process.exit(0));
}
process.on('SIGINT', close);
process.on('SIGTERM', close);
