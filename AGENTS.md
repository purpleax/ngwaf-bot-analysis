# AGENTS.md — NGWAF Bot Analysis (developer / continuation notes)

Context for continuing work on this project. User-facing docs live in
[README.md](README.md); this file is the engineering handoff.

## What this is

A web dashboard for **bot visibility & traffic analysis** on top of the Fastly
Next-Gen WAF. It started life as a threat-triage dashboard and was **pivoted** to
focus on bots (bot types, AI crawlers/fetchers, trends, per-bot
forensics). The old attack engine still exists (`analytics.js`) but now only
powers a small "threat signals carried by bots" panel.

Single-page, scrolling dashboard. No build step, no framework — vanilla JS +
Chart.js (vendored at `public/chart.umd.min.js`) + a small Express server.

## Run it

```bash
cd /path/to/ngwaf-dashboard
npm install          # first time only (node_modules is committed-in-practice/present)
npm start            # → http://localhost:4000  (Ctrl+C to stop)
```

- Port conflict (`EADDRINUSE`) just means it's already running: `lsof -ti:4000 | xargs kill`, or `PORT=4100 npm start`. The server prints a friendly hint on this error.
- Config is in `.env` (git-ignored; already filled on this machine). See `.env.example`.
- Static assets are served `Cache-Control: no-cache` so browser never serves stale `app.js`.
- **Preview pane**: use `.claude/launch.json` (config `ngwaf-dashboard`, `npm start`, port 4000) + `preview_start` so the pane loads the running server. **Do NOT let the pane open `public/index.html` as a static file** — the app is a client that calls `/api/*`, so a bare file shows a blank/white page (all API calls 404). It must be served by Express.

## Standalone macOS binary (Node SEA)

`npm run build:mac` → `build/ngwaf-dashboard`, a single self-contained executable that
runs on a Mac **without Node installed** (script: `scripts/build-sea.sh`, config
`sea-config.json`). Steps: esbuild bundles `server.js`+deps into one CJS file →
`--experimental-sea-config` makes the blob (the four `public/` files are embedded as SEA
**assets**) → the blob is `postject`-injected into a copied Node runtime → ad-hoc codesign.

- **The binary is a frozen snapshot — REBUILD after every code change.** `npm run build:mac`
  bundles the source *at build time*; a running binary never picks up later edits, unlike
  `npm start` (which reads the live files each run). Classic symptom: a feature works under
  `npm start` but not the `.exe` because the binary predates it (e.g. a binary built before
  the customer-name feature returned no `customerName`).
- **Build stamp — check which build you're running.** `GET /api/health` returns
  `{ok, build}`; the footer shows it too. `npm start` reports `build: "dev"`; a packaged
  binary reports e.g. `v2.0.0 built 2026-07-22 22:39 UTC`. The stamp is injected by esbuild
  via `--define:__BUILD_STAMP__` in `build-sea.sh` (version from `package.json` + UTC build
  time); `server.js` falls back to `"dev"` when the token is undefined. Fastest staleness
  check: `curl -s localhost:4000/api/health` — if `build` predates your last edit, rebuild.
- **`server.js` is dual-mode**: `inCJS` picks native `require`/`__dirname` in the bundle vs
  `import.meta.url` in dev; assets come from `sea.getAsset()` when packaged (`seaAPI`) else
  `public/` on disk; `.env` is read from **beside the executable / cwd** first, then the source dir.
- **The token is NOT baked in** — the binary reads a `.env` sitting next to it (or `FASTLY_*`
  env vars) at runtime. Never distribute a build with the `root:read` token embedded.
- **Auto-opens the browser** (`server.js` `openBrowser()` via `open`/`start`/`xdg-open`, spawned
  detached in the `listen` callback). Gated by `wantsBrowser()`: **default = packaged binary only**
  (`seaAPI` truthy), so `npm start`/preview never launch a browser. `OPEN_BROWSER=1` forces it on
  (even in dev), `OPEN_BROWSER=0` off. On `EADDRINUSE` (already running) it still opens the URL so
  the user lands on the existing instance, then exits.
- **Build gotchas (hard-won):** Homebrew's `node` is a *shared* build (links `libnode.dylib`)
  with **no SEA fuse** → injection fails; the script downloads the **official nodejs.org**
  release binary and injects into that. That official runtime is also used to **generate the
  blob** (`--experimental-sea-config`), not just as the injection target — a shared build
  fails that step too, with `Single executable application is disabled`. The build broke
  exactly this way (2026-09) once Homebrew moved node to a version whose shared build ran the
  blob step; fetching the runtime was reordered *before* blob generation to fix it. `NODE_VER`
  tracks `node -v`, so a Homebrew upgrade means a fresh runtime download on the next build. The postject **sentinel fuse differs by build**, so
  it's grepped from the runtime binary, not hardcoded. The copied node is mode `555` → `chmod
  u+w` before postject. Needs network (esbuild/postject via `npx`, + the node tarball, cached in `build/`).
- **Gatekeeper**: ad-hoc signed, so other Macs quarantine it on download — `xattr -d
  com.apple.quarantine ngwaf-dashboard` or right-click→Open. Frictionless distribution needs a
  Developer ID signature + notarization.
- Verified: runs in a clean dir with only `.env` beside it — serves the embedded UI and makes
  live API calls (0 errors); `npm start` dev mode still serves from `public/` unchanged.

## GitHub repository & releases

- **Repo:** <https://github.com/purpleax/ngwaf-bot-analysis> — **public**, owner `purpleax`
  (the `gh` CLI is authenticated as this account; `repo` scope present, `delete_repo` is **not**
  — deleting a repo needs `gh auth refresh -h github.com -s delete_repo` in an interactive
  terminal first).
- **This is a standalone repo, not the parent `scripts/` repo.** The dashboard folder has its
  own `.git` (single commit history), independent of the outer `~/Documents/scripts` repo and
  its `waf-test` remote. Run all git/gh commands from inside the dashboard folder.
- **What's committed / ignored:** source + docs + `.env.example` + `.claude/launch.json` are
  tracked. `.gitignore` excludes `.env`, `node_modules/`, `build/`, `.DS_Store`, and
  `.claude/settings.local.json`. The compiled binary is **not** committed — it ships only as a
  release asset (see below).
- **NEVER commit sensitive data.** Keep the real `.env` token, the demo customer/workspace ids,
  demo hostnames, and local home-directory paths OUT of committed files —
  use placeholders (`<CUSTOMER_ID>`, `<WORKSPACE_ID>`, `/path/to/ngwaf-dashboard`). Scrub
  **before** the first push: a force-push does *not* purge history — GitHub keeps the old commit
  fetchable by full SHA, so the only reliable purge is delete-and-recreate the repo (which is
  exactly what had to be done here once — see the session log).
- **Cutting a release** (downloadable macOS binary):
  1. Bump `version` in `package.json` if needed; `npm run build:mac`.
  2. Sanity-check the fresh binary embeds no secret:
     `TOKEN=$(grep ^FASTLY_API_TOKEN= .env|cut -d= -f2-); grep -aqF "$TOKEN" build/ngwaf-dashboard && echo LEAK || echo clean`
  3. Upload the binary under a **stable, descriptive filename** (the file's basename becomes the
     download name — a `file#label` only sets display text, so name the file itself):
     ```bash
     ln -f build/ngwaf-dashboard build/ngwaf-dashboard-macos-arm64
     gh release create vX.Y.Z build/ngwaf-dashboard-macos-arm64 \
       -R purpleax/ngwaf-bot-analysis --title "vX.Y.Z — macOS (Apple Silicon)" \
       --notes "…download → put .env beside it → xattr -d com.apple.quarantine … → ./run"
     rm build/ngwaf-dashboard-macos-arm64
     ```
  4. Release notes MUST tell users to (a) supply their own `.env` and (b) clear the Gatekeeper
     quarantine (`xattr -d com.apple.quarantine <file>`) — the binary is ad-hoc signed.
- **Current release:** `v2.0.0` (tag at the initial commit) with asset
  `ngwaf-dashboard-macos-arm64` (137 MB, Apple Silicon / arm64 only — Intel Macs need a separate
  x64 build uploaded as a second asset).

## Architecture

```
Browser (public/)  ──HTTP /api/*──►  server.js (Express)  ──HTTPS──►  Fastly unified API
                                        60s in-mem cache    Fastly-Key   (api.fastly.com/ngwaf/v1)
```

`server.js` calls the Fastly **unified API** directly over HTTPS (`fastlyApi.js`);
all analysis is server-side. Every call is scoped by a `customer_id`. The old
SignalSciences MCP server is gone — do not reintroduce corp/site tooling.

| File | Role |
| --- | --- |
| `server.js` | Express, `.env` loader, 60s response cache, `/api/*`, graceful EADDRINUSE. |
| `fastlyApi.js` | Direct client for the unified API. Injects `customer_id`, **retries 429/5xx with backoff**, and NORMALISES responses back into the old field shapes (`signals[]`→`tags[]`, `request_headers[]`→`headersIn[]`, snake→camel, `reasons[]`→object) so `bots.js`/`analytics.js` are unchanged. |
| `bots.js` | **THE CORE.** Bot taxonomy, AI quadrants, verified-by-category breakdown, geo/hosts, master bot list, per-bot profiles, new-bot detection, bucketed trend. |
| `analytics.js` | Attack overview from workspace `events` (threats/priority/trends). Only the `threats` array is still used by the frontend. |
| `public/app.js` | Frontend render pipeline + interactions (see its header comment). |
| `public/index.html`, `public/styles.css` | Shell + styling (dark theme, CSS vars). |

### API endpoints
- `GET /api/workspaces?customer_id=<id>` → `{customerId, customerName, defaultWorkspace, workspaces:[{name,displayName,mode}]}` (discovery for the selector). `customerName` comes from `getCustomerName()` (`GET /customer/{id}` → `.name`, cached `cust:<id>`, `null` if the account isn't visible/on error); the header subtitle and PDF cover "Prepared for" show it, falling back to the id.
- `GET /api/bots` → the full bot analysis payload (primary). See `formatBots()` return shape in `bots.js`.
- `GET /api/overview` → attack overview (`analytics.js`), used for the threat-context panel.
- `GET /api/health`

The data endpoints accept `?customer_id=<id>&workspace=<id|__all__>&window=<24h|7d|14d>`;
`customer_id`/`workspace` fall back to `FASTLY_DEFAULT_CUSTOMER_ID`/`_WORKSPACE_ID`.
`workspace=__all__` aggregates across every workspace for the customer (per-workspace fetch → merge → format).

**Frontend UI flow** (`app.js` `init()` → `discover()` → `refresh()`): a **Customer ID**
input + **Load** button drives everything. On load it calls `/api/workspaces` (using a
`localStorage`-persisted id, else the server default), populates the workspace selector,
then `refresh()` fetches `/api/bots` + `/api/overview`. Type a different customer id + Load
to pivot to any customer the token can see. `state.customerId`/`state.workspace` thread into
every call; a `reqSeq` guard ignores superseded selections.

## The Fastly unified API data source

- Auth: a **Fastly API token** (`FASTLY_API_TOKEN`, sent as `Fastly-Key`) against `https://api.fastly.com`. NGWAF lives under `/ngwaf/v1/workspaces[/{id}/{requests|events|…}]`. **`customer_id` is a required query param on every call** (a `Fastly-Customer-ID` header is silently ignored).
- **Workspace id == the old site id.** A demo customer (id `<CUSTOMER_ID>`) has three workspaces (ids `<WORKSPACE_ID>`):
  - `<WORKSPACE_EDGE_DEMO>` — **Edge Demo** (almost no bot/attack data)
  - `<WORKSPACE_PUBLISHING>` — **Publishing** (lots of general traffic, few bots)
  - `<WORKSPACE_ECOMMERCE>` — **eCommerce** (the rich demo workspace and the current `.env` default — always test here; serves the demo shop + storefront hosts)
- The token is `root:read` and can see other customers too; the UI's customer-ID field discovers any customer's workspaces.
- **Do NOT edit the FastlyMCP2 server** (a separate local tool, the `fastly-ngwaf` entry in `~/.claude.json`) as part of dashboard work — it's a separate standalone tool. The dashboard talks to `api.fastly.com` on its own via `fastlyApi.js`.
- Demo traffic is generated by scripts the user runs from `../Generate AI Bots/` and `../Generate Bots/` (see their `categories.ini` for the exact bot user-agents/IPs — the `AI_BOTS`/`SEARCH_BOTS`/`TOOL_BOTS` maps in `bots.js` were matched to these). So the dashboard is populated by whatever those generators last produced.

## Bot data model (key concepts)

NGWAF tags each request. Taxonomy (see the [system-signals doc](https://www.fastly.com/documentation/guides/next-gen-waf/signals/using-system-signals/)):
`VERIFIED-BOT[.<SUBTYPE>]`, `VERIFIED-BOT.AI-CRAWLER`, `VERIFIED-BOT.AI-FETCHER`,
`SUSPECTED-BOT[.HEADLESS|.AI-CRAWLER|.AI-FETCHER]`, `SUSPECTED-BAD-BOT`,
`SCANNER`, `IMPOSTOR`, `DATACENTER`, `CHALLENGED`.

- **Three verdicts are treated as mutually exclusive**: `VERIFIED-BOT` +
  `SUSPECTED-BOT` + `SUSPECTED-BAD-BOT` = "identified bots" (an absolute count).
- **No human / bot-% figures.** The dashboard deliberately does **not** report a
  "human" count or a "% of traffic" bot share. The request total comes from the
  NGWAF *requests* feed (inspected/logged requests — see the data-source note),
  **not** true CDN edge volume, so `total − bots` is not a reliable human count and
  `bots ÷ total` overstates the bot share. We couldn't reliably map a workspace to
  its backing CDN service to get the true total, so these were removed (2026-07).
  Report absolute bot counts; AI share is expressed as `pctOfBots` (÷ identified
  bots), never `pctOfTraffic`. The KPI reads **"Requests Inspected"**, not "Total
  Requests". Don't reintroduce `human`/`botPct`/`pctOfTraffic`/`composition`.
- **AI crawler vs fetcher**: crawler = training scrape (GPTBot, ClaudeBot, CCBot);
  fetcher = live user-triggered retrieval (OAI-SearchBot, ChatGPT-User). Each is
  verified or unverified → 4 quadrants.
- **Exact vs sampled**: category *totals* and per-bucket *totals* come from the
  response `meta.total` (exact; surfaced as `totalCount` by `fastlyApi.js`). Per-bot
  counts, geo, hosts, per-bucket bot splits come
  from bounded samples and are **scaled by `total/sampled`** per category. Treat
  high-volume per-bot figures as estimates. AI crawler/fetcher subtype counts use
  their exact dedicated totals.
- **New-this-window**: a bot whose name wasn't seen in a first-half query
  (`from:-Hh until:-(H/2)h tag:<verdict>` for the 3 verdict parents). Generic
  buckets ("Suspected bot", "Unclassified bad bot", …) are excluded.
- **Per-bot profile**: JA3/JA4, hosting network (see portability note below), methods,
  status codes, user-agents, first/last seen, top paths, example requests.

## Hard-won constraints (READ before changing data fetching)

- **`customer_id` is REQUIRED on every unified-API call** — workspace sub-resources return `400 "Site not found"` without it. Customer scoping is a query param; the `Fastly-Customer-ID` header is silently ignored.
- **The requests endpoint carries the time range INSIDE the `q` query**: `from:-168h [until:-84h] [tag:X]`. The tag/time DSL is preserved from the old SignalSciences syntax, so `bots.js` query strings are unchanged. `meta.total` is the exact count; `data[]` is capped at `limit` (a single page returns ≥500, well above our max sample of 300 — no cursor paging needed).
- **The requests API caps every search at 7 days** — `400: Search time interval exceeded - must be 7 days or less` (exactly 168h is allowed). So any window >7d is **chunked** into ≤168h segments by `windowChunks()`/the `full:true` jobs in `fetchWorkspaceBots` (their exact totals + sampled data are summed/merged); `firstHalf` (168h span) and per-bucket jobs already fit. `WINDOW_HOURS` = `{24h:24, 7d:168, 14d:336}`; the UI selector offers **Last 24h / 7 days / 14 days** and `server.js` whitelists exactly those (analytics.js `WINDOW_SECONDS` mirrors it). Keep the whitelist, `WINDOW_HOURS`, and the `<option>` list in sync when changing periods.
- **The requests store only retains recent history** — on the demo eCommerce workspace data goes back ~14 days, nothing older (probed 2026-07); that retention, not the query cap, is why **30d was dropped** — a longer period would just return empty older chunks.
- **Per-request `signals[]`** carries the taxonomy tags AND the bot name in `value` (e.g. `{id:"VERIFIED-BOT.AI-FETCHER", value:"OpenAI SearchBot"}`); `ja3`/`ja4`, `country`, `remote_ip`, `remote_hostname` are all top-level native fields. `fastlyApi.js` maps these back to the old shapes.
- **Portability — no ASN in the API.** The requests/events endpoints do **not** expose ASN anywhere (checked list + detail + `summation`). ASN only ever lived in the customer-injected `Z-Asn`/`Z-Asn-Name` VCL headers, so the dashboard **must not** depend on them. `networkOf()` in `bots.js` attributes "hosting network" portably from the native **`DATACENTER` signal** value (cloud/hosting provider, ~76% of reqs) with a **reverse-DNS `remote_hostname`** fallback (~77%); residential/ISP IPs are left unattributed. Don't reintroduce `Z-*` header reads.
- **Suspected-bot detection reasons live in the signal `value`, and `signal:"…"`
  filtering has two silent failure modes.** NGWAF records *why* a request was
  called a suspected bot in the `SUSPECTED-BOT` signal's `value` (detector
  `BotDetectRule`, scope `system`): `Missing header(s)`, `User-Agent: Crawler`,
  `User-Agent: Common Automation`. These are **not** `.SUBTYPE` tags — there is no
  `tag:SUSPECTED-BOT.MISSING-HEADERS`; `tag:MISSING-HEADERS` returns 0. AI bots
  tagged `SUSPECTED-BOT` put their *bot name* in the same field (`ClaudeBot`).
  Two traps, both of which return a plausible number rather than an error:
  - **`-signal:"X"` negation is silently dropped** — it returns the identical
    count to the positive `signal:"X"`, i.e. the exact opposite set. Measured:
    both forms gave 24,589. (`-tag:` negation *does* work — positive + negative
    sum to the parent — so it is only `signal:` that is broken.) **Never exclude
    by negating**; query the reason positively and subtract.
  - **An unmatched `signal:` filter is silently ignored and returns the ENTIRE
    parent set.** `signal:"ZZZ-GARBAGE"` and `signal:"ClaudeBot"` both return the
    full `tag:SUSPECTED-BOT` total with mixed values in `data[]`. So a reason is
    only trusted once the filter is verified **by content** — read back a sample
    and require every row to actually carry that value (`countSuspectedReasons`,
    `REASON_PROBE`). A count-only check ("smaller than the parent") is a heuristic
    that can pass by luck on a single-reason category, and the totals drift under
    live traffic anyway since parent and reason are measured seconds apart.

  The reasons **partition** the non-AI suspected traffic — independently verified:
  `tag:SUSPECTED-BOT -tag:SUSPECTED-BOT.AI-CRAWLER -tag:SUSPECTED-BOT.AI-FETCHER`
  = 75,893 vs the three reason counts summing to 75,734 (0.21%, live drift). That
  is what makes subtraction exact rather than an estimate.
- **Events**: `/events?customer_id=&from=<RFC3339>[&until=]`. `reasons` is an array `[{signal_id,count}]` (normalised to a `{signal:count}` object); `sample_request` mirrors a request record; `source` is the IP. Drives the threat-context `threats`. `get_analytics`/`get_suspicious_ips` were **dropped** (unused by the UI) — `topIPs`/`priority`/`trends` are dormant.
- **Rate limiting (429)**: the requests API rejects bursts. Mitigations in place — `fastlyApi.js` retries 429/5xx with backoff; `bots.js` runs queries via `mapPool` (bounded concurrency: 5 per workspace, 3 workspaces in the aggregate). Don't fan out unbounded.
- **AI double-count gotcha**: AI requests are also tagged `VERIFIED-BOT`/`SUSPECTED-BOT`, so the trend-bucket bumping skips AI in the verified/suspected buckets (they're counted by the AI jobs). Preserve this if you touch `fetchWorkspaceBots`.
- **Node has no `timeout` builtin on macOS zsh** — don't use it in test one-liners.

### Suspected-bot reason exclusions (the "Exclusions" control)

A single false-positive-prone detection reason can dominate the suspected-bot
category — on the demo eCommerce workspace `Missing header(s)` alone is ~30% of
all suspected-bot volume, and excluding it drops `Google-Read-Aloud` and
`Googlebot` out of the suspected list entirely. The top-bar **Exclusions** menu
(a native `<details>`, the only popup here, so it needs no dismissal JS) lets an
operator drop one reason from the entire report.

The load-bearing design decision: **the exclusion is applied at format time, not
fetch time.**

- `fetchWorkspaceBots` always fetches *everything* and stores the suspected sample
  **partitioned by reason** (`raw.suspectedParts`), plus each reason's exact total
  (`raw.suspectedReasons`, from `countSuspectedReasons`).
- `materialiseSuspected(raw, excluded)` folds the kept partitions back into the
  flat shapes the rest of `formatBots` already reads (`cat.suspected`, the
  `suspected:*` entries of `raw.bots`, `geoByCat`/`hostsByCat`, `bucketBots[i]
  .suspected`). **Everything downstream was left untouched** — KPIs, trend,
  taxonomy, tables and the PDF all recompute for free.
- It returns a **shallow clone**; `raw` is shared between cached views (see
  `workspaceRaw`) and must stay read-only. Keep it that way.

Consequences worth preserving:

- `rawCache` stays keyed `<cust>:<ws>:<window>` with **no exclusion in the key**,
  so every exclusion combination shares one fetch. Toggling a reason within the
  60s raw TTL costs **no API calls** (measured 1.4 ms); outside the TTL it is a
  normal cold load. Only `server.js`'s *formatted* cache key carries the
  exclusion set (sorted, so any order reuses one entry).
- Exclusion subtracts the reason's **exact** count, so headline numbers stay exact
  — the user's explicit priority is accuracy over report-generation speed. Per-bot
  rows inside the category remain sampled-and-scaled as before (the scale factor
  recomputes from the kept partitions, so it stays consistent).
- Reasons are passed as a **repeated** `?exclude=` param, not comma-separated —
  the values contain commas and colons.
- `refresh()` **prunes** any persisted reason the current window/workspace cannot
  filter on, so a stale `localStorage` entry can never silently claim to filter.
- The PDF cover gains an "Excluded" row and a summary sentence — a filtered report
  must say so on its face.

Cost: 1 extra count query per discovered reason (×2 on 14d, chunked), run in a
bounded `mapPool(…, 5)` *after* the main pool. Roughly +1–5s on a cold load,
which is inside the baseline's own run-to-run variance on this API (baseline
measured 14–22s for a cold 7d, not the 8s this file used to quote). Raising that
concurrency to 6 made it *worse* (rate limiting), so leave it at 5.

## Performance

- Single-workspace `/api/bots` ≈ 8s cold (~2× on 14d — queries are chunked), instant when 60s-cached.
- `workspace=__all__` ≈ 30–50s cold (every per-workspace query × 3 workspaces). It's the
  heaviest, secondary view.
- **Two cache layers (both 60s):** `server.js` caches the *formatted* response per
  `bots:<cust>:<ws|__all__>:<window>`; `bots.js` `workspaceRaw()` caches each workspace's
  *raw* aggregate per `<cust>:<ws>:<window>`. The raw cache lets the aggregate reuse raws
  already fetched by single-workspace views (loading the default eCommerce view then clicking
  "All workspaces" reuses eCommerce and only fetches the other two; a repeated `__all__`
  reuses all three → merge/format only, no API), and dedupes concurrent identical fetches.
  `nowMs` is rounded to the minute (`minuteNow()`) so raws fetched close together share bucket
  edges and merge cleanly. `mergeBotRaw`/`formatBots` are read-only on the raw, so sharing is
  safe — keep it that way. To speed `__all__` further: raise `RAW_TTL_MS` (trades freshness),
  trim sample limits in `AI_CATS`/`OTHER_CATS`, or reduce the bucket count.

## Testing / verifying changes

- Backend: `curl -s "http://localhost:4000/api/bots?customer_id=<CUSTOMER_ID>&workspace=<WORKSPACE_ID>&window=7d" | python3 -m json.tool`. Spot-check a category count against a direct `GET /ngwaf/v1/workspaces/{id}/requests?customer_id=&q=from:-168h tag:VERIFIED-BOT` `meta.total`.
- Frontend: drive it with the chrome-devtools MCP (`navigate_page`, `evaluate_script`, `take_screenshot`, `list_console_messages`). Always switch to the **eCommerce** workspace — the default Edge Demo is nearly empty. Bots take ~8s to load; wait before asserting.
- After editing `server.js`/`fastlyApi.js`, restart the server; after editing frontend files, just reload (no-cache header handles it).

## Status & possible next steps

**Most recent work (unified-API pivot — the big one):** the whole data layer was moved
off the deprecated SignalSciences MCP server onto the **Fastly unified API**
(`fastlyApi.js`), all SignalSciences/corp/site references purged. Added the **customer-ID
field + workspace discovery** (any customer the token can see). Made network attribution
**portable** (`networkOf()` — native `DATACENTER` signal + reverse DNS, no `Z-*` header
injection). Config is now `FASTLY_API_TOKEN` + `FASTLY_DEFAULT_CUSTOMER_ID` (+ optional
`_WORKSPACE_ID`, `FASTLY_API_BASE_URL`). `mcpClient.js` and the MCP SDK dependency are gone.
All verified end-to-end (backend curl + browser). See the Architecture / constraints above.

Done (bot features): full bot taxonomy, AI quadrants, per-bucket trend (by
classification / AI split), geo/hosts, master bot list (verdict + category filters),
per-bot forensic profiles (JA3/JA4/hosting-network/…), new-this-window detection,
insights narrative (top of page), threat-context bridge, clickable KPIs/taxonomy, dropdowns.

**Most recent session (2026-07):**
- **Section order** — **General Bot Traffic** first, then the dedicated **AI** section (`renderDash()` in `app.js`).
- **Verified bots by category** — `panelVerifiedBreakdown()` shows the top bots inside each verified-bot class (Search engine, Monitoring, AI crawler/fetcher, …). Backend: each non-AI verified bot agg carries a `subtype` (set in `ingestOther`, carried through merge + `botRow`), and `formatBots()` builds `verified.subtypeBreakdown` (AI classes draw their bots from the AI list).
- **Human / bot-% removed** — see the "No human / bot-% figures" note in the data model above.
- **Fastly branding** — red `fastly` wordmark (CSS text, not an image — the sourced logo had a baked-in white bg) + red favicon, brand-red accents throughout.
- **Print to PDF** — a **🖨 PDF** button (top bar) → `window.print()`. A print-only, dark, landscape, branded report: cover page (`buildReportCover()` fills `#reportCover` on `beforeprint`, sets the filename, resizes charts) + running footer, styled by the `@media print` block in `styles.css`. Cover/footer are `display:none` on screen. To preview print CSS without printing, clone the `@media print` rules onto a screen `<style>` and dispatch a `beforeprint` event.
- **`.env` default workspace** is now the demo eCommerce workspace.
- **Reporting periods** — "Window" relabelled **"Reporting period"** in the UI; **30d replaced with 14d** (the requests API caps queries at 7 days and the store only holds ~14 days). Windows >7d are chunked into ≤7-day queries — see the constraints note above. "New this window" panel renamed **"Emerging Bots"**.

**Dedicated AI section** (`panelAISection()` in `app.js`, fed by the enriched
`ai` object in `bots.js` `formatBots()`): AI-specific insights narrative, traffic
overview (verified/unverified split bar + blocked/robots-compliance meters),
verified×intent 2×2 matrix, AI-at-a-glance stats, crawler-vs-fetcher trend
(`cAITrend`, estimated split by ratio) + doughnut (`cAIType`), **AI-by-operator**
table (grouping via `AI_OPERATORS` map / `aiOperator()` — OpenAI, Anthropic,
Google, …), per-bot drill table, and AI top-paths / geo (`raw.aiGeo`) / networks
(`raw.aiNetworks`). New `ai` fields: `pctOfBots` (never `pctOfTraffic` — see the data-model note above), `verifiedPct`,
`blockRatePct`, `compliancePct` (robots.txt/sitemap hits ÷ AI path hits),
`operators`, `geo`, `networks`, `newBots`, `distinctOperators`. AI geo/networks are pooled
sample counts scaled by one overall AI factor (`fAI`) — estimates.

**This session (2026-07-23):**
- **Bar-row label truncation fix** — the shared `barRows()` helper (`app.js`) renders a
  fixed-width `.lbl`; longer hostnames in **Hosts targeted** (~23 chars) were being
  ellipsis-truncated at `130px`. Added `.barrow .lbl.mono { width: 200px; }`
  in `styles.css` so the **mono** label variant (hosts, paths, networks — the long ones) gets
  more room; short non-mono labels (countries) stay at `130px`. Each label still carries a
  `title` tooltip for anything longer than even the wider width.
- **Standing convention: rebuild the SEA binary after every code change** — the user asked
  that `npm run build:mac` run after each code edit (the binary is a frozen snapshot; see the
  "Standalone macOS binary" section). Applies to code edits, not docs-only changes.
- **README rewritten** to match the current code (the unified-API pivot had left it stale):
  removed the cut "bot vs human"/human-share language, 30d→14d, fixed the sections list
  (General Bot Traffic → AI section, Emerging Bots, Verified-by-category, PDF button),
  trend-view options, and the `bots.js` file-table row.
- **Published to GitHub + first release.** Made the dashboard its own standalone repo
  (<https://github.com/purpleax/ngwaf-bot-analysis>, public) and cut release **v2.0.0** with the
  macOS binary as a downloadable asset. In the process: scrubbed the demo customer/workspace ids,
  demo hostnames and the local home-directory path out of `CLAUDE.md`; because a
  post-push scrub leaves the old commit fetchable by SHA, the repo was **deleted and recreated**
  to guarantee a clean public history. See the new "GitHub repository & releases" section for the
  repo layout, the no-secrets-in-commits rule, and the release recipe.

**This session (2026-09-15):**
- **Suspected-bot reason exclusions** — the Exclusions control described above,
  spanning `bots.js` (reason partitioning, exact per-reason counts, the
  content-verified filterability probe, `materialiseSuspected`), `server.js`
  (repeated `?exclude=` param + cache key), `public/app.js` (menu, persistence,
  status line, PDF cover) and `public/styles.css` (the `.menu-*` rules).
- Found and documented two silent `signal:` filtering failure modes in the
  requests API — see the constraints section. Both would have produced confidently
  wrong numbers; the content check is what makes the feature trustworthy.
- `resetFilters` was **hoisted out of `init()`** to module scope so the exclusions
  menu can call it; it was previously a `const` local to `init`.
- **Fixed `scripts/build-sea.sh`** — it had been generating the SEA blob with the
  *system* node, which stopped working when Homebrew's node moved to v26.7.0 (a
  shared build reports `Single executable application is disabled`). Steps 2 and 3
  are now swapped so the official runtime is fetched first and used for the blob.
  Rebuilt and verified standalone: correct build stamp, no token embedded,
  exclusions working against the live API.

Open ideas the user may pick up:
- Make the per-bucket bot split exact (currently sampled+scaled) via per-bucket verdict count queries — costs latency.
- `CHALLENGE-TOKEN-VALID/INVALID` pass/fail breakdown (data is 0 right now).
- A double-click `.command` launcher so Terminal isn't needed.
- Speed up `__all__` (per-workspace raw caching).

## Conventions

- Vanilla JS, 2-space indent, terse helpers (`fmt`, `esc`, `pct`). Match existing style.
- Colours are CSS vars in `styles.css` (`--good/--medium/--high/--low/--accent`); JS chart palette is the `C` object in `app.js`. Keep verdict colours consistent (good=green, suspicious=amber, bad=red, ai=teal). Fastly brand red is `--brand` (`#ff282d`) — used for the wordmark logo, header/section accents, buttons and the PDF report; keep it distinct from the `bad`/danger red.
- Bot classification maps live in `bots.js` (`AI_CATS`, `OTHER_CATS`, `VERIFIED_SUBTYPES`, `AI_BOTS`, `SEARCH_BOTS`, `TOOL_BOTS`, `AI_OPERATORS`) — edit there to add/reclassify bots. When adding an AI bot to `AI_BOTS`, also map its name in `AI_OPERATORS` so it groups under the right company (else it falls into "Other / unrecognised").
