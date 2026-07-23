# NGWAF Bot Analysis

A web dashboard for understanding the **bot traffic** hitting your sites behind
the Fastly Next-Gen WAF — what kinds of bots, how much, from where, and how the
mix is trending. It scrolls as a single analysis view (no drill-through needed
to see the big picture), with click-to-expand example requests where useful.

The view is split into two blocks: a **General Bot Traffic** section, then a
dedicated **AI Bots & Crawlers** section.

**KPI strip** — Requests Inspected, Bot Requests, Verified Bots, AI Bot Hits,
Bad / Scanner / Impostor, and Bots Blocked (absolute counts; each card jumps to
its section). The dashboard reports absolute bot counts — it deliberately does
**not** show a "human" count or a "% of traffic" bot share (the request feed is
inspected/logged requests, not true CDN edge volume, so that ratio would mislead).

**General Bot Traffic**

1. **Analysis & insights** — an auto-generated narrative of the key findings.
2. **Bot classification** — good vs suspicious vs bad, as a share of identified bots.
3. **At a glance** — verified, AI, unverified, bad, scanners, impostors,
   datacenter-origin counts.
4. **Bot activity over time** — a dropdown switches between *by classification*
   (verified / AI / suspected / bad) and *AI: crawler vs fetcher*.
5. **Bot taxonomy** — every NGWAF bot category with volume, block rate, and a
   plain-English meaning; plus a **verified-bot subtype** breakdown (search
   engine, SEO, monitoring, marketing, research, security tools, accessibility,
   content fetcher, page preview, platform integrations) and a **Verified bots by
   category** panel showing the top bots inside each verified class.
6. **Emerging Bots** — bots seen only in the recent half of the reporting period
   (emerging crawlers, fresh scanners, new impostors), each expandable.
7. **Top bots** — every bot ranked across all categories, filterable by verdict
   (good / suspicious / bad) **and** by category (dropdown); each row expands to a
   full **bot profile** — first/last seen, source IPs, countries, hosts, methods,
   status codes, **hosting network**, **JA3/JA4 fingerprints**, user-agents, top paths,
   and example requests.
8. **Traffic analysis** — top paths hit by bots, bot traffic by country, hosts
   targeted.
9. **Threat signals carried by bots** — the attack payloads (SQLi, traversal, …)
   that malicious bots are carrying, for a security bridge.

**AI Bots & Crawlers** — AI/LLM traffic split into four quadrants (**verified vs
unverified × crawler vs fetcher**), with its own insights narrative, traffic
overview (verified split + blocked / robots-compliance meters), an AI-by-operator
table (OpenAI, Anthropic, Google, …), crawler-vs-fetcher trend, and a per-bot
drill table (GPTBot, ClaudeBot, CCBot, OAI-SearchBot, PerplexityBot, AI2Bot, …)
with status, allowed vs blocked, what they fetch (`/robots.txt`, `/sitemap.xml`,
content), plus AI top paths / country / source networks. *Crawlers* bulk-scrape
for training; *fetchers* retrieve live for a user query — unverified spoofers are
flagged in red.

**Print to PDF** — a **🖨 PDF** button renders a print-only, branded landscape
report (cover page + running footer).

**Clickable throughout:** KPI cards jump to their section, bot-taxonomy rows
filter the Top-bots list by category, and any bot row (AI, Top bots, Emerging)
expands into its full profile. Workspace / reporting period / trend-view /
category are all dropdowns.

The taxonomy maps directly to Fastly's
[system signals](https://www.fastly.com/documentation/guides/next-gen-waf/signals/using-system-signals/):
`VERIFIED-BOT[.<SUBTYPE>]`, `VERIFIED-BOT.AI-CRAWLER`, `VERIFIED-BOT.AI-FETCHER`,
`SUSPECTED-BOT[.HEADLESS|.AI-CRAWLER|.AI-FETCHER]`, `SUSPECTED-BAD-BOT`,
`SCANNER`, `IMPOSTOR`, `DATACENTER`, `CHALLENGED`. The three top-level verdicts
(`VERIFIED-BOT` / `SUSPECTED-BOT` / `SUSPECTED-BAD-BOT`) are treated as mutually
exclusive; their sum is "identified bots" — an absolute count (no human/share
figure is derived from it).

A **customer-ID field**, a workspace selector, and a reporting-period selector
(24h / 7d / 14d) drive the whole view:

- **Customer ID** — type a Fastly customer id and hit **Load** to discover that
  customer's NGWAF workspaces (scoped by `?customer_id=`). It's remembered across
  reloads.
- **Per-workspace** — pick a single workspace (e.g. Edge Demo / Publishing / eCommerce).
- **All workspaces** — a customer-wide aggregate merging every workspace.

## How it works

```
Browser (public/)  ──HTTP──►  server.js (Express)  ──HTTPS──►  Fastly unified API
   dashboard + charts           /api/* JSON        Fastly-Key   (api.fastly.com/ngwaf/v1)
```

`server.js` calls the Fastly unified API directly over HTTPS (`fastlyApi.js`,
`Fastly-Key` auth). Every call is scoped to a `customer_id`; bot intelligence is
derived from the workspace `requests` endpoint (`/ngwaf/v1/workspaces/{id}/requests`)
using its inline tag/time query syntax, and threat context from `/events`.

| File            | Role                                                                    |
| --------------- | ----------------------------------------------------------------------- |
| `server.js`     | Express server, `.env` loader, 60s response cache, `/api/*`.            |
| `fastlyApi.js`  | Direct client for the Fastly unified API; injects `customer_id`, retries 429/5xx, normalises responses. |
| `bots.js`       | **The core** — bot taxonomy, AI quadrants, verified-by-category, geo/hosts, master bot list, trends, from workspace request tag queries. |
| `analytics.js`  | Attack overview from workspace `events` (powers the "threat signals" bridge).|
| `public/`       | Static frontend (dashboard panels, Chart.js).                           |

The frontend calls `/api/workspaces` to discover workspaces, then `/api/bots` (the
primary data) and secondarily `/api/overview` (threat context) in parallel; bot
panels render as soon as bot data lands. The data endpoints accept
`?customer_id=<id>&workspace=<id|__all__>&window=<24h|7d|14d>`. Windows longer
than 7 days are chunked into ≤7-day queries (the requests API caps each search at
7 days).

## Download (prebuilt macOS binary)

A standalone macOS build is attached to each
[GitHub release](https://github.com/purpleax/ngwaf-bot-analysis/releases) — no Node
install required (Apple Silicon / arm64):

```bash
# download ngwaf-dashboard-macos-arm64 from the Releases page, then:
xattr -d com.apple.quarantine ngwaf-dashboard-macos-arm64   # clear Gatekeeper (ad-hoc signed)
# put a filled-in .env beside it (see .env.example), then:
./ngwaf-dashboard-macos-arm64                                # → opens http://localhost:4000
```

The binary reads a `.env` sitting next to it at runtime; it does **not** embed any token.
See CLAUDE.md for how the binary is built (`npm run build:mac`) and how releases are cut.

## Setup (from source)

```bash
npm install
cp .env.example .env   # then fill in the values
npm start              # → http://localhost:4000
```

### Configuration (`.env`)

| Variable                       | Purpose                                              |
| ------------------------------ | ---------------------------------------------------- |
| `FASTLY_API_TOKEN`             | Fastly API token, sent as `Fastly-Key` (read access is enough). |
| `FASTLY_DEFAULT_CUSTOMER_ID`   | Customer id the UI opens on.                          |
| `FASTLY_DEFAULT_WORKSPACE_ID`  | Optional workspace pre-selected on load.              |
| `FASTLY_API_BASE_URL`          | Optional API base override (default `https://api.fastly.com`). |
| `PORT`                         | Web server port (default 4000).                       |

`.env` is git-ignored. The token needs read visibility into whichever customers
you point the dashboard at.

## Notes & limits

- **Read-only.** The dashboard only reads data; it never creates rules or writes.
- **Request-store retention.** Bot data comes from the workspace `requests`
  endpoint, which only retains recent request history (~14 days on the demo). The
  14d window reflects however far back the store actually goes — this retention,
  not the 7-day query cap, is why longer periods aren't offered.
- **Bot sampling.** Category *totals* and per-bucket *totals* are exact (from the
  response `meta.total`). Per-bot counts, per-path/geo/host distributions, and block-rate
  figures come from a bounded sample per category and are **scaled** back to the
  exact category total; for very high-volume categories treat them as estimates.
  AI crawler/fetcher subtype counts use their exact dedicated totals.
- **Absolute counts, no human/share.** "Identified bots" is the sum of the three
  mutually-exclusive verdicts (`VERIFIED-BOT` + `SUSPECTED-BOT` + `SUSPECTED-BAD-BOT`).
  The dashboard reports absolute counts only — no "human" figure and no "% of
  traffic" bot share, because the requests feed is inspected/logged requests, not
  true CDN edge volume. AI share is expressed as a % of identified bots, not of traffic.
- **Hosting network (not ASN).** The API doesn't expose ASN, so the "hosting
  network" dimension is derived portably from Fastly's native datacenter detection
  plus reverse DNS (Amazon AWS, Google Cloud, …). Residential / ISP IPs without
  either are shown unattributed. No CDN/VCL header injection is required.
- **New-this-window** detection compares against the first half of the window
  (three verdict-parent queries), so it's reliable for named bots; generic
  buckets ("Suspected bot", etc.) are excluded.
- **Activity trend** is built from per-bucket request count queries (exact totals)
  plus the sampled per-category counts.
- **All-workspaces** runs every per-workspace query across the customer's
  workspaces; it's the heaviest view (~30–50s cold, then 60s-cached). A single
  workspace is ~8s cold / instant warm.
- **Bot detection maps** live in `bots.js`: `AI_CATS` (the four AI quadrant
  tags), `OTHER_CATS` (verified/bad/suspected/scanner/impostor/…),
  `VERIFIED_SUBTYPES` (VERIFIED-BOT children → labels), and the user-agent maps
  `AI_BOTS` / `SEARCH_BOTS` / `TOOL_BOTS`. Edit these to add bots, tags, or
  reclassify. Bot queries run with bounded concurrency (`mapPool`).
- **Attack-signal severity map** lives in `analytics.js` (`SIGNALS`) — powers the
  "threat signals carried by bots" panel.
