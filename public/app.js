/*
 * NGWAF Bot Analysis — frontend (vanilla JS, no build step).
 *
 * Data flow:
 *   init() → discover(customerId) → loadWorkspaces() → refresh()
 *   The customer-id field discovers that customer's workspaces (/api/workspaces),
 *   populates the selector, then refresh() fetches /api/bots (primary) then
 *   /api/overview (secondary threat context) with a reqSeq guard so a superseded
 *   workspace/window change is ignored.
 *   state.bots / state.overview hold the last payloads; renderKPIs() + renderDash()
 *   repaint from them.
 *
 * Render model: renderDash() rebuilds #dash.innerHTML from panel*() functions
 *   (each returns an HTML string), then drawCharts() (Chart.js) and
 *   wireInteractions() attach behaviour. Charts are tracked in `charts[]` and
 *   destroyed on every repaint. No framework, no virtual DOM.
 *
 * Panels (top→bottom): Insights, Verdict/Summary, Trend, Taxonomy/Subtypes,
 *   Verified-by-category, AI bots, Emerging bots, Top bots, Traffic
 *   (paths/geo/hosts), Threat context.
 *
 * Interactions: KPI cards scroll to a data-sec section; bot-taxonomy rows filter
 *   the Top-bots list by category; Top-bots has verdict chips + a category
 *   dropdown; the trend has a view dropdown (class / AI); any bot
 *   row (AI, Top bots, New) expands via drillTable()+attachDrill() into
 *   botProfile() (fingerprints, hosting network, methods, paths, example requests).
 *
 * state.botFilter / state.catFilter reset to 'all' on site/window change so a
 * taxonomy-click filter never sticks.
 */
(() => {
  const $ = (s) => document.querySelector(s);
  const fmt = (n) => (n == null ? '—' : Number(n).toLocaleString());
  const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ALL = '__all__';

  const state = { customerId: null, customerName: null, workspace: null, window: '7d', bots: null, overview: null, workspaceNames: {}, workspaceModes: {}, botFilter: 'all', catFilter: 'all', trendView: 'class', exclude: [], reqSeq: 0 };
  const charts = [];
  const wsLabel = (id) => (id && id !== ALL ? state.workspaceNames[id] || id : 'All workspaces');
  const winLabel = (w) => (w === '24h' ? 'last 24h' : w === '14d' ? 'last 14 days' : 'last 7 days');

  const C = { good: '#37d67a', ai: '#4fd1c5', suspicious: '#ffb020', bad: '#ff5c6c', blue: '#4f8cff', verified: '#37d67a' };
  const verdictColor = (v) => C[v] || C.blue;
  const dotFor = (v) => `<span class="sdot" style="background:${verdictColor(v)}"></span>`;
  const verdictChip = (v) => `<span class="verdict ${v}">${v}</span>`;

  // ---- data ---------------------------------------------------------------
  async function getJSON(u) { const r = await fetch(u); if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`); return r.json(); }
  const cq = () => (state.customerId ? `customer_id=${encodeURIComponent(state.customerId)}&` : '');
  const loadWorkspaces = (customerId) => getJSON(`/api/workspaces${customerId ? `?customer_id=${encodeURIComponent(customerId)}` : ''}`);
  // Reasons go out as a repeated param — the values contain commas and colons.
  const excludeQS = () => state.exclude.map((r) => `&exclude=${encodeURIComponent(r)}`).join('');
  const loadBots = () => getJSON(`/api/bots?${cq()}workspace=${encodeURIComponent(state.workspace)}&window=${state.window}${excludeQS()}`);
  const loadOverview = () => getJSON(`/api/overview?${cq()}workspace=${encodeURIComponent(state.workspace)}&window=${state.window}`);
  const setStatus = (m, e) => { const s = $('#statusLine'); s.textContent = m || ''; s.className = 'status' + (e ? ' error' : ''); };

  // ---- shared table drill-down --------------------------------------------
  function drillTable(headers, rows) {
    if (!rows.length) return '<div class="empty">Nothing to show.</div>';
    const body = rows.map((r) => {
      const cells = r.cells.map((c, i) => `<td class="${c.num ? 'num' : ''}" ${r.attr || ''}>${i === 0 ? '<span class="arrow">▸</span> ' : ''}${c.html}</td>`).join('');
      return `<tr class="drill" data-key="${esc(r.key)}" ${r.attr || ''}>${cells}</tr>
        <tr class="drill-body" data-body="${esc(r.key)}" hidden><td colspan="${headers.length}">${r.detail}</td></tr>`;
    }).join('');
    return `<table><thead><tr>${headers.map((h) => `<th class="${h.num ? 'num' : ''}">${esc(h.label)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table>`;
  }
  function attachDrill(root) {
    root.querySelectorAll('tr.drill').forEach((tr) => tr.addEventListener('click', () => {
      const key = tr.dataset.key;
      const row = root.querySelector(`tr[data-body="${CSS.escape(key)}"]`);
      const open = row && row.hidden;
      root.querySelectorAll('tr.drill-body').forEach((b) => { b.hidden = true; });
      root.querySelectorAll('tr.drill').forEach((r) => { r.classList.remove('open'); const a = r.querySelector('.arrow'); if (a) a.textContent = '▸'; });
      if (row) row.hidden = !open;
      tr.classList.toggle('open', open);
      const a = tr.querySelector('.arrow'); if (a) a.textContent = open ? '▾' : '▸';
    }));
  }
  function botExamplesTable(examples, showSite) {
    if (!examples || !examples.length) return '<div class="empty">No example requests captured.</div>';
    const rows = examples.map((e) => `<tr>
      <td class="nowrap">${e.blocked ? '<span class="sev high">blocked</span>' : '<span class="sev low">allowed</span>'}</td>
      <td class="mono">${esc(e.method || '')} ${esc(e.path || '/')}</td>
      <td class="mono">${esc(e.host || '')}</td>
      <td class="mono">${e.ip ? esc(e.ip) : '—'}${e.country ? ` <span class="pill">${esc(e.country)}</span>` : ''}</td>
      ${showSite ? `<td>${esc(wsLabel(e.workspace))}</td>` : ''}
      <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.userAgent)}">${esc(e.userAgent || '')}</td>
      <td class="num">${e.status || '—'}</td></tr>`).join('');
    return `<p class="section-title" style="margin:4px 0 8px">Example requests</p>
      <table class="sub"><thead><tr><th>Action</th><th>Request</th><th>Host</th><th>Source</th>${showSite ? '<th>Site</th>' : ''}<th>User-agent</th><th class="num">Code</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  // Rich per-bot profile (fingerprints, hosting network, paths, methods) + example requests.
  function botProfile(b, showSite) {
    const when = (t) => (t ? new Date(t).toLocaleString() : '—');
    const chips = (arr, mono) => (arr && arr.length ? arr.map((x) => `<span class="pill ${mono ? 'mono' : ''}">${esc(x.key != null ? x.key : x)}${x.count != null ? ` · ${fmt(x.count)}` : ''}</span>`).join(' ') : '—');
    const kv = (k, v) => `<div class="kv"><span class="k">${k}</span><span class="v">${v}</span></div>`;
    const pathRows = barRows((b.paths || []).slice(0, 8), (p) => p.key, (p) => p.count, C.blue, true);
    return `<div class="profile">
      <div class="kvgrid">
        ${kv('First seen', when(b.firstSeen))}
        ${kv('Last seen', when(b.lastSeen))}
        ${kv('Requests', fmt(b.requests))}
        ${kv('Blocked', fmt(b.blocked))}
        ${kv('Source IPs', fmt(b.sourceIPs))}
        ${kv('Countries', chips(b.countries))}
        ${kv('Hosts', chips(b.hosts, true))}
        ${kv('Methods', chips(b.methods))}
        ${kv('Status codes', chips(b.statuses))}
        ${kv('Hosting network', chips(b.networks, true))}
        ${kv('JA3', chips(b.ja3, true))}
        ${kv('JA4', chips(b.ja4, true))}
      </div>
      ${b.userAgents && b.userAgents.length ? `<div class="kv" style="margin-top:8px"><span class="k">User-agent(s)</span><span class="v mono" style="word-break:break-all">${b.userAgents.map((u) => esc(u)).join('<br>')}</span></div>` : ''}
      <div class="panel-row cols-2" style="margin-top:12px">
        <div><p class="section-title">Top paths</p>${pathRows}</div>
        <div>${botExamplesTable(b.examples, showSite)}</div>
      </div>
    </div>`;
  }

  // ---- distribution bar rows (CSS) ----------------------------------------
  function barRows(items, keyFn, valFn, color = C.blue, mono = false) {
    if (!items.length) return '<div class="empty">No data.</div>';
    const max = Math.max(...items.map(valFn), 1);
    return items.map((it) => {
      const v = valFn(it);
      return `<div class="barrow"><span class="lbl ${mono ? 'mono' : ''}" title="${esc(keyFn(it))}">${esc(keyFn(it))}</span>
        <span class="track"><span class="fill" style="width:${Math.max(2, (100 * v) / max)}%;background:${color}"></span></span>
        <span class="val">${fmt(v)}</span></div>`;
    }).join('');
  }

  // ---- KPIs ---------------------------------------------------------------
  // The six headline figures, shared by the on-screen KPI strip and the PDF cover.
  function kpiItems() {
    const t = state.bots?.totals;
    if (!t) return [['Bot data', 'loading…', '']];
    return [
      ['Requests Inspected', fmt(t.totalRequests), 'sec-trend'],
      ['Bot Requests', fmt(t.identifiedBots), 'sec-topbots'],
      ['Verified Bots', fmt(t.verified), 'sec-taxonomy'],
      ['AI Bot Hits', fmt(state.bots.ai.total), 'sec-ai'],
      ['Bad / Scanner / Impostor', fmt(t.badBots), 'sec-topbots'],
      ['Bots Blocked', fmt(t.botsBlocked), 'sec-taxonomy'],
    ];
  }

  function renderKPIs() {
    const items = kpiItems();
    $('#kpis').innerHTML = items.map(([l, v, tgt]) => `<div class="kpi${tgt ? ' clickable' : ''}"${tgt ? ` data-target="${tgt}"` : ''}><div class="v">${v}</div><div class="l">${esc(l)}</div></div>`).join('');
    $('#kpis').querySelectorAll('.kpi.clickable').forEach((k) => k.addEventListener('click', () => {
      const el = document.querySelector(`[data-sec="${k.dataset.target}"]`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
  }

  // ---- panels (return HTML) -----------------------------------------------
  function panelVerdict() {
    return `<div class="card"><h2>Bot classification</h2><div class="chart-wrap short"><canvas id="cVerdict"></canvas></div></div>`;
  }

  function panelSummary() {
    const b = state.bots, t = b.totals;
    const rows = [
      ['Verified good bots', t.verified, 'good'],
      ['AI crawlers &amp; fetchers', b.ai.total, 'good'],
      ['Unverified / suspected', t.suspiciousBots, 'suspicious'],
      ['Bad bots', b.bad.total, 'bad'],
      ['Scanners', b.scanner.total, 'bad'],
      ['Impostor (spoofed)', b.impostor.total, 'bad'],
      ['Datacenter-origin', t.datacenter, 'suspicious'],
    ];
    return `<div class="card"><h2>At a glance</h2><ul class="stat-list">${rows.map(([n, v, vd]) =>
      `<li><span>${dotFor(vd)} ${n}</span><span class="n">${fmt(v)}</span></li>`).join('')}</ul></div>`;
  }

  function panelTrend() {
    const opt = (v, l) => `<option value="${v}" ${state.trendView === v ? 'selected' : ''}>${l}</option>`;
    return `<div class="card" data-sec="sec-trend"><h2>Bot activity over time
      <span style="margin-left:auto"><select id="trendView" class="mini-select">${opt('class', 'By classification')}${opt('ai', 'AI: crawler vs fetcher')}</select></span></h2>
      <div class="chart-wrap"><canvas id="cTrend"></canvas></div></div>`;
  }

  function panelTaxonomy() {
    const c = state.bots.categories;
    const row = (label, cat, vd, catKey) => `<tr class="${catKey ? 'clickrow' : ''}" ${catKey ? `data-cat="${esc(catKey)}"` : ''}>
      <td>${dotFor(vd)} ${label}${catKey ? ' <span class="arrow">›</span>' : ''}</td><td class="num">${fmt(cat.total)}</td>
      <td class="num">${cat.blocked == null ? '—' : fmt(cat.blocked)}</td>
      <td class="num">${cat.blockRatePct == null ? '—' : cat.blockRatePct + '%'}</td>
      <td class="hint" style="text-transform:none">${esc(cat.note || '')}</td></tr>`;
    return `<div class="card" data-sec="sec-taxonomy"><h2>Bot taxonomy <span class="tag">click a category to filter the bot list</span></h2>
      <table><thead><tr><th>Category</th><th class="num">Requests</th><th class="num">Blocked</th><th class="num">Rate</th><th>What it means</th></tr></thead><tbody>
        ${row('Verified bots', c.verified, 'good', 'Verified')}
        ${row('AI crawlers (verified)', c.aiCrawlerV, 'good', 'AI crawler')}
        ${row('AI fetchers (verified)', c.aiFetcherV, 'good', 'AI fetcher')}
        ${row('AI crawlers (unverified)', c.aiCrawlerS, 'suspicious', 'AI crawler')}
        ${row('AI fetchers (unverified)', c.aiFetcherS, 'suspicious', 'AI fetcher')}
        ${row('Bad bots', c.bad, 'bad', 'Bad bot')}
        ${row('Scanners', c.scanner, 'bad', 'Scanner')}
        ${row('Suspected bots', c.suspected, 'suspicious', 'Suspected')}
        ${row('Impostor bots', c.impostor, 'bad', 'Impostor')}
        ${row('Datacenter', c.datacenter, 'suspicious')}
      </tbody></table>
      ${state.bots.totals.headlessSample ? `<p class="hint">${fmt(state.bots.totals.headlessSample)} headless-browser bot request(s) seen in sampling.</p>` : ''}</div>`;
  }

  function panelSubtypes() {
    const subs = state.bots.verified.subtypes;
    return `<div class="card"><h2>Verified-bot categories <span class="tag">what good bots are doing</span></h2>
      ${barRows(subs, (s) => s.label, (s) => s.count, C.good)}
      <p class="hint">AI categories exact; others estimated from a sample.</p></div>`;
  }

  // Top bots within each verified-bot category (Search engine, Monitoring, AI, …).
  function panelVerifiedBreakdown() {
    const groups = state.bots.verified.subtypeBreakdown || [];
    if (!groups.length) return '';
    const blocks = groups.map((g) => {
      const bots = g.bots || [];
      const body = bots.length
        ? barRows(bots, (b) => b.name, (b) => b.requests, g.isAI ? C.ai : C.good)
        : '<div class="empty" style="padding:10px 0">No individual bots identified in the sample.</div>';
      return `<div class="vbreak">
        <div class="vbreak-head">${dotFor(g.isAI ? 'ai' : 'good')}<span class="vbreak-label">${esc(g.label)}</span>
          <span class="vbreak-count">${fmt(g.count)}</span></div>
        ${body}</div>`;
    }).join('');
    return `<div class="card" data-sec="sec-verified-breakdown"><h2>Verified bots by category <span class="tag">top bots in each verified-bot class</span></h2>
      <div class="vbreak-grid">${blocks}</div>
      <p class="hint">Requests are estimated from a bounded sample; AI categories use exact totals. Use the Top-bots list below for full per-bot profiles.</p></div>`;
  }

  // ===== Dedicated AI Bots & Crawlers section =============================
  function panelAISection() {
    const a = state.bots.ai;
    const head = `<div class="section-head ai" data-sec="sec-ai">
      <span class="section-head-bar"></span>
      <div class="section-head-txt"><h2>🧠 AI Bots &amp; Crawlers</h2>
        <p>Who is scraping this site for AI — training crawlers, live fetchers, verified vs unverified, and what they take.</p></div>
      <span class="section-head-stat"><b>${fmt(a.total)}</b> AI requests · ${a.pctOfBots}% of identified bots</span></div>`;
    if (!a.total) {
      return head + '<div class="card"><div class="empty">No AI bot or crawler activity detected in this reporting period.</div></div>';
    }
    return [
      head,
      panelAIInsights(),
      `<div class="panel-row cols-3-wide">${panelAIOverview()}${panelAIMatrix()}${panelAIStats()}</div>`,
      panelAITrend(),
      `<div class="panel-row cols-2">${panelAIOperators()}${panelAIIntent()}</div>`,
      panelAIBots(),
      `<div class="panel-row cols-3">${panelAIPaths()}${panelAIGeo()}${panelAINetworks()}</div>`,
    ].join('');
  }

  function panelAIInsights() {
    const a = state.bots.ai;
    const op = a.operators[0];
    const topBot = a.bots[0];
    const topCountry = a.geo[0];
    const ins = [];
    ins.push(['🧠', `<b>${fmt(a.total)} AI bot requests</b> — ${a.pctOfBots}% of all identified bots. ${fmt(a.crawlerTotal)} are <b>training crawlers</b>, ${fmt(a.fetcherTotal)} are <b>live fetchers</b>.`]);
    if (a.suspectedTotal) ins.push(['⚠️', `<b style="color:var(--high)">${fmt(a.suspectedTotal)} unverified</b> AI requests (${100 - a.verifiedPct}%) couldn't be confirmed against a published operator identity — these may be spoofing a legitimate AI bot.`]);
    else ins.push(['✅', `All ${fmt(a.total)} AI requests were <b>verified</b> against published operator identities — no spoofing detected.`]);
    if (op) ins.push(['🏢', `Most AI traffic comes from <b>${esc(op.operator)}</b> (${fmt(op.requests)} requests across ${op.bots.length} bot${op.bots.length > 1 ? 's' : ''})${a.distinctOperators > 1 ? `, one of ${a.distinctOperators} distinct AI operators` : ''}.`]);
    if (topBot) ins.push(['🤖', `Busiest AI bot: <b>${esc(topBot.name)}</b> (${esc(topBot.operator)}) with ${fmt(topBot.requests)} requests from ${fmt(topBot.sourceIPs)} IP(s).`]);
    ins.push(['🛑', a.blocked ? `<b>${fmt(a.blocked)} AI requests blocked</b> (${a.blockRatePct}% of AI traffic).` : `No AI requests were blocked — all AI traffic was allowed through.`]);
    if (a.compliancePct != null) ins.push(['📄', `<b>${a.compliancePct}%</b> of AI requests targeted <span class="mono">/robots.txt</span> or <span class="mono">/sitemap</span> — a good-citizen signal (well-behaved crawlers check these first).`]);
    if (topCountry) ins.push(['🌍', `Most AI traffic originates from <b>${esc(topCountry.key)}</b> (${fmt(topCountry.count)} requests).`]);
    if (a.newBots.length) ins.push(['🆕', `<b>${a.newBots.length} emerging AI bot(s)</b> (new to the recent half of the reporting period): ${a.newBots.slice(0, 3).map((b) => esc(b.name)).join(', ')}.`]);
    return `<div class="card"><h2>AI analysis &amp; insights</h2><ul class="insights">${ins.map(([ic, txt]) => `<li><span class="ic">${ic}</span><span>${txt}</span></li>`).join('')}</ul></div>`;
  }

  function panelAIOverview() {
    const a = state.bots.ai;
    const vTot = a.verifiedTotal, sTot = a.suspectedTotal, tot = a.total || 1;
    const bar = `<span style="width:${(100 * vTot) / tot}%;background:${C.good}"></span><span style="width:${(100 * sTot) / tot}%;background:${C.suspicious}"></span>`;
    const meter = (label, val, of, color) => `<div class="ai-meter"><div class="ai-meter-top"><span>${label}</span><span class="vv">${of ? pct(val, of) + '%' : fmt(val)}</span></div><div class="ai-meter-track"><span style="width:${of ? pct(val, of) : 0}%;background:${color}"></span></div></div>`;
    return `<div class="card"><h2>AI traffic overview</h2>
      <div class="big"><span class="n">${fmt(a.total)}</span><span class="u">AI requests · ${a.pctOfBots}% of identified bots</span></div>
      <div class="split-bar">${bar}</div>
      <div class="legend"><div class="it"><span class="sw" style="background:${C.good}"></span>Verified <span class="vv">${fmt(vTot)} · ${a.verifiedPct}%</span></div>
        <div class="it"><span class="sw" style="background:${C.suspicious}"></span>Unverified <span class="vv">${fmt(sTot)} · ${100 - a.verifiedPct}%</span></div></div>
      <div style="margin-top:14px">
        ${meter('Blocked', a.blocked, a.total, C.bad)}
        ${a.compliancePct != null ? meter('robots.txt / sitemap compliance', a.compliancePct, 100, C.ai) : ''}
      </div></div>`;
  }

  function panelAIMatrix() {
    const q = state.bots.ai.quadrants;
    const cell = (val, label, vd) => `<div class="ai-cell ${vd}"><div class="ai-cell-v">${fmt(val)}</div><div class="ai-cell-l">${label}</div></div>`;
    return `<div class="card"><h2>Verified × intent matrix <span class="tag">crawler = training · fetcher = live retrieval</span></h2>
      <div class="ai-matrix">
        ${cell(q.crawlerVerified, 'Verified crawler', 'good')}
        ${cell(q.fetcherVerified, 'Verified fetcher', 'good')}
        ${cell(q.crawlerSuspected, 'Unverified crawler', 'suspicious')}
        ${cell(q.fetcherSuspected, 'Unverified fetcher', 'suspicious')}
      </div>
      <p class="hint">Unverified quadrants (amber) are bots claiming an AI identity we couldn't confirm — the highest-risk AI traffic.</p></div>`;
  }

  function panelAIStats() {
    const a = state.bots.ai;
    const rows = [
      ['Training crawlers', a.crawlerTotal, 'ai'],
      ['Live fetchers', a.fetcherTotal, 'ai'],
      ['Verified AI', a.verifiedTotal, 'good'],
      ['Unverified AI', a.suspectedTotal, 'suspicious'],
      ['Blocked', a.blocked, 'bad'],
      ['Distinct AI bots', a.distinctBots, 'good'],
      ['Distinct operators', a.distinctOperators, 'good'],
      ['Emerging bots', a.newBots.length, a.newBots.length ? 'suspicious' : 'good'],
    ];
    return `<div class="card"><h2>AI at a glance</h2><ul class="stat-list">${rows.map(([n, v, vd]) =>
      `<li><span>${dotFor(vd)} ${n}</span><span class="n">${fmt(v)}</span></li>`).join('')}</ul></div>`;
  }

  function panelAITrend() {
    return `<div class="card"><h2>AI activity over time <span class="tag">training crawlers vs live fetchers per bucket (estimated split)</span></h2>
      <div class="chart-wrap"><canvas id="cAITrend"></canvas></div></div>`;
  }

  function panelAIOperators() {
    const ops = state.bots.ai.operators;
    if (!ops.length) return `<div class="card"><h2>AI operators</h2><div class="empty">No operators identified.</div></div>`;
    const rows = ops.map((o) => {
      const vd = o.unverified && !o.verified ? 'suspicious' : 'good';
      const types = [o.crawler ? 'crawler' : null, o.fetcher ? 'fetcher' : null].filter(Boolean).join('/') || '—';
      return `<tr><td>${dotFor(vd)} ${esc(o.operator)}</td>
        <td class="mono" style="white-space:nowrap">${esc(types)}</td>
        <td class="num">${fmt(o.requests)}</td><td class="num">${fmt(o.blocked)}</td>
        <td class="hint" style="text-transform:none;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(o.bots.join(', '))}">${esc(o.bots.join(', '))}</td></tr>`;
    }).join('');
    return `<div class="card"><h2>AI by operator <span class="tag">who is scraping you</span></h2>
      <table><thead><tr><th>Operator</th><th>Intent</th><th class="num">Requests</th><th class="num">Blocked</th><th>Bots</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function panelAIIntent() {
    return `<div class="card"><h2>Crawler vs fetcher <span class="tag">training scrape vs live retrieval</span></h2>
      <div class="chart-wrap short"><canvas id="cAIType"></canvas></div>
      <p class="hint"><b>Crawlers</b> (GPTBot, ClaudeBot, CCBot) bulk-scrape to <b>train</b> models — high volume, index-wide. <b>Fetchers</b> (OAI-SearchBot, ChatGPT-User) retrieve a page <b>live</b> to answer a user's question — lower volume, targeted. Blocking crawlers protects content from training; blocking fetchers can remove you from AI answers.</p></div>`;
  }

  function panelAIBots() {
    const a = state.bots.ai;
    const showSite = state.bots.scope?.type === 'all';
    const rows = a.bots.map((x) => ({
      key: `ai-${x.name}`,
      cells: [
        { html: `${dotFor(x.verified ? 'good' : 'suspicious')} ${esc(x.name)}${x.isNew ? ' <span class="verdict suspicious" style="font-size:9px">new</span>' : ''}` },
        { html: `<span class="pill">${esc(x.operator)}</span>` },
        { html: x.classes.map((c) => `<span class="pill">${esc(c)}</span>`).join(' ') },
        { html: x.verified ? '<span class="verdict good">verified</span>' : '<span class="verdict suspicious">unverified</span>' },
        { html: fmt(x.requests), num: true }, { html: fmt(x.blocked), num: true },
        { html: fmt(x.sourceIPs), num: true },
        { html: `<span class="mono">${esc(x.topPath || '—')}</span>` },
      ],
      detail: botProfile(x, showSite),
    }));
    const headers = [{ label: 'AI bot' }, { label: 'Operator' }, { label: 'Intent' }, { label: 'Status' }, { label: 'Requests', num: true }, { label: 'Blocked', num: true }, { label: 'IPs', num: true }, { label: 'Top path' }];
    return `<div class="card"><h2>Per-bot breakdown <span class="tag">every AI bot seen · click a row for a full forensic profile</span></h2>
      ${drillTable(headers, rows)}
      <div class="chart-wrap short" style="margin-top:14px"><canvas id="cAI"></canvas></div></div>`;
  }

  function panelAIPaths() {
    const a = state.bots.ai;
    return `<div class="card"><h2>What AI bots fetch</h2>
      ${barRows(a.topPaths.slice(0, 10), (p) => p.path, (p) => p.count, C.ai, true)}
      <p class="hint">Top paths pulled by AI bots (sampled). Well-behaved crawlers hit <span class="mono">/robots.txt</span> &amp; <span class="mono">/sitemap.xml</span> first.</p></div>`;
  }

  function panelAIGeo() {
    const a = state.bots.ai;
    return `<div class="card"><h2>AI traffic by country</h2>
      ${barRows(a.geo, (g) => g.key, (g) => g.count, C.blue)}
      <p class="hint">Origin countries for AI bot requests (estimated from samples).</p></div>`;
  }

  function panelAINetworks() {
    const a = state.bots.ai;
    return `<div class="card"><h2>AI source networks</h2>
      ${barRows(a.networks, (n) => n.key, (n) => n.count, C.suspicious, true)}
      <p class="hint">Hosting networks the AI bots originate from (Fastly datacenter detection + reverse DNS) — legitimate AI operators publish their IP ranges.</p></div>`;
  }

  function panelTopBots() {
    const showSite = state.bots.scope?.type === 'all';
    const cats = ['all', ...[...new Set(state.bots.allBots.map((b) => b.category))]];
    if (!cats.includes(state.catFilter)) state.catFilter = 'all';
    const rows = state.bots.allBots
      .filter((b) => (state.botFilter === 'all' || b.verdict === state.botFilter) && (state.catFilter === 'all' || b.category === state.catFilter))
      .map((x) => ({
        key: `tb-${x.category}-${x.name}`,
        cells: [
          { html: `${dotFor(x.verdict)} ${esc(x.name)}${x.isNew ? ' <span class="verdict suspicious" style="font-size:9px">new</span>' : ''}` },
          { html: `<span class="pill">${esc(x.category)}</span>` },
          { html: verdictChip(x.verdict) },
          { html: fmt(x.requests), num: true }, { html: fmt(x.blocked), num: true },
          { html: fmt(x.sourceIPs), num: true },
          { html: `<span class="mono">${esc(x.topPath || '—')}</span>` },
        ],
        detail: botProfile(x, showSite),
      }));
    const headers = [{ label: 'Bot' }, { label: 'Category' }, { label: 'Verdict' }, { label: 'Requests', num: true }, { label: 'Blocked', num: true }, { label: 'IPs', num: true }, { label: 'Top path' }];
    const chip = (f, lbl) => `<button class="fchip ${state.botFilter === f ? 'on' : ''}" data-filter="${f}">${lbl}</button>`;
    const catOpts = cats.map((c) => `<option value="${esc(c)}" ${state.catFilter === c ? 'selected' : ''}>${c === 'all' ? 'All categories' : esc(c)}</option>`).join('');
    return `<div class="card" data-sec="sec-topbots"><h2>Top bots <span class="tag">ranked across all categories · click a row for a full profile</span>
      <span style="margin-left:auto"><select id="catFilter" class="mini-select">${catOpts}</select></span></h2>
      <div class="fchips">${chip('all', 'All')}${chip('good', 'Good')}${chip('suspicious', 'Suspicious')}${chip('bad', 'Bad')}</div>
      <div id="topBotsTable">${drillTable(headers, rows)}</div></div>`;
  }

  function panelNewBots() {
    const nb = state.bots.newBots || [];
    if (!nb.length) return '';
    const showSite = state.bots.scope?.type === 'all';
    const rows = nb.map((x) => ({
      key: `nb-${x.category}-${x.name}`,
      cells: [
        { html: `${dotFor(x.verdict)} ${esc(x.name)}` },
        { html: `<span class="pill">${esc(x.category)}</span>` },
        { html: verdictChip(x.verdict) },
        { html: fmt(x.requests), num: true },
        { html: x.firstSeen ? esc(new Date(x.firstSeen).toLocaleString()) : '—' },
        { html: `<span class="mono">${esc(x.topPath || '—')}</span>` },
      ],
      detail: botProfile(x, showSite),
    }));
    const headers = [{ label: 'Bot' }, { label: 'Category' }, { label: 'Verdict' }, { label: 'Requests', num: true }, { label: 'First seen' }, { label: 'Top path' }];
    return `<div class="card" data-sec="sec-new"><h2>Emerging Bots <span class="tag">bots seen only in the recent half of the reporting period — worth watching · click for a profile</span></h2>
      ${drillTable(headers, rows)}</div>`;
  }

  function panelTraffic() {
    const b = state.bots;
    return `<div class="panel-row cols-3">
      <div class="card"><h2>Top paths hit by bots</h2>${barRows(mergePaths(b), (p) => p.key, (p) => p.count, C.blue, true)}</div>
      <div class="card"><h2>Bot traffic by country</h2>${barRows(b.geo, (g) => g.key, (g) => g.count, C.ai)}</div>
      <div class="card"><h2>Hosts targeted</h2>${barRows(b.hosts, (h) => h.key, (h) => h.count, C.suspicious, true)}</div>
    </div>`;
  }
  // Aggregate a "top paths" list from the category path data we have (AI + bad).
  function mergePaths(b) {
    const m = new Map();
    for (const p of b.ai.topPaths) m.set(p.path, (m.get(p.path) || 0) + p.count);
    for (const grp of [b.bad.bots, b.scanner.bots, b.verified.bots]) for (const x of grp) if (x.topPath) m.set(x.topPath, (m.get(x.topPath) || 0) + x.requests);
    return [...m.entries()].map(([key, count]) => ({ key, count })).sort((a, z) => z.count - a.count).slice(0, 10);
  }

  // Section divider introducing the general (non-AI) bot traffic below.
  function panelGeneralHead() {
    const t = state.bots.totals;
    return `<div class="section-head general" data-sec="sec-general">
      <span class="section-head-bar"></span>
      <div class="section-head-txt"><h2>🌐 General Bot Traffic</h2>
        <p>All automated traffic — verified crawlers, suspected &amp; bad bots, scanners and impostors.</p></div>
      <span class="section-head-stat"><b>${fmt(t.identifiedBots)}</b> bot requests</span></div>`;
  }

  function panelInsights() {
    const b = state.bots, t = b.totals, a = b.ai;
    const top = b.allBots[0];
    const topCountry = b.geo[0];
    const badPct = b.categories.bad.blockRatePct;
    const scanPct = b.categories.scanner.blockRatePct;
    const ins = [];
    ins.push(['🤖', `<b>${fmt(t.identifiedBots)} identified bot requests</b> — the combined verified, suspected and bad-bot traffic seen across ${fmt(t.totalRequests)} inspected requests.`]);
    ins.push(['✅', `<b>${fmt(t.verified)} verified good-bot requests</b> (${pct(t.verified, t.identifiedBots)}% of bots) — legitimate crawlers, monitoring and integrations.`]);
    ins.push(['🧠', `<b>${fmt(a.total)} AI bot hits</b>: ${fmt(a.crawlerTotal)} crawler vs ${fmt(a.fetcherTotal)} fetcher${a.suspectedTotal ? `; <b style="color:var(--high)">${fmt(a.suspectedTotal)} unverified</b> AI bots spoofing identity` : ''}.`]);
    ins.push(['🛑', `<b>${fmt(t.badBots)} malicious/scanner/impostor requests</b>${badPct != null ? ` — bad bots blocked at ${badPct}%${scanPct != null ? `, scanners at ${scanPct}%` : ''}` : ''}.`]);
    if (b.impostor.total) ins.push(['🥸', `<b>${fmt(b.impostor.total)} impostor requests</b> spoofing verified bots (e.g. ${esc(b.impostor.bots[0]?.name || 'fake bot')}).`]);
    if (top) ins.push(['📈', `Busiest bot: <b>${esc(top.name)}</b> (${esc(top.category)}) with ${fmt(top.requests)} requests.`]);
    if (topCountry) ins.push(['🌍', `Most bot traffic originates from <b>${esc(topCountry.key)}</b> (${fmt(topCountry.count)} requests).`]);
    if (t.datacenter) ins.push(['🏢', `<b>${fmt(t.datacenter)} requests</b> originate from datacenter/cloud networks — a strong automation signal.`]);
    return `<div class="card"><h2>Analysis &amp; insights</h2><ul class="insights">${ins.map(([ic, txt]) => `<li><span class="ic">${ic}</span><span>${txt}</span></li>`).join('')}</ul></div>`;
  }

  function panelThreatContext() {
    const o = state.overview;
    if (!o || !o.threats?.length) return '';
    const rows = o.threats.slice(0, 6).map((s) => `<tr>
      <td><span class="sev ${s.severity}">${esc(s.severity)}</span> ${esc(s.label)}</td>
      <td class="num">${fmt(s.requests)}</td><td class="num">${fmt(s.blocked)}</td></tr>`).join('');
    return `<div class="card"><h2>Threat signals carried by bots <span class="tag">attack payloads seen in flagged traffic</span></h2>
      <table><thead><tr><th>Attack signal</th><th class="num">Requests</th><th class="num">Blocked</th></tr></thead><tbody>${rows}</tbody></table>
      <p class="hint">Malicious bots frequently carry these attack payloads. Full attack analysis is available via the NGWAF events API.</p></div>`;
  }

  // ---- charts -------------------------------------------------------------
  const gridColor = 'rgba(140,155,185,.12)', tickColor = '#8a97b1';
  function doughnut(id, labels, data, colors) {
    const ctx = document.getElementById(id); if (!ctx) return;
    charts.push(new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: '#141926', borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'right', labels: { color: tickColor, boxWidth: 12, padding: 10 } } } },
    }));
  }
  function stacked(id, labels, datasets) {
    const ctx = document.getElementById(id); if (!ctx) return;
    charts.push(new Chart(ctx, {
      type: 'bar', data: { labels, datasets: datasets.map((d) => ({ ...d, borderRadius: 4 })) },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: tickColor, boxWidth: 12 } } },
        scales: { x: { stacked: true, grid: { color: gridColor }, ticks: { color: tickColor } }, y: { stacked: true, beginAtZero: true, grid: { color: gridColor }, ticks: { color: tickColor, precision: 0 } } } },
    }));
  }

  function trendDatasets(tr) {
    if (state.trendView === 'ai') {
      return [
        { label: 'AI crawlers', data: tr.ai.map((_, i) => Math.round(tr.ai[i] * ((state.bots.ai.crawlerTotal || 0) / (state.bots.ai.total || 1)))), backgroundColor: C.ai },
        { label: 'AI fetchers', data: tr.ai.map((_, i) => Math.round(tr.ai[i] * ((state.bots.ai.fetcherTotal || 0) / (state.bots.ai.total || 1)))), backgroundColor: '#9b8cff' },
      ];
    }
    return [
      { label: 'Verified', data: tr.verified, backgroundColor: C.good },
      { label: 'AI bots', data: tr.ai, backgroundColor: C.ai },
      { label: 'Suspected', data: tr.suspected, backgroundColor: C.suspicious },
      { label: 'Bad', data: tr.bad, backgroundColor: C.bad },
    ];
  }

  function drawCharts() {
    const b = state.bots;
    const comp = b.totals;
    doughnut('cVerdict', ['Good', 'Suspicious', 'Bad'], [comp.goodBots, comp.suspiciousBots, comp.badBots], [C.good, C.suspicious, C.bad]);
    stacked('cTrend', b.trend.labels, trendDatasets(b.trend));
    // AI-specific charts
    if (b.ai.total) {
      if (document.getElementById('cAIType')) {
        doughnut('cAIType', ['Training crawlers', 'Live fetchers'], [b.ai.crawlerTotal, b.ai.fetcherTotal], [C.ai, '#9b8cff']);
      }
      if (document.getElementById('cAITrend')) {
        const tr = b.trend, cRatio = (b.ai.crawlerTotal || 0) / (b.ai.total || 1), fRatio = (b.ai.fetcherTotal || 0) / (b.ai.total || 1);
        stacked('cAITrend', tr.labels, [
          { label: 'Training crawlers', data: tr.ai.map((v) => Math.round(v * cRatio)), backgroundColor: C.ai },
          { label: 'Live fetchers', data: tr.ai.map((v) => Math.round(v * fRatio)), backgroundColor: '#9b8cff' },
        ]);
      }
    }
    const ab = b.ai.bots;
    if (document.getElementById('cAI')) {
      charts.push(new Chart(document.getElementById('cAI'), {
        type: 'bar',
        data: { labels: ab.map((x) => x.name), datasets: [
          { label: 'Allowed', data: ab.map((x) => x.allowed), backgroundColor: C.good, borderRadius: 4 },
          { label: 'Blocked', data: ab.map((x) => x.blocked), backgroundColor: C.bad, borderRadius: 4 },
        ] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: tickColor, boxWidth: 12 } } },
          scales: { x: { stacked: true, grid: { color: gridColor }, ticks: { color: tickColor } }, y: { stacked: true, beginAtZero: true, grid: { color: gridColor }, ticks: { color: tickColor, precision: 0 } } } },
      }));
    }
  }

  // ---- render -------------------------------------------------------------
  function renderDash() {
    charts.forEach((c) => c.destroy()); charts.length = 0;
    if (!state.bots) { $('#dash').innerHTML = '<div class="skeleton">Loading bot analysis…</div>'; return; }
    $('#dash').innerHTML = [
      // --- general bot traffic first ---
      panelGeneralHead(),
      panelInsights(),
      `<div class="panel-row cols-2">${panelVerdict()}${panelSummary()}</div>`,
      panelTrend(),
      `<div class="panel-row cols-2">${panelTaxonomy()}${panelSubtypes()}</div>`,
      panelVerifiedBreakdown(),
      panelNewBots(),
      panelTopBots(),
      panelTraffic(),
      panelThreatContext(),
      // --- clear break, then the dedicated AI section ---
      panelAISection(),
    ].join('');
    drawCharts();
    attachDrill($('#dash'));
    wireInteractions();
  }

  function rerenderTopBots() {
    const card = [...$('#dash').querySelectorAll('.card')].find((el) => el.querySelector('.fchips'));
    if (!card) return;
    card.outerHTML = panelTopBots();
    attachDrill($('#dash'));
    wireInteractions();
  }

  function wireInteractions() {
    const dash = $('#dash');
    // Top-bots verdict chips
    dash.querySelectorAll('.fchip').forEach((c) => c.addEventListener('click', () => { state.botFilter = c.dataset.filter; rerenderTopBots(); }));
    // Top-bots category dropdown
    const cf = dash.querySelector('#catFilter');
    if (cf) cf.addEventListener('change', (e) => { state.catFilter = e.target.value; rerenderTopBots(); });
    // Trend view dropdown
    const tv = dash.querySelector('#trendView');
    if (tv) tv.addEventListener('change', (e) => {
      state.trendView = e.target.value;
      const idx = charts.findIndex((c) => c.canvas?.id === 'cTrend');
      if (idx >= 0) { charts[idx].destroy(); charts.splice(idx, 1); }
      stacked('cTrend', state.bots.trend.labels, trendDatasets(state.bots.trend));
    });
    // Taxonomy rows → filter the bot list by category
    dash.querySelectorAll('tr.clickrow').forEach((r) => r.addEventListener('click', () => {
      state.catFilter = r.dataset.cat; state.botFilter = 'all';
      rerenderTopBots();
      document.querySelector('[data-sec="sec-topbots"]')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
  }

  // ---- printable report cover (print-only, filled at print time) ----------
  function buildReportCover() {
    const el = $('#reportCover');
    if (!el) return;
    const t = state.bots?.totals;
    const when = new Date().toLocaleString(undefined, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    const meta = [
      ['Prepared for', state.customerName || state.customerId || '—', !state.customerName],
      ['Property / workspace', wsLabel(state.workspace), false],
      ['Reporting period', winLabel(state.window).replace(/^last/, 'Last'), false],
      ['Generated', when, false],
    ];
    // A filtered report must say so on its face, or the numbers can't be trusted.
    if (state.exclude.length) meta.push(['Excluded', state.exclude.join(', '), false]);
    let summary = 'Bot traffic analysis for the selected Fastly Next-Gen WAF property.';
    if (t) {
      const a = state.bots.ai;
      summary = `Over the ${winLabel(state.window)}, this property saw <b>${fmt(t.identifiedBots)} identified bot requests</b> `
        + `across verified, suspected and bad-bot categories, from ${fmt(t.totalRequests)} requests inspected by the Next-Gen WAF. `
        + `This includes <b>${fmt(a.total)} AI bot &amp; crawler hits</b> and <b>${fmt(t.badBots)} malicious, scanner or impostor requests</b>, `
        + `of which ${fmt(t.botsBlocked)} were blocked.`;
      if (state.exclude.length) {
        summary += ` Suspected-bot figures exclude the detection reason${state.exclude.length > 1 ? 's' : ''} `
          + `${state.exclude.map((r) => `<b>${esc(r)}</b>`).join(', ')}, removed from every figure in this report.`;
      }
    }
    const stats = kpiItems().map(([l, v]) => `<div class="rc-stat"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join('');
    el.innerHTML = `
      <div class="rc-top">
        <span class="rc-logo fastly-word">fastly</span>
        <span class="rc-kicker">Next-Gen WAF · Bot Intelligence</span>
      </div>
      <div class="rc-mid">
        <div class="rc-eyebrow">Bot Traffic Report</div>
        <h1 class="rc-title">Bot Traffic Analysis</h1>
        <p class="rc-sub">A snapshot of automated traffic reaching this web property — verified crawlers, AI bots, and malicious or impostor bots — captured from request-level Next-Gen WAF signals.</p>
        <div class="rc-meta">${meta.map(([k, v, mono]) => `<div><span>${esc(k)}</span><b class="${mono ? 'mono' : ''}">${esc(v)}</b></div>`).join('')}</div>
      </div>
      <div class="rc-summary">
        <div class="rc-summary-line">${summary}</div>
        <div class="rc-stats">${stats}</div>
      </div>`;
  }

  // ---- suspected-bot exclusions -------------------------------------------
  // A single noisy detection reason ("Missing header(s)") can dominate the
  // suspected-bot category and skew the whole report. Excluding one re-requests
  // the payload with ?exclude= — the server subtracts that reason's *exact*
  // count, so headline numbers stay exact rather than becoming estimates.
  const LS_EXCLUDE = 'ngwaf.excludeReasons';

  function renderExcludeMenu() {
    const panel = $('#excludePanel'); const sum = $('#excludeSummary');
    if (!panel || !sum) return;
    const reasons = state.bots?.suspected?.reasons || [];
    const n = state.exclude.length;
    sum.textContent = n ? `Exclusions · ${n}` : 'Exclusions';
    sum.classList.toggle('active', n > 0);

    if (!reasons.length) {
      panel.innerHTML = '<div class="menu-empty">No suspected-bot detection reasons in this window.</div>';
      return;
    }
    const rows = reasons.map((r) => {
      const on = state.exclude.includes(r.reason);
      // Values the API cannot filter on (bot names rather than detection
      // reasons) are shown for context but never offered as excludable.
      const dis = r.filterable ? '' : 'disabled';
      const note = r.filterable ? '' : '<span class="menu-note" title="The NGWAF requests API does not honour a signal filter for this value">not filterable</span>';
      return `<label class="menu-row ${dis ? 'is-disabled' : ''}">
          <input type="checkbox" data-reason="${esc(r.reason)}" ${on ? 'checked' : ''} ${dis} />
          <span class="menu-label">${esc(r.reason)}</span>
          ${note}<span class="menu-count">${fmt(r.total)}</span>
        </label>`;
    }).join('');
    panel.innerHTML = `<div class="menu-head">Exclude suspected-bot reasons</div>${rows}
      <div class="menu-foot">
        <button class="btn small" id="excludeClear" ${n ? '' : 'disabled'}>Clear all</button>
        <span class="menu-hint">Applies to every chart, table and the PDF.</span>
      </div>`;

    panel.querySelectorAll('input[data-reason]').forEach((cb) => {
      cb.addEventListener('change', () => {
        const r = cb.getAttribute('data-reason');
        state.exclude = cb.checked ? [...new Set([...state.exclude, r])] : state.exclude.filter((x) => x !== r);
        persistExclusions(); resetFilters(); refresh();
      });
    });
    $('#excludeClear')?.addEventListener('click', () => {
      state.exclude = []; persistExclusions(); resetFilters(); refresh();
    });
  }

  function persistExclusions() {
    try { localStorage.setItem(LS_EXCLUDE, JSON.stringify(state.exclude)); } catch { /* ignore */ }
  }
  function restoreExclusions() {
    try { const v = JSON.parse(localStorage.getItem(LS_EXCLUDE) || '[]'); if (Array.isArray(v)) state.exclude = v.filter((x) => typeof x === 'string'); } catch { /* ignore */ }
  }

  // Short human phrase for the status line, banner and PDF cover.
  const excludeLabel = () => (state.exclude.length ? `excluding ${state.exclude.map((r) => `“${r}”`).join(', ')}` : '');

  // ---- orchestration ------------------------------------------------------
  // Reset the Top-bots filters when the data set changes, so they never
  // "stick" from a previous taxonomy-row click.
  const resetFilters = () => { state.botFilter = 'all'; state.catFilter = 'all'; };

  async function refresh() {
    const seq = (state.reqSeq += 1);
    const stale = () => seq !== state.reqSeq;
    setStatus('Loading bot analysis…');
    state.bots = null; state.overview = null;
    renderKPIs(); renderDash();
    let bots;
    try { bots = await loadBots(); } catch (e) { if (!stale()) setStatus(e.message, true); return; }
    if (stale()) return;
    state.bots = bots;
    // Drop any persisted reason the current window/workspace cannot filter on,
    // so a stale localStorage entry can't silently claim to be filtering.
    const usable = new Set((bots.suspected?.reasons || []).filter((r) => r.filterable).map((r) => r.reason));
    if (state.exclude.some((r) => !usable.has(r))) { state.exclude = state.exclude.filter((r) => usable.has(r)); persistExclusions(); }
    renderKPIs(); renderDash(); renderExcludeMenu();
    setStatus(`Loaded · ${wsLabel(state.workspace)} · ${winLabel(state.window)}${bots.errors?.length ? ` · ${bots.errors.length} source(s) degraded` : ''} · adding threat context…`);
    // Threat context is secondary; fold it in when ready.
    try { const ov = await loadOverview(); if (!stale()) { state.overview = ov; renderDash(); } } catch { /* ignore */ }
    if (stale()) return;
    const ex = excludeLabel();
    setStatus(`Updated ${new Date().toLocaleTimeString()} · ${wsLabel(state.workspace)} · ${winLabel(state.window)}${ex ? ` · ${ex}` : ''}${bots.errors?.length ? ` · ${bots.errors.length} source(s) degraded` : ''}`);
  }

  const LS_KEY = 'ngwaf.customerId';

  // Fill the workspace selector from a /api/workspaces response.
  function populateWorkspaces(s) {
    state.customerId = s.customerId || state.customerId;
    state.customerName = s.customerName || null;
    if (state.customerId) $('#customerInput').value = state.customerId;
    $('#corpLabel').textContent = state.customerId
      ? `Fastly Next-Gen WAF · customer: ${state.customerName || state.customerId} · bot analysis`
      : 'Fastly Next-Gen WAF · bot analysis';
    const cn = $('#customerName');
    cn.textContent = state.customerName || '';
    cn.hidden = !state.customerName;
    state.workspaceNames = {}; state.workspaceModes = {};
    const sel = $('#siteSelect'); sel.innerHTML = '';
    const allOpt = document.createElement('option'); allOpt.value = ALL; allOpt.textContent = `All workspaces (${s.workspaces.length})`; sel.append(allOpt);
    for (const ws of s.workspaces) {
      state.workspaceNames[ws.name] = ws.displayName; state.workspaceModes[ws.name] = ws.mode || 'unknown';
      const o = document.createElement('option'); o.value = ws.name; o.textContent = ws.displayName + (ws.mode ? ` (${ws.mode})` : ''); sel.append(o);
    }
    state.workspace = s.defaultWorkspace || s.workspaces[0]?.name || null;
    sel.value = state.workspace;
  }

  // Discover a customer's workspaces, remember the id, then load the dashboard.
  async function discover(customerId, { andRefresh = true } = {}) {
    setStatus(`Discovering workspaces${customerId ? ` for ${customerId}` : ''}…`);
    $('#customerName').hidden = true; // clear any prior name while resolving
    let s;
    try { s = await loadWorkspaces(customerId); } catch (e) { setStatus(e.message, true); return; }
    populateWorkspaces(s);
    if (state.customerId) { try { localStorage.setItem(LS_KEY, state.customerId); } catch { /* ignore */ } }
    if (!s.workspaces.length) {
      setStatus('No workspaces found for this customer id.', true);
      state.bots = null; state.overview = null; renderKPIs(); renderDash();
      return;
    }
    if (andRefresh) await refresh();
  }

  async function init() {
    $('#windowSelect').addEventListener('change', (e) => { state.window = e.target.value; resetFilters(); refresh(); });
    $('#siteSelect').addEventListener('change', (e) => { state.workspace = e.target.value; resetFilters(); refresh(); });
    $('#refreshBtn').addEventListener('click', refresh);
    $('#printBtn').addEventListener('click', () => window.print());
    // Build the PDF cover, name the file, and re-fit charts for the print layout.
    let savedTitle = document.title;
    window.addEventListener('beforeprint', () => {
      savedTitle = document.title;
      buildReportCover();
      const ws = wsLabel(state.workspace).replace(/[^\w-]+/g, '-').replace(/^-|-$/g, '');
      document.title = `Fastly-Bot-Traffic-Report${ws ? '-' + ws : ''}`;
      charts.forEach((c) => { try { c.resize(); } catch { /* ignore */ } });
    });
    window.addEventListener('afterprint', () => {
      document.title = savedTitle;
      charts.forEach((c) => { try { c.resize(); } catch { /* ignore */ } });
    });
    const doLoad = () => { const v = $('#customerInput').value.trim(); discover(v || null); };
    $('#loadBtn').addEventListener('click', doLoad);
    $('#customerInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doLoad(); } });
    // Show the server build stamp in the footer ("dev" under npm start, or the
    // binary's build date) so a stale packaged build is obvious at a glance.
    getJSON('/api/health').then((h) => { const el = $('#buildStamp'); if (el && h.build) el.textContent = h.build === 'dev' ? 'dev build' : h.build; }).catch(() => {});
    setStatus('Connecting to Fastly…');
    restoreExclusions();
    renderExcludeMenu();
    let persisted = null; try { persisted = localStorage.getItem(LS_KEY); } catch { /* ignore */ }
    await discover(persisted || null);
  }
  init();
})();
