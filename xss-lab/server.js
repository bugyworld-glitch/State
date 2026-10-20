/*
 * XSS Practice Lab — a DELIBERATELY VULNERABLE web application.
 *
 * ============================= SECURITY WARNING =============================
 * This app contains intentional Cross-Site Scripting (XSS) vulnerabilities for
 * educational use ONLY. Do NOT deploy it on a public network, a shared host, or
 * anywhere reachable from the internet. Run it locally, on a loopback address,
 * inside an isolated VM/container, or on an air-gapped lab machine.
 * ===========================================================================
 *
 * Zero dependencies — uses only Node's built-in `http` module.
 *   node server.js            # vulnerabilities exposed, no CSP (default)
 *   CSP=on node server.js     # start with the Content-Security-Policy enabled
 *   PORT=8080 node server.js   # change the listening port
 *
 * The CSP can also be toggled live from the UI; the choice is stored in a
 * cookie so you can see, side by side, how the same payloads behave with and
 * without a policy in place.
 */

'use strict';

const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT) || 3000;
const CSP_DEFAULT = String(process.env.CSP || '').toLowerCase() === 'on';

// A restrictive policy: no inline scripts, no inline event handlers, no eval.
// This is what actually stops the reflected and DOM payloads below from firing.
const CSP_POLICY = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'";

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

/** Escape text for safe insertion into HTML. Used by the "safe" demos only. */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Read a named cookie from the request header. */
function getCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return undefined;
}

/** Decide whether CSP is on for this request: cookie overrides the env default. */
function cspEnabled(req) {
  const cookie = getCookie(req, 'csp');
  if (cookie === 'on') return true;
  if (cookie === 'off') return false;
  return CSP_DEFAULT;
}

// ---------------------------------------------------------------------------
// Shared HTML layout
// ---------------------------------------------------------------------------

function layout(req, { title, body }) {
  const on = cspEnabled(req);
  const toggleTo = on ? 'off' : 'on';
  const badge = on
    ? '<span class="badge badge-on">CSP: ON</span>'
    : '<span class="badge badge-off">CSP: OFF</span>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · XSS Lab</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header>
    <nav>
      <a href="/" class="brand">XSS&nbsp;Lab</a>
      <a href="/reflected">Reflected</a>
      <a href="/search">Search (reflected)</a>
      <a href="/dom">DOM-based</a>
      <a href="/safe">Safe (fixed)</a>
    </nav>
    <div class="status">
      ${badge}
      <a class="toggle" href="/csp?set=${toggleTo}">Turn CSP ${toggleTo}</a>
    </div>
  </header>
  <main>
    ${body}
  </main>
  <footer>
    <p>⚠️ Deliberately vulnerable — for local practice only. Never expose this to a network.</p>
  </footer>
</body>
</html>`;
}

function send(req, res, status, html, extraHeaders = {}) {
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    // Keep the lab from being embedded in someone else's page.
    'X-Frame-Options': 'DENY',
    ...extraHeaders,
  };
  if (cspEnabled(req)) {
    headers['Content-Security-Policy'] = CSP_POLICY;
  }
  res.writeHead(status, headers);
  res.end(html);
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

function pageHome(req, res) {
  const on = cspEnabled(req);
  const body = `
  <h1>XSS Practice Lab</h1>
  <p>A minimal, intentionally vulnerable app for practising Cross-Site Scripting.
  Each page isolates one classic sink. Toggle the Content-Security-Policy to see
  how a policy neutralises payloads that otherwise fire.</p>

  <p>CSP is currently <strong>${on ? 'ON' : 'OFF'}</strong>.
  ${on
    ? 'Payloads that rely on inline scripts or inline event handlers should be blocked — watch the browser console.'
    : 'Nothing is stopping injected markup from executing.'}</p>

  <section class="cards">
    <article class="card">
      <h2>1 · Reflected XSS</h2>
      <p>A <code>name</code> parameter is written straight into the HTML response.</p>
      <p><a href="/reflected?name=${encodeURIComponent('<script>alert(document.domain)</script>')}">Try a payload →</a></p>
    </article>
    <article class="card">
      <h2>2 · Reflected XSS (search)</h2>
      <p>A search box echoes your query back into the page unescaped.</p>
      <p><a href="/search?q=${encodeURIComponent('<img src=x onerror=alert(1)>')}">Try a payload →</a></p>
    </article>
    <article class="card">
      <h2>3 · DOM-based XSS</h2>
      <p>Client-side JavaScript reads <code>location.hash</code> and drops it into
      the DOM with <code>innerHTML</code> — the payload never touches the server.</p>
      <p><a href="/dom#${encodeURIComponent('<img src=x onerror=alert(document.domain)>')}">Try a payload →</a></p>
    </article>
    <article class="card">
      <h2>4 · Safe version</h2>
      <p>The same inputs, properly escaped / handled, for comparison.</p>
      <p><a href="/safe?name=${encodeURIComponent('<script>alert(1)</script>')}">See it neutralised →</a></p>
    </article>
  </section>

  <h2>How to practise</h2>
  <ol>
    <li>With CSP <strong>off</strong>, land a working alert on each vulnerable page.</li>
    <li>Turn CSP <strong>on</strong> and retry the same payloads — note what the
      browser console reports and which payloads still work.</li>
    <li>Compare each sink with its entry on the <a href="/safe">Safe</a> page to
      see the fix.</li>
  </ol>`;
  send(req, res, 200, layout(req, { title: 'Home', body }));
}

function pageReflected(req, res, url) {
  const name = url.searchParams.get('name');
  // VULNERABLE: user input concatenated directly into the HTML response.
  const greeting = name !== null
    ? `<div class="result">Hello, ${name}!</div>`
    : '<p class="muted">No name supplied yet.</p>';

  const body = `
  <h1>Reflected XSS</h1>
  <p>The <code>name</code> query parameter is inserted into the page without
  any encoding. The sink is a plain string concatenation on the server.</p>

  <form method="get" action="/reflected">
    <label>Your name
      <input type="text" name="name" value="" placeholder="e.g. &lt;script&gt;alert(1)&lt;/script&gt;" autofocus>
    </label>
    <button type="submit">Greet me</button>
  </form>

  ${greeting}

  <details>
    <summary>What's happening</summary>
    <pre><code>// server.js
const greeting = \`&lt;div&gt;Hello, \${name}!&lt;/div&gt;\`;  // input never escaped</code></pre>
    <p>Payload to try: <code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code>
    or, when a script tag is filtered, <code>&lt;img src=x onerror=alert(1)&gt;</code>.</p>
  </details>`;
  send(req, res, 200, layout(req, { title: 'Reflected', body }));
}

function pageSearch(req, res, url) {
  const q = url.searchParams.get('q');
  // VULNERABLE: the query is reflected into the results heading unescaped.
  const results = q !== null
    ? `<div class="result">You searched for: ${q}</div>
       <p class="muted">0 results found.</p>`
    : '';

  const body = `
  <h1>Reflected XSS — search</h1>
  <p>A search page that echoes <code>q</code> back into the results summary.
  This mirrors the single most common reflected-XSS pattern on the web.</p>

  <form method="get" action="/search">
    <label>Search
      <input type="search" name="q" value="" placeholder="try &lt;img src=x onerror=alert(1)&gt;" autofocus>
    </label>
    <button type="submit">Search</button>
  </form>

  ${results}

  <details>
    <summary>What's happening</summary>
    <pre><code>const results = \`You searched for: \${q}\`;  // reflected, not escaped</code></pre>
  </details>`;
  send(req, res, 200, layout(req, { title: 'Search', body }));
}

function pageDom(req, res) {
  // The server sends a static, harmless page. The vulnerability is entirely
  // client-side: the inline script below reads location.hash and writes it
  // into the DOM with innerHTML. The payload lives in the URL fragment, so it
  // is never sent to the server at all.
  const body = `
  <h1>DOM-based XSS</h1>
  <p>Put a payload after the <code>#</code> in the URL. Client-side JavaScript
  reads <code>location.hash</code> and injects it with <code>innerHTML</code>.
  Because it is a fragment, the payload never reaches the server.</p>

  <p>Example:
  <code>/dom#&lt;img src=x onerror=alert(document.domain)&gt;</code></p>

  <label>Or type a fragment and apply it
    <input type="text" id="payload" placeholder="&lt;img src=x onerror=alert(1)&gt;">
  </label>
  <button id="apply" type="button">Apply to #hash</button>

  <h2>Rendered output</h2>
  <div id="output" class="result"><em>Waiting for a hash…</em></div>

  <details>
    <summary>What's happening</summary>
    <pre><code>// loaded from /static/dom.js
const payload = decodeURIComponent(location.hash.slice(1));
document.getElementById('output').innerHTML = payload;  // DOM sink</code></pre>
    <p>With CSP on, <code>&lt;img onerror&gt;</code> is blocked because inline
    event handlers are disallowed. Note that an external script file is used
    here (not an inline <code>&lt;script&gt;</code>) precisely so the page itself
    keeps working under <code>script-src 'self'</code>.</p>
  </details>

  <script src="/static/dom.js"></script>`;
  send(req, res, 200, layout(req, { title: 'DOM-based', body }));
}

function pageSafe(req, res, url) {
  const name = url.searchParams.get('name');
  // SAFE: the same input, HTML-escaped before it reaches the page.
  const greeting = name !== null
    ? `<div class="result">Hello, ${escapeHtml(name)}!</div>`
    : '<p class="muted">No name supplied yet.</p>';

  const body = `
  <h1>Safe version (fixed)</h1>
  <p>Identical inputs to the vulnerable pages, but every value is encoded for
  its context before being inserted. Try the payloads that worked elsewhere —
  here they render as inert text.</p>

  <form method="get" action="/safe">
    <label>Your name
      <input type="text" name="name" value="${escapeHtml(name || '')}" placeholder="try a payload">
    </label>
    <button type="submit">Greet me</button>
  </form>

  ${greeting}

  <h2>The fixes</h2>
  <ul>
    <li><strong>Reflected:</strong> HTML-encode <code>&amp; &lt; &gt; " '</code>
      before inserting into markup (done server-side here).</li>
    <li><strong>DOM:</strong> use <code>textContent</code> / <code>setAttribute</code>
      instead of <code>innerHTML</code>; never build HTML from untrusted strings.</li>
    <li><strong>Defence in depth:</strong> ship a Content-Security-Policy such as
      <code>${escapeHtml(CSP_POLICY)}</code>.</li>
  </ul>

  <h2>Safe DOM demo</h2>
  <p>Fragment is written with <code>textContent</code>, so it can never execute:</p>
  <div id="safe-output" class="result"><em>Waiting for a hash…</em></div>
  <script src="/static/safe-dom.js"></script>`;
  send(req, res, 200, layout(req, { title: 'Safe', body }));
}

function pageCspToggle(req, res, url) {
  const set = url.searchParams.get('set');
  const value = set === 'on' ? 'on' : 'off';
  const body = `<h1>CSP ${value === 'on' ? 'enabled' : 'disabled'}</h1>
  <p>Content-Security-Policy is now <strong>${value.toUpperCase()}</strong> for your session.</p>
  <p><a href="/">← Back to the lab</a></p>`;
  // Set the cookie, then render. We cannot use cspEnabled(req) for the header
  // yet (the cookie isn't on the incoming request), so set it explicitly.
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Frame-Options': 'DENY',
    'Set-Cookie': `csp=${value}; Path=/; SameSite=Lax`,
  };
  if (value === 'on') headers['Content-Security-Policy'] = CSP_POLICY;
  // Render layout as if the new value is active so the badge is correct.
  const fakeReq = { headers: { cookie: `csp=${value}` } };
  res.writeHead(200, headers);
  res.end(layout(fakeReq, { title: 'CSP', body }));
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

const STATIC = {
  '/static/style.css': {
    type: 'text/css; charset=utf-8',
    body: `:root{--bg:#0f1420;--panel:#1a2234;--fg:#e6eaf2;--muted:#8b97b0;--accent:#6ea8fe;--on:#2ecc71;--off:#e74c3c;--border:#2a3550}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:center;padding:.75rem 1.25rem;background:var(--panel);border-bottom:1px solid var(--border)}
nav{display:flex;flex-wrap:wrap;gap:1rem;align-items:center}
nav a{color:var(--fg);text-decoration:none}
nav a:hover{color:var(--accent)}
nav .brand{font-weight:700;color:var(--accent)}
.status{display:flex;gap:.75rem;align-items:center}
.badge{font-size:.8rem;padding:.2rem .55rem;border-radius:999px;font-weight:700}
.badge-on{background:rgba(46,204,113,.15);color:var(--on);border:1px solid var(--on)}
.badge-off{background:rgba(231,76,60,.15);color:var(--off);border:1px solid var(--off)}
.toggle{font-size:.85rem;color:var(--accent);text-decoration:none}
main{max-width:860px;margin:0 auto;padding:1.5rem 1.25rem 3rem}
h1{margin-top:0}
a{color:var(--accent)}
code{background:#0b0f18;border:1px solid var(--border);border-radius:4px;padding:.1rem .35rem;font-size:.9em}
pre{background:#0b0f18;border:1px solid var(--border);border-radius:8px;padding:1rem;overflow:auto}
pre code{border:0;padding:0;background:none}
form{margin:1rem 0;display:flex;gap:.75rem;align-items:flex-end;flex-wrap:wrap}
label{display:flex;flex-direction:column;gap:.35rem;font-size:.9rem;color:var(--muted)}
input{min-width:280px;padding:.55rem .65rem;border-radius:6px;border:1px solid var(--border);background:#0b0f18;color:var(--fg)}
button{padding:.55rem 1rem;border-radius:6px;border:0;background:var(--accent);color:#0b0f18;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.1)}
.result{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem;margin:1rem 0}
.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1rem;margin:1.5rem 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem}
.card h2{margin-top:0;font-size:1.05rem}
details{margin:1rem 0;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.75rem 1rem}
summary{cursor:pointer;font-weight:600}
footer{max-width:860px;margin:0 auto;padding:1rem 1.25rem 2rem;color:var(--muted);font-size:.9rem}
@media(max-width:560px){input{min-width:0;width:100%}}`,
  },
  '/static/dom.js': {
    type: 'application/javascript; charset=utf-8',
    // VULNERABLE DOM sink. Served as an external file (not inline) so it still
    // loads under `script-src 'self'`; the *payload* it injects is what CSP
    // blocks when enabled.
    body: `(function () {
  var out = document.getElementById('output');
  function render() {
    var raw = location.hash.slice(1);
    var payload = raw ? decodeURIComponent(raw) : '';
    if (!payload) {
      out.innerHTML = '<em>Waiting for a hash…</em>';
      return;
    }
    // DOM-based XSS sink: untrusted fragment written as HTML.
    out.innerHTML = payload;
  }
  window.addEventListener('hashchange', render);
  render();
  var apply = document.getElementById('apply');
  if (apply) {
    apply.addEventListener('click', function () {
      var val = document.getElementById('payload').value;
      location.hash = encodeURIComponent(val);
    });
  }
})();`,
  },
  '/static/safe-dom.js': {
    type: 'application/javascript; charset=utf-8',
    body: `(function () {
  var out = document.getElementById('safe-output');
  function render() {
    var raw = location.hash.slice(1);
    var payload = raw ? decodeURIComponent(raw) : '';
    // SAFE: textContent cannot execute markup.
    out.textContent = payload || 'Waiting for a hash…';
  }
  window.addEventListener('hashchange', render);
  render();
})();`,
  },
};

function serveStatic(req, res, pathname) {
  const asset = STATIC[pathname];
  if (!asset) return false;
  const headers = { 'Content-Type': asset.type };
  if (cspEnabled(req)) headers['Content-Security-Policy'] = CSP_POLICY;
  res.writeHead(200, headers);
  res.end(asset.body);
  return true;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    send(req, res, 400, layout(req, { title: 'Bad request', body: '<h1>400</h1>' }));
    return;
  }

  const p = url.pathname;

  if (p.startsWith('/static/')) {
    if (!serveStatic(req, res, p)) {
      send(req, res, 404, layout(req, { title: 'Not found', body: '<h1>404</h1>' }));
    }
    return;
  }

  switch (p) {
    case '/':         return pageHome(req, res);
    case '/reflected': return pageReflected(req, res, url);
    case '/search':   return pageSearch(req, res, url);
    case '/dom':      return pageDom(req, res);
    case '/safe':     return pageSafe(req, res, url);
    case '/csp':      return pageCspToggle(req, res, url);
    default:
      send(req, res, 404, layout(req, {
        title: 'Not found',
        body: '<h1>404 — not found</h1><p><a href="/">Back to the lab</a></p>',
      }));
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ⚠️  XSS Practice Lab — DELIBERATELY VULNERABLE. Local use only.');
  console.log('  ─────────────────────────────────────────────────────────────');
  console.log(`  Listening on   http://localhost:${PORT}`);
  console.log(`  CSP default    ${CSP_DEFAULT ? 'ON' : 'OFF'} (toggle live in the UI)`);
  console.log('');
});
