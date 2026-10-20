# XSS Practice Lab

A small, **deliberately vulnerable** web app for practising **DOM-based** and
**reflected** Cross-Site Scripting (XSS), with an **optional Content-Security-Policy**
you can toggle to see how a policy neutralises the same payloads.

Zero dependencies — it uses only Node's built-in `http` module.

> ⚠️ **Security warning**
> This application contains intentional vulnerabilities for learning purposes
> only. **Do not** deploy it on a public network, a shared host, or anywhere
> reachable from the internet. Run it locally (loopback), in an isolated VM, or
> in a throwaway container.

## Run it

```bash
cd xss-lab
node server.js              # vulnerabilities exposed, CSP OFF (default)
CSP=on node server.js       # start with the Content-Security-Policy enabled
PORT=8080 node server.js    # listen on a different port
```

Then open <http://localhost:3000>. You can also toggle the CSP live from the
header of any page (the choice is stored in a `csp` cookie), so you can compare
behaviour with and without a policy without restarting.

## What's in the lab

| Page | Route | Vulnerability | Sink |
|------|-------|---------------|------|
| Reflected | `/reflected?name=…` | Reflected XSS | Server concatenates `name` into the HTML response |
| Search | `/search?q=…` | Reflected XSS | Server echoes `q` into the results summary |
| DOM-based | `/dom#…` | DOM-based XSS | Client JS writes `location.hash` via `innerHTML` |
| Safe | `/safe?name=…` | *(fixed)* | Same inputs, correctly encoded / handled |

### Starter payloads

```
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

- **Reflected:** `/reflected?name=<script>alert(1)</script>`
- **Search:** `/search?q=<img src=x onerror=alert(1)>`
- **DOM-based:** `/dom#<img src=x onerror=alert(document.domain)>`
  (the payload is in the URL fragment, so it never reaches the server)

## Suggested exercises

1. With **CSP off**, land a working `alert()` on each vulnerable page.
2. Turn **CSP on** and retry the same payloads. Watch the browser console:
   - inline `<script>` and inline event handlers (`onerror`, `onload`) are
     blocked by `script-src 'self'`;
   - think about which payloads could still work (e.g. a same-origin script, a
     dangling-markup / data-exfil trick) and why a CSP is *defence in depth*,
     not a substitute for output encoding.
3. Compare each sink against the **Safe** page to see the corresponding fix.

## The CSP used

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'
```

Notes:

- The DOM page deliberately loads its script from an **external file**
  (`/static/dom.js`) rather than an inline `<script>`, so the page keeps working
  under `script-src 'self'`. What the policy blocks is the **injected** inline
  handler in your payload — which is exactly the point.
- `style-src` allows `'unsafe-inline'` only so the demo styling stays simple; a
  production policy would tighten this too.

## How each bug is fixed (see `/safe`)

- **Reflected:** HTML-encode `& < > " '` before inserting user input into
  markup (`escapeHtml()` in `server.js`).
- **DOM:** use `textContent` / `setAttribute` instead of `innerHTML`; never
  build HTML from untrusted strings (`/static/safe-dom.js`).
- **Defence in depth:** ship a restrictive Content-Security-Policy.

## Files

```
xss-lab/
├── server.js              # zero-dependency HTTP server + all routes
├── package.json
├── README.md
└── (static assets are served inline from server.js:
      /static/style.css, /static/dom.js, /static/safe-dom.js)
```
