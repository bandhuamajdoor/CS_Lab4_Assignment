/**
 * GET-based CSRF Demonstration & Mitigation
 * Student: Shivam Mishra (IIT2024215) | IT-30001 Web Server Security | Lab Assignment 4
 * Variant: CSRF — GET-based forged action
 *
 * HOW TO RUN (one command, two sites):
 *   npm install
 *   node server.js
 *   Victim app:   http://localhost:3001
 *   Attacker page: http://127.0.0.1:3002   (a different host on purpose — that is what
 *                                            makes the request cross-site)
 *
 * DEMO FLOW (also the video flow):
 *   1. Open the victim app first — this sets the simulated session cookie,
 *      exactly as a real logged-in user would already be logged in.
 *   2. Open the attacker page and click the "Claim" link.
 *      In VULNERABLE mode the forged GET runs and ₹5000 moves to "attacker".
 *   3. Click "Switch to Mitigated Mode", go back to the attacker page and
 *      click the SAME link. It is now blocked, the balance does not change,
 *      and the blocked attempt is logged on the dashboard.
 *
 * Only your own local demo app is ever touched. Do not point this at any
 * real site, shared infrastructure, or anyone else's account.
 */
const express = require('express');
const crypto = require('crypto');

const VICTIM_PORT = 3001;
const ATTACKER_PORT = 3002;

// ---------------------------------------------------------------------------
// Simulated state (in-memory, like the XSS demo's in-memory comment store)
// ---------------------------------------------------------------------------
const INITIAL_BALANCE = 10000;
let balance = INITIAL_BALANCE;
let transactions = [
    { to: 'campus-store', amount: 500, note: 'Starting demo history (not an attack)' },
];
let blockedAttempts = [];

// Toggle state for live demo & viva (false = Vulnerable, true = Mitigated)
let isMitigated = false;

// The synchronizer token. Issued only on the victim dashboard, never to the
// attacker site. The attacker cannot read it cross-origin, so a forged link
// cannot guess it. It is generated once at server start for this demo.
const csrfToken = crypto.randomBytes(16).toString('hex');
const SESSION_COOKIE = 'session_id=IIITA_CSRF_SESSION_2024215';

// Small HTML escaper, used only for displaying attacker-supplied values
// (names/amounts) safely in the dashboard. It is NOT the CSRF mitigation.
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function victimPage({ message = '', messageClass = '' } = {}) {
    const txRows = transactions.map((t) => `
        <div class="tx"><span>→ ${escapeHtml(t.to)}</span><span>₹${escapeHtml(t.amount)}</span><span class="muted">${escapeHtml(t.note)}</span></div>`).join('');
    const blockedRows = blockedAttempts.length
        ? blockedAttempts.map((b) => `
        <div class="tx blocked"><span>⛔ Blocked: to=${escapeHtml(b.to)}, amount=₹${escapeHtml(b.amount)}</span><span class="muted">${escapeHtml(b.reason)}</span></div>`).join('')
        : '<div class="muted">No blocked attempts yet.</div>';

    // Legitimate transfer form. In mitigated mode it carries the token;
    // in vulnerable mode there is no token field at all — that absence is
    // exactly what the attacker exploits.
    const tokenField = isMitigated
        ? `<input type="hidden" name="csrf_token" value="${csrfToken}" />`
        : '';

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>IT-30001 | GET-based CSRF Demonstration</title>
        <style>
            :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --danger: #ef4444; --safe: #10b981; --accent: #3b82f6; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); max-width: 820px; margin: 0 auto; padding: 2rem; line-height: 1.5; }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 1.5rem; }
            .badge { padding: 0.4rem 0.9rem; border-radius: 9999px; font-weight: 700; font-size: 0.85rem; }
            .badge-vuln { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--danger); }
            .badge-safe { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--safe); }
            .controls { background: var(--card); padding: 1.25rem; border-radius: 0.5rem; margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: center; justify-content: space-between; border: 1px solid #334155; }
            button { cursor: pointer; padding: 0.6rem 1.1rem; border-radius: 0.375rem; border: none; font-weight: 600; font-size: 0.9rem; }
            .btn-toggle { background: var(--accent); color: white; }
            .btn-reset { background: #475569; color: white; }
            .btn-submit { background: var(--safe); color: #064e3b; font-weight: 700; }
            .form-box, .card { background: var(--card); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
            input { width: 100%; padding: 0.75rem; margin-top: 0.4rem; margin-bottom: 1rem; border-radius: 0.375rem; border: 1px solid #475569; background: #0f172a; color: white; box-sizing: border-box; font-family: inherit; }
            .balance { font-size: 2rem; font-weight: 800; margin: 0.25rem 0; }
            .tx { display: flex; gap: 1rem; justify-content: space-between; padding: 0.6rem 0; border-bottom: 1px solid #334155; font-size: 0.9rem; }
            .tx.blocked { color: #fca5a5; }
            .muted { color: var(--muted); font-size: 0.85rem; }
            .msg { padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; font-weight: 600; }
            .msg-ok { background: rgba(16, 185, 129, 0.15); border: 1px solid var(--safe); }
            .msg-bad { background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); }
            code { color: #a5b4fc; font-weight: 600; word-break: break-all; }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h2 style="margin:0;">Campus Wallet — Victim App</h2>
                <small style="color: var(--muted);">IT-30001 Web Server Security • CSRF Variant: GET-based forged action • User: Alice (logged in)</small>
            </div>
            <span class="badge ${isMitigated ? 'badge-safe' : 'badge-vuln'}">
                ${isMitigated ? '🛡️ MITIGATED: CSRF TOKEN CHECK ON' : '⚠️ VULNERABLE: NO CSRF TOKEN CHECK'}
            </span>
        </div>

        ${message ? `<div class="msg ${messageClass}">${message}</div>` : ''}

        <div class="card">
            <div class="muted">Current balance</div>
            <div class="balance">₹${balance}</div>
            <div class="muted">Session cookie set by this app: <code>${SESSION_COOKIE}</code> — the browser sends it automatically with every request to localhost:3001, including a forged one.</div>
        </div>

        <div class="controls">
            <div>
                <strong>Current Mode:</strong> ${isMitigated ? 'Synchronizer token required on /transfer' : 'No proof of intent on /transfer'}
                <div style="font-size: 0.8rem; color: var(--muted);">
                    ${isMitigated ? 'A /transfer request without the correct csrf_token is rejected.' : 'Any GET to /transfer from a logged-in browser is executed.'}
                </div>
            </div>
            <div style="display:flex; gap:0.5rem;">
                <form method="POST" action="/toggle" style="margin:0;"><button type="submit" class="btn-toggle">Switch to ${isMitigated ? 'Vulnerable' : 'Mitigated'} Mode</button></form>
                <form method="POST" action="/reset" style="margin:0;"><button type="submit" class="btn-reset">Reset</button></form>
            </div>
        </div>

        <div class="form-box">
            <h3 style="margin-top:0;">Legitimate transfer (from this dashboard)</h3>
            <form method="GET" action="/transfer">
                ${tokenField}
                <label>To</label>
                <input type="text" name="to" placeholder="e.g., campus-store" required />
                <label>Amount (₹)</label>
                <input type="number" name="amount" min="1" placeholder="e.g., 100" required />
                <button type="submit" class="btn-submit">Send via GET /transfer</button>
            </form>
            <div class="muted">${isMitigated ? 'This form carries the hidden csrf_token, so it passes the check.' : 'This form carries no token — and neither does the attacker link. The server cannot tell them apart.'}</div>
        </div>

        <div class="card">
            <h3 style="margin-top:0;">Transfers</h3>
            ${txRows}
            <h3>Blocked attempts (mitigated mode only)</h3>
            ${blockedRows}
        </div>

        <div class="card">
            <h3 style="margin-top:0;">Attacker link to try (open the attacker page, do not paste this here)</h3>
            <p class="muted">Attacker page: <code>http://127.0.0.1:3002</code> — click its Claim link. The forged request is:</p>
            <code>http://localhost:3001/transfer?to=attacker&amp;amount=5000</code>
        </div>
    </body>
    </html>`;
}

function resultPage(title, body) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" /><title>${title}</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#f8fafc;max-width:720px;margin:2rem auto;padding:2rem;line-height:1.5} a{color:#93c5fd} .card{background:#1e293b;padding:1.5rem;border-radius:.5rem;border:1px solid #334155}</style>
    </head><body><div class="card"><h2>${title}</h2>${body}<p><a href="http://localhost:3001/">← Back to Campus Wallet</a></p></div></body></html>`;
}

// ---------------------------------------------------------------------------
// VICTIM APP (localhost:3001)
// ---------------------------------------------------------------------------
const victim = express();
victim.use(express.urlencoded({ extended: true }));

victim.get('/', (req, res) => {
    // Simulated login: visiting the dashboard sets the session cookie.
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}; Path=/`);
    res.send(victimPage());
});

// ===========================================================================
// (a) VULNERABLE IMPLEMENTATION — GET-based forged action
// This handler changes state (money moves) on a plain GET and checks only
// that a session cookie is present. It never asks: did the user intend
// THIS request, from THIS site? A browser sends the cookie automatically,
// so a link on any other site can trigger it.
// ===========================================================================
victim.get('/transfer', (req, res) => {
    const cookie = req.headers.cookie || '';
    if (!cookie.includes('session_id=')) {
        return res.status(401).send(resultPage('Not logged in',
            '<p>Visit <a href="http://localhost:3001/">the dashboard</a> first so the session cookie is set, then try the attacker link again.</p>'));
    }

    const to = String(req.query.to || '').trim();
    const amount = parseInt(req.query.amount, 10);
    if (!to || !Number.isFinite(amount) || amount <= 0) {
        return res.status(400).send(resultPage('Bad transfer',
            '<p>Missing or invalid <code>to</code> / <code>amount</code>.</p>'));
    }

    // =======================================================================
    // (d) MITIGATION IMPLEMENTED — Synchronizer (anti-CSRF) token
    // In mitigated mode the same GET must carry the per-session token that
    // only the victim dashboard knows. The attacker page never sees it
    // (cross-origin pages cannot read the victim dashboard), so a forged
    // link cannot supply it and is rejected before any money moves.
    // =======================================================================
    if (isMitigated && req.query.csrf_token !== csrfToken) {
        blockedAttempts.push({ to, amount, reason: 'Missing or invalid csrf_token' });
        return res.status(403).send(resultPage('⛔ Blocked — CSRF token check failed',
            `<p>The forged request <code>/transfer?to=${escapeHtml(to)}&amp;amount=${escapeHtml(amount)}</code> carried no valid token, so it was rejected.</p><p>Balance unchanged: <strong>₹${balance}</strong>.</p>`));
    }

    // (c) ROOT CAUSE, in one line: state changes on a GET with no proof of
    // intent, so the browser's automatic cookie turns a foreign link into
    // an authenticated action. Everything below this line is the effect.
    balance -= amount;
    transactions.push({ to, amount, note: isMitigated ? 'Legitimate (token verified)' : 'Executed — no token was required' });
    res.send(resultPage('Transfer complete',
        `<p>₹${escapeHtml(amount)} sent to <strong>${escapeHtml(to)}</strong>.</p><p>New balance: <strong>₹${balance}</strong>.</p>`));
});

victim.post('/toggle', (req, res) => {
    isMitigated = !isMitigated;
    res.redirect('/');
});

victim.post('/reset', (req, res) => {
    balance = INITIAL_BALANCE;
    transactions = [{ to: 'campus-store', amount: 500, note: 'Starting demo history (not an attack)' }];
    blockedAttempts = [];
    res.redirect('/');
});

// ---------------------------------------------------------------------------
// ATTACKER APP (127.0.0.1:3002) — a different host, therefore cross-site.
// It contains no victim code and no token. It only offers a tempting link.
// The browser, not the attacker server, does the damage: clicking the link
// makes a top-level GET to the victim app, and the browser attaches the
// victim session cookie automatically.
// ---------------------------------------------------------------------------
const attacker = express();
attacker.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8" /><title>Free Campus Credit — Claim Now!</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#fff7ed;color:#431407;max-width:720px;margin:2rem auto;padding:2rem;line-height:1.5;text-align:center} a.btn{display:inline-block;background:#ea580c;color:white;padding:1rem 2rem;border-radius:.5rem;font-weight:800;text-decoration:none;font-size:1.1rem} code{background:#ffedd5;padding:.2rem .4rem;border-radius:.25rem;word-break:break-all} .note{margin-top:2rem;text-align:left;background:#fef3c7;border:1px solid #f59e0b;padding:1rem;border-radius:.5rem;font-size:.9rem}</style>
    </head>
    <body>
        <h1>🎉 You won FREE campus credit!</h1>
        <p>Click below to claim your reward instantly. No login needed here —<br/>that is the point. Your browser is already logged in over on the wallet site.</p>
        <p><a class="btn" href="http://localhost:3001/transfer?to=attacker&amount=5000">Claim ₹5000 Free Credit →</a></p>
        <p style="color:#9a3412;">This page lives at <code>127.0.0.1:3002</code>. The link points at <code>localhost:3001</code>.</p>
        <div class="note">
            <strong>For the demo / viva — what this link actually is:</strong><br/>
            <code>&lt;a href="http://localhost:3001/transfer?to=attacker&amp;amount=5000"&gt;Claim ₹5000 Free Credit&lt;/a&gt;</code><br/><br/>
            The same forged action written as an image tag would be<br/>
            <code>&lt;img src="http://localhost:3001/transfer?to=attacker&amp;amount=5000" /&gt;</code><br/>
            That image form is shown here as code only, on purpose: modern browsers send the session cookie on a top-level link click (which is why the link reliably works), while their default SameSite=Lax handling blocks it on a cross-site image sub-request. The link version is therefore the honest, reproducible exploit for this demo, and SameSite is covered as a theory mitigation in the report.
        </div>
        <p><a href="http://localhost:3001/">Back to Campus Wallet (to check your balance)</a></p>
    </body>
    </html>`);
});

victim.listen(VICTIM_PORT, () => {
    console.log(`Campus Wallet (victim) running at http://localhost:${VICTIM_PORT}`);
    console.log(`Attacker page running at http://127.0.0.1:${ATTACKER_PORT}`);
});
attacker.listen(ATTACKER_PORT, () => {
    console.log(`Attacker page listening on port ${ATTACKER_PORT}`);
});
