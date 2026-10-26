const express = require('express');
const app = express();
const PORT = 3000;

// Middleware to parse URL-encoded form bodies (from POST requests)
app.use(express.urlencoded({ extended: true }));

// In-memory database storing comments (simulating server-side persistence)
let comments = [
    { author: "Asha", text: "Excited for the upcoming Cultural Council events!", time: "10:15 AM" },
    { author: "Rohan", text: "Does anyone have the schedule for the photography workshop?", time: "10:42 AM" }
];

// Toggle state for live demo & viva (false = Vulnerable, true = Mitigated)
let isMitigated = false;

// ============================================================================
// MITIGATION: Context-Aware Output Encoding (HTML Body Context)
// Converts special characters into safe HTML entities so the browser treats
// untrusted input strictly as text data, never as executable code/tags.
// ============================================================================
function encodeHTML(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

app.get('/', (req, res) => {
    // Set a simulated non-HttpOnly session cookie so the exploit can demonstrate
    // reading cookies & tokens (Session Hijacking impact)
    res.setHeader('Set-Cookie', 'session_id=IIITA_AUTH_TOKEN_987654321; Path=/');

    let commentsHTML = '';

    comments.forEach((c) => {
        if (!isMitigated) {
            // ================================================================
            // (a) VULNERABLE IMPLEMENTATION (Stored XSS)
            // Untrusted input stored on the server is concatenated directly
            // into the HTML response without encoding.
            // ================================================================
            commentsHTML += `
                <div class="comment-card">
                    <div class="comment-meta"><strong>${c.author}</strong> <span>• ${c.time}</span></div>
                    <div class="comment-body">${c.text}</div>
                </div>`;
        } else {
            // ================================================================
            // (d) MITIGATION IMPLEMENTED (Context-Aware Output Encoding)
            // Untrusted input is HTML-entity encoded before being placed
            // into the HTML body context.
            // ================================================================
            commentsHTML += `
                <div class="comment-card">
                    <div class="comment-meta"><strong>${encodeHTML(c.author)}</strong> <span>• ${c.time}</span></div>
                    <div class="comment-body">${encodeHTML(c.text)}</div>
                </div>`;
        }
    });

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>IT-30001 | Stored XSS Demonstration</title>
        <style>
            :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --danger: #ef4444; --safe: #10b981; --accent: #3b82f6; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); max-width: 820px; margin: 0 auto; padding: 2rem; line-height: 1.5; }
            .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 1.5rem; }
            .badge { padding: 0.4rem 0.9rem; border-radius: 9999px; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.5px; }
            .badge-vuln { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--danger); }
            .badge-safe { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--safe); }
            .controls { background: var(--card); padding: 1.25rem; border-radius: 0.5rem; margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: center; justify-content: space-between; border: 1px solid #334155; }
            button { cursor: pointer; padding: 0.6rem 1.1rem; border-radius: 0.375rem; border: none; font-weight: 600; font-size: 0.9rem; transition: opacity 0.15s; }
            button:hover { opacity: 0.9; }
            .btn-toggle { background: var(--accent); color: white; }
            .btn-reset { background: #475569; color: white; }
            .btn-submit { background: var(--safe); color: #064e3b; font-weight: 700; }
            .form-box { background: var(--card); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem; border: 1px solid #334155; }
            input, textarea { width: 100%; padding: 0.75rem; margin-top: 0.4rem; margin-bottom: 1rem; border-radius: 0.375rem; border: 1px solid #475569; background: #0f172a; color: white; box-sizing: border-box; font-family: inherit; }
            .comment-card { background: var(--card); padding: 1.1rem 1.25rem; border-radius: 0.5rem; margin-bottom: 1rem; border-left: 4px solid ${isMitigated ? 'var(--safe)' : 'var(--danger)'}; }
            .comment-meta { font-size: 0.9rem; margin-bottom: 0.4rem; }
            .comment-meta span { color: var(--muted); font-size: 0.8rem; }
            .comment-body { font-family: monospace; font-size: 0.95rem; background: #0f172a; padding: 0.65rem; border-radius: 0.25rem; overflow-x: auto; }
            .payload-helper { background: #1e1b4b; border: 1px solid #4338ca; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; font-size: 0.85rem; }
            code { color: #a5b4fc; font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h2 style="margin:0;">Campus Discussion Board</h2>
                <small style="color: var(--muted);">IT-30001 Web Server Security • Variant 1: Stored (Persistent) XSS</small>
            </div>
            <span class="badge ${isMitigated ? 'badge-safe' : 'badge-vuln'}">
                ${isMitigated ? '🛡️ MITIGATED: OUTPUT ENCODING ON' : '⚠️ VULNERABLE: RAW HTML RENDERING'}
            </span>
        </div>

        <div class="controls">
            <div>
                <strong>Current Mode:</strong> ${isMitigated ? 'Context-Aware HTML Encoding' : 'Unencoded String Concatenation'}
                <div style="font-size: 0.8rem; color: var(--muted);">
                    ${isMitigated ? 'Special characters (<, >, &, ", \\\') are converted to HTML entities.' : 'User input is concatenated directly into the HTML response.'}
                </div>
            </div>
            <div style="display:flex; gap:0.5rem;">
                <form method="POST" action="/toggle" style="margin:0;">
                    <button type="submit" class="btn-toggle">
                        Switch to ${isMitigated ? 'Vulnerable' : 'Mitigated'} Mode
                    </button>
                </form>
                <form method="POST" action="/reset" style="margin:0;">
                    <button type="submit" class="btn-reset">Reset DB</button>
                </form>
            </div>
        </div>

        <div class="payload-helper">
            <strong>Demo Exploit Payload (Copy & Paste into Comment Box):</strong>
            <br><br>
            <strong>Cookie / Session Exposure Demonstration:</strong>
            <br>
            <code>&lt;script&gt;alert("XSS Executed! Stolen Cookie: " + document.cookie)&lt;/script&gt;</code>
        </div>

        <div class="form-box">
            <h3 style="margin-top:0;">Post a Public Comment</h3>
            <form method="POST" action="/comment">
                <label>Your Name</label>
                <input type="text" name="author" placeholder="e.g., Attacker" required />
                <label>Comment</label>
                <textarea name="text" rows="3" placeholder="Enter normal text or an XSS payload..." required></textarea>
                <button type="submit" class="btn-submit">Post Comment to Server</button>
            </form>
        </div>

        <h3>Stored Comments (${comments.length})</h3>
        ${commentsHTML}
    </body>
    </html>
    `);
});

// Endpoint to store a new comment
app.post('/comment', (req, res) => {
    const { author, text } = req.body;
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    // Stored as ordinary content in the server's data store
    comments.push({ author, text, time });
    res.redirect('/');
});

// Endpoint to toggle between Vulnerable and Mitigated modes
app.post('/toggle', (req, res) => {
    isMitigated = !isMitigated;
    res.redirect('/');
});

// Endpoint to clear injected payloads
app.post('/reset', (req, res) => {
    comments = [
        { author: "Asha", text: "Excited for the upcoming Cultural Council events!", time: "10:15 AM" },
        { author: "Rohan", text: "Does anyone have the schedule for the photography workshop?", time: "10:42 AM" }
    ];
    res.redirect('/');
});

app.listen(PORT, () => {
    console.log(`Stored XSS Lab Server running at http://localhost:${PORT}`);
});