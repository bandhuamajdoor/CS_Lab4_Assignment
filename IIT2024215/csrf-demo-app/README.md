# GET-based CSRF Demonstration & Mitigation

**Student Roll Number:** IIT2024215  
**Course:** IT-30001 Web Server Security  
**Lab Assignment:** 4 (Variant: GET-based forged action CSRF)

---

## Overview

This application demonstrates **Cross-Site Request Forgery (CSRF) via a state-changing GET request** on a simulated Campus Wallet, along with its server-side mitigation via a **synchronizer (anti-CSRF) token**.

- **Vulnerable Mode:** A GET to `/transfer?to=...&amount=...` moves money whenever the browser carries the victim's session cookie. No proof of intent is required, so a link on a completely different site can trigger it.
- **Mitigated Mode:** The same GET must carry the per-session `csrf_token` issued only on the victim dashboard. A forged link cannot supply that token, so it is rejected with a 403 and the balance does not change.

One file runs both sides for easy local demo, but they are different origins on purpose:

- Victim app: `http://localhost:3001`
- Attacker page: `http://127.0.0.1:3002`

Only this local demo app is ever touched. Do not point it at any real site or shared infrastructure.

---

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

---

## Installation & Setup

1. Navigate to this directory:
   ```bash
   cd IIT2024215/csrf-demo-app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server (this starts both the victim app and the attacker page):
   ```bash
   node server.js
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:3001
   ```

---

## Demonstration & Testing

### 0. Get logged in first (do this once)

Open `http://localhost:3001`. Visiting the dashboard sets the simulated session cookie (`session_id=IIITA_CSRF_SESSION_2024215`), exactly as a real user would already be logged in. Note the starting balance: **₹10000**.

### 1. Testing the Vulnerability (Vulnerable Mode)

1. Ensure the top badge displays `⚠️ VULNERABLE: NO CSRF TOKEN CHECK`.
2. Open the attacker page in another tab:
   ```
   http://127.0.0.1:3002
   ```
3. Click **Claim ₹5000 Free Credit**.
4. The forged request runs:
   ```
   http://localhost:3001/transfer?to=attacker&amount=5000
   ```
5. Go back to `http://localhost:3001` and check: the balance is now **₹5000**, and the transfer to `attacker` is in the history. You never typed anything on the wallet site — the click on the other site did it, because your browser attached the wallet session cookie automatically.

### 2. Testing the Mitigation (Mitigated Mode)

1. On the wallet dashboard, click **Switch to Mitigated Mode**.
2. The badge updates to `🛡️ MITIGATED: CSRF TOKEN CHECK ON`.
3. Open the attacker page again and click the **same** Claim link.
4. The request is rejected with **403 — CSRF token check failed**, the balance stays where it was, and the attempt appears under **Blocked attempts** on the dashboard.
5. A legitimate transfer still works: use the transfer form on the dashboard itself. In mitigated mode that form carries the hidden `csrf_token`, so it passes the check.

### 3. Resetting the State

- Click **Reset** on the dashboard to restore the balance to ₹10000 and clear the history and blocked-attempt log.

---

## Why the link, not the image tag?

The classic CSRF write-up also shows an `<img>` version of the same forged GET. It is shown on the attacker page as code only, on purpose: modern browsers send the session cookie on a top-level link click (which is why the link version reproduces reliably), while their default `SameSite=Lax` handling blocks the cookie on a cross-site image sub-request. The link version is therefore the honest, reproducible exploit for this demo, and SameSite is discussed as a theory mitigation in the report.

---

## Files

- `server.js` — victim app (port 3001) + attacker page (port 3002), with the vulnerable handler, root cause, and token mitigation marked in comments.
- `package.json` — Express dependency only.
