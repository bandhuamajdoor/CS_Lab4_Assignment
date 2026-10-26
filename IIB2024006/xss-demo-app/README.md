# Stored XSS Demonstration & Mitigation

**Student Roll Number:** IIB2024006  
**Course:** IT-30001 Web Server Security  
**Lab Assignment:** 4 (Variant 1: Stored XSS)

---

## Overview

This application demonstrates **Stored (Persistent) Cross-Site Scripting (XSS)** on a simulated Campus Discussion Board, along with its server-side mitigation via **Context-Aware Output Encoding (HTML Body Context)**.

- **Vulnerable Mode:** User-submitted comments are stored in the server's data store and concatenated directly into the HTML response without sanitization or encoding.
- **Mitigated Mode:** Special characters (`<`, `>`, `&`, `"`, `'`) are converted to their corresponding safe HTML entities before being injected into the HTML document body, neutralizing script execution.

---

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

---

## Installation & Setup

1. Navigate to this directory:
   ```bash
   cd IIB2024006/xss-demo-app
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   node server.js
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

---

## Demonstration & Testing

### 1. Testing the Vulnerability (Vulnerable Mode)
1. Ensure the top badge displays `⚠️ VULNERABLE: RAW HTML RENDERING`.
2. In the "Post a Public Comment" form, enter:
   - **Name:** `Attacker`
   - **Comment:** 
     ```html
     <script>alert("XSS Executed! Stolen Cookie: " + document.cookie)</script>
     ```
3. Click **Post Comment to Server**.
4. The injected JavaScript executes in the browser, showing the alert dialog containing the simulated session cookie (`session_id=IIITA_AUTH_TOKEN_987654321`), demonstrating potential session hijacking.

### 2. Testing the Mitigation (Mitigated Mode)
1. Click **Switch to Mitigated Mode** at the top controls.
2. The badge updates to `🛡️ MITIGATED: OUTPUT ENCODING ON`.
3. Post the same script payload or reload the page:
   ```html
   <script>alert("XSS Executed! Stolen Cookie: " + document.cookie)</script>
   ```
4. The payload is rendered purely as plain text (`&lt;script&gt;...&lt;/script&gt;`), preventing execution.

### 3. Resetting the State
- Click **Reset DB** to restore the comments list to its initial clean state.
