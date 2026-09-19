# SECURECODE-X

Professional local-first cybersecurity dashboard for deterministic analysis of AI-generated code.

## GitHub Pages
The `public/` folder is a completely static version. It performs the same deterministic rule checks directly in the browser, so the analyzer works on GitHub Pages without Node.js, a backend, an API key, or an LLM.

For GitHub Pages, publish the contents of `public/` from the repository root (or copy `index.html`, `styles.css`, and `app.js` to the repository root).

## Vercel / Node
The `api/` folder contains the Express API version. `npm install` then `npm start` runs the local server.

## Detection rules
SQL injection, command injection, XSS, hardcoded secrets, weak crypto, unsafe deserialization, and path traversal.

This is a hackathon-ready prototype, not a replacement for a full production SAST engine. Regex-based rules can have false positives; the architecture can later be upgraded with AST/CFG/interprocedural analysis.
