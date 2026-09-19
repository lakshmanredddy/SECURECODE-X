# SECURECODE-X

Professional local-first cybersecurity dashboard for deterministic analysis of AI-generated code.

## Run
Node.js 18+ required.

```bash
npm install
npm start
```
Open http://localhost:3000

## Included
- Dark blue/cyan professional UI
- Python, JavaScript, Java, C/C++, HTML
- Deterministic vulnerability rules
- SQL injection, command injection, XSS, hardcoded secrets, weak crypto, unsafe deserialization, path traversal
- Evidence lines and source-to-sink style traces
- Severity/confidence
- Demo snippets
- JSON report export

This is a hackathon-ready prototype, not a replacement for a full production SAST engine. Regex-based rules can have false positives; the architecture is ready for AST/CFG/interprocedural analyzers later.
