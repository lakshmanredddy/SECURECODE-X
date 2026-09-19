
const code = document.getElementById('code');
const lang = document.getElementById('lang');
const out = document.getElementById('out');
const status = document.getElementById('status');
const lines = document.getElementById('lines');
const exportBtn = document.getElementById('export');

let last = null;

const demos = {
  python: `from flask import request

def login():
    user = request.args.get("user")
    query = "SELECT * FROM users WHERE name = '" + user + "'"
    return db.execute(query)`,
  javascript: `app.get("/search", (req,res) => {
  const userInput = req.query.q;
  res.send("<h1>" + userInput + "</h1>");
});`,
  java: `String user = request.getParameter("user");
String query = "SELECT * FROM users WHERE name='" + user + "'";
Statement stmt = connection.createStatement();
stmt.executeQuery(query);`,
  cpp: `std::string userInput;
std::cin >> userInput;
std::string cmd = "ping " + userInput;
system(cmd.c_str());`,
  html: `<script>
const value = location.search;
document.write(value);
</script>`
};

const rules = [
  {
    id:'SQLI-001', name:'Potential SQL Injection', severity:'Critical', confidence:'High',
    languages:['python','javascript','java','cpp'],
    source: /(request\.|req\.|input\(|params|query|user(name)?\s*=|argv)/i,
    sink: /(execute\s*\(|executemany\s*\(|query\s*\(|createStatement\s*\(|raw\s*\()/i,
    message:'Untrusted input appears to reach a SQL execution sink through string construction.',
    remediation:'Use parameterized queries or prepared statements.'
  },
  {
    id:'CMD-001', name:'Potential Command Injection', severity:'Critical', confidence:'High',
    languages:['python','javascript','java','cpp'],
    source: /(request\.|req\.|input\(|argv|params|user_input|userInput)/i,
    sink: /(os\.system\s*\(|subprocess\.(run|Popen|call)\s*\(|child_process\.(exec|execSync)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()/i,
    message:'Externally controlled data appears to reach a command execution API.',
    remediation:'Avoid shell interpretation; use safe argument arrays and strict allowlists.'
  },
  {
    id:'XSS-001', name:'Potential Cross-Site Scripting', severity:'High', confidence:'Medium',
    languages:['javascript','html'],
    source: /(location\.search|location\.hash|req\.query|req\.params|request\.getParameter|userInput)/i,
    sink: /(innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\()/i,
    message:'User-controlled content appears to reach an HTML sink without visible encoding.',
    remediation:'Prefer textContent or a trusted sanitizer and encode untrusted HTML.'
  },
  {
    id:'SECRET-001', name:'Hardcoded Secret', severity:'High', confidence:'High',
    languages:['python','javascript','java','cpp'],
    pattern: /(api[_-]?key|secret|password|token|access[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/i,
    message:'A credential-like value is hardcoded in source code.',
    remediation:'Move secrets to environment variables or a secret manager and rotate exposed credentials.'
  },
  {
    id:'CRYPTO-001', name:'Weak Cryptography', severity:'Medium', confidence:'High',
    languages:['python','javascript','java','cpp'],
    pattern: /\b(md5|sha1|des|rc4)\b/i,
    message:'A weak or legacy cryptographic primitive was detected.',
    remediation:'Use modern approved cryptographic primitives.'
  },
  {
    id:'DESER-001', name:'Unsafe Deserialization', severity:'High', confidence:'Medium',
    languages:['python','java'],
    pattern: /(pickle\.loads?\s*\(|ObjectInputStream\s*\(|readObject\s*\()/i,
    message:'A deserialization API can be dangerous when input is not fully trusted.',
    remediation:'Avoid deserializing untrusted data; use safe formats and explicit validation.'
  },
  {
    id:'PATH-001', name:'Potential Path Traversal', severity:'High', confidence:'Medium',
    languages:['python','javascript','java'],
    source: /(request\.|req\.|input\(|params|query|filename|fileName)/i,
    sink: /(open\s*\(|readFile\s*\(|writeFile\s*\(|FileInputStream\s*\(|FileOutputStream\s*\()/i,
    message:'Externally influenced path data appears to reach a file operation.',
    remediation:'Normalize paths and enforce an allowlisted base directory.'
  }
];

function lineAt(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}
function lineText(text, line) {
  return (text.split(/\r?\n/)[line - 1] || '').trim();
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}
function analyzeLocal(source, language) {
  const findings = [];
  for (const rule of rules) {
    if (!rule.languages.includes(language)) continue;
    if (rule.pattern) {
      const match = rule.pattern.exec(source);
      if (match) {
        const line = lineAt(source, match.index);
        findings.push({
          id:rule.id,name:rule.name,severity:rule.severity,confidence:rule.confidence,
          message:rule.message, remediation:rule.remediation,
          evidence:[{line,text:lineText(source,line),role:'match'}],
          trace:['matching code construct',`rule ${rule.id}`,'deterministic match']
        });
      }
      continue;
    }
    const sourceMatch = rule.source.exec(source);
    const sinkMatch = rule.sink.exec(source);
    if (sourceMatch && sinkMatch) {
      const sourceLine = lineAt(source, sourceMatch.index);
      const sinkLine = lineAt(source, sinkMatch.index);
      findings.push({
        id:rule.id,name:rule.name,severity:rule.severity,confidence:rule.confidence,
        message:rule.message, remediation:rule.remediation,
        evidence:[
          {line:sourceLine,text:lineText(source,sourceLine),role:'source'},
          {line:sinkLine,text:lineText(source,sinkLine),role:'sink'}
        ],
        trace:[
          `line ${sourceLine}: source-like input`,
          'data-flow candidate',
          `line ${sinkLine}: dangerous sink`,
          'deterministic rule match'
        ]
      });
    }
  }
  return findings;
}
function makeReport(source, language) {
  const findings = analyzeLocal(source, language);
  const counts = {Critical:0,High:0,Medium:0,Low:0};
  findings.forEach(f => counts[f.severity]++);
  return {
    success:true,
    engine:'SECURECODE-X Deterministic Analyzer',
    llmUsed:false,
    externalApiUsed:false,
    localAnalysis:true,
    language,
    analyzedLines:source.split(/\r?\n/).length,
    findings,
    summary:{
      total:findings.length,
      critical:counts.Critical,
      high:counts.High,
      medium:counts.Medium,
      low:counts.Low,
      status:findings.length ? 'Issues detected' : 'No deterministic matches detected'
    },
    analyzedAt:new Date().toISOString()
  };
}
function update() {
  lines.textContent = `${code.value ? code.value.split(/\r?\n/).length : 0} lines`;
}
function render(report) {
  let html = `<div class="summary">
    <div class="sum"><b>${report.summary.total}</b><small>Total</small></div>
    <div class="sum"><b style="color:#ff4e6a">${report.summary.critical}</b><small>Critical</small></div>
    <div class="sum"><b style="color:#ff8b57">${report.summary.high}</b><small>High</small></div>
    <div class="sum"><b style="color:#ffc45d">${report.summary.medium}</b><small>Medium</small></div>
  </div>`;
  if (!report.findings.length) {
    html += `<div class="empty"><strong>No deterministic matches</strong><p>The current rule set found no supported vulnerability pattern.</p></div>`;
  } else {
    report.findings.forEach(f => {
      html += `<article class="finding ${f.severity.toLowerCase()}">
        <div class="finding-head"><h4>${esc(f.name)}</h4><span class="badge">${esc(f.severity)} · ${esc(f.confidence)}</span></div>
        <p>${esc(f.message)}</p>
        ${(f.evidence || []).map(e => `<div class="evidence"><span>LINE ${e.line}</span>${esc(e.text)}</div>`).join('')}
        <div class="trace">${(f.trace || []).map(t => `<span>${esc(t)}</span>`).join('')}</div>
        <div class="remed">↳ ${esc(f.remediation)}</div>
      </article>`;
    });
  }
  out.className = '';
  out.innerHTML = html;
}
function demo() {
  code.value = demos[lang.value] || '';
  update();
  runAnalysis();
}
function runAnalysis() {
  if (!code.value.trim()) return;
  status.textContent = 'Running deterministic rules';
  last = makeReport(code.value, lang.value);
  status.textContent = `${last.summary.total} finding${last.summary.total === 1 ? '' : 's'} · ${last.analyzedLines} lines`;
  exportBtn.disabled = false;
  render(last);
}
document.getElementById('demo').onclick = demo;
document.getElementById('heroDemo').onclick = () => {
  document.getElementById('analyzer').scrollIntoView({behavior:'smooth'});
  setTimeout(demo, 350);
};
document.getElementById('clear').onclick = () => {
  code.value = '';
  last = null;
  exportBtn.disabled = true;
  update();
  out.className = 'empty';
  out.innerHTML = '<strong>Evidence starts here</strong><p>Run an analysis to see findings, severity and source-to-sink evidence.</p>';
  status.textContent = 'Waiting for input';
};
document.getElementById('run').onclick = runAnalysis;
code.oninput = update;
lang.onchange = () => {
  if (!code.value.trim()) demo();
};
exportBtn.onclick = () => {
  if (!last) return;
  const blob = new Blob([JSON.stringify(last,null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `securecode-x-report-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
};
demo();
