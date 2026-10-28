// Shared test helpers for the single-file frontend (partico/Partico-updated.html).
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const HTML_PATH = path.join(__dirname, '..', 'Partico-updated.html');

function readHtml() {
  return fs.readFileSync(HTML_PATH, 'utf8');
}

// Every inline <script> body, with its id (if any) and the line it starts on.
function inlineScripts(html = readHtml()) {
  const out = [];
  const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(html))) {
    const attrs = m[1] || '';
    if (/\ssrc=/.test(attrs)) continue;
    const id = (attrs.match(/\sid="([^"]+)"/) || [])[1] || null;
    const line = html.slice(0, m.index).split('\n').length;
    out.push({ id, line, code: m[2] });
  }
  return out;
}

// Run the pure logic blocks (logic-shared plus the named ones) in a sandbox and return window.PL.
function loadLogic(...ids) {
  const scripts = inlineScripts();
  // The sandbox's global object stands in for the browser's window.
  const sandbox = { Date, Math, JSON, console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  for (const want of ['logic-shared', ...ids]) {
    const s = scripts.find((x) => x.id === want);
    if (!s) throw new Error('No <script id="' + want + '"> in Partico-updated.html');
    vm.runInContext(s.code, sandbox, { filename: want });
  }
  return sandbox.PL;
}

module.exports = { readHtml, inlineScripts, loadLogic, HTML_PATH };
