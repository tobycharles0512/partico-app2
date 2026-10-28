// Guards the classic Partico failure: one missing ")" in the precompiled JSX
// crashes the whole app to a stuck loading screen. Every inline script must parse.
const test = require('node:test');
const assert = require('node:assert');
const vm = require('vm');
const { inlineScripts, loadLogic } = require('./helpers');

test('every inline <script> parses', () => {
  const scripts = inlineScripts();
  assert.ok(scripts.length > 3, 'expected several inline scripts');
  for (const s of scripts) {
    assert.doesNotThrow(() => new vm.Script(s.code, { filename: 'inline script at line ' + s.line }), 'script at line ' + s.line + (s.id ? ' (#' + s.id + ')' : ''));
  }
});

test('shared partyDate prefers the confirmed date, falls back to the first option', () => {
  const PL = loadLogic();
  assert.strictEqual(PL.partyDate({ confirmedDate: { date: '2026-10-31', time: '20:00' }, dates: [{ date: '2026-11-01' }] }).getDate(), 31);
  assert.strictEqual(PL.partyDate({ dates: [{ date: '2026-11-02', time: '19:30' }] }).getHours(), 19);
  assert.strictEqual(PL.partyDate({ dates: [] }), null);
  assert.strictEqual(PL.partyDate(null), null);
});
