const { test } = require('node:test');
const assert = require('node:assert');
const {
  validateMessageText,
  buildMessage,
  appendMessage,
  buildMessageNotif,
} = require('./messages');

test('validateMessageText rejects empty and whitespace', () => {
  assert.strictEqual(validateMessageText(''), false);
  assert.strictEqual(validateMessageText('   '), false);
  assert.strictEqual(validateMessageText(null), false);
  assert.strictEqual(validateMessageText(undefined), false);
  assert.strictEqual(validateMessageText('hi'), true);
});

test('buildMessage trims text and stamps sender into readBy', () => {
  const msg = buildMessage({ from: 'user_a', text: '  hello  ' });
  assert.strictEqual(msg.from, 'user_a');
  assert.strictEqual(msg.text, 'hello');
  assert.deepStrictEqual(msg.readBy, ['user_a']);
  assert.ok(typeof msg.id === 'string' && msg.id.length > 0);
  assert.ok(typeof msg.timestamp === 'number');
});

test('appendMessage appends without mutating the original thread', () => {
  const original = [{ id: '1', from: 'x', text: 'a', timestamp: 1, readBy: ['x'] }];
  const msg = buildMessage({ from: 'y', text: 'b' });
  const next = appendMessage(original, msg);
  assert.strictEqual(next.length, 2);
  assert.strictEqual(original.length, 1, 'original thread must not be mutated');
  assert.strictEqual(next[1].text, 'b');
});

test('appendMessage treats undefined/null thread as empty', () => {
  const msg = buildMessage({ from: 'y', text: 'b' });
  assert.strictEqual(appendMessage(undefined, msg).length, 1);
  assert.strictEqual(appendMessage(null, msg).length, 1);
});

test('buildMessageNotif produces a message notif with a trimmed preview', () => {
  const longText = 'x'.repeat(100);
  const notif = buildMessageNotif({
    partyId: 'party_1',
    guestId: 'guest_1',
    from: 'host_1',
    text: longText,
  });
  assert.strictEqual(notif.type, 'message');
  assert.strictEqual(notif.partyId, 'party_1');
  assert.strictEqual(notif.guestId, 'guest_1');
  assert.strictEqual(notif.from, 'host_1');
  assert.strictEqual(notif.read, false);
  assert.ok(notif.preview.length <= 60);
  assert.ok(typeof notif.id === 'string' && notif.id.length > 0);
  assert.ok(typeof notif.timestamp === 'number');
});
