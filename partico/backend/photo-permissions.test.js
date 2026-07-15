const { test } = require('node:test');
const assert = require('node:assert');
const { sanitizePhotosSync } = require('./photo-permissions');

function photo(overrides) {
  return { id: 'ph_1', userId: 'sam', userName: 'Sam', dataUrl: 'data:orig', timestamp: 1, removalRequest: null, ...overrides };
}

test('the host may add, edit, or delete any photo unrestricted', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam' }), photo({ id: 'ph_2', userId: 'jess' })];
  const incoming = [photo({ id: 'ph_2', userId: 'jess', dataUrl: 'data:edited' })]; // ph_1 deleted, ph_2 edited
  const result = sanitizePhotosSync(existing, incoming, 'jess', true);
  assert.deepStrictEqual(result, incoming);
});

test('a guest can freely edit their own photo', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', dataUrl: 'data:orig' })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', dataUrl: 'data:edited' })];
  const result = sanitizePhotosSync(existing, incoming, 'sam', false);
  assert.strictEqual(result[0].dataUrl, 'data:edited');
});

test('a guest can delete their own photo', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam' })];
  const result = sanitizePhotosSync(existing, [], 'sam', false);
  assert.deepStrictEqual(result, []);
});

test("a guest cannot delete another user's photo by omitting it from the sync", () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam' })];
  const result = sanitizePhotosSync(existing, [], 'maya', false);
  assert.strictEqual(result.length, 1, "sam's photo must survive maya's sync");
  assert.strictEqual(result[0].id, 'ph_1');
});

test("a guest cannot edit another user's photo fields", () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', dataUrl: 'data:orig' })];
  const incoming = [photo({ id: 'ph_1', userId: 'maya', dataUrl: 'data:tampered' })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.strictEqual(result[0].dataUrl, 'data:orig');
  assert.strictEqual(result[0].userId, 'sam');
});

test('a guest can flag a removal request on a photo they do not own', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: null })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: { by: 'maya', reason: 'Wrong moment', note: '' } })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.deepStrictEqual(result[0].removalRequest, { by: 'maya', reason: 'Wrong moment', note: '' });
});

test('a guest cannot forge a removal request under someone else\'s name', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: null })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: { by: 'leo', reason: 'Wrong moment', note: '' } })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.strictEqual(result[0].removalRequest, null);
});

test('a guest cannot overwrite a pending request already raised by someone else', () => {
  const mayaRequest = { by: 'maya', reason: 'Wrong moment', note: '' };
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: mayaRequest })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: { by: 'leo', reason: 'Just prefer it down', note: '' } })];
  const result = sanitizePhotosSync(existing, incoming, 'leo', false);
  assert.deepStrictEqual(result[0].removalRequest, mayaRequest);
});

test('the original requester can retract their own pending request', () => {
  const mayaRequest = { by: 'maya', reason: 'Wrong moment', note: '' };
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: mayaRequest })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: null })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.strictEqual(result[0].removalRequest, null);
});

test('a non-requester cannot clear someone else\'s pending request', () => {
  const mayaRequest = { by: 'maya', reason: 'Wrong moment', note: '' };
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: mayaRequest })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: null })];
  const result = sanitizePhotosSync(existing, incoming, 'leo', false);
  assert.deepStrictEqual(result[0].removalRequest, mayaRequest);
});

test('the photo owner can clear (keep) a pending request on their own photo', () => {
  const mayaRequest = { by: 'maya', reason: 'Wrong moment', note: '' };
  const existing = [photo({ id: 'ph_1', userId: 'sam', removalRequest: mayaRequest })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: null })];
  const result = sanitizePhotosSync(existing, incoming, 'sam', false);
  assert.strictEqual(result[0].removalRequest, null);
});

test('a guest can add a brand-new photo attributed to themselves', () => {
  const incoming = [photo({ id: 'ph_new', userId: 'maya' })];
  const result = sanitizePhotosSync([], incoming, 'maya', false);
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].id, 'ph_new');
});

test('a guest cannot add a new photo impersonating another uploader', () => {
  const incoming = [photo({ id: 'ph_new', userId: 'sam' })];
  const result = sanitizePhotosSync([], incoming, 'maya', false);
  assert.deepStrictEqual(result, []);
});
