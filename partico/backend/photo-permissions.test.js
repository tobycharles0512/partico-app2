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

// ── Photo reactions: reactions = { [userId]: emoji }, one per user per photo ──

test('a guest can add their own reaction to someone else\'s photo', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam' })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '🔥' } })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.deepStrictEqual(result[0].reactions, { maya: '🔥' });
});

test('a guest can change and clear their own reaction', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '🔥', leo: '😂' } })];
  const changed = sanitizePhotosSync(existing, [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '😍', leo: '😂' } })], 'maya', false);
  assert.deepStrictEqual(changed[0].reactions, { maya: '😍', leo: '😂' });
  const cleared = sanitizePhotosSync(existing, [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })], 'maya', false);
  assert.deepStrictEqual(cleared[0].reactions, { leo: '😂' });
});

test('a guest cannot forge, change or delete another user\'s reaction', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '🙌', jess: '🔥' } })]; // drops leo, forges jess
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.deepStrictEqual(result[0].reactions, { leo: '😂', maya: '🙌' });
});

test('an invalid reaction value is dropped (not one of the four emoji)', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '🔥' } })];
  const result = sanitizePhotosSync(existing, [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: '💩' } })], 'maya', false);
  assert.ok(!result[0].reactions || !('maya' in result[0].reactions), 'invalid emoji must not be stored');
  const objVal = sanitizePhotosSync([photo({ id: 'ph_1', userId: 'sam' })], [photo({ id: 'ph_1', userId: 'sam', reactions: { maya: { x: 1 } } })], 'maya', false);
  assert.ok(!objVal[0].reactions || !('maya' in objVal[0].reactions));
});

test('non-object reactions are ignored but other users\' existing reactions survive', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })];
  for (const bad of [['🔥'], '🔥', 42, null]) {
    const result = sanitizePhotosSync(existing, [photo({ id: 'ph_1', userId: 'sam', reactions: bad })], 'maya', false);
    assert.deepStrictEqual(result[0].reactions, { leo: '😂' });
  }
});

test('the photo owner can react to their own photo but cannot touch others\' reactions', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', dataUrl: 'data:edited', reactions: { sam: '🙌', maya: '🔥' } })];
  const result = sanitizePhotosSync(existing, incoming, 'sam', false);
  assert.strictEqual(result[0].dataUrl, 'data:edited');
  assert.deepStrictEqual(result[0].reactions, { leo: '😂', sam: '🙌' });
});

test('the photo owner editing their photo without reactions keeps others\' reactions', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })];
  const result = sanitizePhotosSync(existing, [photo({ id: 'ph_1', userId: 'sam' })], 'sam', false);
  assert.deepStrictEqual(result[0].reactions, { leo: '😂' });
});

test('a new photo keeps only the uploader\'s own reaction', () => {
  const incoming = [photo({ id: 'ph_new', userId: 'maya', reactions: { maya: '😍', leo: '🔥' } })];
  const result = sanitizePhotosSync([], incoming, 'maya', false);
  assert.deepStrictEqual(result[0].reactions, { maya: '😍' });
});

test('reactions do not interfere with removal-request rules', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam' })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', removalRequest: { by: 'maya', reason: 'x', note: '' }, reactions: { maya: '🔥' } })];
  const result = sanitizePhotosSync(existing, incoming, 'maya', false);
  assert.deepStrictEqual(result[0].removalRequest, { by: 'maya', reason: 'x', note: '' });
  assert.deepStrictEqual(result[0].reactions, { maya: '🔥' });
});

test('the host remains unrestricted for reactions', () => {
  const existing = [photo({ id: 'ph_1', userId: 'sam', reactions: { leo: '😂' } })];
  const incoming = [photo({ id: 'ph_1', userId: 'sam', reactions: { jess: '🔥' } })];
  assert.deepStrictEqual(sanitizePhotosSync(existing, incoming, 'host', true), incoming);
});
