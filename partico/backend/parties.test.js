const { test } = require('node:test');
const assert = require('node:assert');
const { buildStatePartyOr } = require('./parties');

test('buildStatePartyOr always includes the host and public-party conditions', () => {
  const f = buildStatePartyOr('user_1', []);
  assert.ok(f.includes('host_id.eq.user_1'), 'includes own hosted parties');
  assert.ok(f.includes('data->>isPrivate.eq.false'), 'includes parties marked public');
  assert.ok(f.includes('data->>isPrivate.is.null'), 'includes parties with no privacy flag');
  assert.ok(!f.includes('id.in'), 'no invite clause when there are no invites');
});

test('buildStatePartyOr includes invited party ids when present', () => {
  const f = buildStatePartyOr('user_1', ['p_a', 'p_b']);
  assert.ok(f.includes('id.in.(p_a,p_b)'), 'includes invited parties');
  assert.ok(f.includes('host_id.eq.user_1'), 'still includes own hosted parties');
  assert.ok(f.includes('data->>isPrivate.eq.false'), 'still includes public parties');
});

test('a brand-new account (no hosted parties, no invites) still gets the public-event conditions', () => {
  // Regression: new accounts saw an empty Discover feed because /api/state only
  // returned the user's own + invited parties, never other hosts' public events.
  const f = buildStatePartyOr('new_user', []);
  assert.ok(
    f.includes('data->>isPrivate.eq.false') && f.includes('data->>isPrivate.is.null'),
    'public events are fetched even with nothing of the user\'s own'
  );
});

// ── mergeGuestPartySync: a non-host guest's sync may only touch guest-writable fields ──
const { mergeGuestPartySync } = require('./parties');

function storedParty() {
  return {
    title: 'Host title',
    description: 'Host desc',
    dates: ['2026-11-01'],
    confirmedDate: '2026-11-01',
    inviteViews: 9,
    checklist: [{ id: 'c1', text: 'Buy ice', done: false }],
    photos: [{ id: 'ph_1', userId: 'sam', dataUrl: 'data:sam', removalRequest: null }],
    pops: [{ id: 'pop_1', message: 'Hi', timestamp: 1, readBy: ['host'] }],
  };
}

test('mergeGuestPartySync keeps every host-controlled field from the stored party', () => {
  const incoming = {
    id: 'p1', hostId: 'evil', invites: [{ userId: 'x' }],
    title: 'Hacked', description: '', dates: [], confirmedDate: null, inviteViews: 0,
    checklist: [], isPrivate: false, newField: 'x',
    photos: storedParty().photos, pops: storedParty().pops,
  };
  const out = mergeGuestPartySync(storedParty(), incoming, 'maya');
  const s = storedParty();
  assert.strictEqual(out.title, s.title);
  assert.strictEqual(out.description, s.description);
  assert.deepStrictEqual(out.dates, s.dates);
  assert.strictEqual(out.confirmedDate, s.confirmedDate);
  assert.strictEqual(out.inviteViews, 9);
  assert.deepStrictEqual(out.checklist, s.checklist);
  assert.ok(!('isPrivate' in out) && !('newField' in out), 'unknown/host fields are not introduced');
  assert.ok(!('id' in out) && !('hostId' in out) && !('invites' in out));
});

test('mergeGuestPartySync applies the guest\'s own new photo and reaction', () => {
  const incoming = {
    ...storedParty(),
    title: 'stale',
    photos: [
      { id: 'ph_1', userId: 'sam', dataUrl: 'data:sam', removalRequest: null, reactions: { maya: '🔥' } },
      { id: 'ph_2', userId: 'maya', dataUrl: 'data:maya' },
    ],
  };
  const out = mergeGuestPartySync(storedParty(), incoming, 'maya');
  assert.strictEqual(out.title, 'Host title');
  assert.strictEqual(out.photos.length, 2);
  assert.deepStrictEqual(out.photos[0].reactions, { maya: '🔥' });
  assert.strictEqual(out.photos[1].id, 'ph_2');
});

test('mergeGuestPartySync: a stale photos list cannot drop others\' photos', () => {
  const out = mergeGuestPartySync(storedParty(), { photos: [] }, 'maya');
  assert.strictEqual(out.photos.length, 1);
});

test('mergeGuestPartySync: a guest can only add themselves to a pop\'s readBy', () => {
  const incoming = {
    pops: [
      { id: 'pop_1', message: 'EDITED', timestamp: 1, readBy: ['maya', 'leo'] }, // dropped host, added maya + forged leo
      { id: 'pop_new', message: 'guest pop', timestamp: 2, readBy: ['maya'] },     // guest cannot create pops
    ],
  };
  const out = mergeGuestPartySync(storedParty(), incoming, 'maya');
  assert.strictEqual(out.pops.length, 1);
  assert.strictEqual(out.pops[0].message, 'Hi');
  assert.deepStrictEqual(out.pops[0].readBy.sort(), ['host', 'maya']);
});

test('mergeGuestPartySync: omitted or missing pops leave stored pops untouched', () => {
  const out = mergeGuestPartySync(storedParty(), { photos: storedParty().photos }, 'maya');
  assert.deepStrictEqual(out.pops, storedParty().pops);
});

test('mergeGuestPartySync tolerates empty stored data', () => {
  const out = mergeGuestPartySync(null, { title: 'x', photos: [{ id: 'ph_9', userId: 'maya' }] }, 'maya');
  assert.ok(!('title' in out));
  assert.deepStrictEqual(out.photos.map((p) => p.id), ['ph_9']);
});
