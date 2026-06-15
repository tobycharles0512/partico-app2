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
