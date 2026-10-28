// Pure logic behind the redesigned Friends screen (PL.friends in <script id="logic-friends">).
const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-friends');
// PL runs in a vm sandbox, so its arrays have another realm's prototype; compare plain copies.
const plain = (a) => Array.from(a || []);

const inv = (userId, status) => ({ userId, status });
const party = (id, hostId, invites, extra) => Object.assign({ id, title: id, hostId, invites, status: 'upcoming', dates: [] }, extra || {});

test('partiesTogether counts parties where both of you were host or accepted guest', () => {
  const parties = [
    party('a', 'me', [inv('sam', 'accepted')], { dates: [{ date: '2026-01-01' }] }),
    party('b', 'sam', [inv('me', 'accepted')], { dates: [{ date: '2026-03-01' }] }),
    party('c', 'zoe', [inv('me', 'accepted'), inv('sam', 'accepted')], { dates: [{ date: '2026-02-01' }] }),
    party('d', 'me', [inv('sam', 'pending')]),
    party('e', 'zoe', [inv('me', 'declined'), inv('sam', 'accepted')]),
    party('f', 'zoe', [inv('me', 'accepted')]),
  ];
  const got = PL.friends.partiesTogether(parties, 'me', 'sam');
  assert.deepStrictEqual(plain(got).map((p) => p.id), ['b', 'c', 'a'], 'most recent first');
});

test('partiesTogether tolerates missing data', () => {
  assert.deepStrictEqual(plain(PL.friends.partiesTogether(null, 'me', 'sam')), []);
  assert.deepStrictEqual(plain(PL.friends.partiesTogether([party('x', 'me', null), null], 'me', 'sam')), []);
  assert.deepStrictEqual(plain(PL.friends.partiesTogether([party('x', 'me', [])], 'me', 'me')), []);
});

test('filterByName matches first, last or full name, ignoring case and accents', () => {
  const users = [
    { id: 1, firstName: 'Zoë', lastName: 'Martín' },
    { id: 2, firstName: 'Sam', lastName: 'Jones' },
    { id: 3, firstName: 'samira', lastName: '' },
    { id: 4 },
  ];
  const ids = (q) => plain(PL.friends.filterByName(users, q)).map((u) => u.id);
  assert.deepStrictEqual(ids('zoe'), [1]);
  assert.deepStrictEqual(ids('MARTIN'), [1]);
  assert.deepStrictEqual(ids('zoe mar'), [1]);
  assert.deepStrictEqual(ids('sam'), [2, 3]);
  assert.deepStrictEqual(ids('jones'), [2]);
  assert.deepStrictEqual(ids('  '), [1, 2, 3, 4], 'blank query keeps everyone');
  assert.deepStrictEqual(ids(''), [1, 2, 3, 4]);
  assert.deepStrictEqual(ids('nobody'), []);
  assert.deepStrictEqual(plain(PL.friends.filterByName(null, 'x')), []);
});

test('hostableParties lists my upcoming hosted parties the friend is not invited to', () => {
  const now = new Date('2026-10-28T12:00:00');
  const parties = [
    party('later', 'me', [], { dates: [{ date: '2026-12-01', time: '20:00' }] }),
    party('soon', 'me', [inv('zoe', 'accepted')], { confirmedDate: { date: '2026-11-01', time: '19:00' } }),
    party('tbd', 'me', []),
    party('already', 'me', [inv('sam', 'pending')], { dates: [{ date: '2026-11-05' }] }),
    party('gone', 'me', [], { dates: [{ date: '2026-10-01' }] }),
    party('pastStatus', 'me', [], { status: 'past', dates: [{ date: '2026-12-10' }] }),
    party('notMine', 'zoe', [], { dates: [{ date: '2026-11-20' }] }),
  ];
  const got = plain(PL.friends.hostableParties(parties, 'me', 'sam', now)).map((p) => p.id);
  assert.deepStrictEqual(got, ['soon', 'later', 'tbd'], 'soonest first, undated last');
  assert.deepStrictEqual(plain(PL.friends.hostableParties(parties, 'me', 'sam', now.getTime())).map((p) => p.id), got, 'accepts a timestamp');
  assert.deepStrictEqual(plain(PL.friends.hostableParties(null, 'me', 'sam', now)), []);
});
