// Pure logic behind the home Memories section (pin board, recap, polaroids, albums, reactions).
const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-memories');
const M = PL.memories;

// Values built inside the vm sandbox have foreign prototypes, so compare plain copies.
const plain = (x) => JSON.parse(JSON.stringify(x));
const DAY = 86400000;
const NOW = new Date('2026-10-28T12:00:00').getTime();
const iso = (daysAgo) => new Date(NOW - daysAgo * DAY).toISOString().slice(0, 10);
const ph = (id, ts, extra) => Object.assign({ id, userId: 'u2', userName: 'Sam Lee', dataUrl: 'data:' + id, timestamp: ts }, extra || {});
const party = (id, daysAgo, opts) => Object.assign({
  id, title: 'Party ' + id, hostId: 'h', invites: [], photos: [],
  confirmedDate: daysAgo == null ? null : { date: iso(daysAgo), time: '20:00' }, dates: []
}, opts || {});
const going = (uid) => ({ userId: uid, status: 'accepted' });

test('toggleReaction sets, switches and clears only my reaction, without mutating', () => {
  const p0 = ph('a', 1, { reactions: { u9: '😂' } });
  const p1 = M.toggleReaction(p0, 'me', '🔥');
  assert.deepStrictEqual(plain(p1.reactions), { u9: '😂', me: '🔥' });
  assert.deepStrictEqual(plain(p0.reactions), { u9: '😂' }, 'original untouched');
  assert.strictEqual(p1.id, 'a');
  assert.strictEqual(p1.dataUrl, 'data:a');
  const p2 = M.toggleReaction(p1, 'me', '😍');
  assert.deepStrictEqual(plain(p2.reactions), { u9: '😂', me: '😍' });
  const p3 = M.toggleReaction(p2, 'me', '😍');
  assert.deepStrictEqual(plain(p3.reactions), { u9: '😂' });
  assert.deepStrictEqual(plain(M.toggleReaction(ph('b', 1), 'me', '🙌').reactions), { me: '🙌' });
  assert.strictEqual(M.toggleReaction(p0, null, '🔥'), p0, 'no user, no change');
});

test('reactionCounts tallies every emoji and defaults the four reactions to 0', () => {
  assert.deepStrictEqual(plain(M.REACTIONS), ['🔥', '😂', '😍', '🙌']);
  const c = M.reactionCounts(ph('a', 1, { reactions: { a: '🔥', b: '🔥', c: '😂' } }));
  assert.deepStrictEqual(plain(c), { '🔥': 2, '😂': 1, '😍': 0, '🙌': 0 });
  assert.deepStrictEqual(plain(M.reactionCounts(ph('b', 1))), { '🔥': 0, '😂': 0, '😍': 0, '🙌': 0 });
  assert.strictEqual(M.reactionTotal(ph('a', 1, { reactions: { a: '🔥', b: '😂' } })), 2);
});

test('boardParties keeps hosted + accepted parties, max 12, in party order', () => {
  const ps = [
    party('h1', 5, { hostId: 'me' }),
    party('g1', 5, { invites: [going('me')] }),
    party('p1', 5, { invites: [{ userId: 'me', status: 'pending' }] }),
    party('x', 5)
  ];
  assert.deepStrictEqual(plain(M.boardParties(ps, 'me').map((p) => p.id)), ['h1', 'g1']);
  const many = Array.from({ length: 15 }, (_, i) => party('m' + i, 1, { hostId: 'me' }));
  assert.strictEqual(M.boardParties(many, 'me').length, 12);
  assert.deepStrictEqual(plain(M.boardParties(ps, null)), []);
});

test('pinPos gives a stable in-bounds scatter', () => {
  const a = M.pinPos('abc', 4, 9);
  assert.deepStrictEqual(plain(a), plain(M.pinPos('abc', 4, 9)));
  for (let i = 0; i < 12; i++) {
    const p = M.pinPos('id' + i, i, 12);
    assert.ok(p.left >= 0 && p.left <= 75, 'left ' + p.left);
    assert.ok(p.top >= 0 && p.top <= 82, 'top ' + p.top);
    assert.ok(Math.abs(p.rotation) <= 11);
  }
});

test('recapSlides uses my parties of the last 60 days', () => {
  const ps = [
    party('old', 200, { hostId: 'me', photos: [ph('o1', NOW - 200 * DAY)] }),
    party('a', 10, { hostId: 'me', invites: [going('u2'), going('u3')], photos: [ph('a1', NOW - 10 * DAY), ph('a2', NOW - 9 * DAY, { reactions: { u2: '🔥', u3: '🔥', u4: '😂' } }), ph('a3', NOW - 9 * DAY)] }),
    party('b', 30, { invites: [going('me')], photos: [ph('b1', NOW - 30 * DAY, { reactions: { u5: '😍' } })] }),
    party('notmine', 5, { photos: [ph('n1', NOW - 5 * DAY, { reactions: { x: '🔥', y: '🔥', z: '🔥' } })] })
  ];
  const s = M.recapSlides(ps, 'me', NOW);
  assert.deepStrictEqual(plain(s.map((x) => x.kind)), ['recap', 'most', 'reactions', 'hottest']);
  assert.strictEqual(s[0].parties, 2);
  assert.strictEqual(s[0].photos, 4);
  assert.strictEqual(s[0].recent, true);
  assert.strictEqual(s[1].party.id, 'a');
  assert.strictEqual(s[1].count, 3);
  assert.strictEqual(s[1].guests, 2);
  assert.strictEqual(s[2].party.id, 'a');
  assert.strictEqual(s[2].count, 3);
  assert.strictEqual(s[3].photo.id, 'a2');
  assert.strictEqual(s[3].count, 2);
  assert.ok(s.every((x) => x.photo && x.photo.dataUrl));
});

test('recapSlides falls back to the most recent photo parties and skips empty reaction slides', () => {
  const ps = [
    party('x', 400, { hostId: 'me', photos: [ph('x1', NOW - 400 * DAY)] }),
    party('y', 100, { hostId: 'me', photos: [ph('y1', NOW - 100 * DAY), ph('y2', NOW - 99 * DAY)] })
  ];
  const s = M.recapSlides(ps, 'me', NOW);
  assert.deepStrictEqual(plain(s.map((x) => x.kind)), ['recap', 'most']);
  assert.strictEqual(s[0].recent, false);
  assert.strictEqual(s[0].parties, 2);
  assert.strictEqual(s[1].party.id, 'y');
  assert.deepStrictEqual(plain(M.recapSlides([party('z', 5, { hostId: 'me' })], 'me', NOW)), []);
});

test('albums: my photo parties, latest photo as cover, NEW within 3 days, newest first', () => {
  const ps = [
    party('a', 20, { hostId: 'me', photos: [ph('a1', NOW - 20 * DAY), ph('a2', NOW - 1 * DAY)] }),
    party('b', 10, { invites: [going('me')], photos: [ph('b1', NOW - 10 * DAY)] }),
    party('c', 2, { hostId: 'me' }),
    party('d', 2, { photos: [ph('d1', NOW)] })
  ];
  const al = M.albums(ps, 'me', NOW);
  assert.deepStrictEqual(plain(al.map((x) => x.party.id)), ['a', 'b']);
  assert.strictEqual(al[0].cover.id, 'a2');
  assert.strictEqual(al[0].count, 2);
  assert.strictEqual(al[0].isNew, true);
  assert.strictEqual(al[1].isNew, false);
  assert.ok(al[0].date instanceof Date);
});

test('latestPhotos returns my newest photos with their party', () => {
  const ps = [
    party('a', 20, { hostId: 'me', photos: [ph('a1', 1), ph('a2', 5)] }),
    party('b', 10, { invites: [going('me')], photos: [ph('b1', 3)] }),
    party('d', 2, { photos: [ph('d1', 9)] })
  ];
  const l = M.latestPhotos(ps, 'me', 2);
  assert.deepStrictEqual(plain(l.map((x) => x.photo.id)), ['a2', 'b1']);
  assert.strictEqual(l[1].party.id, 'b');
});

test('onThisDay finds a party I went to with photos 358-372 days ago', () => {
  const ps = [
    party('early', 357, { hostId: 'me', photos: [ph('e', 1)] }),
    party('yr', 366, { invites: [going('me'), going('u2'), going('u3')], photos: [ph('y1', 1), ph('y2', 2)] }),
    party('nophotos', 365, { hostId: 'me' })
  ];
  const o = M.onThisDay(ps, 'me', NOW);
  assert.strictEqual(o.party.id, 'yr');
  assert.strictEqual(o.photo.id, 'y1');
  assert.strictEqual(o.count, 2);
  assert.strictEqual(o.others, 3, 'host + 3 accepted, minus me');
  assert.strictEqual(M.onThisDay([party('h', 365, { hostId: 'me', invites: [going('u2')], photos: [ph('h1', 1)] })], 'me', NOW).others, 1, 'my own party: the accepted guests');
  assert.strictEqual(M.onThisDay([ps[0], ps[2]], 'me', NOW), null);
  assert.strictEqual(M.onThisDay([party('late', 373, { hostId: 'me', photos: [ph('l', 1)] })], 'me', NOW), null);
});

test('ago gives short relative times', () => {
  assert.strictEqual(M.ago(NOW - 20 * 1000, NOW), 'just now');
  assert.strictEqual(M.ago(NOW - 5 * 60000, NOW), '5m ago');
  assert.strictEqual(M.ago(NOW - 3 * 3600000, NOW), '3h ago');
  assert.strictEqual(M.ago(NOW - 2 * DAY, NOW), '2d ago');
  assert.ok(/[A-Z][a-z]{2}/.test(M.ago(NOW - 30 * DAY, NOW)));
  assert.strictEqual(M.ago(0, NOW), '');
});
