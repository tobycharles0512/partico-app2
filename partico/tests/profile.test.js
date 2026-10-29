// Profile stats: the analytics that moved off the home screen and onto the profile.
const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-profile');

const ME = 'me';
const DAY = 86400000;
// Arrays built inside the vm sandbox have a different Array prototype; copy them before deepStrictEqual.
const arr = (a) => Array.from(a);
// "Now" for every test: Wed 28 Oct 2026, 12:00 local time.
const NOW = new Date(2026, 9, 28, 12, 0, 0);

// Local-time ISO date/time for a moment `days` before NOW (negative = future).
function at(days, now = NOW) {
  const d = new Date(now.getTime() - days * DAY);
  const pad = (n) => String(n).padStart(2, '0');
  return { date: d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()), time: pad(d.getHours()) + ':' + pad(d.getMinutes()) };
}
let seq = 0;
function party({ host = ME, daysAgo, confirmed = true, invites = [], photos = 0, dates } = {}) {
  const when = daysAgo === undefined ? null : at(daysAgo);
  return {
    id: 'p' + ++seq,
    title: 'Party ' + seq,
    hostId: host,
    status: 'upcoming',
    dates: dates || (when ? [{ id: 'd1', ...when }] : []),
    confirmedDate: confirmed && when ? when : null,
    invites,
    photos: Array.from({ length: photos }, (_, i) => ({ id: 'ph' + i })),
  };
}
const inv = (userId, status, extra = {}) => ({ userId, status, plusOneRequested: false, plusOneApproved: false, ...extra });
const going = (n, extra) => Array.from({ length: n }, (_, i) => inv('g' + i + Math.random(), 'accepted', extra));

test('empty data gives zeros, no NaN, and six empty month buckets', () => {
  const s = PL.profile.stats([], ME, NOW);
  assert.strictEqual(s.hosted30, 0);
  assert.strictEqual(s.hostedDelta, 0);
  assert.strictEqual(s.guests30, 0);
  assert.strictEqual(s.guestsDelta, 0);
  assert.strictEqual(s.attended, 0);
  assert.strictEqual(s.photos, 0);
  assert.strictEqual(s.rsvpRate, 0);
  assert.strictEqual(s.months.length, 6);
  assert.ok(s.months.every((m) => m.guests === 0));
  assert.strictEqual(s.bestMonth, null);
  assert.deepStrictEqual(arr(PL.profile.pastParties([], ME, NOW)), []);
});

test('tolerates missing arrays and a null party list', () => {
  const s = PL.profile.stats(null, ME, NOW);
  assert.strictEqual(s.hosted30, 0);
  const odd = { id: 'x', hostId: ME, dates: [{ date: at(3).date }], confirmedDate: null };
  const s2 = PL.profile.stats([odd], ME, NOW);
  assert.strictEqual(s2.hosted30, 1);
  assert.strictEqual(s2.guests30, 0);
  assert.strictEqual(s2.photos, 0);
});

test('hosted in the last 30 days, with delta vs the 30 days before', () => {
  const parties = [party({ daysAgo: 2 }), party({ daysAgo: 20 }), party({ daysAgo: 40 }), party({ host: 'someone', daysAgo: 5 })];
  const s = PL.profile.stats(parties, ME, NOW);
  assert.strictEqual(s.hosted30, 2);
  assert.strictEqual(s.hostedDelta, 1);
  const s2 = PL.profile.stats([party({ daysAgo: 35 }), party({ daysAgo: 45 })], ME, NOW);
  assert.strictEqual(s2.hosted30, 0);
  assert.strictEqual(s2.hostedDelta, -2);
});

test('a party exactly 30 days ago counts in the last 30 days; exactly 60 in the window before', () => {
  const s = PL.profile.stats([party({ daysAgo: 30 })], ME, NOW);
  assert.strictEqual(s.hosted30, 1);
  assert.strictEqual(s.hostedDelta, 1);
  const s2 = PL.profile.stats([party({ daysAgo: 60 })], ME, NOW);
  assert.strictEqual(s2.hosted30, 0);
  assert.strictEqual(s2.hostedDelta, -1);
  const s3 = PL.profile.stats([party({ daysAgo: 61 })], ME, NOW);
  assert.strictEqual(s3.hostedDelta, 0);
});

test('a party just after 30 days ago is still in, one just before is out', () => {
  const inside = party({ daysAgo: 29.99 });
  const outside = party({ daysAgo: 30.01 });
  assert.strictEqual(PL.profile.stats([inside], ME, NOW).hosted30, 1);
  assert.strictEqual(PL.profile.stats([outside], ME, NOW).hosted30, 0);
});

test('future parties and parties with no date are ignored for the time-based figures', () => {
  const parties = [
    party({ daysAgo: -3, invites: going(5) }),
    party({ invites: going(4) }),
    party({ daysAgo: -0.01, invites: going(2) }),
  ];
  const s = PL.profile.stats(parties, ME, NOW);
  assert.strictEqual(s.hosted30, 0);
  assert.strictEqual(s.guests30, 0);
  assert.ok(s.months.every((m) => m.guests === 0));
  assert.strictEqual(s.bestMonth, null);
});

test('falls back to the first proposed date when nothing is confirmed', () => {
  const s = PL.profile.stats([party({ daysAgo: 4, confirmed: false, invites: going(3) })], ME, NOW);
  assert.strictEqual(s.hosted30, 1);
  assert.strictEqual(s.guests30, 3);
});

test('guests = accepted guests + approved plus-ones only', () => {
  const invites = [
    inv('a', 'accepted', { plusOneRequested: true, plusOneApproved: true }),
    inv('b', 'accepted', { plusOneRequested: true, plusOneApproved: false }),
    inv('c', 'accepted'),
    inv('d', 'maybe'),
    inv('e', 'declined', { plusOneRequested: true, plusOneApproved: true }),
    inv('f', 'pending'),
  ];
  const s = PL.profile.stats([party({ daysAgo: 3, invites }), party({ daysAgo: 40, invites: going(1) })], ME, NOW);
  assert.strictEqual(s.guests30, 4); // a, a's +1, b, c
  assert.strictEqual(s.guestsDelta, 3);
});

test('guests at parties hosted by someone else do not count', () => {
  const s = PL.profile.stats([party({ host: 'other', daysAgo: 3, invites: [inv(ME, 'accepted'), ...going(6)] })], ME, NOW);
  assert.strictEqual(s.guests30, 0);
});

test('attended = past parties hosted by someone else where you accepted (all time)', () => {
  const parties = [
    party({ host: 'x', daysAgo: 400, invites: [inv(ME, 'accepted')] }),
    party({ host: 'x', daysAgo: 3, invites: [inv(ME, 'accepted')] }),
    party({ host: 'x', daysAgo: 3, invites: [inv(ME, 'maybe')] }),
    party({ host: 'x', daysAgo: 3, invites: [inv(ME, 'declined')] }),
    party({ host: 'x', daysAgo: -3, invites: [inv(ME, 'accepted')] }),
    party({ host: 'x', invites: [inv(ME, 'accepted')] }),
    party({ daysAgo: 3, invites: [inv(ME, 'accepted')] }),
  ];
  assert.strictEqual(PL.profile.stats(parties, ME, NOW).attended, 2);
});

test('photos across parties you hosted or accepted, nothing else', () => {
  const parties = [
    party({ daysAgo: 3, photos: 4 }),
    party({ host: 'x', daysAgo: 3, photos: 5, invites: [inv(ME, 'accepted')] }),
    party({ host: 'x', daysAgo: 3, photos: 7, invites: [inv(ME, 'declined')] }),
    party({ host: 'x', daysAgo: 3, photos: 9 }),
  ];
  assert.strictEqual(PL.profile.stats(parties, ME, NOW).photos, 9);
});

test('RSVP rate = accepted / responded across invites to your parties; pending excluded', () => {
  const invites = [inv('a', 'accepted'), inv('b', 'accepted'), inv('c', 'accepted'), inv('d', 'declined'), inv('e', 'pending'), inv('f', 'pending')];
  const s = PL.profile.stats([party({ daysAgo: 3, invites }), party({ host: 'x', daysAgo: 3, invites: [inv('z', 'declined')] })], ME, NOW);
  assert.strictEqual(s.rsvpRate, 75);
});

test('RSVP rate counts maybe as a reply, rounds, and includes future parties', () => {
  const s = PL.profile.stats([party({ daysAgo: -10, invites: [inv('a', 'accepted'), inv('b', 'maybe'), inv('c', 'declined')] })], ME, NOW);
  assert.strictEqual(s.rsvpRate, 33);
});

test('RSVP rate is 0 when nobody has replied yet', () => {
  const s = PL.profile.stats([party({ daysAgo: 3, invites: [inv('a', 'pending')] })], ME, NOW);
  assert.strictEqual(s.rsvpRate, 0);
});

test('six month buckets ending with the current month, guests at your past parties', () => {
  const parties = [
    party({ daysAgo: 1, invites: going(2) }), // Oct
    party({ daysAgo: 30, invites: going(3) }), // 28 Sep
    party({ daysAgo: 60, invites: going(1, { plusOneRequested: true, plusOneApproved: true }) }), // 29 Aug -> 2 guests
    party({ daysAgo: 200, invites: going(9) }), // too old
    party({ daysAgo: -2, invites: going(9) }), // future, this month
  ];
  const s = PL.profile.stats(parties, ME, NOW);
  assert.deepStrictEqual(arr(s.months.map((m) => m.label)), ['May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct']);
  assert.deepStrictEqual(arr(s.months.map((m) => m.guests)), [0, 0, 0, 2, 3, 2]);
  assert.deepStrictEqual(arr(s.months.map((m) => m.month)), [4, 5, 6, 7, 8, 9]);
  assert.ok(s.months.every((m) => m.year === 2026));
  assert.strictEqual(s.bestMonth, 'Sep');
});

test('month buckets span a year boundary', () => {
  const now = new Date(2027, 1, 10, 12); // 10 Feb 2027
  const dec = { ...party({ invites: going(4) }), dates: [{ id: 'd', date: '2026-12-31', time: '22:00' }], confirmedDate: { date: '2026-12-31', time: '22:00' } };
  const sep = { ...party({ invites: going(7) }), dates: [{ id: 'd', date: '2026-09-15', time: '20:00' }], confirmedDate: null };
  const aug = { ...party({ invites: going(1) }), dates: [{ id: 'd', date: '2026-08-31', time: '20:00' }], confirmedDate: null };
  const s = PL.profile.stats([dec, sep, aug], ME, now);
  assert.deepStrictEqual(arr(s.months.map((m) => m.label)), ['Sep', 'Oct', 'Nov', 'Dec', 'Jan', 'Feb']);
  assert.deepStrictEqual(arr(s.months.map((m) => m.year)), [2026, 2026, 2026, 2026, 2027, 2027]);
  assert.deepStrictEqual(arr(s.months.map((m) => m.guests)), [7, 0, 0, 4, 0, 0]);
  assert.strictEqual(s.bestMonth, 'Sep');
});

test('best month prefers the most recent on a tie', () => {
  const parties = [party({ daysAgo: 1, invites: going(3) }), party({ daysAgo: 60, invites: going(3) })];
  assert.strictEqual(PL.profile.stats(parties, ME, NOW).bestMonth, 'Oct');
});

test('now may be a timestamp and defaults to the current time', () => {
  const s = PL.profile.stats([party({ daysAgo: 3 })], ME, NOW.getTime());
  assert.strictEqual(s.hosted30, 1);
  const real = PL.profile.stats([], ME);
  assert.strictEqual(real.months[5].month, new Date().getMonth());
});

test('pastParties: hosted or accepted, already happened, most recent first', () => {
  const a = party({ daysAgo: 10 });
  const b = party({ host: 'x', daysAgo: 2, invites: [inv(ME, 'accepted')] });
  const c = party({ host: 'x', daysAgo: 50, invites: [inv(ME, 'accepted')] });
  const skipMaybe = party({ host: 'x', daysAgo: 1, invites: [inv(ME, 'maybe')] });
  const skipDeclined = party({ host: 'x', daysAgo: 1, invites: [inv(ME, 'declined')] });
  const skipNotMine = party({ host: 'x', daysAgo: 1 });
  const skipFuture = party({ daysAgo: -1 });
  const skipUndated = party({});
  const out = PL.profile.pastParties([c, skipMaybe, a, skipFuture, b, skipDeclined, skipUndated, skipNotMine], ME, NOW);
  assert.deepStrictEqual(arr(out.map((r) => r.party.id)), [b.id, a.id, c.id]);
  assert.deepStrictEqual(arr(out.map((r) => r.hosted)), [false, true, false]);
  assert.ok(out.every((r) => r.date instanceof Date));
  assert.strictEqual(out[0].date.getTime(), PL.partyDate(b).getTime());
});

test('pastParties tolerates null input', () => {
  assert.deepStrictEqual(arr(PL.profile.pastParties(null, ME, NOW)), []);
});
