// Pure logic behind the redesigned Home screen (PL.home in <script id="logic-home">).
const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-home');
const H = PL.home;
// Values built inside the vm sandbox have foreign prototypes; compare them as plain JSON.
const plain = (v) => JSON.parse(JSON.stringify(v));

// Wed 28 Oct 2026, 10:00 local time
const NOW = new Date(2026, 9, 28, 10, 0, 0);
const ME = 'me';

const inv = (userId, status, extra = {}) => ({ userId, status, plusOneRequested: false, plusOneApproved: false, ...extra });
const party = (id, date, extra = {}) => ({ id, title: id, hostId: 'h', status: 'upcoming', dates: date ? [{ date, time: '20:00' }] : [], confirmedDate: null, invites: [], ...extra });

test('greeting follows the time of day', () => {
  assert.strictEqual(H.greeting(new Date(2026, 9, 28, 8)), 'Morning');
  assert.strictEqual(H.greeting(new Date(2026, 9, 28, 12)), 'Afternoon');
  assert.strictEqual(H.greeting(new Date(2026, 9, 28, 17, 59)), 'Afternoon');
  assert.strictEqual(H.greeting(new Date(2026, 9, 28, 18)), 'Evening');
});

test('relativeDays counts calendar days, not 24h blocks', () => {
  assert.strictEqual(H.relativeDays(new Date(2026, 9, 28, 23), NOW), 'Tonight');
  assert.strictEqual(H.relativeDays(new Date(2026, 9, 29, 1), NOW), 'Tomorrow');
  assert.strictEqual(H.relativeDays(new Date(2026, 9, 31, 20), NOW), 'In 3 days');
  assert.strictEqual(H.relativeDays(new Date(2026, 9, 27, 20), NOW), 'Yesterday');
  assert.strictEqual(H.relativeDays(new Date(2026, 9, 20, 20), NOW), '8 days ago');
  assert.strictEqual(H.relativeDays(null, NOW), 'Date TBD');
});

test('nextParty picks the soonest hosted or accepted party from today on', () => {
  const parties = [
    party('past', '2026-10-20', { invites: [inv(ME, 'accepted')] }),
    party('later', '2026-11-10', { invites: [inv(ME, 'accepted')] }),
    party('mine', '2026-11-02', { hostId: ME }),
    party('pending', '2026-10-29', { invites: [inv(ME, 'pending')] }),
    party('declined', '2026-10-29', { invites: [inv(ME, 'declined')] }),
    party('nodate', null, { invites: [inv(ME, 'accepted')] }),
    party('notupcoming', '2026-10-30', { hostId: ME, status: 'past' }),
  ];
  assert.strictEqual(H.nextParty(parties, ME, NOW).id, 'mine');
  parties.push(party('today', '2026-10-28', { invites: [inv(ME, 'accepted')] }));
  assert.strictEqual(H.nextParty(parties, ME, NOW).id, 'today', 'a party earlier today still counts as next');
  assert.strictEqual(H.nextParty([], ME, NOW), null);
  assert.strictEqual(H.nextParty(parties, null, NOW), null);
});

test('nextParty prefers the confirmed date over the first proposed one', () => {
  const p = party('a', '2026-10-29', { confirmedDate: { date: '2026-12-01', time: '19:00' }, hostId: ME });
  const q = party('b', '2026-11-15', { hostId: ME });
  assert.strictEqual(H.nextParty([p, q], ME, NOW).id, 'b');
});

test('attending lists upcoming accepted parties (not hosted, not past), soonest first', () => {
  const parties = [
    party('b', '2026-11-10', { invites: [inv(ME, 'accepted')] }),
    party('a', '2026-11-01', { invites: [inv(ME, 'accepted')] }),
    party('old', '2026-10-01', { invites: [inv(ME, 'accepted')] }),
    party('host', '2026-11-01', { hostId: ME }),
    party('maybe', '2026-11-01', { invites: [inv(ME, 'maybe')] }),
  ];
  assert.deepStrictEqual(plain(H.attending(parties, ME, NOW).map((p) => p.id)), ['a', 'b']);
});

test('hosting lists my upcoming hosted parties, dateless ones last', () => {
  const parties = [
    party('tbd', null, { hostId: ME }),
    party('late', '2026-12-01', { hostId: ME }),
    party('soon', '2026-10-30', { hostId: ME }),
    party('gone', '2026-10-01', { hostId: ME }),
    party('theirs', '2026-10-30'),
  ];
  assert.deepStrictEqual(plain(H.hosting(parties, ME, NOW).map((p) => p.id)), ['soon', 'late', 'tbd']);
});

test('weekStrip returns Mon-Sun of the current week with roles', () => {
  const parties = [
    party('host', '2026-10-30', { hostId: ME }),
    party('go', '2026-10-30', { invites: [inv(ME, 'accepted')] }),
    party('mon', '2026-10-26', { invites: [inv(ME, 'accepted')] }),
    party('pend', '2026-10-27', { invites: [inv(ME, 'pending')] }),
    party('nextweek', '2026-11-02', { hostId: ME }),
  ];
  const week = H.weekStrip(parties, ME, NOW);
  assert.strictEqual(week.length, 7);
  assert.deepStrictEqual(plain(week.map((d) => d.label)), ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']);
  assert.deepStrictEqual(plain(week.map((d) => d.day)), [26, 27, 28, 29, 30, 31, 1]);
  assert.deepStrictEqual(plain(week.map((d) => d.isToday)), [false, false, true, false, false, false, false]);
  assert.strictEqual(week[0].key, '2026-10-26');
  assert.deepStrictEqual(plain(week[0].parties.map((x) => x.role)), ['going']);
  assert.strictEqual(week[1].parties.length, 0, 'pending invites are not on the strip');
  assert.deepStrictEqual(plain(week[4].parties.map((x) => x.party.id + ':' + x.role)), ['host:host', 'go:going']);
  assert.strictEqual(week[6].parties.length, 0);
});

test('weekStrip starts on Monday even when today is Sunday', () => {
  const week = H.weekStrip([], ME, new Date(2026, 10, 1, 12));
  assert.strictEqual(week[0].key, '2026-10-26');
  assert.strictEqual(week[6].isToday, true);
});

test('monthGrid lays out whole Mon-Sun weeks covering the month', () => {
  const parties = [
    party('first', '2026-10-01', { hostId: ME }),
    party('go', '2026-10-30', { invites: [inv(ME, 'accepted')] }),
    party('pend', '2026-10-12', { invites: [inv(ME, 'pending')] }),
    party('nov', '2026-11-02', { invites: [inv(ME, 'accepted')] }),
  ];
  const m = H.monthGrid(parties, ME, NOW, 0);
  assert.strictEqual(m.title, 'October 2026');
  assert.strictEqual(m.days.length % 7, 0);
  assert.strictEqual(m.days.length, 35, 'Oct 2026 spans five Mon-Sun weeks');
  assert.strictEqual(m.days[0].key, '2026-09-28', 'starts on the Monday before the 1st');
  assert.strictEqual(m.days[0].inMonth, false);
  assert.strictEqual(m.days[3].key, '2026-10-01');
  assert.strictEqual(m.days[3].inMonth, true);
  assert.deepStrictEqual(plain(m.days[3].parties.map((x) => x.role)), ['host']);
  assert.strictEqual(m.days.find((d) => d.key === '2026-10-12').parties.length, 0, 'pending invites are not shown');
  assert.strictEqual(m.days.find((d) => d.key === '2026-10-28').isToday, true);
  assert.strictEqual(m.days[m.days.length - 1].key, '2026-11-01');
  assert.strictEqual(m.count, 2, 'counts parties inside the month only');
});

test('monthGrid steps between months and across the year end', () => {
  const next = H.monthGrid([], ME, NOW, 1);
  assert.strictEqual(next.title, 'November 2026');
  assert.strictEqual(next.days[0].key, '2026-10-26');
  assert.ok(next.days.every((d) => !d.isToday || d.key === '2026-10-28'));
  const jan = H.monthGrid([], ME, NOW, 3);
  assert.strictEqual(jan.title, 'January 2027');
  const prev = H.monthGrid([], ME, NOW, -1);
  assert.strictEqual(prev.title, 'September 2026');
  assert.strictEqual(prev.days.length % 7, 0);
});

test('rsvpBreakdown counts each status and approved plus-ones', () => {
  const p = party('p', '2026-11-01', {
    invites: [
      inv('a', 'accepted', { plusOneRequested: true, plusOneApproved: true }),
      inv('b', 'accepted'),
      inv('c', 'maybe'),
      inv('d', 'pending'),
      inv('e', 'pending'),
      inv('f', 'declined'),
    ],
  });
  assert.deepStrictEqual(plain({ ...H.rsvpBreakdown(p) }), { accepted: 2, maybe: 1, pending: 2, declined: 1, total: 6, plusOnes: 1, going: 3 });
  assert.deepStrictEqual(plain({ ...H.rsvpBreakdown({}) }), { accepted: 0, maybe: 0, pending: 0, declined: 0, total: 0, plusOnes: 0, going: 0 });
});

test('pendingPlusOnes matches the manage screen: requested but not yet approved', () => {
  const p = party('p', '2026-11-01', {
    invites: [
      inv('a', 'accepted', { plusOneRequested: true, plusOneApproved: false }),
      inv('b', 'accepted', { plusOneRequested: true, plusOneApproved: true }),
      inv('c', 'accepted', { plusOneRequested: false, plusOneApproved: false }),
      inv('d', 'maybe', { plusOneRequested: true }),
    ],
  });
  assert.strictEqual(H.pendingPlusOnes(p), 2);
  assert.strictEqual(H.pendingPlusOnes({}), 0);
});

test('checklistProgress falls back to unsaved default items', () => {
  const pr = H.checklistProgress(party('p', '2026-11-01'));
  assert.strictEqual(pr.isDefault, true);
  assert.ok(pr.total >= 3);
  assert.strictEqual(pr.done, 0);
  assert.strictEqual(pr.allDone, false);
  assert.ok(pr.items.every((i) => i.id && i.text && i.done === false));
});

test('checklistProgress counts a saved checklist', () => {
  const p = party('p', '2026-11-01', { checklist: [{ id: 'x', text: 'X', done: true }, { id: 'y', text: 'Y', done: false }] });
  const pr = H.checklistProgress(p);
  assert.deepStrictEqual(plain([pr.isDefault, pr.done, pr.total, pr.allDone]), [false, 1, 2, false]);
  p.checklist[1].done = true;
  assert.strictEqual(H.checklistProgress(p).allDone, true);
});

test('toggleChecklistItem materialises defaults and flips one item without mutating', () => {
  const p = party('p', '2026-11-01');
  const first = H.checklistProgress(p).items[0];
  const next = H.toggleChecklistItem(p, first.id);
  assert.strictEqual(next.find((i) => i.id === first.id).done, true);
  assert.strictEqual(next.filter((i) => i.done).length, 1);
  assert.strictEqual(p.checklist, undefined, 'party not mutated');
  const saved = { ...p, checklist: next };
  const back = H.toggleChecklistItem(saved, first.id);
  assert.strictEqual(back.find((i) => i.id === first.id).done, false);
  assert.strictEqual(saved.checklist[0].done, true, 'saved list not mutated');
});

test('countdownParts splits the remaining time, null once it has started', () => {
  const t = new Date(NOW.getTime() + ((2 * 24 + 3) * 3600 + 4 * 60 + 5) * 1000);
  assert.deepStrictEqual(plain({ ...H.countdownParts(t, NOW) }), { d: 2, h: 3, m: 4, s: 5 });
  assert.strictEqual(H.countdownParts(new Date(NOW.getTime() - 1000), NOW), null);
  assert.strictEqual(H.countdownParts(null, NOW), null);
});

test('headerLine shows the date and how long until the next party', () => {
  assert.strictEqual(H.headerLine(null, NOW), 'Wed 28 Oct · Nothing planned yet');
  assert.strictEqual(H.headerLine(party('Halloween Bash', '2026-10-31'), NOW), 'Wed 28 Oct · 3 days until Halloween Bash');
  assert.strictEqual(H.headerLine(party('Drinks', '2026-10-29'), NOW), 'Wed 28 Oct · Drinks is tomorrow');
  assert.strictEqual(H.headerLine(party('Drinks', '2026-10-28'), NOW), 'Wed 28 Oct · Drinks is tonight');
});

test('fmtShort and fmtTime format compactly', () => {
  assert.strictEqual(H.fmtShort(new Date(2026, 9, 31, 20)), 'Sat 31 Oct');
  assert.strictEqual(H.fmtTime(new Date(2026, 9, 31, 20)), '8pm');
  assert.strictEqual(H.fmtTime(new Date(2026, 9, 31, 19, 30)), '7:30pm');
  assert.strictEqual(H.fmtTime(new Date(2026, 9, 31, 0, 5)), '12:05am');
});
