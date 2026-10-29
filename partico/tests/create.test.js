const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-create');
const C = PL.create;

// Arrays/objects built inside the vm sandbox have a different prototype; copy before deepStrictEqual.
const plain = (o) => JSON.parse(JSON.stringify(o));
// "Now" for every test: Wed 28 Oct 2026, 12:00 local time.
const NOW = new Date(2026, 9, 28, 12, 0, 0);

function form(over = {}) {
  return {
    title: '', description: '', isPrivate: true, audience: 'everyone', dates: [], useSingleDate: true,
    address: '', parkingAddress: '', venueLat: null, venueLng: null, parkingLat: null, parkingLng: null,
    dresscode: '', inspirationLinks: [''], inspirationImages: [], menuItems: [], dietary: '', menuInput: '',
    drinkOptions: [], askDrinkPref: false, drinkInput: '', customQuestions: [], questionInput: '',
    fireworksEnabled: true, fireworksColors: ['#00ff41'], fireworksStyle: 'classic', eventType: 'party',
    customEventName: '', coverImage: null, playlistUrl: '', moodBoard: [], smartSections: {}, inviteFont: '',
    inviteEffect: 'auto', maxCapacity: '', invitedUsers: [], dateInput: '', timeInput: '',
    ...over,
  };
}
const opt = (date, time = '20:00', id = date + time) => ({ id, date, time, votes: [] });

test('fmtDay and fmtTime give short invite-style labels', () => {
  assert.strictEqual(C.fmtDay('2026-11-14'), 'Sat 14 Nov');
  assert.strictEqual(C.fmtDay(''), '');
  assert.strictEqual(C.fmtTime('20:00'), '8pm');
  assert.strictEqual(C.fmtTime('19:30'), '7:30pm');
  assert.strictEqual(C.fmtTime('00:00'), '12am');
  assert.strictEqual(C.fmtTime('12:05'), '12:05pm');
  assert.strictEqual(C.fmtTime(''), '');
});

test('whenText: single date, voting, and nothing yet', () => {
  assert.strictEqual(C.whenText(form({ dates: [opt('2026-11-14', '20:00')] })), 'Sat 14 Nov · 8pm');
  assert.strictEqual(C.whenText(form({ dates: [opt('2026-11-14', '')] })), 'Sat 14 Nov');
  assert.strictEqual(C.whenText(form()), '');
  assert.strictEqual(C.whenText(form({ useSingleDate: false, dates: [opt('2026-11-14'), opt('2026-11-21')] })), '2 date options · guests vote');
  assert.strictEqual(C.whenText(form({ useSingleDate: false, dates: [opt('2026-11-14')] })), '1 date option · guests vote');
  assert.strictEqual(C.whenText(form({ useSingleDate: false })), '');
});

test('validateEssentials: name and a date are required', () => {
  const e = plain(C.validateEssentials(form(), NOW));
  assert.ok(e.title);
  assert.ok(e.date);
  assert.deepStrictEqual(plain(C.validateEssentials(form({ title: 'Toby 22', dates: [opt('2026-11-14')] }), NOW)), {});
  assert.ok(C.validateEssentials(form({ title: '   ', dates: [opt('2026-11-14')] }), NOW).title, 'whitespace-only name');
});

test('validateEssentials: a single date may be today but not in the past', () => {
  assert.deepStrictEqual(plain(C.validateEssentials(form({ title: 'x', dates: [opt('2026-10-28')] }), NOW)), {});
  assert.match(C.validateEssentials(form({ title: 'x', dates: [opt('2026-10-27')] }), NOW).date, /passed/);
});

test('validateEssentials: voting needs at least two options, none in the past', () => {
  const vote = (dates) => C.validateEssentials(form({ title: 'x', useSingleDate: false, dates }), NOW);
  assert.match(vote([opt('2026-11-14')]).date, /two/);
  assert.deepStrictEqual(plain(vote([opt('2026-11-14'), opt('2026-11-21')])), {});
  assert.match(vote([opt('2026-10-01'), opt('2026-11-21')]).date, /passed/);
});

test('validateExtras: open parties need a max number of guests (the old canNext rule)', () => {
  assert.deepStrictEqual(plain(C.validateExtras(form())), {});
  assert.ok(C.validateExtras(form({ isPrivate: false })).guests);
  assert.ok(C.validateExtras(form({ isPrivate: false, maxCapacity: '0' })).guests);
  assert.deepStrictEqual(plain(C.validateExtras(form({ isPrivate: false, maxCapacity: '40' }))), {});
});

test('sortOptions orders by date then time without mutating the input', () => {
  const input = [opt('2026-11-21', '19:00', 'c'), opt('2026-11-14', '21:00', 'b'), opt('2026-11-14', '18:00', 'a')];
  const out = C.sortOptions(input);
  assert.deepStrictEqual(Array.from(out, (d) => d.id), ['a', 'b', 'c']);
  assert.strictEqual(input[0].id, 'c');
  assert.deepStrictEqual(plain(C.sortOptions(null)), []);
});

test('privacy: three choices map onto isPrivate + audience and back', () => {
  assert.strictEqual(C.privacyOf(form()), 'invite');
  assert.strictEqual(C.privacyOf(form({ isPrivate: false, audience: 'friends' })), 'friends');
  assert.strictEqual(C.privacyOf(form({ isPrivate: false, audience: 'everyone' })), 'public');
  assert.strictEqual(C.privacyOf(form({ isPrivate: false, audience: 'mutual' })), 'public');
  assert.deepStrictEqual(plain(C.privacyPatch('invite')), { isPrivate: true });
  assert.deepStrictEqual(plain(C.privacyPatch('friends')), { isPrivate: false, audience: 'friends' });
  assert.deepStrictEqual(plain(C.privacyPatch('public')), { isPrivate: false, audience: 'everyone' });
});

test('suggestedCards: by event type and its smart sections, in card order, no duplicates', () => {
  const dinner = Array.from(C.suggestedCards('dinner', ['menu_preview', 'dietary', 'seating']));
  assert.ok(dinner.includes('menu'));
  assert.ok(dinner.includes('smart'));
  const club = Array.from(C.suggestedCards('club_night', ['dress_code', 'door_time', 'tickets']));
  for (const id of ['playlist', 'drinks', 'dress', 'smart']) assert.ok(club.includes(id), id + ' for club');
  const bday = Array.from(C.suggestedCards('birthday', ['gift_list']));
  assert.ok(bday.includes('playlist') && bday.includes('drinks'));
  const bbq = Array.from(C.suggestedCards('bbq', ['what_to_bring', 'dietary', 'parking']));
  assert.ok(bbq.includes('menu') && bbq.includes('parking'));
  assert.strictEqual(new Set(bbq).size, bbq.length);
  // Suggested ids follow the master card order.
  const order = Array.from(C.CARDS);
  const idx = bbq.map((id) => order.indexOf(id));
  assert.deepStrictEqual(idx, [...idx].sort((a, b) => a - b));
  assert.deepStrictEqual(Array.from(C.suggestedCards('custom', [])), []);
  assert.ok(!Array.from(C.suggestedCards('casual', [])).includes('smart'));
});

test('CARDS cover every optional field group of the old wizard ("Who can join" is on the Invite step)', () => {
  for (const id of ['dress', 'menu', 'drinks', 'questions', 'playlist', 'mood', 'parking', 'smart', 'effect']) {
    assert.ok(Array.from(C.CARDS).includes(id), id);
  }
  assert.ok(!Array.from(C.CARDS).includes('guests'), 'who can join should not be an extras card');
  assert.strictEqual(C.cardSummary('guests', form()), '');
});

test('cardSummary: empty when nothing set, a short line when something is', () => {
  const f = form();
  for (const id of Array.from(C.CARDS)) assert.strictEqual(C.cardSummary(id, f), '', id + ' should be empty');
  assert.strictEqual(C.cardSummary('dress', form({ dresscode: 'Black tie' })), 'Black tie');
  assert.match(C.cardSummary('dress', form({ inspirationImages: ['a', 'b'] })), /2 photos/);
  assert.match(C.cardSummary('dress', form({ inspirationLinks: ['', 'https://x'] })), /1 link/);
  assert.strictEqual(C.cardSummary('menu', form({ menuItems: ['Lasagne', 'Salad', 'Tiramisu'] })), 'Lasagne, Salad +1');
  assert.strictEqual(C.cardSummary('menu', form({ dietary: 'Nut free' })), 'Dietary notes added');
  assert.strictEqual(C.cardSummary('drinks', form({ drinkOptions: ['\u{1F37A} Beer', 'Aperol'], askDrinkPref: true })), 'Beer, Aperol · asking guests');
  assert.strictEqual(C.cardSummary('drinks', form({ askDrinkPref: true })), 'Asking guests what they like');
  assert.strictEqual(C.cardSummary('questions', form({ customQuestions: [{ id: 1, text: 'a' }] })), '1 question');
  assert.strictEqual(C.cardSummary('questions', form({ customQuestions: [{ id: 1, text: 'a' }, { id: 2, text: 'b' }] })), '2 questions');
  assert.strictEqual(C.cardSummary('playlist', form({ playlistUrl: 'https://open.spotify.com/playlist/x' })), 'Spotify playlist');
  assert.strictEqual(C.cardSummary('playlist', form({ playlistUrl: 'https://music.apple.com/x' })), 'Apple Music playlist');
  assert.strictEqual(C.cardSummary('playlist', form({ playlistUrl: 'https://youtube.com/x' })), 'Playlist linked');
  assert.strictEqual(C.cardSummary('mood', form({ moodBoard: ['a'] })), '1 photo');
  assert.strictEqual(C.cardSummary('parking', form({ parkingAddress: 'NCP High St' })), 'NCP High St');
  assert.strictEqual(C.cardSummary('parking', form({ parkingLat: 51.5, parkingLng: -0.1 })), 'Pinned on the map');
  assert.strictEqual(C.cardSummary('smart', form({ smartSections: { gift_list: 'Books', parking: '  ' } })), '1 section filled in');
  assert.strictEqual(C.cardSummary('effect', form({ inviteEffect: 'petals' })), 'Petals');
  assert.strictEqual(C.cardSummary('effect', form({ fireworksEnabled: false })), 'Fireworks off');
  assert.strictEqual(C.cardSummary('effect', form({ fireworksStyle: 'stars' })), 'Stars fireworks');
  assert.strictEqual(C.cardSummary('guests', form({ isPrivate: false, audience: 'friends', maxCapacity: '30' })), 'Friends can find it · max 30');
  assert.strictEqual(C.cardSummary('guests', form({ isPrivate: false, audience: 'mutual' })), 'Public · mutual friends');
  assert.strictEqual(C.cardSummary('nope', f), '');
});

test('cardSummary: the basics sections used by edit mode', () => {
  assert.strictEqual(C.cardSummary('name', form({ title: 'Toby 22', description: 'Bring cake' })), 'Toby 22 · Bring cake');
  assert.strictEqual(C.cardSummary('look', form(), { typeLabel: 'Birthday' }), 'Birthday · theme colours');
  assert.strictEqual(C.cardSummary('look', form({ coverImage: 'data:x' }), { typeLabel: 'Birthday' }), 'Birthday · your photo');
  assert.strictEqual(C.cardSummary('when', form({ dates: [opt('2026-11-14')] })), 'Sat 14 Nov · 8pm');
  assert.strictEqual(C.cardSummary('where', form({ address: 'The Crown, 116 Cloudesley Rd' })), 'The Crown, 116 Cloudesley Rd');
});

test('placeName: first part of the address for the preview card', () => {
  assert.strictEqual(C.placeName('The Crown, 116 Cloudesley Rd, London'), 'The Crown');
  assert.strictEqual(C.placeName('  Jake\'s flat  '), "Jake's flat");
  assert.strictEqual(C.placeName(''), '');
});

test('inviteLabel counts invites', () => {
  assert.strictEqual(C.inviteLabel(0), 'Create party');
  assert.strictEqual(C.inviteLabel(1), 'Create & send 1 invite \u{1F48C}');
  assert.strictEqual(C.inviteLabel(3), 'Create & send 3 invites \u{1F48C}');
});

test('effectPlan maps an opening effect onto the app\'s particles and fireworks', () => {
  assert.deepStrictEqual(plain(C.effectPlan('none', 'birthday', true)), { particles: null, fireworks: false });
  assert.deepStrictEqual(plain(C.effectPlan('fireworks', 'birthday', false)), { particles: null, fireworks: true });
  assert.deepStrictEqual(plain(C.effectPlan('auto', 'birthday', true)), { particles: 'birthday', fireworks: true });
  assert.deepStrictEqual(plain(C.effectPlan('auto', 'custom', false)), { particles: 'party', fireworks: false });
  assert.strictEqual(C.effectPlan('confetti', 'wedding', true).particles, 'birthday');
  assert.strictEqual(C.effectPlan('petals', 'party', true).particles, 'wedding');
  assert.ok(C.effectPlan('bubbles', 'party', true).particles);
});

test('isBlank: an untouched form is not worth keeping as a draft', () => {
  assert.strictEqual(C.isBlank(form()), true);
  assert.strictEqual(C.isBlank(form({ title: 'x' })), false);
  assert.strictEqual(C.isBlank(form({ dates: [opt('2026-11-14')] })), false);
  assert.strictEqual(C.isBlank(form({ menuItems: ['Cake'] })), false);
});

test('draftFor strips transient inputs and oversized images', () => {
  const big = 'data:image/jpeg;base64,' + 'A'.repeat(500);
  const small = 'data:image/jpeg;base64,AAAA';
  const d = C.draftFor(form({ title: 'x', menuInput: 'half typed', dateInput: '2026-11-01', coverImage: big, moodBoard: [small, big], inspirationImages: [big] }), { maxImageChars: 200, maxTotalChars: 1e6 });
  for (const k of ['menuInput', 'drinkInput', 'questionInput', 'dateInput', 'timeInput']) assert.ok(!(k in d), k + ' kept');
  assert.strictEqual(d.title, 'x');
  assert.strictEqual(d.coverImage, null);
  assert.deepStrictEqual(Array.from(d.moodBoard), [small]);
  assert.deepStrictEqual(Array.from(d.inspirationImages), []);
});

test('draftFor drops images entirely when the whole draft would be too big', () => {
  const img = 'data:image/jpeg;base64,' + 'B'.repeat(150);
  const d = C.draftFor(form({ title: 'x', coverImage: img, moodBoard: [img, img, img] }), { maxImageChars: 1000, maxTotalChars: 1200 });
  assert.deepStrictEqual(Array.from(d.moodBoard), []);
  assert.ok(JSON.stringify(d).length <= 1200);
  assert.strictEqual(d.title, 'x');
});

test('draftKey is per user', () => {
  assert.strictEqual(C.draftKey('u1'), 'partico_create_draft_u1');
  assert.strictEqual(C.draftKey(null), 'partico_create_draft_anon');
});
