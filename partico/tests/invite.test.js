// Pure logic behind the redesigned InvitationScreen (PL.invite in <script id="logic-invite">).
const test = require('node:test');
const assert = require('node:assert');
const { loadLogic } = require('./helpers');
const PL = loadLogic('logic-invite');

const plain = (v) => JSON.parse(JSON.stringify(v));

test('shouldShowEnvelope: only for invites the guest has not answered', () => {
  assert.strictEqual(PL.invite.shouldShowEnvelope({ status: 'pending' }), true);
  assert.strictEqual(PL.invite.shouldShowEnvelope(null), true);
  assert.strictEqual(PL.invite.shouldShowEnvelope({}), true);
  assert.strictEqual(PL.invite.shouldShowEnvelope({ status: 'accepted' }), false);
  assert.strictEqual(PL.invite.shouldShowEnvelope({ status: 'maybe' }), false);
  assert.strictEqual(PL.invite.shouldShowEnvelope({ status: 'declined' }), false);
});

test('steps: declined goes straight to the reason then done', () => {
  const party = { dates: [{ id: 'a' }, { id: 'b' }], customQuestions: [{ id: 'q' }], askDrinkPref: true, drinkOptions: ['Beer'] };
  assert.deepStrictEqual(plain(PL.invite.steps(party, 'declined')), ['envelope', 'rsvp', 'cancel_reason', 'done']);
});

test('steps: accepted/maybe include optional steps only when the party has them', () => {
  const bare = {};
  assert.deepStrictEqual(plain(PL.invite.steps(bare, 'accepted')), ['envelope', 'rsvp', 'plus_one', 'dietary', 'ask_host', 'done']);
  assert.deepStrictEqual(plain(PL.invite.steps(bare, '')), ['envelope', 'rsvp', 'plus_one', 'dietary', 'ask_host', 'done']);
  const full = { dates: [{ id: 'a' }], customQuestions: [{ id: 'q', text: 'Q?' }], askDrinkPref: true, drinkOptions: ['Beer'] };
  assert.deepStrictEqual(plain(PL.invite.steps(full, 'maybe')), ['envelope', 'rsvp', 'dates', 'plus_one', 'dietary', 'drinks', 'questions', 'ask_host', 'done']);
});

test('steps: no date vote once the host confirmed a date; no drinks unless asked', () => {
  const p = { dates: [{ id: 'a' }], confirmedDate: { date: '2026-11-01' }, askDrinkPref: false, drinkOptions: ['Beer'] };
  assert.deepStrictEqual(plain(PL.invite.steps(p, 'accepted')), ['envelope', 'rsvp', 'plus_one', 'dietary', 'ask_host', 'done']);
  assert.ok(!PL.invite.steps({ askDrinkPref: true, drinkOptions: [] }, 'accepted').includes('drinks'));
});

test('progress: step x of y with a clamped percentage', () => {
  assert.deepStrictEqual(plain(PL.invite.progress(1, 4)), { current: 1, total: 4, label: 'Step 1 of 4', pct: 25 });
  assert.deepStrictEqual(plain(PL.invite.progress(4, 4)), { current: 4, total: 4, label: 'Step 4 of 4', pct: 100 });
  assert.strictEqual(PL.invite.progress(9, 4).current, 4);
  assert.strictEqual(PL.invite.progress(0, 4).current, 1);
  assert.strictEqual(PL.invite.progress(1, 0).pct, 0);
});

test('blockReason: only the yes/maybe/no choice is required', () => {
  assert.strictEqual(PL.invite.blockReason('rsvp', { rsvp: '' }), 'Select an option to continue');
  assert.strictEqual(PL.invite.blockReason('rsvp', { rsvp: 'maybe' }), '');
  assert.strictEqual(PL.invite.blockReason('dates', { rsvp: 'accepted', selectedDates: [] }), '');
  assert.strictEqual(PL.invite.blockReason('plus_one', { rsvp: 'accepted', plusOne: 'yes', plusOneName: '' }), '');
});

test('buildResponse: exact payload shape sent to respondToInvite', () => {
  const r = PL.invite.buildResponse({ rsvp: 'accepted', cancelReason: 'Work/school clash', selectedDates: ['a'], plusOne: 'yes', plusOneName: 'Alex', dietary: 'Vegan \u{1F331}', drinkPrefs: ['Beer'], answers: { q: 'hi' } });
  assert.deepStrictEqual(plain(r), { status: 'accepted', cancelReason: '', dateVotes: ['a'], plusOneRequested: true, plusOneName: 'Alex', dietary: 'Vegan \u{1F331}', drinkPreferences: ['Beer'], answers: { q: 'hi' } });
  assert.deepStrictEqual(Object.keys(r), ['status', 'cancelReason', 'dateVotes', 'plusOneRequested', 'plusOneName', 'dietary', 'drinkPreferences', 'answers']);
  const d = PL.invite.buildResponse({ rsvp: 'declined', cancelReason: 'Family commitment', selectedDates: [], plusOne: 'no', plusOneName: 'Alex', dietary: '', drinkPrefs: [], answers: {} });
  assert.strictEqual(d.cancelReason, 'Family commitment');
  assert.strictEqual(d.plusOneRequested, false);
  assert.strictEqual(d.plusOneName, '');
});

test('customReasonText: textarea shows only a free-text reason', () => {
  assert.strictEqual(PL.invite.customReasonText(''), '');
  assert.strictEqual(PL.invite.customReasonText('Family commitment'), '');
  assert.strictEqual(PL.invite.customReasonText('Another reason'), 'Another reason');
  assert.strictEqual(PL.invite.customReasonText('Away that weekend'), 'Away that weekend');
});

test('summaryRows: what a going guest answered', () => {
  const party = { dates: [{ id: 'a', date: '2026-11-01' }, { id: 'b', date: '2026-11-08' }], customQuestions: [{ id: 'q1' }, { id: 'q2' }] };
  const resp = { status: 'accepted', cancelReason: '', dateVotes: ['b', 'a', 'gone'], plusOneRequested: true, plusOneName: 'Alex', dietary: 'Vegan', drinkPreferences: ['Beer', 'Wine'], answers: { q1: 'yes', q2: '  ' } };
  const rows = plain(PL.invite.summaryRows(resp, party, { hostName: 'Sam', fmtDate: (d) => 'D' + d.slice(-2) }));
  assert.deepStrictEqual(rows, [
    ['Answer', "Going \u{1F389}"],
    ['Dates', 'D01, D08'],
    ['Plus one', 'Alex · awaiting Sam'],
    ['Dietary', 'Vegan'],
    ['Drinks', 'Beer, Wine'],
    ['Questions', '1 of 2 answered'],
  ]);
});

test('summaryRows: just you, no extras, maybe and declined', () => {
  const party = {};
  const going = plain(PL.invite.summaryRows({ status: 'maybe', dateVotes: [], plusOneRequested: false, dietary: '', drinkPreferences: [], answers: {} }, party, {}));
  assert.deepStrictEqual(going, [['Answer', "Maybe \u{1F914}"], ['Plus one', 'Just you']]);
  const no = plain(PL.invite.summaryRows({ status: 'declined', cancelReason: 'Family commitment' }, party, {}));
  assert.deepStrictEqual(no, [['Answer', "Can't make it"], ['Reason', 'Family commitment']]);
  assert.deepStrictEqual(plain(PL.invite.summaryRows({ status: 'declined', cancelReason: '' }, party)), [['Answer', "Can't make it"]]);
  assert.deepStrictEqual(plain(PL.invite.summaryRows(null, party)), []);
});

test('summaryRows: plus one without a name, unnamed host', () => {
  const rows = plain(PL.invite.summaryRows({ status: 'accepted', plusOneRequested: true, plusOneName: '' }, {}, {}));
  assert.deepStrictEqual(rows[1], ['Plus one', 'Requested · awaiting the host']);
});

test('initialChoice: pre-selects a previous answer, never "pending"', () => {
  assert.strictEqual(PL.invite.initialChoice({ status: 'accepted' }), 'accepted');
  assert.strictEqual(PL.invite.initialChoice({ status: 'maybe' }), 'maybe');
  assert.strictEqual(PL.invite.initialChoice({ status: 'declined' }), 'declined');
  assert.strictEqual(PL.invite.initialChoice({ status: 'pending' }), '');
  assert.strictEqual(PL.invite.initialChoice(null), '');
});
