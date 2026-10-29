// Fake backend data for boot.test.js. Shapes mirror partico/backend/server.js:
//   GET /api/state     -> { user, friends, following, followers, friendRequests,
//                           outgoingRequests, incomingRequests, parties, profiles }
//   GET /api/discover  -> { parties (with viewerRelationship), profiles }
//   GET /api/users/search -> { users: publicUser[] }
//   GET /api/auth/me   -> { user }
// Parties are composeParty() output: party.data spread + id/hostId + invites
// ({...invite.data, userId, status}). Profiles of other people are publicUser().
// Dates are relative to "now" so upcoming parties stay upcoming forever.

const PIXEL_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

function day(offset) {
  const d = new Date();
  d.setDate(d.getDate() + offset);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

const ME = 'u_me';
const T = Date.now();

// Full rows (what's in partico_users); others are exposed through publicUser().
const rows = {
  u_me: { id: ME, username: 'tobyc', email: 'toby@example.com', firstName: 'Toby', lastName: 'Charles', phone: '07700900000', bio: 'Always up for a party', profilePic: null, is_public: false, created_at: '2026-01-01T00:00:00Z' },
  u_ava: { id: 'u_ava', username: 'avat', email: 'ava.thompson@example.com', firstName: 'Ava', lastName: 'Thompson', bio: '', profilePic: null, is_public: false },
  u_ben: { id: 'u_ben', username: 'beno', email: 'ben.okafor@example.com', firstName: 'Ben', lastName: 'Okafor', bio: 'New flat!', profilePic: null, is_public: false },
  u_chloe: { id: 'u_chloe', username: 'chloem', email: 'chloe.martin@example.com', firstName: 'Chloe', lastName: 'Martin', bio: '', profilePic: null, is_public: true },
  u_dev: { id: 'u_dev', username: 'devp', email: 'dev.patel@example.com', firstName: 'Dev', lastName: 'Patel', bio: '', profilePic: null, is_public: false },
  u_ella: { id: 'u_ella', username: 'ellar', email: 'ella.rossi@example.com', firstName: 'Ella', lastName: 'Rossi', bio: '', profilePic: PIXEL_PNG, is_public: false },
  u_finn: { id: 'u_finn', username: 'finnw', email: 'finn.walsh@example.com', firstName: 'Finn', lastName: 'Walsh', bio: '', profilePic: null, is_public: false },
  u_grace: { id: 'u_grace', username: 'gracel', email: 'grace.lin@example.com', firstName: 'Grace', lastName: 'Lin', bio: 'Met you at Ella\'s', profilePic: null, is_public: false },
  u_hana: { id: 'u_hana', username: 'hanak', email: 'hana.kim@example.com', firstName: 'Hana', lastName: 'Kim', bio: 'Live music', profilePic: null, is_public: true },
};

function maskEmail(email) {
  const [local, domain] = email.split('@');
  const maskedLocal = local.length <= 4 ? (local[0] || '') + '***' : local.slice(0, 3) + '*****' + local.slice(-3);
  const dot = domain.lastIndexOf('.');
  const name = dot > 0 ? domain.slice(0, dot) : domain;
  const tld = dot > 0 ? domain.slice(dot) : '';
  const maskedName = name.length <= 3 ? (name[0] || '') + '***' : name.slice(0, 2) + '***' + name.slice(-1);
  return maskedLocal + '@' + maskedName + tld;
}
function publicUser(u) {
  return { id: u.id, username: u.username, email: maskEmail(u.email), firstName: u.firstName || '', lastName: u.lastName || '', bio: u.bio || '', profilePic: u.profilePic || null, is_public: u.is_public === true };
}

const FRIENDS = ['u_ava', 'u_ben', 'u_chloe', 'u_dev', 'u_ella', 'u_finn'];

// Invite as created by the app's inviteToParty(), then RSVP'd.
function invite(userId, status, extra = {}) {
  return { userId, status, dateVotes: [], drinkPref: '', dietary: '', answers: {}, plusOneRequested: false, plusOneApproved: false, plusOneName: '', costumeTheme: '', dressCodeStyle: '', drinkPreferences: [], expectedDrinks: 1, questions: [], respondedAt: status === 'pending' ? null : T - 3600e3, ...extra };
}
function photo(id, userId, name, offsetMs) {
  return { id, userId, userName: name, dataUrl: PIXEL_PNG, timestamp: T - offsetMs };
}
// Party as created by the app's createParty().
function party(p) {
  return {
    description: '', isPrivate: true, dates: [], confirmedDate: null,
    location: { address: '', parkingAddress: '', venueLat: null, venueLng: null, parkingLat: null, parkingLng: null },
    dressCode: { description: '', inspirationLinks: [], inspirationImages: [] },
    menu: { items: [], dietary: '' }, drinkOptions: [], askDrinkPref: false, customQuestions: [],
    invites: [], photos: [],
    fireworks: { enabled: true, colors: ['#00ff41', '#00d944'], style: 'classic' },
    eventType: 'party', customEventName: '', eventSize: 'big', coverImage: null, playlistUrl: '',
    moodBoard: [], smartSections: {}, inviteFont: '', inviteEffect: 'auto', inviteViews: 0,
    maxCapacity: null, audience: 'everyone', pops: [], status: 'upcoming',
    inviteLink: 'https://partico.app/#join-party?partyId=' + p.id, createdAt: T - 86400e3 * 7,
    ...p,
  };
}

const TITLES = {
  hosted: 'Rooftop Halloween Bash',
  attending: "Chloe's Birthday Dinner",
  invited: "Ben's Housewarming",
  pastHosted: 'Summer Garden Party',
  pastAttended: "Ella's Graduation",
  discover: 'Open Mic Night',
};

const parties = [
  // Hosted by me, upcoming, invites in every status; Ava wants a +1 not yet approved.
  party({
    id: 'p_hosted', hostId: ME, title: TITLES.hosted, description: 'Costumes mandatory.', eventType: 'halloween',
    dates: [{ date: day(12), time: '20:00' }, { date: day(13), time: '20:00' }],
    location: { address: '1 Rooftop Lane, London', parkingAddress: '', venueLat: 51.51, venueLng: -0.12, parkingLat: null, parkingLng: null },
    menu: { items: ['Pumpkin soup'], dietary: '' }, drinkOptions: ['Punch', 'Beer'], askDrinkPref: true,
    customQuestions: ['What are you dressing as?'],
    invites: [
      invite('u_ava', 'accepted', { plusOneRequested: true, plusOneName: 'Sam Rivers', plusOneApproved: false, dateVotes: [day(12)], drinkPref: 'Punch', answers: { 0: 'A vampire' } }),
      invite('u_ella', 'accepted'),
      invite('u_ben', 'maybe'),
      invite('u_chloe', 'pending'),
      invite('u_dev', 'declined'),
    ],
    pops: [{ id: 'pop1', from: ME, text: 'Bring a torch!', timestamp: T - 7200e3, readBy: [ME] }],
  }),
  // Upcoming party I'm attending (soonest => "next party" on home).
  party({
    id: 'p_attending', hostId: 'u_chloe', title: TITLES.attending, eventType: 'birthday',
    confirmedDate: { date: day(5), time: '19:30' }, dates: [{ date: day(5), time: '19:30' }],
    location: { address: '22 Market St, London', parkingAddress: '', venueLat: null, venueLng: null, parkingLat: null, parkingLng: null },
    invites: [
      invite(ME, 'accepted', { thread: [{ id: 'm1', from: 'u_chloe', text: 'Can you bring candles?', timestamp: T - 5400e3, readBy: ['u_chloe'] }] }),
      invite('u_finn', 'accepted'),
    ],
  }),
  // Pending invite to me, with a cover photo.
  party({
    id: 'p_invited', hostId: 'u_ben', title: TITLES.invited, description: 'Come see the new place.',
    dates: [{ date: day(20), time: '18:00' }], coverImage: PIXEL_PNG,
    invites: [invite(ME, 'pending'), invite('u_ava', 'accepted')],
  }),
  // Past party I hosted, with photos.
  party({
    id: 'p_past_hosted', hostId: ME, title: TITLES.pastHosted, status: 'past',
    confirmedDate: { date: day(-60), time: '14:00' }, dates: [{ date: day(-60), time: '14:00' }],
    invites: [invite('u_ava', 'accepted'), invite('u_finn', 'accepted')],
    photos: [photo('ph1', ME, 'Toby Charles', 60 * 86400e3), photo('ph2', 'u_ava', 'Ava Thompson', 59 * 86400e3)],
    createdAt: T - 90 * 86400e3,
  }),
  // Past party I attended, with photos (one with a pending removal request).
  party({
    id: 'p_past_attended', hostId: 'u_ella', title: TITLES.pastAttended, status: 'past',
    confirmedDate: { date: day(-30), time: '18:00' }, dates: [{ date: day(-30), time: '18:00' }],
    invites: [invite(ME, 'accepted'), invite('u_dev', 'accepted')],
    photos: [
      photo('ph3', 'u_ella', 'Ella Rossi', 30 * 86400e3),
      { ...photo('ph4', ME, 'Toby Charles', 29 * 86400e3), removalRequest: { by: 'u_dev', byName: 'Dev Patel', reason: 'unflattering', note: '', at: T - 86400e3 } },
    ],
    createdAt: T - 45 * 86400e3,
  }),
];

const discoverParty = {
  ...party({
    id: 'p_discover', hostId: 'u_hana', title: TITLES.discover, isPrivate: false, audience: 'everyone', eventType: 'party',
    dates: [{ date: day(9), time: '21:00' }],
    location: { address: 'The Old Bell, London', parkingAddress: '', venueLat: 51.52, venueLng: -0.1, parkingLat: null, parkingLng: null },
    invites: [invite('u_grace', 'accepted')],
  }),
  viewerRelationship: 'stranger',
};

function stateResponse() {
  const me = rows.u_me;
  const following = [...FRIENDS];
  const followers = [...FRIENDS, 'u_grace'];
  const ids = new Set([ME, ...FRIENDS, 'u_grace']);
  parties.forEach((p) => { ids.add(p.hostId); p.invites.forEach((i) => ids.add(i.userId)); });
  return {
    user: { ...me, friends: FRIENDS, following, followers, outgoingRequests: [] },
    friends: FRIENDS,
    following,
    followers,
    friendRequests: [{ from: 'u_grace', status: 'pending' }],
    outgoingRequests: [],
    incomingRequests: ['u_grace'],
    parties: JSON.parse(JSON.stringify(parties)),
    profiles: [...ids].map((id) => (id === ME ? { ...rows[id] } : publicUser(rows[id]))),
  };
}

function discoverResponse() {
  return { parties: [JSON.parse(JSON.stringify(discoverParty))], profiles: [publicUser(rows.u_hana)] };
}

function searchResponse(q) {
  const needle = (q || '').toLowerCase();
  if (!needle) return { users: [] };
  return { users: Object.values(rows).filter((u) => u.id !== ME && [u.username, u.email, u.firstName, u.lastName].some((f) => (f || '').toLowerCase().includes(needle))).map(publicUser) };
}

// What localStorage holds after a real login (ls.set JSON-encodes everything).
const AUTH_TOKEN = 'test.jwt.token';
function seedLocalStorage() {
  return {
    partico_auth_token: JSON.stringify(AUTH_TOKEN),
    partico_current_user: JSON.stringify({ friends: [], friendRequests: [], parties: [], notifs: [], ...rows.u_me }),
    partico_visited: 'yes',
    partico_force_dark_v1: 'true',
    partico_dark_mode: 'true',
  };
}

module.exports = { ME, rows, TITLES, FRIENDS, publicUser, stateResponse, discoverResponse, searchResponse, seedLocalStorage, AUTH_TOKEN };
