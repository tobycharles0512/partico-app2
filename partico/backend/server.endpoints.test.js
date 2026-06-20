// Integration tests for the follow-graph Express endpoints.
//
// These exercise the real route handlers in server.js (doFollow / doRespond /
// doUnfollow, /api/follow*, /api/state) against a SCRIPTABLE STUB that stands
// in for the Supabase client. They verify the handler logic that unit tests
// don't reach: decision ordering, which row/status gets written, response
// assembly, auth wiring, and the two bugs found during preview testing.
//
// SCOPE / HONEST CAVEAT: the stub records and answers queries; it does NOT
// reproduce PostgREST filter semantics. So these prove the handlers DECIDE and
// WRITE the right things, not that the `.or()/.eq()` strings return the right
// rows from a real database. True end-to-end still needs a live Supabase run.

process.env.JWT_SECRET = 'test-secret';
process.env.SUPABASE_URL = '';            // keep server.js from building a real client
process.env.SUPABASE_SERVICE_ROLE_KEY = '';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const { app, __setSupabase } = require('./server');

const ME = 'u_me';
const token = jwt.sign({ id: ME }, 'test-secret');

let server, base;
before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server && server.close());

// A chainable stub that records every terminal query and answers via `resolve`.
function makeStub(resolve) {
  const calls = [];
  function from(table) {
    const q = { table, op: 'select', cols: null, eq: {}, neq: {}, or: null, in: null, payload: null, conflict: null, single: false, selectedAfterWrite: false };
    const exec = () => { const result = resolve(q) || { data: null, error: null }; calls.push({ q, result }); return result; };
    const b = {
      select(cols) { if (q.op === 'select') q.cols = cols; else q.selectedAfterWrite = true; return b; },
      eq(c, v) { q.eq[c] = v; return b; },
      neq(c, v) { q.neq[c] = v; return b; },
      or(s) { q.or = s; return b; },
      in(c, v) { q.in = [c, v]; return b; },
      limit() { return b; },
      upsert(payload, conflict) { q.op = 'upsert'; q.payload = payload; q.conflict = conflict; return b; },
      update(payload) { q.op = 'update'; q.payload = payload; return b; },
      delete() { q.op = 'delete'; return b; },
      maybeSingle() { q.single = true; return Promise.resolve(exec()); },
      single() { q.single = true; return Promise.resolve(exec()); },
      then(onF, onR) { return Promise.resolve(exec()).then(onF, onR); },
    };
    return b;
  }
  return { from, calls };
}

// Wrap a resolver so the requireAuth user lookup always succeeds for ME.
function authAware(resolve) {
  return (q) => {
    if (q.table === 'partico_users' && q.single && q.cols === '*' && q.eq.id === ME) {
      return { data: { id: ME, username: 'me', email: 'me@test.app', is_public: false }, error: null };
    }
    return resolve(q);
  };
}

function api(path, opts = {}) {
  return fetch(base + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(opts.headers || {}) },
  }).then(async (r) => ({ status: r.status, body: await r.json() }));
}

// Resolve a partico_follows single read by its edge direction.
function edge(q, fwdStatus, revStatus) {
  if (q.table !== 'partico_follows' || !q.single) return undefined;
  if (q.eq.follower_id === ME) return { data: fwdStatus ? { status: fwdStatus } : null, error: null };       // me -> target (forward)
  return { data: revStatus ? { status: revStatus } : null, error: null };                                    // target -> me (reverse)
}

test('POST /api/follow: following a PUBLIC account writes an active edge, no reverse activation', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_users' && q.cols === 'id, is_public') return { data: { id: 'u_pub', is_public: true }, error: null };
    const e = edge(q, null, null); if (e) return e;
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow', { method: 'POST', body: JSON.stringify({ targetId: 'u_pub' }) });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'active');
  const upserts = stub.calls.filter((c) => c.q.op === 'upsert');
  assert.equal(upserts.length, 1);
  assert.equal(upserts[0].q.payload.status, 'active');
  assert.equal(stub.calls.filter((c) => c.q.op === 'update').length, 0);
});

test('POST /api/follow: following a PRIVATE account writes a pending request', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_users' && q.cols === 'id, is_public') return { data: { id: 'u_priv', is_public: false }, error: null };
    const e = edge(q, null, null); if (e) return e;
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow', { method: 'POST', body: JSON.stringify({ targetId: 'u_priv' }) });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'pending');
  assert.equal(stub.calls.find((c) => c.q.op === 'upsert').q.payload.status, 'pending');
});

test('POST /api/follow: a reverse request makes both active (friends)', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_users' && q.cols === 'id, is_public') return { data: { id: 'u_x', is_public: false }, error: null };
    const e = edge(q, null, 'pending'); if (e) return e; // they already requested me
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow', { method: 'POST', body: JSON.stringify({ targetId: 'u_x' }) });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'friend');
  assert.equal(stub.calls.find((c) => c.q.op === 'upsert').q.payload.status, 'active');
  const upd = stub.calls.find((c) => c.q.op === 'update');
  assert.ok(upd, 'reverse edge should be activated');
  assert.equal(upd.q.payload.status, 'active');
  assert.equal(upd.q.eq.follower_id, 'u_x');
  assert.equal(upd.q.eq.followee_id, ME);
});

test('POST /api/follow: an existing active follow is NOT downgraded to pending (regression)', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_users' && q.cols === 'id, is_public') return { data: { id: 'u_priv', is_public: false }, error: null };
    const e = edge(q, 'active', null); if (e) return e; // I already actively follow them; they are now private
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow', { method: 'POST', body: JSON.stringify({ targetId: 'u_priv' }) });
  assert.equal(res.status, 200);
  assert.equal(stub.calls.find((c) => c.q.op === 'upsert').q.payload.status, 'active'); // stayed active, not pending
});

test('POST /api/follow: self-follow is rejected with no DB writes', async () => {
  const stub = makeStub(authAware(() => ({ data: null, error: null })));
  __setSupabase(stub);
  const res = await api('/api/follow', { method: 'POST', body: JSON.stringify({ targetId: ME }) });
  assert.equal(res.status, 400);
  assert.equal(stub.calls.filter((c) => ['upsert', 'update', 'delete'].includes(c.q.op)).length, 0);
});

test('POST /api/follow/respond: accepting a real request activates it and creates the return edge', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_follows' && q.op === 'update') return { data: [{ follower_id: 'u_x', followee_id: ME }], error: null };
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow/respond', { method: 'POST', body: JSON.stringify({ fromUserId: 'u_x', accept: true }) });
  assert.equal(res.status, 200);
  assert.ok(stub.calls.find((c) => c.q.op === 'update'), 'incoming edge updated to active');
  const up = stub.calls.find((c) => c.q.op === 'upsert');
  assert.ok(up, 'return edge created');
  assert.equal(up.q.payload.status, 'active');
});

test('POST /api/follow/respond: accepting with NO pending request creates no phantom follow (regression)', async () => {
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_follows' && q.op === 'update') return { data: [], error: null }; // nothing matched
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/follow/respond', { method: 'POST', body: JSON.stringify({ fromUserId: 'u_x', accept: true }) });
  assert.equal(res.status, 200);
  assert.equal(stub.calls.filter((c) => c.q.op === 'upsert').length, 0); // no return edge manufactured
});

test('POST /api/follow/respond: declining deletes the incoming pending edge', async () => {
  const stub = makeStub(authAware(() => ({ data: null, error: null })));
  __setSupabase(stub);
  const res = await api('/api/follow/respond', { method: 'POST', body: JSON.stringify({ fromUserId: 'u_x', accept: false }) });
  assert.equal(res.status, 200);
  const del = stub.calls.find((c) => c.q.op === 'delete');
  assert.ok(del, 'pending edge deleted');
  assert.equal(del.q.eq.follower_id, 'u_x');
  assert.equal(del.q.eq.followee_id, ME);
});

test('POST /api/unfollow: deletes only the caller\'s outbound edge', async () => {
  const stub = makeStub(authAware(() => ({ data: null, error: null })));
  __setSupabase(stub);
  const res = await api('/api/unfollow', { method: 'POST', body: JSON.stringify({ targetId: 'u_x' }) });
  assert.equal(res.status, 200);
  const del = stub.calls.find((c) => c.q.op === 'delete');
  assert.ok(del);
  assert.equal(del.q.eq.follower_id, ME);   // my outbound edge only
  assert.equal(del.q.eq.followee_id, 'u_x');
});

test('GET /api/state: derives friends/following/followers/requests from follow rows', async () => {
  const followRows = [
    { follower_id: ME, followee_id: 'fr', status: 'active' },
    { follower_id: 'fr', followee_id: ME, status: 'active' },   // mutual => friend
    { follower_id: ME, followee_id: 'pub', status: 'active' },  // one-way following
    { follower_id: ME, followee_id: 'req', status: 'pending' }, // outgoing request
    { follower_id: 'inc', followee_id: ME, status: 'pending' }, // incoming request
  ];
  const stub = makeStub(authAware((q) => {
    if (q.table === 'partico_follows' && q.op === 'select') return { data: followRows, error: null };
    if (q.table === 'partico_party_invites') return { data: [], error: null };
    if (q.table === 'partico_parties') return { data: [], error: null };
    if (q.table === 'partico_users' && q.in) return { data: [{ id: ME, username: 'me', email: 'me@test.app' }], error: null };
    return { data: null, error: null };
  }));
  __setSupabase(stub);
  const res = await api('/api/state');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.friends.sort(), ['fr']);
  assert.deepEqual(res.body.following.sort(), ['fr', 'pub']);
  assert.deepEqual(res.body.followers.sort(), ['fr']);
  assert.deepEqual(res.body.outgoingRequests.sort(), ['req']);
  assert.deepEqual(res.body.incomingRequests.sort(), ['inc']);
  assert.deepEqual(res.body.friendRequests, [{ from: 'inc', status: 'pending' }]);
  // the new arrays are also attached to user (what the frontend reads)
  assert.deepEqual(res.body.user.following.sort(), ['fr', 'pub']);
  assert.deepEqual(res.body.user.followers.sort(), ['fr']);
});
