const { test } = require('node:test');
const assert = require('node:assert');
const { followAction, relationshipFromEdges, deriveRelationships } = require('./follows');

test('followAction: following a public account is active immediately', () => {
  assert.deepEqual(followAction({ targetIsPublic: true, reverseStatus: null }),
    { forward: 'active', activateReverse: false });
});

test('followAction: following a private account is a pending request', () => {
  assert.deepEqual(followAction({ targetIsPublic: false, reverseStatus: null }),
    { forward: 'pending', activateReverse: false });
});

test('followAction: reverse pending (they requested us) -> friends', () => {
  assert.deepEqual(followAction({ targetIsPublic: false, reverseStatus: 'pending' }),
    { forward: 'active', activateReverse: true });
});

test('followAction: reverse active (they follow us) -> follow back makes friends', () => {
  assert.deepEqual(followAction({ targetIsPublic: true, reverseStatus: 'active' }),
    { forward: 'active', activateReverse: true });
});

test('followAction: reverse pending toward a public target -> friends', () => {
  assert.deepEqual(followAction({ targetIsPublic: true, reverseStatus: 'pending' }),
    { forward: 'active', activateReverse: true });
});

test('relationshipFromEdges: self', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 'v' }), 'self');
});

test('relationshipFromEdges: both active = friend', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: 'active', reverse: 'active' }), 'friend');
});

test('relationshipFromEdges: forward active only = following', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: 'active', reverse: null }), 'following');
});

test('relationshipFromEdges: reverse active only = follower', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: null, reverse: 'active' }), 'follower');
});

test('relationshipFromEdges: forward pending = requested', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: 'pending', reverse: null }), 'requested');
});

test('relationshipFromEdges: reverse pending = incoming', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: null, reverse: 'pending' }), 'incoming');
});

test('relationshipFromEdges: shared friend = mutual', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: null, reverse: null, viewerFriendIds: ['x'], targetFriendIds: ['x'] }), 'mutual');
});

test('relationshipFromEdges: nothing = stranger', () => {
  assert.equal(relationshipFromEdges({ viewerId: 'v', targetId: 't', forward: null, reverse: null, viewerFriendIds: ['x'], targetFriendIds: ['y'] }), 'stranger');
});

test('deriveRelationships: splits edges into the client lists', () => {
  const rows = [
    { follower_id: 'me', followee_id: 'fr', status: 'active' },   // me -> fr
    { follower_id: 'fr', followee_id: 'me', status: 'active' },    // fr -> me  => friend
    { follower_id: 'me', followee_id: 'pub', status: 'active' },   // me follows public, one-way
    { follower_id: 'me', followee_id: 'req', status: 'pending' },  // outgoing request
    { follower_id: 'inc', followee_id: 'me', status: 'pending' },  // incoming request
    { follower_id: 'fan', followee_id: 'me', status: 'active' },   // fan follows me, one-way
  ];
  const r = deriveRelationships('me', rows);
  assert.deepEqual(r.friends.sort(), ['fr']);
  assert.deepEqual(r.following.sort(), ['fr', 'pub']);
  assert.deepEqual(r.followers.sort(), ['fan', 'fr']);
  assert.deepEqual(r.outgoingRequests.sort(), ['req']);
  assert.deepEqual(r.incomingRequests.sort(), ['inc']);
});
