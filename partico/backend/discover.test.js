const { test } = require('node:test');
const assert = require('node:assert');
const { relationshipTo, canDiscover, selectDiscoverable } = require('./discover');

test('relationshipTo: host is a direct friend', () => {
  assert.equal(relationshipTo('v', 'h', ['h'], []), 'friend');
});

test('relationshipTo: shared friend makes the host mutual', () => {
  assert.equal(relationshipTo('v', 'h', ['x'], ['x']), 'mutual');
});

test('relationshipTo: no connection is a stranger', () => {
  assert.equal(relationshipTo('v', 'h', ['x'], ['y']), 'stranger');
});

test('relationshipTo: viewer is the host', () => {
  assert.equal(relationshipTo('v', 'v', [], []), 'self');
});

test('canDiscover: everyone is visible to all relationships', () => {
  assert.equal(canDiscover('everyone', 'stranger'), true);
  assert.equal(canDiscover(undefined, 'stranger'), true); // missing => everyone
});

test('canDiscover: mutual is visible to friend and mutual only', () => {
  assert.equal(canDiscover('mutual', 'friend'), true);
  assert.equal(canDiscover('mutual', 'mutual'), true);
  assert.equal(canDiscover('mutual', 'stranger'), false);
});

test('canDiscover: friends is visible to direct friends only', () => {
  assert.equal(canDiscover('friends', 'friend'), true);
  assert.equal(canDiscover('friends', 'mutual'), false);
  assert.equal(canDiscover('friends', 'stranger'), false);
});

test('selectDiscoverable: keeps events the viewer may see, drops private and own', () => {
  const parties = [
    { id: 'p1', hostId: 'h1', isPrivate: false, audience: 'everyone' },
    { id: 'p2', hostId: 'h2', isPrivate: false, audience: 'mutual' },
    { id: 'p3', hostId: 'h3', isPrivate: false, audience: 'friends' },
    { id: 'p4', hostId: 'h4', isPrivate: true, audience: 'everyone' },
    { id: 'p5', hostId: 'me', isPrivate: false, audience: 'everyone' },
  ];
  const result = selectDiscoverable({
    parties,
    viewerId: 'me',
    viewerFriendIds: ['h3', 'shared'],
    hostFriendsById: { h1: [], h2: ['shared'], h3: [] },
  });
  assert.deepEqual(result.map((p) => p.id).sort(), ['p1', 'p2', 'p3']);
});

test('selectDiscoverable: hides mutual/friends events from an unconnected viewer', () => {
  const parties = [
    { id: 'p2', hostId: 'h2', isPrivate: false, audience: 'mutual' },
    { id: 'p3', hostId: 'h3', isPrivate: false, audience: 'friends' },
  ];
  const result = selectDiscoverable({
    parties,
    viewerId: 'me',
    viewerFriendIds: [],
    hostFriendsById: { h2: ['x'], h3: ['y'] },
  });
  assert.deepEqual(result.map((p) => p.id), []);
});
