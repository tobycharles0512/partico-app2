// Pure, dependency-free helpers deciding which public events a viewer may
// discover. Kept separate from server.js so they can be unit-tested without
// a database. See docs/superpowers/specs/2026-06-17-friends-only-public-events-design.md

// Relationship of a viewer to a host:
//   'self'    - the viewer is the host
//   'friend'  - the host is a direct friend of the viewer
//   'mutual'  - the viewer and host share at least one friend
//   'stranger'- no connection
function relationshipTo(viewerId, hostId, viewerFriendIds, hostFriendIds) {
  if (hostId === viewerId) return 'self';
  const vFriends = viewerFriendIds || [];
  if (vFriends.includes(hostId)) return 'friend';
  const vSet = new Set(vFriends);
  if ((hostFriendIds || []).some((fid) => vSet.has(fid))) return 'mutual';
  return 'stranger';
}

// Can a viewer with the given relationship discover an event of this audience?
function canDiscover(audience, relationship) {
  const a = audience || 'everyone';
  if (a === 'everyone') return true;
  if (a === 'mutual') return relationship === 'friend' || relationship === 'mutual';
  if (a === 'friends') return relationship === 'friend';
  return false;
}

// Filter composed party objects down to the ones the viewer may discover.
// Private events and the viewer's own events are excluded (own events arrive
// via /api/state). hostFriendsById maps a host id to that host's friend ids.
function selectDiscoverable({ parties, viewerId, viewerFriendIds, hostFriendsById }) {
  const friendsById = hostFriendsById || {};
  return (parties || []).filter((p) => {
    if (p.isPrivate) return false;
    if (p.hostId === viewerId) return false;
    const rel = relationshipTo(viewerId, p.hostId, viewerFriendIds, friendsById[p.hostId] || []);
    return canDiscover(p.audience, rel);
  });
}

module.exports = { relationshipTo, canDiscover, selectDiscoverable };
