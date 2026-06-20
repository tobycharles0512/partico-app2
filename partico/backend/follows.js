// Pure, dependency-free helpers for the directed follow graph.
// Each partico_follows row is one edge: follower_id -> followee_id, with
// status 'active' | 'pending'. A mutual active pair = "friends".
// See docs/superpowers/specs/2026-06-18-public-private-accounts-follow-model-design.md

// Decide the edge mutations when `viewer` follows `target`.
//   targetIsPublic : boolean  - the target's is_public flag
//   reverseStatus  : 'active' | 'pending' | null - existing target->viewer edge
// Returns { forward: 'active'|'pending', activateReverse: boolean }.
// If the target already follows or has already requested the viewer, the
// viewer following back makes them friends (both edges active).
function followAction({ targetIsPublic, reverseStatus }) {
  if (reverseStatus === 'active' || reverseStatus === 'pending') {
    return { forward: 'active', activateReverse: true };
  }
  return { forward: targetIsPublic ? 'active' : 'pending', activateReverse: false };
}

// Resolve the viewer's relationship label to a target.
// forward = viewer->target status, reverse = target->viewer status
// (each 'active' | 'pending' | null). viewerFriendIds / targetFriendIds drive
// the friend-of-friend 'mutual' tier.
function relationshipFromEdges({ viewerId, targetId, forward, reverse, viewerFriendIds, targetFriendIds }) {
  if (targetId === viewerId) return 'self';
  if (forward === 'active' && reverse === 'active') return 'friend';
  if (forward === 'active') return 'following';
  if (reverse === 'active') return 'follower';
  if (forward === 'pending') return 'requested';
  if (reverse === 'pending') return 'incoming';
  const vSet = new Set(viewerFriendIds || []);
  if ((targetFriendIds || []).some((id) => vSet.has(id))) return 'mutual';
  return 'stranger';
}

// From all partico_follows rows that involve `userId`, derive the lists the
// client needs. rows: [{ follower_id, followee_id, status }].
function deriveRelationships(userId, rows) {
  const fwd = new Map(); // other -> status of userId->other
  const rev = new Map(); // other -> status of other->userId
  for (const r of rows || []) {
    if (r.follower_id === userId) fwd.set(r.followee_id, r.status);
    if (r.followee_id === userId) rev.set(r.follower_id, r.status);
  }
  const friends = [];
  const following = [];        // active forward (includes friends)
  const followers = [];        // active reverse (includes friends)
  const outgoingRequests = []; // pending forward
  const incomingRequests = []; // pending reverse
  for (const o of new Set([...fwd.keys(), ...rev.keys()])) {
    const f = fwd.get(o) || null;
    const rv = rev.get(o) || null;
    if (f === 'active' && rv === 'active') friends.push(o);
    if (f === 'active') following.push(o);
    if (rv === 'active') followers.push(o);
    if (f === 'pending') outgoingRequests.push(o);
    if (rv === 'pending') incomingRequests.push(o);
  }
  return { friends, following, followers, outgoingRequests, incomingRequests };
}

module.exports = { followAction, relationshipFromEdges, deriveRelationships };
