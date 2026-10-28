// Pure helper for validating a party's `photos[]` sync payload.
//
// The whole party (including photos) is normally upserted as one JSON blob
// from whatever guest happens to sync it — there's no per-field auth beyond
// "is this user invited?". This function tightens that for photos so a guest
// can only ever: edit/delete their own uploads, and set/retract a
// removalRequest attributed to themselves on someone else's upload, and
// set/change/clear only their OWN entry in any photo's `reactions`. The host
// bypasses all of this, matching the unrestricted control they already have
// over invites and other party fields.
function resolveRemovalRequest(existingRequest, incomingRequest, syncingUserId) {
  const existingIsSyncers = !!existingRequest && existingRequest.by === syncingUserId;

  if (!incomingRequest) {
    // Retracting: only the original requester may clear their own request.
    if (!existingRequest || existingIsSyncers) return null;
    return existingRequest;
  }

  // Raising/updating a request: only valid when attributed to the syncing user,
  // and it can't stomp on someone else's already-pending request.
  if (incomingRequest.by !== syncingUserId) return existingRequest || null;
  if (existingRequest && !existingIsSyncers) return existingRequest;
  return incomingRequest;
}

// Photo reactions: reactions = { [userId]: emoji }, at most one per user.
const ALLOWED_REACTIONS = ['🔥', '😂', '😍', '🙌'];

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Start from the stored reactions (every OTHER user's entry is kept verbatim —
// nobody may forge, change or delete someone else's reaction), then set,
// change or clear only the syncing user's own entry from the incoming photo.
// Returns undefined when there is nothing to store and nothing was stored.
function mergeReactions(existingReactions, incomingReactions, syncingUserId) {
  const out = {};
  if (isPlainObject(existingReactions)) {
    for (const [uid, emoji] of Object.entries(existingReactions)) {
      if (uid === '__proto__' || uid === syncingUserId) continue;
      out[uid] = emoji;
    }
  }
  const mine = isPlainObject(incomingReactions) && Object.prototype.hasOwnProperty.call(incomingReactions, syncingUserId)
    ? incomingReactions[syncingUserId]
    : undefined;
  if (ALLOWED_REACTIONS.includes(mine) && syncingUserId !== '__proto__') out[syncingUserId] = mine;

  if (Object.keys(out).length === 0 && !isPlainObject(existingReactions)) return undefined;
  return out;
}

function withReactions(photo, reactions) {
  const result = { ...photo };
  if (reactions === undefined) delete result.reactions;
  else result.reactions = reactions;
  return result;
}

function sanitizePhotosSync(existingPhotos, incomingPhotos, syncingUserId, isHost) {
  const existing = Array.isArray(existingPhotos) ? existingPhotos : [];
  const incoming = Array.isArray(incomingPhotos) ? incomingPhotos : [];

  if (isHost) return incoming;

  const incomingById = new Map(incoming.map((p) => [p.id, p]));
  const result = [];

  for (const oldPhoto of existing) {
    const incomingPhoto = incomingById.get(oldPhoto.id);
    const ownsPhoto = oldPhoto.userId === syncingUserId;

    if (ownsPhoto) {
      if (incomingPhoto) {
        result.push(withReactions(incomingPhoto, mergeReactions(oldPhoto.reactions, incomingPhoto.reactions, syncingUserId)));
      }
      continue; // owner deleted their own photo — allowed, just don't carry it forward
    }

    if (!incomingPhoto) {
      result.push(oldPhoto); // can't delete someone else's photo by omission
      continue;
    }

    result.push(withReactions({
      ...oldPhoto,
      removalRequest: resolveRemovalRequest(oldPhoto.removalRequest, incomingPhoto.removalRequest, syncingUserId)
    }, mergeReactions(oldPhoto.reactions, incomingPhoto.reactions, syncingUserId)));
  }

  const existingIds = new Set(existing.map((p) => p.id));
  for (const p of incoming) {
    if (!existingIds.has(p.id) && p.userId === syncingUserId) {
      result.push(withReactions(p, mergeReactions(undefined, p.reactions, syncingUserId)));
    }
  }

  return result;
}

module.exports = { sanitizePhotosSync, mergeReactions, ALLOWED_REACTIONS };
