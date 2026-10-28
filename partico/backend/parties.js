// Pure helpers for the parties a user should load in their account state.

// Builds the PostgREST `or` filter describing which parties a user should
// receive from GET /api/state:
//   - parties they host
//   - parties they're invited to
//   - every public party (so the Discover feed works for brand-new accounts)
//
// The privacy flag lives inside the party's JSON `data` column. The frontend
// treats `!isPrivate` as public, so a party counts as public when isPrivate is
// explicitly false OR the flag is absent (null).
function buildStatePartyOr(meId, invitedPartyIds = []) {
  const conds = [`host_id.eq.${meId}`];
  if (Array.isArray(invitedPartyIds) && invitedPartyIds.length > 0) {
    conds.push(`id.in.(${invitedPartyIds.join(',')})`);
  }
  conds.push('data->>isPrivate.eq.false');
  conds.push('data->>isPrivate.is.null');
  return conds.join(',');
}

// ── Guest party sync ──
//
// The frontend syncs the WHOLE party object through POST /api/parties/sync,
// including from invited guests whose local cache may be stale. A guest's sync
// must never overwrite host-controlled fields (title, dates, description,
// checklist, inviteViews, ...). The only party fields a guest legitimately
// changes through a sync are:
//   - photos: addPhoto/addPhotos, removePhoto (own), requestPhotoRemoval,
//     resolvePhotoRemoval, and photo reactions — see sanitizePhotosSync.
//   - pops:   markPopRead adds the guest's id to a pop's readBy.
// Everything else is taken from the stored row.
const { sanitizePhotosSync } = require('./photo-permissions');

// A guest may only ADD themselves to readBy on pops that already exist. They
// can't create, edit, delete or reorder pops, nor touch anyone else's read mark.
function mergeGuestPopReads(existingPops, incomingPops, userId) {
  if (!Array.isArray(existingPops)) return existingPops;
  const incomingById = new Map(
    (Array.isArray(incomingPops) ? incomingPops : [])
      .filter((p) => p && p.id != null)
      .map((p) => [p.id, p])
  );
  return existingPops.map((pop) => {
    const inc = pop && incomingById.get(pop.id);
    const readBy = Array.isArray(pop && pop.readBy) ? pop.readBy : [];
    if (!inc || !Array.isArray(inc.readBy) || !inc.readBy.includes(userId) || readBy.includes(userId)) return pop;
    return { ...pop, readBy: [...readBy, userId] };
  });
}

function mergeGuestPartySync(existingData, incomingParty, userId) {
  const base = existingData && typeof existingData === 'object' ? existingData : {};
  const incoming = incomingParty && typeof incomingParty === 'object' ? incomingParty : {};
  const result = { ...base };
  delete result.id;
  delete result.hostId;
  delete result.invites;

  result.photos = sanitizePhotosSync(base.photos, incoming.photos, userId, false);
  if (Array.isArray(base.pops)) result.pops = mergeGuestPopReads(base.pops, incoming.pops, userId);
  return result;
}

module.exports = { buildStatePartyOr, mergeGuestPartySync, mergeGuestPopReads };
