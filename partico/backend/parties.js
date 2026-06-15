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

module.exports = { buildStatePartyOr };
