# Drinks: custom brands & multi-select preferences — design

**Date:** 2026-06-17
**File touched:** `partico-app2/partico/Partico-updated.html` (the live frontend)

## Problem

On the event builder's "Drinks" step the host taps preset pills (Champagne, Wine, Beer, …) plus a pill labelled **"Custom"**. Tapping "Custom" just toggles a literal pill called "Custom" into the list — there is no text input, so a host can never actually name a specific drink or brand. An unused `drinkInput` state variable shows this was meant to work but was never wired up.

On the guest side, the RSVP "Drink Preference" step only lets a guest pick **one** option. A guest who likes both wine and a particular beer cannot say so.

## Goal

1. Let the host add their own specific drinks/brands (e.g. Corona, Stella Artois, Aperol Spritz, Diet Coke) as well as the broad presets.
2. Make this obvious on the page — especially helpful for bigger events.
3. Let guests pick **multiple** drinks they'd enjoy, so the host can stock what everyone actually wants.
4. Let guests **type in their own** drink if it isn't on the host's list.

## Design

### Host — event builder, Step 5 "Drinks"

- **Remove** the broken `"Custom"` entry from the `drinkPresets` array. The remaining presets stay unchanged.
- **Add a "custom drink" input box** below the preset pills, styled as a highlighted card:
  - Heading: **"✏️ Add your choice of drink or brand"**
  - Helper text: *"Name specific beers, wines, cocktails — anything. Guests pick exactly what they'd like, so you stock what everyone actually wants."*
  - A text input (`form.drinkInput`) + a green `+` button. Pressing `+` or Enter adds the trimmed value to `form.drinkOptions` and clears the input. This mirrors the existing custom-questions pattern (`addQuestion`).
  - Ignore blank input and duplicates (case-insensitive) silently.
- **Custom drinks render as pills** in the same wrap row as presets. Because custom pills aren't in `drinkPresets`, they get a small ✕ affordance to remove them (tapping the pill toggles it off, same as `addDrink`). Presets keep their existing tap-to-toggle behaviour with no ✕.
- The "Ask guests drink preference?" toggle card stays as-is.

New handler (mirrors `addQuestion` at ~line 2310):

```js
const addCustomDrink = () => {
  const v = form.drinkInput.trim();
  if (!v) return;
  if (form.drinkOptions.some((d) => d.toLowerCase() === v.toLowerCase())) { set("drinkInput", ""); return; }
  set("drinkOptions", [...form.drinkOptions, v]);
  set("drinkInput", "");
};
```

### Guest — RSVP "Drink Preference" step

- Convert from single-select string to **multi-select array**.
- State: `const [drinkPrefs, setDrinkPrefs] = useState(myInvite?.drinkPreferences || (myInvite?.drinkPref ? [myInvite.drinkPref] : []));` — initialises from the new array, falling back to the old single string for already-submitted RSVPs.
- Each option in `party.drinkOptions` toggles in/out of `drinkPrefs` (checkmark shown when present). "💧 No preference" is a special row that, when tapped, clears `drinkPrefs` to `[]`; it shows as selected only when `drinkPrefs` is empty.
- Heading copy: **"Drink Preferences"**, sub: *"Pick everything you'd enjoy — tap as many as you like"*.
- **Guest "add your own" box.** Below the option rows, a dashed card labelled *"Not on the list? ➕ Add your own"* with a text input (`guestDrinkInput` state) + `+` button. Pressing `+` or Enter adds the trimmed value into `drinkPrefs` (selected immediately) and clears the input; blank and case-insensitive duplicates are ignored. Guest-added drinks render as selected rows in the same list and can be toggled off like any other.
  - These free-text entries live in the same `drinkPreferences` array, so they flow into the host's guest row and stat bars with no extra work.

### Save / data model

- The invite object already carries both `drinkPref: ""` (string, legacy) and `drinkPreferences: []` (array). We make **`drinkPreferences` the canonical field**.
- `handleSubmit` saves `drinkPreferences: drinkPrefs` (drop `drinkPref` from the payload).
- The invite seed objects (lines ~742 and ~1000) already include `drinkPreferences: []` / will be normalised; no schema migration needed since it's client-side localStorage/synced JSON.

### Host dashboard (responses view)

Two read sites must use the array, with a fallback to the legacy string so old RSVPs still show:

- **Per-guest row** (~line 2905): replace `inv.drinkPref` display with a joined list — `(inv.drinkPreferences && inv.drinkPreferences.length ? inv.drinkPreferences.join(", ") : inv.drinkPref)`.
- **Drink stats counts** (~lines 2847–2853): iterate each guest's `drinkPreferences` array (fallback to `[inv.drinkPref]` when the array is empty but the string is set), incrementing `drinkCounts[drink]` per chosen drink. The existing horizontal-bar render stays the same.

> Note: `computeStats` (~line 884) already reads `invite.drinkPreferences`, so it becomes correct automatically once guests save the array.

## Out of scope (YAGNI)

- No nested "brands grouped under a category" structure — flat list only.
- No per-drink quantity / "expected drinks" changes.
- No backend schema changes (data is JSON, client-driven).

## Testing / verification

Manual walkthrough in the app:
1. Create a big event → Drinks step → confirm no "Custom" pill; add "Corona" and "Aperol Spritz" via the input; confirm they appear as removable pills and the hint text reads correctly.
2. Remove a custom pill; confirm it disappears.
3. As a guest, RSVP → Drinks step → select multiple drinks; type a drink not on the list ("Espresso Martini") and confirm it's added + selected; verify "No preference" clears all of them; submit.
4. As host, open responses → confirm the guest row lists all chosen drinks and the drink stat bars count each one.
5. Re-open a previously-submitted RSVP (old single `drinkPref`) → confirm it still displays and pre-selects correctly.
