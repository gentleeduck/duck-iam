---
'@gentleduck/auth': major
---

Expired sessions are no longer accepted at any privileged gate.

`SessionsImpl.getBySid` hashed the sid and returned whatever the store had — no expiry check at all. `resolveBySid`, in the same file, checks both deadlines and deletes the row. Two reads that look alike, one of them unsafe, and four call sites depended on the unsafe one:

- **`completeStepUp`** — an expired sid completed a step-up, and `rotateOrCreate` minted a brand new live session from the dead one. Presenting an expired sid did not merely pass the gate; it resurrected the session.
- **`impersonate`** — an expired admin session could start an impersonation, and the app's own `authorize(real, target)` callback was handed that dead session to judge.
- **`completePasswordReset`** — a stale session with `aal >= 2` satisfied the MFA gate, so a valid reset token plus a long-dead session changed the password with no live MFA behind it.
- The Redis store serving rows past `expiresAt` was correct layering — expiry is the facet's policy, not the store's — but this is what made it reachable.

`getBySid` now refuses a session past either deadline and deletes the row, the same side effect `resolveBySid` has. Folded into the read rather than patched at each call site, so the fifth caller added later cannot reintroduce it.

**`fresh` is computed, not read.** It was a persisted boolean that only `touch()` ever refreshed, so a session written `fresh: true` and never touched still claimed freshness weeks later — and the password-reset gate reads exactly that field. `getBySid` now derives it from `rotatedAt` and `freshnessMs`.

**Also:** the date narrowing copy-pasted across `getBySid`, `touch` and `resolveBySid` is one `isSessionExpired` helper now, which removed the four `as number` casts those copies carried. It fails closed on a non-finite or missing deadline, because `NaN < now` is `false` — a lenient read keeps a should-be-dead session alive forever.

**Breaking:**

- `getBySid` returns `null` for an expired session instead of the row, and **deletes** it. Code relying on it to read expired rows must go to `Sessions.Store.getByHash` directly.
- The `fresh` field on a session returned by `getBySid` is now computed from `rotatedAt`. A session that was stored `fresh: true` but rotated longer ago than `freshnessMs` now reports `false` — which is what the gates guarding password changes and step-up were always meant to see.
- New exports `isSessionExpired` and `isSessionFresh` from `~/core/sessions`.

**Not covered:** `resolveBySid` still reports the stored `fresh` rather than recomputing it. Closing that means threading `freshnessMs` through an exported signature, which wants its own decision.
