---
'@gentleduck/auth': patch
---

Deleting an identity now ends every way into it, and a restore no longer resurrects claims the account can no longer prove.

`flows.signIn` re-reads the identity behind a `startSession` intent, so every sign-in provider was already covered. The credential-first surfaces were not: they resolve a credential row and hand back `row.identityId` without ever looking at the identity.

- `apiKeys.verify()` refuses a key whose identity has been soft-deleted or erased, reporting `AUTH_APIKEY_INVALID` — the same code as an unknown key, so whether an id still exists is not something an unauthenticated caller can probe. `M2MImpl.exchange()` is covered by the same check; it previously minted a live bearer token for a deleted account. `apiKeyProvider()` wires the identity store in automatically, and the constructor argument is optional so a direct `new ApiKeysFacet(...)` keeps working.
- `authRefreshoauthToken` accepts an optional `identities` probe and refuses to refresh for a deleted identity. The check runs before the CAS claim and before the provider exchange, so a dead refresh costs nothing and leaves the row intact for a later restore.
- `softDelete` clears `emailVerified`. The unique indexes are partial on `deletedAt` and `findByEmail` filters the same way, so the address is genuinely free while the row is hidden; restoring must not hand back a verified claim to an address the identity may no longer control.
- `restore` refuses once the grace window has closed, reporting `AUTH_GRACE_EXPIRED`. The SQL bridges previously cleared `deletedAt` unconditionally, bringing back accounts whose window had long since closed — including ones already queued for hard purge — while the memory adapter refused them. The dialects now agree with the memory adapter.
- `restore` refuses when the address was claimed while the row was hidden, reporting `AUTH_EMAIL_TAKEN` instead of a raw unique-index driver error on SQL, or two live rows sharing an email on an adapter with no such index.

`assertRestorable`, `assertEmailFree` and `profileEmail` are exported from `~/adapters/sql` for bridge authors implementing `restore`.

Known gap, pinned as a `FINDING:` test rather than fixed: `completePasswordReset` still writes a new password to a soft-deleted account. It cannot produce a login, since both `findByEmail` and `findById` hide the row, but the write and its `recovery.password.completed` event both land.
