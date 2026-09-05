---
'@gentleduck/auth': patch
---

Every mutating call on the public API now answers with what it did.

A write that returns `void` cannot be told apart from a write that matched nothing, and forces a second read for information the statement already had. Across the engine's surface, the mutating calls now return the row, the rows, or the count they touched — `null` / `[]` / `0` when nothing matched.

**Identities.** `softDelete`, `erase`, `link`, `unlink` and `merge` return the row (`restore` already did). Where the dialect has `RETURNING` this is the same round trip; MySQL re-selects by primary key, as it already does for `update` and `restore`. `erase` answers with the row as it was immediately before deletion; `merge` with the survivor, already carrying the union of both provider lists.

**Sessions.** `revoke` and `revokeByHash` return the session they ended — the row is already read to find it. `revokeAllForIdentity` returns the sessions it ended, so "you were signed out of 4 devices" needs no second query; that list was already read to emit one event per session.

**Credentials.** The store's `revoke` and `delete` return the row, `deleteByKind` the rows. On top of that, `apiKeys.revoke` answers with the key it revoked, and `mfa.removeTotp` / `removeWebauthnMfa` answer `{ removed }` — the count, not the rows, which carry the shared secret.

**Orgs.** `removeMember` answers with the membership as it stands left, `setRoles` with the membership carrying its new roles — the *sanitized* set actually stored, not the one passed in.

**Flows.** `completeAccountDeletion`, `cancelAccountDeletion`, `completeEmailVerification`, `linkProvider` and `unlinkProvider` carry the identity back as `identity`, alongside the fields they already returned. `completeAccountDeletion`'s `restorableUntil` is now read off the `deletedAt` the store actually wrote rather than a second reading of the clock, so the deadline reported is the one `restore` is measured against.

**Operations, webhooks, pending, anomaly.** `operations.maintenance` / `readOnly` return the resulting `State`. `webhooks.deliverOne` returns one `Delivery` per eligible endpoint — `{ endpointId, delivered, attempts, lastError? }`. `pending.flush` returns `{ published }` and `discard` `{ discarded }`. `anomaly.unregister` returns whether it removed anything.

Assertions (`apiKeys.requireScopes`, `operations.assertOperationsForRoute`, `hijack.applyReaction`), registrations (`anomaly.register`, `providers.register`) and `plugins.dispose` stay `void`: they throw or they do not, and a return value would be noise.

Four silent failures fell out of making the returns honest:

- `merge` wrote nothing and reported success when the survivor or the dup did not exist. On the SQL dialects it was worse than a no-op: the dup's credentials and sessions were re-pointed at an identity that was not there and the dup was then deleted. The memory adapter had always refused this; every dialect now agrees, and `IdentitiesFacet.merge` checks the survivor before any of it runs, reporting `AUTH_UNAUTHENTICATED`.
- `flows.completeAccountDeletion` reported `{ identityId, restorableUntil }` for a valid token whose identity had since been erased, promising a grace window over nothing. It now reports `AUTH_RECOVERY_TOKEN_INVALID`.
- `webhooks.deliverOne` dropped a permanently failed delivery in silence when no dead-letter sink was configured — no log, no return value, nothing to distinguish it from one that landed. This was pinned as a finding; the per-endpoint outcome closes it.
- `identities.eraseMany`'s loop fallback reports `not-found` for an id that was not there, matching the set-based path, which always did.

**Breaking for custom adapter authors.** `Identities.Store` and `SqlBridge.Identity` type `softDelete`, `erase`, `link`/`insertProviderLink`, `unlink`/`deleteProviderLink` and `merge` as returning the row or `null`; `Credential.Store` and `SqlBridge.Credential` type `revoke` and `delete` the same way and `deleteByKind` as returning the rows; `Org.Store` types `removeMember` and `setRoles` as returning the membership or `null`. An adapter that returns `void` will not typecheck; return what you touched.
