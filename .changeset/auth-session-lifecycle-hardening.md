---
'@gentleduck/auth': major
---

Harden session creation, rotation and expiry.

`sessions.create` validated that `factors` was an array of at most 16 but never what was
in it. The Redis reader drops an unlisted method and a non-Date `completedAt` on the way
back out, so a malformed entry persisted a row that could not be read back intact. Each
entry is now checked to be `{ method: FactorMethod, completedAt: Date }`. `fingerprint`
is header-derived like `ip` and `userAgent` and is now capped like them, at 256
characters.

`rotateOrCreate` handled `credential-change` after minting the replacement and then
skipped that row by id while sweeping, which only held because the store had already been
read. It sweeps the identity first and mints afterwards, so the ordering is not
load-bearing. The purpose switch gained a `never` default: adding a purpose without
deciding its revocation semantics is a build error rather than a silent no-op, which is
how a new purpose would otherwise ship revoking nothing.

`touch` extended a session's sliding expiry without checking it first, so a session whose
`expiresAt` had already passed, or was non-finite, was revived by the next request that
touched it, even though `resolveBySid` would have rejected it. It deletes the row and
fails closed.

`session.created` now carries the identity when the caller already holds it (sign-in,
sign-up, impersonation), so a listener does not have to re-read the row it was just
handed. `createGuest` and `promoteGuest` return the csrf token they were already minting,
and `promoteGuest` forwards `fingerprint` and `actingAs`, so guest device-binding
survives promotion.

BREAKING: `sessions.create` throws `AUTH_MISCONFIGURED` on a malformed factor entry it
used to persist. Callers building factors by hand should confirm `completedAt` is a
`Date` and not an ISO string.
