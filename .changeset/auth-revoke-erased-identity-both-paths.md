---
'@gentleduck/auth': major
---

Refuse a session whose identity was erased, on both resolution paths.

`resolveSession` resolves a request two ways: a transport that can verify a token
statelessly, else a lookup by sid. Only the sid path refused an erased identity. The
verify path did the same lookup and returned `{ session, identity: null }`, which is
truthy, so `makeGuard` passed it and a deleted user was authenticated.

The check now lives in `finalize`, which both paths already call, so neither can skip it
and a third added later cannot either. `resolveBySid` keeps its own copy because it is
exported and callable directly.

Reaching the weaker path was one line: `jwtTransport` and `dpopTransport` both define
`verify` and are exported from the same module as `cookieTransport` and
`bearerTransport`, so adding one to an existing `compositeTransport` array moved every
request onto it with no other change and no test failing.

BREAKING: `resolveSession` now throws `AUTH_SESSION_REVOKED` on the verify path where it
previously returned a result with a null identity. Callers treating a null return as
"not signed in" will see the error instead, which is what the sid path already did.

Both paths also agree on a cross-tenant token now. The tenant comparison moved into
`resolveBySid`, which is the only place it can run before the erased-identity throw, so
a token for a foreign tenant looks absent on either path whether or not its identity
still exists, and the identity is never looked up at all.
