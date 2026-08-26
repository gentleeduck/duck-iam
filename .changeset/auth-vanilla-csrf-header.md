---
'@gentleduck/auth': patch
---

Fix the vanilla client never sending the CSRF header, so every cookie-authenticated
write (`signOut` included) failed the server's `verifyCsrf` check. `createAuthClient`
now reads the CSRF cookie (`__Host-duck-csrf` by default) and echoes it on the
configured header (`x-csrf-token` by default) for any non-safe method; safe methods
(`GET`/`HEAD`/`OPTIONS`/`TRACE`) are left alone. Both names are configurable via
`csrfCookieName`/`csrfHeaderName` on `Cfg`.

`Provider`'s props and `client/react`'s types also gain the `Profile` generic they
were missing (`IProviderProps` had no type param, `client` was typed `Client<any>`),
so a consumer's custom profile type now flows through instead of being erased.
