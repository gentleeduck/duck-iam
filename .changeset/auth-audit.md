---
'@gentleduck/auth': minor
---

**A JWT verify key needs its `alg`.** `JwtTransport` refuses a `verifyKeys` entry, a `rotateSignKey` `verifyKey`
or a `signKey` that is HS256, the default when `alg` is omitted, but holds a PEM. Accepted, the public key became the
HMAC secret, and anyone holding it could sign a token for any identity. `rotateSignKey` also refuses a `verifyKey`
whose `alg` differs from the `signKey`'s, or an HS256 one with a different secret, as the constructor already did. If
your config now throws, add the `alg` the key was made for.

**An authoritative transport's refusal holds.** A composite member set `authoritative: true` refused a token, and
the engine then resolved the same token from the session store, since the refusal was `AUTH_SESSION_REVOKED`, which
reads as "not mine". DPoP beside a plain bearer, the case the flag exists for, was not protected at all. The veto is
now `AUTH_INVALID_CREDENTIALS`: `resolveSession` rejects with it, `orNull()` does not read it as an anonymous
request, and the store is not asked.

**An impersonation stays in the operator's tenant.** `impersonate` put the impersonating session in whatever
`tenantId` its caller passed, and never checked it against the operator's session. An operator signed in to one
tenant could act as a user in another, and `releaseImpersonation` then signed the operator in to that tenant as
themselves. With no `tenantId`, an operator in a tenant got a session in no tenant, which the tenant's routes
refuse. The impersonation is now in the operator's session's tenant. A `tenantId` naming another tenant throws
`AUTH_UNAUTHENTICATED` before `authorize` is asked.

**A rotated API key stays in its tenant.** `apiKeys.rotate(id)` called without the tenant context, as the docs
call it, answered a key with no tenant. That key no longer signed in at its own tenant, and did sign in on a request
with no tenant, which the key it replaced was refused. The successor now keeps the key's tenant.

**A TOTP enrollment begun before a WebAuthn factor cannot be finished after it.** `beginTotpEnrollment` refuses
while the account has a WebAuthn factor, but `confirmTotpEnrollment` confirmed any enrollment already pending.
Someone holding the password could begin one before the owner added a security key, confirm it afterwards, and step
up to AAL 2 past the key, holding the backup codes it minted. The confirm now refuses too, `AUTH_MFA_REQUIRED` with
`methods: ['webauthn']`.

**CSRF and a bearer on its own header or scheme.** A `bearerTransport({ scheme })` or `bearerTransport({ header })`
client was signed in and then refused `AUTH_CSRF` on every mutating request, since the bearer exemption only knew
`Authorization: Bearer`. `csrfGuard` and the Nest `makeGuard` now ask the engine's transport whether the request
carries a credential outside the Cookie header. `verifyCsrf` takes an optional `transport` for the same check. If
you set `isBearer: true` to work around this, drop it: it also skipped the token check for cookie requests.

**A password reset is no longer undone by a background rehash.** After a hashing-parameter upgrade, a sign-in
rehashes its stored password in the background. A reset that landed while that hash ran had its new row overwritten
with the old password's hash, so the old password worked again and the new one did not. `rehash` now rewrites a row
only while it still holds the password that was verified.

**An account nobody had proven the address of is cleared when its owner proves it.**

- A password reset now proves the address it was mailed to, as a magic link already did. On an account whose
  address was not verified, a reset kept whatever the person who signed it up had linked or enrolled. Someone who
  signed up with another person's address could link their own GitHub or create an API key, wait for the owner to
  reset the password, and then sign in to the account the owner had just recovered. Completing a reset on such an
  account now removes its provider links and credentials, in every tenant, and marks the address verified. A reset
  that carries a session of the same account keeps them, since its caller already held the account. As with a magic
  link, `'link-if-verified'` now links a federated sign-in into an account a reset proved.
- A magic link marked the address proven before it cleared the account. The squatter could stop the clearing
  part-way by changing their own password while it ran, which kept their password and left the account verified, so
  no later link cleared it. Now their sessions go first, then their providers and credentials, read twice to catch a
  write in flight, and the address is marked proven last. A clearing that fails leaves it unproven for the next
  link. `session.revoked` is emitted for each of the squatter's sessions.

**An account deletion link dies when the account changes address.** A deletion link mailed to the address the
account held deleted the account even after the account had moved to a new one, so whoever still held the old
mailbox could delete an account its owner had moved away from them. The link now carries the address it was mailed
to and is refused, `AUTH_RECOVERY_TOKEN_INVALID`, once the account no longer holds it, as reset and magic links
already were. A deletion link issued before this release carries no address and is refused.

**Links mailed from a `callbackPath` with a query work.** Reset, verification, deletion, undo and magic links were
built as `callbackPath + '?token=…'`, so a path such as `/auth?mode=reset` mailed a link whose token read as part
of `mode`, and every such link was dead. The token is now set as the link's `token` parameter, beside the path's
own query and before any fragment, and it replaces a `token` the path already carries.

**`new AuthEngine` reads `baseUrl` as `createAuth` does.** A trailing slash mailed links to `//auth/…`, which a
route at `/auth/…` does not match, and a `baseUrl` that is not an absolute http(s) URL was accepted. The constructor
now drops the slash and refuses such a value with `AUTH_MISCONFIGURED`.

**A second account at a provider is refused, not reported as linked.** An identity holds one login per provider.
When a second arrived, every store kept the first and answered as if it had linked the second.

- `flows.linkProvider` reported success and emitted `identity.linked` for a GitHub account it never linked, so its
  owner's next sign-in with that account found no identity.
- Under `'link-if-verified'`, a second GitHub account whose verified email matched an identity already linked to
  GitHub was signed in to that identity, every time, without ever appearing among its links.

`identities.link` now refuses another account at a provider the identity holds, `AUTH_PROVIDER_TAKEN`, on every
store, and that OAuth sign-in fails. Re-linking the account it already holds is still a no-op. If you implement
`Identities.Store` yourself, refuse the same way; `runIdentityStoreCompliance` now checks it.

**GitHub sign-in completes.** GitHub's token endpoint answers form-encoded unless asked for JSON, and nothing asked,
so every `github()` sign-in failed with `AUTH_PROVIDER_FAILED`. Every request to an IdP now asks for JSON. On
Cloudflare Workers, whose fetch sends no User-Agent, GitHub's API also refused `/user`. Every request now names
`@gentleduck/auth` as its User-Agent.

**Microsoft profiles carry no `avatarUrl`.** Entra's `picture` is Graph's `/me/photo/$value`: the same URL for every
account, and readable only with that account's own Graph token, which the provider does not keep. Every Microsoft
user had the same broken avatar.

**OAuth sign-in against an IdP that is down, slow, or has a query in its endpoint.**

- An IdP that refuses the connection fails the sign-in with `AUTH_PROVIDER_FAILED`. It threw a raw `TypeError`,
  which the documented callback rethrows, so the user got a server error rather than the sign-in page.
- Each request to the IdP gives up after `timeoutMs`, default 10 seconds, set on `OAuthClient` or any preset. One
  that never answered held the sign-in open, and a refused sign-in waited on two revocation calls the same way.
- An authorization endpoint's own query is kept. Azure AD B2C's `?p=<policy>` swallowed `response_type`, and the
  IdP refused every sign-in.
- A used `state` stays refused until it expires. Its nonce was held for ten minutes from the sign-in, and a state
  minted by a node whose clock runs ahead verifies for longer than that, so its callback could be replayed in the
  gap, given the browser's pre-auth cookie and an IdP that accepts a code twice.

**SAML logout cannot be made to inflate a gigabyte.** Over the Redirect binding, `samlSloController`'s
`completeIdp` and `completeSp` handed node-saml the query, and node-saml inflates the message with no bound before it
checks any signature. An unsigned 1 MiB query, which anyone could send, inflated past a gigabyte. A message that
inflates past `SAML_RESPONSE_MAX` is now refused, `AUTH_PROVIDER_FAILED`, before node-saml reads it.

**A SAML password or smartcard alone is not a second factor.** `SAML_MFA_AUTHN_CONTEXTS`, the default
`mfaAuthnContexts`, counted `SecureRemotePassword`, which is a password, and `Smartcard`, which is the card without
its PIN, so an IdP reporting either minted an AAL 2 session. Such a sign-in is now AAL 1. `SmartcardPKI`, the card
with its PIN, still counts. If your IdP reports one of the two for a sign-in it did protect with a second factor, list
it in `mfaAuthnContexts`.

**The SAML routes in the docs tie the relay state to the browser.** Their callback accepted any relay state the app
had issued, and anyone can call `begin` for one. An attacker could begin a sign-in, sign in at the IdP as themselves,
and post that response from someone else's browser, which was then signed in as the attacker. `begin` now sets a
`SameSite=None` cookie holding the relay state, and the callback refuses one that does not match it. If you copied
those routes, do the same.

**OIDC discovery reads what real issuers publish, and gives up on one that stalls.**

- `authFetchOidcDiscovery` refused the documents Google, Apple and Microsoft publish. It required
  `userinfo_endpoint`, `end_session_endpoint` and four lists that OIDC Discovery 1.0 makes optional. It now requires
  only what the spec requires, and an absent list holds the spec's default. It returns the new
  `AuthOidcDiscovery.IPublishedDocument`, whose `userinfo_endpoint` and `end_session_endpoint` are optional. Code
  that read them as strings has to handle them missing.
- The request and its body give up after `timeoutMs`, default 10 seconds, and a body past 64 KiB is refused unread.
  A stalled issuer held the sign-in open, and a 64 MB body was read whole.
- A refused connection, a failed read or a body that is not JSON throws `AUTH_PROVIDER_FAILED`. Each threw a raw
  `TypeError` or `SyntaxError`, which a route answered with a 500.

**Org events name only live memberships.**

- `setRoles` on someone who has left throws `AUTH_MEMBERSHIP_NOT_FOUND`, as the docs said. It wrote the roles onto
  the ended membership and emitted `org.roles.set` with them, so a listener keeping roles current from the events
  granted them back to someone just removed. The memory store refuses the write, and the facet refuses a store
  that answers an ended row. If you implement `Org.Store`, raise for an ended membership in `setRoles` too.
- Removing someone a second time still answers the ended membership, and no longer emits `org.member.removed` again.
- `addMember`, `removeMember` and `setRoles` refuse an `orgId` or `identityId` that is not a non-empty string with
  `AUTH_INVALID_PARAMETERS`. A `null` from a request body became a membership, and `resolveMembership` with a guest
  session's `null` `identityId` answered it, roles and all. `resolveMembership` and `listForIdentity` now answer no
  membership for one.

**The OIDC provider.**

- A public client can revoke its tokens. `revoke` and `introspect` took credentials only from HTTP Basic, so a
  revoke from a public or `client_secret_post` client did nothing, answered 200, and the refresh token went on
  working. Both now take `client_id` and `client_secret` from the body, as `/token` does. A public client must send
  its `client_id`. `revoke` returns `{ error: 'invalid_client' }` when no client authenticates, for the host to send
  as a 401. It returned nothing before, so its return type is now `OidcOP.OauthError | undefined`.
- A client can revoke only its own tokens. Any authenticated client could revoke another's. Another client's token
  is now left alone, and answered 200 as an unknown token is.
- `prompt=login` and `max_age` ask for a fresh sign-in. `authorize` ignored `prompt=login` when someone was signed
  in, and dropped `max_age`, so a client asking for a fresh sign-in got a code for a session of any age. Both now
  answer `login_required`, with `reason` `prompt_login` or `max_age_exceeded`, and `max_age=0` is `prompt=login`.
  Resume the request without `login` in `prompt` and without `max_age`, or it asks again. `prompt` is read as a
  space-separated list. `none` with another value is `invalid_request`, as is a `max_age` that is not whole seconds.
- `completeConsent` checks the scope and PKCE, as `authorize` does. Its input comes back through the host's consent
  form, and an edited post minted a public client's code without PKCE, with scopes the client never registered.
- A refresh token presented by another client is refused without being spent. It was spent first, so the owner's
  next refresh read as reuse and revoked the whole family.
- Erasing or soft-deleting an identity ends its grants. Its tokens introspected active, its refresh token kept
  minting new ones, and an outstanding code still exchanged. Each now answers `{ active: false }` or
  `invalid_grant`, and the refresh family is revoked.
- Registration refuses a `client_uri` or `logo_uri` that is not an `http` or `https` URL of at most 2048 characters
  without userinfo. `POST /register` answers 400 `invalid_client_metadata`, and `registerClient` throws
  `AUTH_INVALID_PARAMETERS`. A `javascript:` `client_uri` was stored, and a consent screen that links it runs the
  script on the provider's origin. A `scope`, `grant_types` or `response_types` of the wrong type also answers 400,
  where it threw a `TypeError`.

**A webhook receiver cannot hold a connection open per event.** The deliverer read each answer's status and left
its body unread, which keeps the connection open until the receiver ends the body. A receiver that never ended its
answers, or answered with a large page, held a socket for every event delivered. The body is now cancelled once
the status is read.

**A webhook endpoint at an IPv6 address receives its events with `resolveHost` wired.** The deliverer handed
`resolveHost` the host with its brackets, `[2606:4700:4700::1111]`, which `lookup` from `node:dns/promises`, the
documented wiring, cannot find. Every event to such an endpoint spent its retries and was dead-lettered unsent. The
resolver now receives an IPv6 host without its brackets, and a name as written.

**The SSRF guard on webhook and captcha endpoints refuses more inward addresses and names.** It now also
refuses `::ffff:0:a.b.c.d`, the IPv4-translated form a SIIT translator carries to the IPv4 address inside it, as
NAT64 already was, and site-local `fec0::/10`. By name it refuses `localhost.localdomain`, `localhost4.localdomain4`
and `localhost6.localdomain6`, which point at loopback in the stock `/etc/hosts` of RHEL-family hosts.

**`authVerifyWebhookSignature` answers `false` for a missing signature.** A signature that is not a string, such as the
`undefined` of a header the request did not carry, threw a `TypeError`, which a receiving route answers with a 500.

**A Redis event bus recovers from a failed subscribe.** `RedisEvents` subscribes to an event's channel when the
event's first `fleet` handler arrives. A subscribe that failed was dropped without a word. Only a later `on()` for the
same event retried it, and after boot none comes, so that server never heard the rest of the fleet again, `authz.revoked`
included. With ioredis defaults this took Redis being down for about 74 seconds at boot. With
`enableOfflineQueue: false` it happened on every start, because the subscribe ran before the client had connected. A
failed subscribe is now logged and retried, after 1 second and doubling to 30, while the event has a `fleet` handler.

**A plugin can run its event handlers once.** `auth.use({ events })` subscribed every handler as `fleet`, and a plugin
had no way to choose otherwise. On one server, `strict({ env: 'production' })` refused such a plugin and named
`{ delivery: 'origin' }` as the remedy, which a plugin could not pass. On a fleet, an audit plugin wrote one row per
server. A plugin's `delivery: 'origin'` now runs its handlers once, on the server that emitted. The default is still
`'fleet'`. A `delivery` that is neither is refused with `AUTH_MISCONFIGURED`.

**Every erased identity reaches `identity.erased`.** `identities.gc()` erased the rows whose grace window had
closed, which is where every soft delete ends, `flows.completeAccountDeletion` included, and emitted nothing. A
`bulkCreate` replace erased the account it replaced without a word too. A host purging its own rows from the event,
a processor told through a webhook, and the audit log heard of neither. `gc` now emits `identity.erased` with
`reason: 'gc'` per row, and a replace with `reason: 'bulkCreate replace'`. **Breaking for a custom
`Identities.Store`: `gc(now)` now answers `{ deleted, ids }`, naming the rows it erased.**

**Idempotency answers what ran.**

- A response the store cannot cache is now answered, and the failure is logged. `handle` threw the store's error
  after the executor had run, so a charge that went through reached the client as an error. Every retry of its key
  then answered 409 for a day. A failed release of the key is logged as well.
- A repeat waiting on a first attempt that fails now runs. It went on polling a key nobody held and answered 409 at
  `pollTimeoutMs`.
- The cached copy of a response leaves out `Set-Cookie`, as `CachedResponse.headers` said it did. A sign-up replayed
  under its key handed out the session it had minted.

**Impossible travel reads a missing position as none.** `authImpossibleTravelDetector` read a `null` or empty
coordinate as 0. A position stored as JSON, where a NaN comes back `null`, or a geo lookup answering `null` for an
address it cannot place, put the user in the Gulf of Guinea. Someone who had not moved scored 1 and was refused
with `AUTH_ANOMALY_DENIED` for hours. Without a number at both ends, the detector now scores nothing.

**The memory limiter keeps up with a flood.** Once it held 1024 live buckets, `MemoryLimiter` scanned all of them
for every new key, so a flood of distinct addresses within one window cost each request a scan of every bucket. It
now sweeps at most once a window.

**A credential date a store cannot hold is refused.** Every store's `credentials.create` refuses an `expiresAt`,
`revokedAt` or `lastUsedAt` that is an `Invalid Date`, or that falls after 9999, with `AUTH_INVALID_PARAMETERS`.
sqlite stored an unreadable date as no date, so an API key created with an `expiresAt` that `Date.parse` could not
read never expired. Memory treated the same key as expired, and pg and mysql failed with `AUTH_ADAPTER_FAILED`.

**MySQL refuses a value its column cannot hold as a bad value, not an adapter failure.** An id outside ASCII,
such as `/users/é`, compared against MySQL's `ascii` key columns, failed with `AUTH_ADAPTER_FAILED`, the code that
says the database broke, so anyone could raise it at will. So did such an id written as an identity, and a value
longer than its column. These now answer `AUTH_INVALID_PARAMETERS`, which is what Postgres answers for an id that is
not a uuid.

**`getByEmail` finds every address `create` stores.** It refused an address over 254 characters with
`AUTH_INVALID_PARAMETERS`, though `create` stores up to 320, so such an identity could not be found by its address.
It now takes up to 320.

**The session cap.**

- A step-up no longer signs the device out at `maxSessionsPerIdentity`. When the stepping-up session was the
  oldest, the cap evicted it before the rotation could downgrade it, and the step-up failed with no session left.
  The cap now runs once a rotation has settled the session it replaces.
- A sign-in that rotates a session at the cap no longer evicts another device as well, and emits `session.revoked`
  once for the session it replaced.
- An expired session that `gc` has not swept yet no longer counts toward the cap, so a live device is not evicted
  in its place.
- An API key's sessions no longer sign its owner out. The cap counted every session of the identity, so a script
  exchanging its key with `m2m` a few times within the token lifetime evicted the owner's browser sessions, though
  the exchange's own row is never read when its token is. The cap now counts and evicts only sessions of the new
  session's kind.

**A TOTP code that is not a string is a wrong code.** `confirmTotpEnrollment`, and `verifyTotp` from
`@gentleduck/auth/providers/mfa`, threw a `TypeError` on one, such as a request body without the field, which a route
answered 500. They now answer `{ ok: false }` and `false`.

**`apiKeys.create` answers the key as stored.** A tenant-bound key now comes back with its `tenantId`, which `list`
reported and `create` left out. An `expiresAt` of `null` comes back as no expiry, which is what was stored, rather
than 1970.

**Configuration refused up front.**

- `cookieTransport` refuses a `path` that does not start with `/`, and a `domain` that is not a bare host, such as
  one with a scheme or a port. Browsers rescoped or dropped such a cookie, and the session never stuck.
- `bearerTransport` refuses a `header` that is not a valid header name. `Headers.get` threw on it for every request.
- `requestPasswordReset`, `requestEmailVerification`, `requestAccountDeletion` and `magicLink` refuse a `ttlMs`
  whose deadline falls after 9999. On Postgres a registered address answered 500 where an unknown one answered
  `{ ok: true }`, and on sqlite the token never expired.
- `redisSessionImpl` and `valkeySessionImpl` refuse a `maxTtlSec` or `gcLeaseSec` that is not a whole number of
  seconds above 0. NaN reached Redis as a TTL, a fraction made every sign-in fail on a real server, and `0`
  deleted the identity index as it was written.
- `redisLimiter`, `valkeyLimiter` and `MemoryLimiter` refuse a `windowMs` that is not a whole number of
  milliseconds. Redis refuses a fractional expiry, so every consume threw, and every sign-in, link request and
  step-up with it.
- `beginSignUp` refuses a `required` stage that does not exist, and `advanceSignUp` refuses one too, with
  `AUTH_MISCONFIGURED`. A misspelled required stage answered a flow token that every later call refused as
  `AUTH_SIGNUP_TOKEN_INVALID`, after writing the identity. A misspelled stage passed to `advanceSignUp` came back
  listed as completed, and then never counted.
- `rememberMeFacet` refuses a `ttlMs` whose deadline falls after 9999. Every `issue` failed with
  `AUTH_INVALID_PARAMETERS`.
- `passkey()`, `beginPasskeyRegistration` and the WebAuthn MFA ceremonies refuse an `rpID` that is not a bare host,
  and an `expectedOrigins` entry that is not an origin as a browser sends it, on that `rpID`, such as one with a
  trailing slash or a default port. Every ceremony failed with `AUTH_PASSKEY_MISMATCH`, and `verifyWebauthnMfa`
  answered `false`, with the reason swallowed. `verifyWebauthnMfa` now throws `AUTH_MISCONFIGURED` for it.
- The captcha verifiers refuse an `expectedHostname` that is not a bare host, such as `https://app.example.com`,
  `app.example.com:8443` or `*.example.com`. Providers report the host bare, so every token failed
  `hostname-mismatch`. A per-call one answers `invalid-expected-hostname` without calling the provider.
- `authImpossibleTravelDetector` refuses a `getLastSeen` that is not a function. It threw on every request carrying
  a position, which the facet logged and skipped, so the detector never scored.
- `AuthWebhookDeliverer` refuses a `signatureHeader` the request already carries: `Content-Type`, `User-Agent`,
  `X-Duck-Delivery-Id`, `X-Duck-Timestamp`, or one the transport owns, such as `Host` or `Content-Length`. The
  signature was merged into that header's value, dropped, or refused by `fetch`, so every delivery failed.
- `apple()` refuses a `privateKey` that is not the P-256 key from the `.p8`, such as an empty one or one whose line
  breaks an env var flattened to `\n`. Each sign-in threw a raw crypto error, which the documented callback route
  answers with a 500.
- `createOidcOP` throws `AUTH_MISCONFIGURED` for a `dcr.initialAccessToken` key that holds `undefined`, a blank
  token, or a `maxRedirectUris` that is not a whole number of 1 or more. Configured as the docs showed, with
  `initialAccessToken: process.env.OIDC_DCR_TOKEN` and the variable unset, it opened registration to anyone. A NaN
  `maxRedirectUris` turned the cap off. To run open registration, leave the key out.
- `authBuildOidcDiscovery` refuses a `prefix` or `jwksPath` that does not start with `/`. Appended to the issuer as
  text, either published the endpoints on another host: `jwksPath: '.evil.example/jwks'` published
  `https://auth.example.com.evil.example/jwks`.
- `authConfigureOidcDiscoveryCache` refuses a NaN or negative `ttlMs`, and a `capacity` that is not a whole number
  of 0 or more. A NaN capacity, as an unset env var gives, never evicted. It was exported as
  `authCfgureOidcDiscoveryCache`, which stays as a deprecated alias.

**The outbound SSRF guard covers the IANA special-purpose blocks it had missed.** `assertSafeOutboundUrl` and
`assertResolvedHostIsPublic` now also refuse the RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) and, on v6, `2001:2::/48` benchmarking, `2001:db8::/32` and `3fff::/20`
documentation, and `5f00::/16` SRv6 segment identifiers. Nothing listens on any of them, so this turns a webhook
or CAPTCHA endpoint pointed at one from a connect timeout into `AUTH_MISCONFIGURED` at config time. Every range
that carries an SSRF risk — loopback, RFC 1918, link-local and the metadata address, CGNAT, multicast, broadcast,
and the IPv4-mapped, IPv4-compatible, NAT64, 6to4 and Teredo tunnel forms — was already refused and is unchanged.

**`client_secret_basic` now form-decodes each half of the Basic payload, as RFC 6749 §2.3.1 requires.** A
conforming client encodes `client_id` and `client_secret` with the `application/x-www-form-urlencoded` algorithm
before base64; the OP compared the halves raw, so a client whose secret contained a space, `+`, `%`, `:`, `&`,
`=` or non-ASCII text was refused with `invalid_client` on a correct secret. Secrets this library generates are
base64url and survive the round trip untouched, so this only affected a client registered with a
`client_secret` or `client_id` supplied by the host. Clients that skip the encoding keep working: the raw
spelling is tried as a second candidate, and both are compared against the stored hash in constant time. A
Basic header also now conclusively owns the `client_id` — an empty half no longer reads one from the request
body.
