---
'@gentleduck/auth': minor
---

Security fixes from the ongoing audit, grouped by what goes wrong if you do not
take them.

**A sign-in link could end up in your metrics and your audit log.** The
`signin.failed` event is audited, and the OpenTelemetry exporter records its
`reason` as an attribute on `auth_signin_total`. Four flows emit that event twice
— once when the channel answers `ok:false`, once when it throws — and while every
`ok:false` branch used fixed text, the `.catch()` branch a few lines below it
interpolated the error. A channel's error message is written by its SDK, and mail
and SMS SDKs quote what they were asked to send, so a throwing transport put the
recipient's address and the rendered body into both sinks. In the magic-link and
password-reset flows that body is the single-use token URL, which is the
credential itself. The affected paths are `flows.delivery` (email verification,
account deletion, and the cancellation mail after a confirmed deletion),
magic-link, password reset, and SAML — where the thrown value comes from
`onSignIn`, your own callback, so the text is whatever you put in it. All four now
emit fixed text. Nothing about the caller's view changes: these paths were already
fire-and-forget and already reported nothing.

**A transport marked `authoritative` did not actually veto.** The flag exists so
that pairing a strict transport with a permissive one stops the permissive one
answering for a token the strict one just refused. `CompositeTransport.verify`
only reached the veto when the strict member's refusal came back as `null`, which
happens for the eight `ABSENT` "no row" codes and nothing else. A refusal spelled
any other way — which is what a custom transport throws, `verify` being typed to
return a session — was caught one level out, recorded as a recoverable fault, and
the loop moved on to the next member, which vouched. The veto now also fires when
an authoritative member throws, rethrowing that member's own error so a bad
credential and an unreachable key server stay distinguishable. No shipped
transport sets the flag, so no default configuration changes.

**One tenant could read another's cached idempotent response.** Both idempotency
stores key an entry on the tenant id joined to the client's own `Idempotency-Key`
header, and `tenantId` is an unvalidated host string — so tenant `acme` sending
the key `eu::k1` landed on the entry tenant `acme::eu` had stored under `k1`, and
read back its status, headers and body. A tenant named `_default` reached the
untenanted namespace with no colon needed, that being the literal sentinel both
stores used for "no tenant". The tenant segment is now URI-encoded, which cannot
span the delimiter and cannot produce the empty string that absence now uses.
Redis keys change shape, so entries in flight at deploy time are missed once and
the request runs again; they are TTL-bounded at 24 hours.

**An org role grant could land on a different identity in a different org.** The
memory adapter keyed memberships on `` `${orgId}:${identityId}` ``, and org ids
are the host's own — `OrgsImpl` bounds and deduplicates the `roles` array and
validates neither id. Org `a:b` member `c` and org `a` member `b:c` were one row,
so `setRoles('a', 'b:c', ['owner'])` granted `owner` to identity `c` in org `a:b`
and answered as though it had done what was asked. The key is now built from the
two ids unambiguously.

**One tenant's MFA factor could clear another tenant's step-up.** Every `mfa`
method takes an optional tenant context and defaults it to `{}`, which is not
"no tenant known" but *unscoped* — the SQL dialects emit no filter for it and the
memory adapter matches every row. The hono adapter, which is the only one that
mounts MFA routes, called all five of them without it, while `completeStepUp`
passes the session's tenant for the same call. So a TOTP factor enrolled under
one tenant verified a step-up presented under another, and `DELETE` on the totp
route removed a factor belonging to a tenant the caller was not signed in to. All
five routes now pass `resolved.session.tenantId`, which each already holds and
has already checked.

**A stolen password reached AAL2 on its own when the second factor was a
security key.** `beginTotpEnrollment` refuses to start over a second factor that
already exists, but it looked for TOTP rows only — so for an identity whose
factor is WebAuthn it saw nothing and let the enrollment through, on a route that
asks for no step-up because first enrollment cannot. The caller then confirmed
against the secret it had just been handed, collected the ten backup codes first
enrollment mints, and spent one on `completeStepUp`, which sets AAL2 on the code
alone. The key was never touched and the victim's credential was left intact, so
the only trace was an `mfa.enrolled` event that looks like the user adding a
factor. The gate now asks whether a second factor exists rather than whether it
is a TOTP. The reverse — registering a key on a TOTP-protected identity — is
reported rather than changed: no adapter mounts a WebAuthn-MFA route, nothing
turns a WebAuthn-MFA verification into an AAL2 session, and refusing it outright
would break adding a backup key.

**An impersonation could be cashed in for an unmarked session as the person
being impersonated.** `impersonate()` never checked whether the session it was
handed was itself an impersonation, and `actingAs.realIdentityId` is copied from
that session's subject — which, while impersonating, is the previous target. So a
second hop recorded the target as the accountable operator, and
`releaseImpersonation` then issued a session as *them*, with no `actingAs` marker
and the ordinary session lifetime instead of the sixty-minute cap. Sixty audited
minutes became seven unmarked days, `actorForSession` stamped every later write
with the target's id rather than the operator's, and the `identity.impersonated`
event for the second hop named the wrong operator. Impersonating from an
impersonated session is now refused; `realSid` was already documented as the real
subject's, and `ActingAs` has only one slot to record an operator in, so a chain
had nowhere to put the truth.

**On Fastify, a refused CSRF check still ran the route.** `fastifyCsrf` is a
`preHandler` hook, and on failure it wrote the 403 and returned. Fastify does not
take a bare `send()` as the end of the chain for an async hook: the hook resolved
with the response still in flight and the route handler ran anyway, so the caller
got a 403 and the write happened — which is all a CSRF attack wants. Returning
the reply, which is the idiom everywhere else in that file, does not fix it;
awaiting it does, because Fastify's `Reply` is thenable and awaiting is what waits
for the send. Verified against fastify 5.12.5. The other adapters are unaffected:
each of them refuses by withholding `next()` or by returning the response, so the
halt is the language's rather than the framework's.

**On Express 4 the hijack policy refused into thin air.** `expressActorContext`
is an async middleware, and the policy refuses by throwing — which is what
`applyReaction` does for `mfa` and `revoke`, and what `onHijack` is documented to
do. Express 4 does not forward a rejected async middleware anywhere, so the
request neither continued nor answered: the socket was held until something timed
out. Express 5 forwards it, which is why this is invisible on a new install and
live on the version Nest 10 ships; `nestActorContext` had the same shape and the
same outcome. Both now hand the error to `next(err)`, verified against express
4.22.3 including that a downstream throw still reaches the error handler exactly
once. `ExpressAdapter.Middleware`'s `next` widens to accept an error, which is
what express passes it anyway.

**The client reported a signed-in user as signed out before it had asked.**
`onChange` replayed the client's state on subscribe, including before anything
had been fetched — and React, Vue, Solid and Svelte all map "no identity" to
`status: 'guest'`, so every binding moved out of `'loading'` in the same tick it
subscribed, with the wrong answer. The `'loading'` state all four declare could
not be observed at all, so an app gating on `status` flashed its sign-in screen
for authenticated users on every load, and one redirecting on `'guest'` sent them
there. The client now replays only a state it actually holds; a signed-out state
that was really read is still one, so a late subscriber is unaffected.

`AuthJwtTransport.rotateSignKey` now clears the same floor the constructor does.
It wrote the new signing key straight into the field the constructor validates,
reaching none of its guards: an empty `key` was accepted, and since HS256 copies
the secret into the verify ring, every token minted afterwards was signed with an
empty HMAC key and forgeable by anyone who tried the empty string. The `kid`
length cap was skipped on the same path. `__weakSigningKey`, which `strict()`
reads to refuse a sub-32-byte HMAC secret in production, was computed once at
construction, so a deployment that booted clean and later rotated to a short
secret went on attesting to the key it had already replaced; it is now computed on
read. The verify ring had the matching hole — `verifyKeys[*].kid` was checked and
the key itself never was — so an empty verify key was accepted straight from
config, with no rotation involved.

`PluginRegistry.install` now refuses a plugin that subscribes to an event the
bus does not carry. The name was cast straight to `keyof Events.EventMap`, and
`on` makes a handler set for whatever string it is given, so a plugin naming a
mistyped or renamed event installed cleanly, appeared in `installed`, and its
handler could never fire — silently, for an audit or alerting plugin listening on
`suspicious` or `lockout`. A new `isEventName` predicate keys off the record the
compiler already proves exhaustive against `EventMap`, and uses `Object.hasOwn`
so `constructor` is not answered yes by the prototype.

**Passkey registration could not complete on the configuration the docs
describe.** `challengeStore` is documented as in-memory by default, and
`PasskeyImpl` honours that by building one store in its constructor and holding it
across both halves of the ceremony. `beginPasskeyRegistration` and
`completePasskeyRegistration` are free functions, and each built its own default
inside its own body — so with the option omitted, `begin` stored the challenge in
one store and `complete` looked in a second, empty one, refusing every
registration with `AUTH_PASSKEY_MISMATCH`. That is the same code a forged response
gets, so the operator was pointed at the authenticator rather than at their
config, and sign-in worked throughout because the class path was never affected.
Both helpers now share one module-level default. Separately, that store only ever
grew: `take` removes the key it is handed and nothing removed an abandoned
ceremony, while `passkey.begin` is unauthenticated, takes a caller-chosen
`sessionId` and rate-limits per that id — so a fresh id each request was a fresh
bucket with nothing bounding the number of ids. `put` now drops expired entries
first, which bounds the map by what is live within the TTL instead of by uptime.

**The new-device detector's documented default was the opposite of its real
one.** `AuthDeviceFingerprint.Cfg.score` said 0.7 sat "under the 0.8 suspicious
threshold, so it does not auto-step-up until an app tunes it up". There is no 0.8:
the defaults are `threshold: 0.7` and `stepUpAt: 0.7`, both compared with `>=`, so
the default score lands exactly on them and one new device raises `suspicious` and
decides `'step-up'` on its own. The behaviour is the sensible one and is
unchanged — lowering the score to match the old text would drop it under
`threshold` too and silence the event, losing the detection along with the
step-up — so the comment now states what the ladder actually does, and what tuning
it down costs.

**BREAKING: `samlProvider` now requires replay protection.** Assertion replay was
the one silence the SAML constructor did not refuse. It already demands a client,
a matching `callbackUrl`, at least one signature it will verify, and either
`verifyRelayState` or an explicit `allowUnsolicited: true` — but `complete`
replay-checked under `if (this.cfg.replayStore)` and said nothing when there was
none, so a deployment that never wired one let a captured SAMLResponse mint a
fresh session on every repeat, for as long as the assertion's own `NotOnOrAfter`
window lasted, which node-saml's `acceptedClockSkewMs` widens. Construction now
fails with `AUTH_MISCONFIGURED` unless you pass `replayStore`, or the new
`allowReplay: true` to accept assertions with no replay protection. As with
`allowUnsolicited`, only a literal `true` waives it, so `allowReplay: false` is
not an accidental opt-out. Existing SAML deployments without a store will refuse
to boot until one of the two is set.

**BREAKING: three in-process defaults are now refused in production.** Each kept
state in one process while being what you get by default, and `strict()` caught
none of them. The engine's default event bus, `AuthInMemoryEvents`, runs its
handlers per node, so a `lockout`, a revocation or a `suspicious` signal raised on
one instance was never heard by the others — which also made `strict()`'s own
`lockout` listener check misleading, a local listener proving nothing about the
fleet. `AuthMemoryPasskeyChallengeStore` holds the challenge that is the whole of
a WebAuthn ceremony's binding, and consuming it on one node left it live on every
other for the rest of the TTL; it was also the only `ChallengeStore` shipped, so
`AuthRedisPasskeyChallengeStore` now ships beside it — its `take` claims with
`DEL` rather than reading then deleting, so only the caller whose `DEL` removed a
key may use the challenge and single-use holds across a fleet.
`MemoryDPoPNonceStore` is a per-node replay cache, which is no replay cache: a
proof one pod rejects was accepted by every other. `strict()` cannot see it at all
— `DPoPVerifier` is built outside the engine — so it refuses itself under
`NODE_ENV=production`, as `MemoryIdempotency` already does, with a
`development: true` escape hatch. In production you now need to pass `events`
(`redisEvents`), `challengeStore: redisPasskeyChallengeStore({ redis })` to
`passkey()`, and `nonceStore: redisDPoPNonceStore({ redis })` to `DPoPVerifier`.

**BREAKING: `anomaly.reactions` is nested rather than keyed `detectorId#kind`.**
The old map held two key spaces at once — a bare kind, and a `#`-joined scoped
form added so a plugin's free-string kind could not claim a reaction written for
someone else. Because signal kinds are deliberately not checked against the union,
a detector could spell a whole scoped key as its own `kind` and collect that
reaction through the *unscoped* fallback, which is the one thing the scoping
existed to prevent. It is now `{ [detectorId]: { [kind]: decision } }`, with `'*'`
as the detector meaning "whoever emitted it" and reserved against registration: a
level is not a delimiter, so there is nothing left to collide. Rewrite
`{ 'new-device': 'deny' }` as `{ '*': { 'new-device': 'deny' } }` and
`{ 'travel#new-device': 'deny' }` as `{ travel: { 'new-device': 'deny' } }`. Two
things that used to pass silently now throw `AUTH_MISCONFIGURED` at construction:
a decision that is not `allow`, `step-up` or `deny` — a misspelling used to be
dropped on the floor, since every comparison against an unknown severity is false
— and a detector entry that is not an object.

**BREAKING: `scan` and `eval` are gone from the Redis client contract.** Neither
had a single caller in the library, yet `RedisLike.Client.scan` was required and
`ValkeyClient.Me` demanded both — so a host wiring its own client had to implement
`SCAN`, which several managed and serverless Redis tiers restrict, for a call that
never happens. Dropping them costs a consumer nothing: an object with extra methods
still satisfies the type, so existing clients keep working unchanged. `FakeRedis`
and `FakeValkey` lose their `scan` with it, which also removes a trap — `FakeRedis`
collected up to `count` *matching* keys per call and so never returned an empty
page with a live cursor, where real Redis treats `COUNT` as a per-iteration hint
and routinely does.

**BREAKING: a closed impersonation window now throws `AUTH_IMPERSONATE_WINDOW_CLOSED`.**
It threw `AUTH_SESSION_REVOKED` before, which is also what every transport throws
for "this is not a token of mine" — so neither the composite transport nor the
engine could prefer it over a sibling's refusal, and both replaced the operator's
verdict with their generic "no transport vouched for the token". The request always
failed closed; what was lost was the signal an SOC alerts on. The new code carries
`{ closedAt }`, sits at 401 like the one it replaces, and is in the absent set, so
`orNull()` and `orDefault()` read it back exactly as before — only code that
branches on the code string sees a difference. It is deliberately not
`AUTH_IMPERSONATE_EXPIRED`, which `releaseImpersonation` raises about a session
that is not an impersonation at all and which must stay loud through the readers.

**BREAKING: `orgs` tenancy is now checkable, and the context is required.**
`Org.Store` asked for a `TenantContext` on every method while neither `Org.Me` nor
`Org.Membership` carried a tenant field — so nothing could tell which scope a row
came back under, and the shipped memory store ignored the argument on all six
methods. `OrgsImpl` also defaulted it to `{}` on all seven public methods, which
made dropping it on the way to the store type-safe and invisible. Both row types
now carry `tenantId: string | null` (`null` = a global row), every `OrgsImpl`
method takes the context explicitly, and every row the facet hands back is checked
against the scope it was read under: a mismatch raises the new
`AUTH_TENANT_SCOPE_VIOLATION` (500, and deliberately outside the absent set, so a
cross-tenant row cannot read back through `orNull()` as "no row"). The host still
performs the scoping — `Org.Store` is still a read interface over their tables —
the library just no longer takes it on trust. A context naming no tenant asks for
everything and accepts everything, so a single-tenant app passes `{}` and writes
`tenantId: null`. The bundled memory store now scopes for real, keying both maps on
the tenant as well as the id, so two tenants using the same org id no longer
overwrite each other's memberships.

**BREAKING: a 5xx your idempotency executor returns is no longer cached.** An
executor that throws already released its claim, so the client's retry under the
same key ran for real. One that caught its own error and answered `{ status: 500 }`
was pinned to the key instead, and for the full 24-hour TTL every retry of that key
got the stale 500 back with the work never running — the exact situation an
Idempotency-Key exists to survive. Whether a failing handler throws or returns is
its own style, not a statement about the operation, so the two now agree: a response
with `status >= 500` releases the key and is returned uncached. 4xx is still cached,
deliberately — a 422 is a decision about the request, and replaying it is correct.
If you relied on a returned 5xx being replayed, return a 4xx or throw instead.

**A refused oauth sign-in now hands the upstream tokens back.** `revocationEndpoint`
was configured by Apple, Google and Discord, validated as a URL, and fetched by
nothing — `OAuthClient` made four outbound calls and none was a revocation. Every
refusal inside `complete()` happens after the authorisation code has been spent, so
the IdP had already minted a live access token and usually a refresh token, and the
package refused the sign-in and left both working until they expired. The default
`onFederationConflict` is `'reject'`, so that was the ordinary path, not a corner.
`OAuthClient.revoke(token, { tokenTypeHint })` is new (RFC 7009, client auth in the
body, `redirect: 'error'`, and `AUTH_MISCONFIGURED` before any request when the
provider exposes no revocation endpoint), and `complete()` calls it best-effort on
the way out so a provider that is down cannot turn a refusal into a different error.
Note: unlinking a provider and deleting an account still cannot revoke upstream, and
no change here could make them — the refresh token is stored only as a sha256 and the
access token is not stored at all, so nothing holds a token by the time either runs.

**BREAKING: a request the anomaly detectors deny is now refused.** `denyAt` was a
threshold nothing could act on: `resolveSession` computed the `allow`/`step-up`/`deny`
decision and every one of the eight adapters dropped it, because
`ActorResolvable.resolveSession` declared its return as `{ session }` alone. An
operator who registered detectors, set `denyAt: 0.95` and wired `requestSecurity`
paid the detector latency, got the `suspicious` event, and had the 0.99-scoring
request served anyway — while the hijack policy sitting in the same object literal
was both evaluated and enforced. The verdict now reaches `onSession` as a second
argument (and `withResolvedActor` as a fourth, for nestjs and grpc), and
`requestSecurity` refuses a `'deny'` with the new `AUTH_ANOMALY_DENIED` (403, carrying
the score). Every adapter gained `onAnomaly` beside `onHijack` to override it. A
`'step-up'` decision reaches `onAnomaly` but is not refused by default: the default
`stepUpAt` and the device-fingerprint detector's default score are both `0.7`, so
refusing on it would demand MFA at every first sight of a device. If you registered
detectors and relied on nothing happening, pass `onAnomaly` to keep that.

**Sign in with Apple now works, and `stateCookie` is no longer ignored.** Apple could
not complete a flow at three independent layers: the authorize request omitted
`response_mode=form_post`, which Apple requires as soon as *any* scope is requested
and the default scopes are `['name', 'email']`; no adapter mounted a POST that could
receive the resulting form post; and the pre-auth cookie was `SameSite=Lax`, which a
browser withholds on a cross-site POST, so the binding check failed even once the
first two were fixed. One new flag carries all three — `OAuth.Options.responseMode`,
set by the provider module rather than the host — so only Apple gets `SameSite=None`
and the other five providers keep `Lax`. `mountHono` now mounts the oauth callback on
POST as well as GET, reading `code`/`state` from a urlencoded body capped at 8KB, and
that POST is deliberately exempt from the CSRF guard: it is the IdP's own form
submitting to us, so an origin check would refuse every real Apple sign-in, and what
authenticates it is the signed `state` plus the `binding` cookie digest inside it —
the same proof the GET callback rests on. A `form_post` provider configured
`secure: false` is now refused at construction, because `SameSite=None` without
`Secure` is dropped by the browser and that is the same silent failure one layer down.
Separately, and found while testing the above: **`stateCookie` was declared on every
provider's options, documented, and forwarded by none of the six provider modules.**
The pre-auth cookie was always `__Host-duck-oauth` with `secure: true`, whatever you
passed — and over http a browser drops a `__Host-` cookie without saying so, so every
oauth sign-in on a development host failed with `AUTH_OAUTH_STATE_MISMATCH` while the
option documented to fix exactly that did nothing. If you set `stateCookie` and worked
around it being ignored, that workaround is now the thing to remove.

**BREAKING: concurrent session writes no longer silently discard each other.**
`Sessions.Store.update(id, patch)` was a read-modify-write with no compare in any
of the five implementations, where `Identities.Store.update` in the same files has
taken an `expectedVersion` and raised `AUTH_STALE_WRITE` all along. It now takes an
optional third argument, `expectedUpdatedAt`: supplied, the write lands only if the
stored `updatedAt` still matches, and a mismatch is `AUTH_STALE_WRITE` (409) rather
than an overwrite; omitted, it is unconditional exactly as before. A guarded write
against a row that is genuinely gone still answers `AUTH_SESSION_REVOKED`, so
absence keeps reading as absence through `orNull()`. `sessions.touch()` now supplies
the guard and retries once, which matters because `fresh` is the flag a sensitive
operation re-authenticates on: a `touch` reading just before a credential change
wrote `fresh: false` put `true` back on top of it, so the password change meant to
force a re-auth was undone by the next request the browser made. Two knock-on
changes you may notice: `updatedAt` is now strictly increasing on every session
write rather than whatever `new Date()` returned (two writes inside one millisecond
used to stamp the same value, which is what made the guard vacuous), and on Postgres
it is truncated to milliseconds, the precision every reader of it already had. If
you implement `Sessions.Store` yourself, the third parameter is optional and
ignoring it keeps today's behaviour — but a store that ignores it cannot be guarded.

A session created while "sign out everywhere" was running could escape it. On the Redis store,
`deleteAllForIdentity` read the identity's session index and then dropped the whole key — so a login that
indexed itself in between had its entry destroyed by the sweep while its record stayed live, leaving a
session no later revoke could ever find. The same wipe sat in `deleteAllForIdentities`. Both now remove
exactly the members they read, which is what the tenant-scoped branch already did.

Revoking every session for an identity now records when it happened, and `create` refuses a session minted
before that instant — so a sign-in already in flight when the revoke ran no longer comes back alive on the
other side of it. The refusal is `AUTH_STALE_WRITE`: it means the sign-in lost a race and can be attempted
again, and it is deliberately not one of the codes `orNull()` swallows, which would have reported it as "no
session". Implemented for the Redis and memory stores; the SQL dialects have nowhere to record the mark
without a schema migration, so they are unchanged.

Concurrent updates to the same session on the Redis store no longer lose a write. The store compared the
row to the caller's expectation and then wrote it, so two clients could both find their expectation intact
and both write, and the first write vanished with nothing raised — on a real server that happened to every
concurrent pair, not to the occasional one. The compare and the write are now a single Lua script. `eval`
is a new optional member of the Redis client interface, forwarded by the valkey adapter; a client that does
not have one is back on the compare-then-write it always did, which is now stated in `RedisSessionImpl`'s
documentation rather than left to be discovered.

An update made without an expectation now re-reads and re-applies its patch when it loses such a race,
rather than overwriting the row that won — it asked for its patch to land on whatever was current, and
that is what it gets.

`sessions.listForIdentity` no longer returns `csrfHash`. It is the "active devices" view, so its rows are
built to be shown to the person they belong to, and every other user-facing exit in the library — the
`/session` endpoint in each server adapter, and the GDPR export — already stripped that field. The return
type is now `Sessions.Public`. The store's `listByIdentity` is unchanged and still answers whole rows.

`ReactClient.Session` was declared as the full session row while the vanilla client it wraps serves the
redacted one, so a React consumer could read a `csrfHash` that never arrives. It and the storybook
decorator's session fixture now use `Sessions.Public`, matching Vue, Solid and Svelte.

A new `session.expired` event, emitted wherever a session dies of age rather than by request — the idle
timeout, the absolute cap, an elapsed impersonation window, and a `gc()` sweep. It is deliberately not
`session.revoked`: a consumer has to be able to tell organic churn from deliberate action. The OpenTelemetry
`session.active` gauge now decrements on it, which fixes a number that could only ever rise: under a sliding
TTL most sessions die of age, every one of those deaths was silent, and the gauge was measuring roughly
"sessions ever created".

`sessions.revokeAllExcept(identityId, keepSid, ctx?)` — the "log out all other devices" primitive, in one
round trip. A `keepSid` it does not recognise revokes everything, rather than silently keeping a session the
caller did not mean to keep.

`session.maxSessionsPerIdentity` caps how many sessions one identity may hold, revoking the oldest to make
room. Unset by default, which is the existing behaviour; guest sessions are not counted. Setting it puts one
extra read on the sign-in path.

**Your captcha's timeout now covers the whole call, not just the handshake.** The
deadline was cleared as soon as the provider's headers arrived, so a provider that
answered `200` and then stalled the body parked the sign-in path indefinitely — the
outage the timeout exists to bound. It now stays armed across the body read and
reports `timeout` either way.

**BREAKING: `expectedAction` is enforced on Turnstile and hCaptcha, not just reCAPTCHA.**
It sits on the shared verify input, so it type-checked against every verifier while
only reCAPTCHA v3 read it — a caller who bound a token to an action on Turnstile got
no check at all, and `action` was never even reported back. Turnstile echoes the
field; it is now parsed, reported, and compared. A provider that sends no action fails
the comparison.

`expectedAction` can also be pinned once at wiring, on `AuthTurnstileVerifier` and
`AuthRecaptchaV3Verifier`, alongside `expectedHostname`; passing it per call still
overrides that. It is deliberately not offered on `AuthHCaptchaVerifier`, whose
siteverify returns no action — asking for one there is not a stricter check, it is
every sign-in refused. That is a compile error, with a wiring-time throw behind it.
Passing one per call to that verifier answers `expected-action-unsupported`, rather
than an `action-mismatch` that never happened.

**A per-call `expectedHostname` of `''` no longer disables the hostname check.** The
constructor already refused an empty hostname; the per-call override got no validation,
and an empty string matched a response that carried no hostname at all — so the value a
caller passes to tighten one call was the one that removed the check. An unusable
override is now `invalid-expected-hostname`, and a non-string one no longer throws out
of a `verify` documented never to throw. A refusal also carries the provider's `action`
and `score` now, which were being dropped on the way out.

`allowInsecureEndpoint` said it permitted "a plaintext or loopback endpoint". It
permits plaintext; the SSRF guard refuses a loopback or private host whatever the flag
says. Documentation only — the guard is unchanged.

**A JWT-mode session no longer reports the wrong hard deadline.** `verify()`
reconstructed `absoluteExpiresAt` from `exp`, so the 30-day ceiling a renewal cannot
move came back as the access token's own 15 minutes, and anything reading it — an
expiry reason, a devices view, an exported session — was reading the wrong number. A
new optional `abs` claim carries the real ceiling, `verify()` refuses a token whose
ceiling has passed even when `exp` has not, and `issue()` will not mint an `exp` past
it. Tokens minted before this change keep verifying, falling back to `exp` exactly as
before.

**BREAKING: the refresh cookie is `sameSite: 'strict'`.** It carries the plaintext SID
and was sent on any top-level cross-site navigation. Set `refresh.sameSite: 'lax'` if
your refresh endpoint is reached by one, or `'none'` if your SPA is on a different
origin to your API. The clear now uses the same attributes as the set, which a
mismatched pair would have left behind.

**A token claiming to be issued in the future is refused.** Nothing bounded `iat` from
above, and every timestamp on the reconstructed session is derived from it, so a
future-dated token produced a session created, rotated and factor-verified in the
future. The allowance is 60 seconds, matching the captcha module's — enough for two
clocks to disagree, not enough to be useful.

`clockSkewSec` adds leeway to `exp` and `abs` for a deployment whose instances disagree
on the time. It defaults to 0, which is the behaviour you have now and matches every
other deadline in the package; raising it widens the window an expired token is
accepted in, so it is opt-in.

**BREAKING: an oauth provider must say what burns its state nonce.** The `state` a flow
issues carries a nonce documented as one-time use, and nothing recorded or compared it,
so a callback URL recovered from browser history, a `Referer` or a proxy log completed
again — for the rest of the state's ten minutes, from any browser still holding the
binding cookie, which only a *successful* completion cleared. Two sessions from one
captured callback.

Every oauth provider now takes `nonceStore`, or `allowStateReplay: true` to state that
it has no replay protection — the shape `samlProvider` already uses for its replay
store, because a store that defaults to off is the same silent gap with an extra step.
`OAuth.NonceStore` is `recordSeen(nonce, ttlMs)`, which `memoryDPoPNonceStore()` and
`redisDPoPNonceStore()` already satisfy:

```ts
github({
  // ...
  nonceStore: redisDPoPNonceStore({ redis, prefix: 'auth:oauth:nonce' }),
})
```

The nonce is burned once the signature, the provider id and the binding cookie have all
been checked and before the code is exchanged, so a replayed callback never reaches your
IdP. A transient exchange failure therefore costs that flow rather than leaving the state
live for a second attempt. `strict()` rejects `allowStateReplay: true` in production, and
`AUTH_OAUTH_NONCE_REPLAY` — declared since the beginning and raised by nothing — is now
what a replay gets.

**A second factor no longer turns an impersonation into an ordinary session as the
target.** `flows.completeStepUp` on an impersonating session returned one with
`actingAs: null`, `aal: 2` and the full session lifetime: a bounded, audited,
hour-capped support session became an unbounded, unaudited one as the customer, with
the operator stranded inside it — `releaseImpersonation` on the new sid throws — and
nothing on the row saying whose hands were on it. Every rotation dropped the marker,
because nothing had ever decided which ones should carry it. Now a table answers that
per rotation purpose: `step-up`, `step-down` and `credential-change` carry the marker
across, everything else does not, and inheriting never extends the window.

**An impersonation window now binds every gate, and the row dies with it.** The window
was enforced when resolving a request and nowhere else, so a closed one was still a
working credential for `sessions.getBySid` — whose callers are all privilege gates —
and `sessions.touch` slid the row's expiry past it on every request. Both refuse now
with `AUTH_IMPERSONATE_WINDOW_CLOSED`, which is in the absent set, so `.orNull()`
readers see absence rather than a throw. Separately, `impersonate` set the marker's
deadline but left the row at your configured TTLs, so a sixty-minute impersonation sat
in the target's own device list for a week and garbage collection at window-close
deleted nothing; the row is now capped to the window on every adapter.

**You can now audit when an impersonation ended, not just that it began.**
`identity.impersonated` recorded every start and nothing recorded a close, so an
incident review could see who began one and never when, or whether, it finished. The
new `identity.impersonation.ended` carries `endedBy: 'release' | 'revoke' | 'expiry'`
and fires from all three. Both events are audited, and `identity.impersonated` now
carries its own `audit.actorId`: it emits outside any request scope, so the automatic
stamper had nothing to read and the envelope arrived empty. Webhook subscribers on
`'*'` will start receiving the new name.

**BREAKING: `flows.releaseImpersonation` returns `sid: string | null`.** It already
returned `''` on the one branch where the operator's own account had been deleted,
erased or merged while they were impersonating, under a type promising a string —
which invites the `session` check to be skipped and the empty string passed onward.
Narrow on `sid` or keep checking `session`; both are now honest.

`SECURITY.md` §12 documented two things that do not exist: an `actingAs.scopes` list to
restrict an operator with, and a `session.impersonate-start` event to audit them by. The
first is not a field — an impersonating session holds the target's full authority, and
the window is the control — and the second is a rotation purpose, so an operator wiring
an audit listener to that name got silence. It now names the real events and records one
known low-severity race, which is that neither release nor start is single-use against
its input sid.

**BREAKING: nine error codes are gone, and a JWT that does not verify no longer claims it was
revoked.** `AUTH_ERRORS` says it lists every code the package raises. Nine of them it did not:
`AUTH_AAL_INSUFFICIENT`, `AUTH_QUOTA_EXCEEDED`, `AUTH_LOCKED`, `AUTH_EMAIL_NOT_VERIFIED`,
`AUTH_EMAIL_CHANGE_PENDING`, `AUTH_IMPERSONATE_REQUIRES_IAM`, `AUTH_SESSION_NOT_FOUND`,
`AUTH_JWT_INVALID` and `AUTH_JWT_KEY_UNKNOWN`. The first seven are deleted — nothing in the
package produced them and the condition each named is either reported by another code
(`AUTH_STEP_UP_REQUIRED` for AAL, `AUTH_RATE_LIMITED` for both a spent bucket and a lockout,
`AUTH_SESSION_REVOKED` or `AUTH_SESSION_EXPIRED` for an absent session) or does not exist in the
library at all. If you branch on one of them today, that branch is already dead code.

The last two are now raised. `JwtTransport.verify` reported every failure as
`AUTH_SESSION_REVOKED` — a malformed token, a tampered signature, a wrong issuer or audience, an
unknown `kid` — though nothing had been revoked, and `AUTH_SESSION_REVOKED` is also what a store
answers for a row that is absent or corrupt. A token that does not verify is `AUTH_JWT_INVALID`,
and one whose `kid` has no configured key is `AUTH_JWT_KEY_UNKNOWN`, carrying that kid: it is what
tells a key rotation you cut over too early from a genuine mass revocation, which until now looked
identical from the outside.

Both new codes are in the absent set, so `.orNull()` still answers `null` and a composite
transport still falls through to its next member — reader behaviour is unchanged, and only the
code and its meta are different.

Seven unused type and value exports went with them: `fail`, `Carries`, `Fault`, `MetaOf`, and
`AuthError.HasRequired`, `AuthError.Faults` and `AuthError.Error`. Each was a pass-through of a
`@gentleduck/errors` type with no reference anywhere; `isSecretKey` stays, since it is the
predicate behind `redactSecrets` and belongs next to it.

**BREAKING: `@gentleduck/auth/i18n` is removed.** The subpath exported a message catalogue, a
Lingui adapter and a default English table. Nothing in the library read any of it: no engine
option took a resolver, no flow resolved a message through one, and the channel template ids in
the default table were named nowhere else, so a catalogue you overrode was never consulted. It
also covered only thirteen error codes, and a code without an entry rendered as its own id.

Message resolution stays where it already was — yours. `Channels.SendInput` hands your channel a
`templateId` and pre-rendered `vars`, and the channel maps that id to its own template store; that
contract has not changed. If you imported `AuthI18nMessageCatalog`, `AuthLinguiResolver` or
`AUTH_DEFAULT_EN_MESSAGES`, copy the table into your app and keep using your own resolver.

**BREAKING: the `duck-auth` CLI is removed**, along with the `@gentleduck/auth/cli` subpath and
the `bin` entry. It provided `init` scaffolding, `doctor`, `keys generate` and `migrate`.

`doctor` ran `AuthEngine.strict()`, which you can call directly at boot — that is where it belongs
anyway, since it fails startup rather than a separate command you have to remember to run.
`keys generate` minted secrets and EC keypairs, which is `node:crypto` (`randomBytes`,
`generateKeyPairSync`) in three lines.

`migrate` is the one to plan for: the package no longer emits DDL. It wrote its migrations by hand
against a generic bridge schema, in parallel with the drizzle adapters declaring the same tables in
TypeScript, and the two had already drifted in both directions. Generate your schema with
drizzle-kit against the adapter schemas, which are still exported from every drizzle subpath —
`authMysqlSchema` and its pg and sqlite counterparts — so there is one declaration of the tables
instead of two.

**BREAKING: the operations module is removed**, along with `OperationsImpl`, the `operations()`
factory and the `Operations` type. Nothing in the package ever enforced either switch —
`assertOperationsForRoute` was called by no adapter or route, no adapter implemented
`Operations.Store`, and `AuthEngine` never constructed one — so the feature was a state object you
had to wire, persist and enforce yourself. A maintenance page belongs at your load balancer, and a
read-only freeze belongs in your own middleware, where the route table is.

Going with it: the events `maintenance.on`, `maintenance.off`, `readonly.on` and `readonly.off`,
which only `OperationsImpl` emitted, and the codes `AUTH_MAINTENANCE` (503), `AUTH_READONLY_MODE`
(423) and `AUTH_OPERATION_NOT_FOUND` (404). If you subscribed to any of the four names, or matched
on any of the three codes, those branches are now unreachable. `AUTH_READONLY_MODE` was the only
423 in the catalogue.

**BREAKING: `@gentleduck/auth/telemetry/otel` and `@gentleduck/auth/openapi` are removed.** Neither
had an importer inside the package; both were layers the host already owns.

`AuthOtelInstrumentation` subscribed to the event bus and kept six counters. `@opentelemetry/api` is
no longer an optional peer dependency. Subscribe your own meter to `auth.events` instead — it is a
`bus.on(name, ...)` per metric, and you already own the exporter and the resource attributes.

`buildOpenApiSpec` and `renderOpenApiYaml` described the auth surface from a route table maintained
by hand, separately from the router that actually mounts those routes; the two had already drifted
by six paths. Generate your spec from the router you mount, or write it against the endpoints in the
README, so the route table is declared once.

**BREAKING: the channels abstraction is replaced by one `deliver` callback.** `@gentleduck/auth/channels`
and its six backend subpaths (console, smtp, resend, ses, twilio, webpush) are gone, along with the
`Channel` contract, `ChannelGuard` and the outbound redactor. `@aws-sdk/client-ses`, `resend`, `twilio`
and `web-push` are no longer optional peer dependencies.

Every outbound token now goes to one callback on the engine config:

```ts
const auth = createAuth({
  baseUrl: 'https://app.example.com',
  deliver: async ({ kind, identity, vars, tenant }) => {
    // kind: 'magic-link' | 'password-reset' | 'email-verification'
    //     | 'account-deletion' | 'account-deletion-cancel'
    await mailer.send(identity.profile.email, render(kind, vars))
  },
  // ...
})
```

The library signs the URL and hands over the recipient's whole identity row, the template vars and the
tenant; you choose the transport and write the template. The token reaches `deliver` and nothing else —
in particular it never goes on the events bus, which `WebhookDeliverer` forwards to external endpoints.

`deliver` is config, not a per-call argument: drop it from `requestPasswordReset`,
`requestEmailVerification`, `requestAccountDeletion` and `magicLink({ ... })`'s per-call sites.
`completeAccountDeletion`'s channel bundle becomes `sendUndoLink?: boolean` — leave it off and
`cancellationToken` still comes back for you to deliver, or to drop, which is how undo is turned off.
`beginProvider('magic-link', { channel })` no longer takes a channel name, and the `channel` field on
magic-link credential metadata is gone.

**Report a delivery failure by throwing.** The `{ ok: false, error }` return is gone, so the two
`signin.failed` reasons `'channel.send rejected delivery'` and `'channel.send threw'` collapse into
`'deliver threw'`. What you throw is never read into the event — it carries the recipient and the
rendered body with the token URL in it.

**You now own the recipient check.** `resolveEmailRecipient` refused a CR or LF in an address before it
reached a transport; nothing in the library does that any more. `canonicalEmail` trims, lowercases and
NFC-normalises, and does not validate structure. If you store addresses from user input and interpolate
them into mail headers, validate them yourself.

`strict({ env: 'production' })` no longer refuses console/noop/test channels by brand. It refuses the one
pairing that cannot work instead: the magic-link provider registered with no `deliver`, which would
otherwise mint a token, store it, answer `{ ok: true }` and send nothing.

`Deliver` and `DeliveryKind` are exported from `@gentleduck/auth` and `@gentleduck/auth/core`, so the
callback can be typed without writing the message shape out by hand.

**The actor types moved into an `Actor` namespace**, matching every other module in `core`. Type-only —
no runtime export changed — but the names did: `ActorContext` is `Actor.Context`, `ActorResolvable` is
`Actor.Resolvable` and `RequestActorOptions` is `Actor.RequestOptions`. Import `Actor` from
`@gentleduck/auth` or `@gentleduck/auth/core` and reach through it. `Engine.Cfg.resolveActor` is now
`Actor.Resolver` rather than a second copy of the same signature, and `src/core/actor/README.md`
documents the precedence ladder, the `withActor(undefined)` fence and what the scope does not do.

**A session store that was merely unwell turned the hijack check off.** `withRequestActor` — which seven
of the eight framework adapters mount — wrapped its `resolveSession` in a bare `catch`, so every failure
that was not "no session" fell through to running the handler unbound: no actor on the writes it made, no
audit envelope, and `onSession` never called, which is where `requestSecurity` puts the hijack and anomaly
refusals. The catch is gone. A request with no token, or with an expired, revoked or forged cookie, still
runs unbound as before; a store that is down, or a session that outlived its identity, now raises, and
every adapter already has a path for that. `AUTH_SESSION_IDENTITY_ERASED` is kept out of the absent set to
stay loud, and this was silencing it.

**Nest could not deliver the refusal it had chosen to make.** `nestActorContext` resolves the session
itself and deliberately lets a store outage fail, but that `await` sat outside the `try` that forwards to
`next(err)`. Nest's HTTP layer is Express, where a rejected async middleware goes nowhere, so the request
hung until something timed out rather than answering. The resolve moved inside the try.

**An empty actor id is no longer an actor.** `withActor('')` and a `resolveActor` returning `''` — what a
host's request context answers when it means "no user" — wrote an empty string into `created_by`,
`updated_by` and `deleted_by`, so `where created_by is null` missed those rows. `''` is now the same fence
`undefined` already was, and records NULL.

`withActor` returns exactly what its callback returns, rather than `T | Promise<T>`; an async callback now
yields a `Promise<T>` you can await without a cast or a wrapper.

**One `ActorOptions<Req>` replaces nine copies of it.** Every adapter declared its own actor-wrapper
options type — the same three fields, differing only in what `getCaller` reads — and gRPC declared them a
ninth time. They are now aliases of one generic exported from `@gentleduck/auth/server/generic`:
`ExpressActorOptions = ActorOptions<ExpressAdapter.Request>`, and so on. Every name you import still
exists and still means the same thing.

**Next.js error responses now carry the same content-type as every other adapter.** `next`'s error path
went through `Response.json`, which omits `charset=utf-8`; elysia, hono and next now answer through one
`jsonResponse`/`errorResponse` pair exported from `@gentleduck/auth/server/generic`, so a client sniffing
the charset gets the same answer whichever adapter is mounted.

**One `burnCredential`, not four copies of it.** Claiming a single-use token by rotating its secret to one
nobody holds — the write that makes magic links, password resets, email verification and deletion
confirmations single-use — was written out separately in each of the four flows. It is one function now,
so the next change to it reaches all four.

**`isFactorMethod` and `isSessionKind` are exported from `@gentleduck/auth/core/sessions`.** They existed
three and two times respectively, once per reader. One of those copies hand-listed the session kinds
rather than reading `AUTH_SESSION_KINDS`, so a kind added to the constant would have been accepted
everywhere except in a JWT. `JwtTransport.IJwtAlg` is now derived from a new exported `AUTH_JWT_ALGS`
rather than restating it.

**Anomaly detection was switched on by configuration and reachable from nothing.** `createAuth` builds an
`AnomalyFacet` and exposes it as `auth.anomaly`, but the two detectors it ships, the fingerprint store
behind one of them and `DEFAULT_ANOMALY_CONFIG` were exported from no import specifier a consumer could
write — and `resolveSession` skips the whole path when nothing is registered. So a host that configured
thresholds, wired `getCaller` and passed an `onAnomaly` got the hijack check and nothing else. All seven
runtime symbols now export from `@gentleduck/auth/core`, alongside `AuthImpossibleTravel`, which was not
exported even as a type.

**A verdict is no longer lost to the bus it was announced on.** `AnomalyFacet.evaluate` emitted
`suspicious` outside a try, and `resolveSession` answered a throw from it by returning the session with no
verdict — so a bus that rejected served the `deny` as an ordinary request. Since the emit only fires when
something was found, the failure landed on exactly the requests the verdict exists for. The emit is logged
now, not thrown, and `resolveSession` logs rather than dropping silently.

**A device you use every day is no longer the one forgotten first.** `AuthMemoryDeviceFingerprintStore`
refreshed a known fingerprint's timestamp but not its position, while eviction took the oldest by
insertion — so past the per-identity cap the daily device was evicted ahead of one seen once, and the
next sign-in from it raised `new-device`, which on the default ladder is an MFA prompt. The store is
least-recently-seen-first now, which is what its eviction already assumed.

**`AuthDeviceFingerprint` and `AuthImpossibleTravel` moved into `anomaly.types.ts`** beside `Anomaly`, so
a detector's config can be named without importing its implementation. `Anomaly.Kind` now admits a
plugin's own kind, which `isValidSignal` has always accepted and the type refused. `Anomaly.Result.score`
was documented as a sum of the signal scores; it is noisy-or, `1 - ∏(1 - score)`, saturating at 1, so a
`denyAt` written against the old documentation was written in the wrong space. `src/core/anomaly/README.md`
is new.

**An anomaly signal's `evidence` is now guaranteed to be a record.** `isValidSignal` checked a detector's
`kind` and `score` and asserted the whole `Anomaly.Signal` type, so a detector returning no `evidence` —
or a string, or an array — put that into `Result.signals` against a declared `Record<string, unknown>`.
It reaches every subscriber of `suspicious`, so the first `Object.keys` downstream threw on a request
that was already the suspicious one. Absent reads as `{}`; anything that is not a record is refused with
the detector's other malformed output. `RequestSnapshot.geo`'s fields are `readonly`, matching the deep
freeze the facet already performed.

**Every constant in the anomaly module moved to `anomaly.constants.ts`**, grouped by the ladder, the
scoring maths and one group per detector — so the two values a deployment is most likely to change, 50
remembered devices per identity and 900 km/h, are in one file instead of inside the implementations.
The fingerprint sentinel formerly called `ABSENT` is `FINGERPRINT_ABSENT`, since `ABSENT` is already
`@gentleduck/auth/core`'s set of error codes meaning "no row". All of these are module-internal; the
public surface is unchanged.

**The anomaly types are fully documented.** `Signal`, `RequestSnapshot`, `Detector`, `Decision`,
`Result`, `AuthDeviceFingerprint.Cfg`, `AuthDeviceFingerprint.IStore` and `AuthImpossibleTravel.Cfg`
each had no doc comment, nor did most of their fields — and the root barrel exports these as types and
nothing else, so that was the whole surface a consumer read on hover.
