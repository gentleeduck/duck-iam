---
'@gentleduck/auth': minor
---

Security fixes from the ongoing audit, grouped by what goes wrong if you do not
take them.

**On Nest, express-session let every request past `makeGuard`.** The guard
skipped resolving whenever `req.session` was already set, taking it for the
session `nestActorContext` had stored there. express-session, mounted the usual
way with `app.use`, sets `req.session` on every request, cookie or not, so each
guarded route admitted a request carrying no credential at all, and `@CurrentSession()`
handed the handler express-session's object as a `Sessions.Me`. `nestActorContext`
skipped on the same check, so a request that did carry a duck-auth cookie ran as
nobody and was never scored by the anomaly detectors. The guard, the middleware
and both decorators now share what duck-auth resolved for that request and never
read `req.session` back. They write it only into an empty slot, because
express-session throws on finding anything else there and the response hangs:
with express-session mounted, `req.session` stays its own, so read
`@CurrentSession()` and `@CurrentIdentity()`. Breaking for a host that assigned
`req.session` itself to feed the decorators: they now answer only what
`makeGuard` or `nestActorContext` resolved.

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
emit fixed text. Nothing about the caller's view changes: for a channel that
rejects, these paths already reported nothing.

**A `deliver` that threw before returning a promise answered a password reset or
magic-link request itself.** Both flows send without awaiting, behind a `.catch()`
that a synchronous throw — a template rendered ahead of the async send — gets past.
A known address then answered a rejection whose message quoted the signed URL, and
an unknown one answered `{ ok: true }`. When the mailer failed and a custom `events`
bus refused the `signin.failed` report, the rejection had nothing awaiting it,
which ends a Node process under the default `--unhandled-rejections=throw`. Both now
send through the same path as email verification and account deletion, which logs a
report the bus refused and never rejects.

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

**A stranger could take over an account that signs in by magic link.** Redeeming a
link never marked the address verified, so after its first sign-in a magic-link
account, with no provider links and only spent links for credentials, looked to
`beginSignUp` like a sign-up someone had abandoned. Anyone who began a sign-up with
its address reclaimed it: the profile was overwritten with theirs, and where
`required` leaves out `'email-verified'` they finished the sign-up holding a session
on the account. A sign-up someone began on the row before the owner's first
magic-link sign-in could likewise still complete into it afterwards, and one they
had finished kept its session, its password and its links. Redeeming a link now
marks the address verified, and the first one to do so also clears what anyone could
have put on the row before the owner proved the address: its other sessions end,
every credential on it is revoked (sign-up flows, a password, an enrolled factor, an
API key), and its provider links are dropped. Breaking for a user who signed up with
a password and never verified the address: after their first magic-link sign-in they
set the password again through a reset. Reclaiming a sign-up that really was
abandoned now also signs out the sessions it held. `'link-if-verified'` now links a
federated sign-in into a magic-link account, which it refused while those accounts
were never verified.

**An account whose second factor is a security key reset its password with the email
link alone.** The reset gate asked only whether the account had TOTP, so WebAuthn-MFA
accounts skipped it. It now asks for any enrolled second factor, and
`AUTH_RECOVERY_REQUIRES_MFA` names the ones enrolled in `methods` (`'totp'`,
`'webauthn'`); the reset mail's `requiresMfa` follows. `flows.completeStepUp` takes
`{ method: 'webauthn', webauthn }`, the same options `mfa.verifyWebauthnMfa` takes, so
such an account can reach the AAL2 session the gate asks for; nothing could turn a
WebAuthn-MFA assertion into one before.

**A magic link or reset link kept working after the account changed its address.**
Both go to the address the account held when they were requested, and neither
checked that it still did, so the old mailbox could sign in or set the password for
the link's lifetime after the owner moved off it; email verification already
refused this. Both now answer `AUTH_RECOVERY_TOKEN_INVALID` once the account's
address differs, case aside. The password-reset row records the address it went to
again, so a reset link issued before this release carries none and is refused; the
user asks for a new one.

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
live on the version Nest 10 ships. It now hands the error to `next(err)`, verified
against express 4.22.3 including that a downstream throw still reaches the error
handler exactly once. `ExpressAdapter.Middleware`'s `next` widens to accept an
error, which is what express passes it anyway.

**BREAKING: `nestActorContext` could not be mounted, so on Nest none of it ran.** It
returned an object with a `use` method, and `consumer.apply()` takes a function or a
middleware class: the documented `consumer.apply(nestActorContext(auth))` failed to
type-check, and with a cast Nest 11 dropped it without a word. Every request reached
its route with no actor on its writes, no audit envelope, and neither the hijack
policy nor the anomaly detectors asked, since `makeGuard` runs neither. It now returns
the middleware function, verified through both `consumer.apply` and `app.use` on Nest
11.1.27, with the whole body inside the `try` so a refusal or a store outage reaches
`next(err)` on Nest 10's Express 4 as well. Breaking for a host that called `.use` on
what it returned.

**BREAKING: on Nest's Fastify platform the handlers answered without a single header.**
`NestAdapter.Response` made `setHeader` optional and every write skipped a reply without
it, which is every reply `@nestjs/platform-fastify` hands over: a sign-in answered 200
with no cookie and no `Cache-Control: no-store`, which under a bearer transport leaves the
token in a body nothing marks uncacheable. `setHeader` is now required and `set` is gone,
so a Fastify reply is a type error, and at runtime a throw rather than a bare answer; the
handlers run on `@nestjs/platform-express`. Separately, the handlers answer an error and
then rethrow it for your filters, and `NestExceptionFilter` answered it a second time: with
the filter on the controller, as the example app mounts it, every refused sign-in logged
`ERR_HTTP_HEADERS_SENT` in place of the auth error. The filter now leaves an answered
response alone.

**On Hono and Next, a refusal from the actor wrapper answered 500.** A step-up the
hijack policy asked for, a session it revoked and a request the anomaly detectors
denied all left `honoActorContext` and `nextWithActor` as a throw, and Hono's default
error handler and a Next route answer any throw with a 500: the client was told the
server broke rather than to step up or sign in again. Both now answer an `AuthError`
below 500 themselves, at its own status with the standard error body, verified on
Hono 4.13.5 and Next 16.3.3; a 5xx and anything else still reach your error handling.
Hono's `app.onError` no longer sees those refusals, and `nextWithActor` now also
answers a 4xx `AuthError` its own handler throws.

**The client reported a signed-in user as signed out before it had asked.**
`onChange` replayed the client's state on subscribe, including before anything
had been fetched — and React, Vue, Solid and Svelte all map "no identity" to
`status: 'guest'`, so every binding moved out of `'loading'` in the same tick it
subscribed, with the wrong answer. The `'loading'` state all four declare could
not be observed at all, so an app gating on `status` flashed its sign-in screen
for authenticated users on every load, and one redirecting on `'guest'` sent them
there. The client now replays only a state it actually holds; a signed-out state
that was really read is still one, so a late subscriber is unaffected.

**On Fastify, signing out cleared the page but not the session.** The vanilla
client labelled every request `content-type: application/json`, the bodiless
sign-out included, and Fastify refuses an empty JSON body before the route runs:
`registerFastify` answered 400, the session stayed live on the server, and the
client cleared its local state anyway. A request is now labelled JSON only when it
carries a body, and every request sends `accept: application/json`. A response
whose body is cut off mid-read now resolves to `AUTH_NETWORK_ERROR` instead of
rejecting.

**On Express and Nest, the adapter's own refusals lost their code.** `applyIntents`
answered an error intent, and an unsafe redirect, as `{ code, detail }` instead of
the `{ ok: false, error: { code, status, detail? } }` envelope everything else
answers, so the client reported a malformed sign-in body, an unknown provider id or
a failed oauth callback as `AUTH_HTTP_ERROR`. `executeIntents`' unsafe-redirect
refusal had the same bare body. All three now answer the envelope.

**An "active devices" list showed devices that were already signed out.**
`sessions.listForIdentity` answered every row the store held, and a store keeps a
session past its idle or absolute deadline until `gc` sweeps it. Every such row
was refused on use but still listed as a signed-in device. It now leaves them out;
the rows stay for `gc` to sweep. `revokeAllExcept` counted them too, so "sign out
other devices" reported more devices than the list showed: it now revokes and
counts the live ones. `revokeAllForIdentity` still removes every row and answers
the ones that were live.

**Sessions slide, so an active user stays signed in.** Nothing called
`sessions.touch`, so a user was signed out `ttlMs` (7 days) after signing in however
active they were, and `absoluteTtlMs` was never reached. `resolveSession` now slides
the idle deadline once less than half of it is left, writing the row at most once
per half TTL. The session cookie and its CSRF companion live to the session's
absolute deadline instead of `maxAgeSec`'s old 7-day default; `maxAgeSec` still
shortens them, and the idle deadline is enforced server-side as before.
`sessions.create`'s `maxExpiresAt` now caps `absoluteExpiresAt` too, so a slide can
never carry an m2m session past its token.

**Signing in again left the previous session live.** No adapter passed
`previousSid` to `flows.signIn`, so a browser that signed in a second time, or where
another account signed in over the first, kept the replaced session valid and
listed as a device. Every adapter's sign-in route, hono's magic-link and passkey
routes, and `oauthCallback` now pass the SID the request carries, and the sign-in
ends it. A host route calling `flows.signIn` itself should pass
`previousSid: auth.transport.extract(req) ?? undefined`. A previous SID naming no
session, such as a signed-out device's cookie, is now ignored rather than emitting
`session.revoked`, and that event names the revoked session's own identity (`null`
for a guest) rather than the one signing in.

**Answering a flow from your own routes.** `koaApplyIntents(intents, ctx)` is new:
copying `executeIntents`' Response onto a Koa ctx with `headers.get` joins every
Set-Cookie into one header, which a browser reads as one cookie.
`ExpressAdapter.Request.params` is `Record<string, string | string[]>`, so a stock
Express 5 `RequestHandler`'s `req` now type-checks where the adapter takes it.

**A 5xx is logged by the server that answers it.** `errorToHttp` turned a crash
or an `AuthError` fault into a response and logged neither, so a fault in an
adapter's own route, such as a database never migrated, answered "internal error"
or a one-line detail and left the server's terminal empty. It now logs the error
behind any 5xx under `[@gentleduck/auth]`, cause chain included; a 4xx logs
nothing. `withGrpc` does the same, and `NestExceptionFilter` answers through
`errorToHttp`. A host error handler that logs a 500 after calling `errorToHttp` or
`errorResponse` now logs it twice, so drop its own line.

**Type changes: React's `useSignUp` and `withNextCsrf`.** `useSignUp` dropped its
options, so it always posted to the `/signup` placeholder no adapter mounts, and
required a `username`. It now takes `useSignUp<Input>({ path })` with `Input`
defaulting to `unknown`. `withNextCsrf` passes every argument on, the route's
`{ params }` included, and returns a handler of the same arguments, as
`nextWithActor` already did. An OAuth provider's `profileToIdentityProfile` may
return `null` to refuse a first sign-in, which the provider already did at
runtime for any falsy answer; the type allowed only a profile, so an app with no
usable profile to make, such as one keyed on an email the IdP did not return,
had nothing to answer with.

`JwtTransport.rotateSignKey` now clears the same floor the constructor does.
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

**BREAKING: `AuthAesGcmDataAtRest` binds `ctx.tag`, and writes `aes-256-gcm.v3`.** `DataAtRest.Context.tag`
went into the KMS envelope's encryption context but not into the AES-GCM key, so a value written under one tag
decrypted under any other. New ciphertexts bind it; `v2` ones still read, whatever tag is passed, and
`needsReEncrypt` reports them. `AuthKmsEnvelopeDataAtRest` now applies the AES-GCM adapter's bounds: a plaintext
must be a string of at most 1 MiB and a ciphertext a string within the matching envelope size, and a malformed
IV, tag or empty wrapped key is refused before KMS is asked to unwrap anything. A non-string plaintext used to
fail with a `TypeError` after a billed KMS call, leaving the data key it minted unzeroed.

`PluginRegistry.install` now refuses a plugin that subscribes to an event the
bus does not carry. The name was cast straight to `keyof Events.EventMap`, and
`on` makes a handler set for whatever string it is given, so a plugin naming a
mistyped or renamed event installed cleanly, appeared in `installed`, and its
handler could never fire — silently, for an audit or alerting plugin listening on
`suspicious` or `lockout`. A new `isEventName` predicate keys off the record the
compiler already proves exhaustive against `EventMap`, and uses `Object.hasOwn`
so `constructor` is not answered yes by the prototype.

`AuthWebhookDeliverer` refuses an endpoint whose `events` is neither `'*'` nor a
list of known event names. Endpoints are usually loaded from a database, so the
type does not reach them: a misspelt or renamed event subscribed the endpoint to
a name the bus never emits, and a string such as `'all'` subscribed it to each of
its characters. Either way the deliverer constructed cleanly and the consumer
received nothing.

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

**A compliance preset could not be applied.** `applyCompliancePreset` was
exported from no entrypoint, and `createAuth` refused the brand it sets as an
unknown key, so the preset session windows and the compliance checks in `strict()`
never ran outside the package's tests. `createAuth({ compliance: 'hipaa' })` now
applies one. A preset's `minAal` is not enforced at sign-in: it makes `strict()`
refuse an engine with no mfa provider, and requiring AAL 2 stays your `checkStepUp`.

**`identities.create` no longer takes a `tenantId`.** Neither it nor `bulkCreate`
passed the field on, since identities are global and only credentials and sessions
are tenanted, so an account created "in" a tenant was not. Passing one is now a type
error rather than a silent no-op.

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

**BREAKING: SAML now works with a real `@node-saml/node-saml` client.** Every SAML
test faked the client, and the fakes were shaped by what the wrapper read. A real
`SAML` instance did not type-check as `Saml.Client`, and cast through, it failed in
four places. node-saml puts no `ID` on a sign-in profile, so the replay store the
provider requires refused every sign-in. It puts no `authnContext` there either, so
`mfaAuthnContexts` never matched and every session was aal 1. It copies each
attribute onto the profile's top level as well as into `attributes`, so
`allowedAttributes` filtered one copy and `onSignIn` received the other, and an
attribute named `ID` or `authnContext` stood in for the real value. And
`completeIdp` called its callback-style `getLogoutResponseUrl` with no callback,
which throws, having asked for a failure status, with no `InResponseTo`, and
without the RelayState the bindings require it to echo. The assertion's ID and
AuthnContextClassRef are now read from the assertion node-saml parsed, `onSignIn`
receives the `Saml.Profile` fields and nothing else, and IdP-initiated logout
answers through `getLogoutResponseUrlAsync` with a Success status, `InResponseTo`
the request, and its RelayState (`RelayState` beside `SAMLRequest` for the POST
binding). `Saml.Client.getLogoutResponseUrl` is replaced by
`getLogoutResponseUrlAsync`, `completeIdp` answers `nameID: string`, and a missing
or malformed input to `beginSp` or `completeIdp` is `AUTH_INVALID_PARAMETERS`
rather than `AUTH_MISCONFIGURED`. `profileToIdentityProfile` is removed: its
result was discarded, `allowedAttributes` is what narrows the profile, and
`onSignIn` is where it becomes an identity. `Saml.Options` is no longer generic.

**A SAML attribute can no longer stand in for the subject's nameID, its format or the session index.**
Reading `ID` and `authnContext` off the assertion left `nameID`, `nameIDFormat` and `sessionIndex` on
node-saml's top level, where an attribute of the same name fills any the assertion leaves unset. An
attribute `nameIDFormat` on a NameID stating no format switched off the check that its email matches
it, and an attribute `nameID` became the subject of an assertion with no NameID. All three are read from
the assertion now, and an assertion with no NameID is refused. An `email` sent as several values is
refused rather than failing with a `TypeError`.

**BREAKING: SAML Single Logout over the Redirect binding requires a signature, and reads only the raw query.**
node-saml verifies a Redirect-binding signature only when one is present, so an unsigned LogoutRequest
naming any user was answered and the host logged that user out; and because the host passed a parsed
`query` beside the raw `originalQuery`, a forged `SAMLRequest` appended to a query the IdP had signed was
the one decoded. `completeIdp` and `completeSp` now take `originalQuery` alone, the query string exactly as
it arrived, read each SAML parameter from it once, and refuse a message without `SigAlg` and `Signature`
or with a parameter repeated. `query` is removed from both inputs. `completeSp` resolves to `void`: its
`nameID` was always `null`, since a LogoutResponse names no subject.

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

**On the Redis bus, one failed `UNSUBSCRIBE` left a node deaf to the fleet, and one
failed `SUBSCRIBE` doubled everything after it.** When the last handler for an event
left and the unsubscribe was refused — a dropped connection says "Connection is
closed." — the rejection had nothing awaiting it, and the event stayed marked as
subscribed, so no later `on()` subscribed again: that node heard nothing from the
other instances for it. The failure is now logged and the channel treated as closed.
Separately, `valkeyPubSubAdapter` kept the listener of a `SUBSCRIBE` that failed, so
the retry the next `on()` makes added a second, and each message ran every handler
twice from then on; it now detaches it.

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

**BREAKING: a session or identity number that came out NaN was taken as given.**
`Number(process.env.X)` of an unset variable is NaN, which `??` does not replace: under
`session.ttlMs`, `absoluteTtlMs` or `freshnessMs` every session was dated unreadably and
expired on arrival, so sign-in succeeded and nothing after it did, and under
`identities.profileMaxBytes` the 16 KiB profile cap was lifted, a 500 KB profile accepted.
`SessionsImpl` and `IdentitiesImpl` now throw `AUTH_MISCONFIGURED` at construction unless the
three session windows are finite and positive, `softDeleteGracePeriodMs` and
`profileMaxBytes` finite and not negative (`0` still disables the cap; a negative one, which
did the same, is refused), and `maxSessionsPerIdentity`, when set, a whole number above 0.

**BREAKING: `sessions.create` refuses a lifetime cap it cannot read, instead of minting the full TTL.**
`ttlMs` only ever shortens a session, and one that was NaN, zero, negative or infinite was dropped
without a word, so the caller asking for a one-minute session got the configured week. A `maxExpiresAt`
that was an `Invalid Date` minted a session that every read refused as expired, and a number in its
place threw a `TypeError`. Both are now `AUTH_INVALID_PARAMETERS`, and a factor whose `completedAt` is an
`Invalid Date` is refused with the non-`Date` ones.

**The Redis session store no longer sends `EX NaN` for a deadline it cannot read.** It took
any `Date` as readable, so a `create` or `update` carrying an `Invalid Date` as
`absoluteExpiresAt` wrote `ex: NaN` and a NaN expiry score. Redis refuses that command, and
a client that drops the option leaves a key with no expiry. Such a row now gets the store's
longest TTL and is scored as already due, which is how the store already handled a
serialised date.

**BREAKING: a password length that came out NaN turned the length check off.** Both
bounds are compared bare and the compliance floor goes through `Math.max`, which answers
NaN for a NaN, so `passwords({ minLength: NaN })` accepted a two-character password even
under `compliance: 'hipaa'`, and `maxLength: NaN` let any length through to the hasher.
`passwords()` now throws `AUTH_MISCONFIGURED` unless both are whole numbers with
`1 <= minLength <= maxLength`.

**BREAKING: a JWT window that came out NaN issued tokens nobody could use.**
`JwtTransport({ ttlMs: NaN })` minted access tokens its own `verify` refuses, so sign-in
answered and every request after it was a 401; `freshnessMs: NaN` made no token fresh, and
`refresh.ttlMs: NaN` wrote a refresh `Max-Age` browsers ignore. `JwtTransport` now throws
`AUTH_MISCONFIGURED` at construction unless all three are finite and positive.

**BREAKING: a reset or magic-link lifetime that came out NaN told a caller which
addresses are registered.** Both write a token only for an address that exists, and the SQL
stores refuse the `Invalid Date` a NaN makes, so on Postgres or MySQL a registered address
answered 500 and an unknown one `{ ok: true }`. `requestPasswordReset`,
`requestEmailVerification` and `requestAccountDeletion` now throw `AUTH_MISCONFIGURED` for a
`ttlMs` that is not finite and positive, before looking anyone up, and `magicLink()` throws it
at construction.

**BREAKING: a WebAuthn challenge lifetime that came out NaN broke every ceremony.** The built-in
stores turned it into a challenge that was already expired, or an `EX NaN` Redis refuses, so
passkey sign-in, passkey registration and WebAuthn MFA all failed with an error that named
none of them. `passkey()` now throws `AUTH_MISCONFIGURED` at construction for a
`challengeTtlMs` that is not finite and positive, and `beginPasskeyRegistration`,
`beginWebauthnMfaEnrollment` and `beginWebauthnMfaVerify` throw it before storing anything.

**WebAuthn MFA could not be enrolled from an ES module.** `beginWebauthnMfaEnrollment` reached
`node:crypto` through `require`, which the ESM build can only shim, and the shim throws under
Node, so enrollment failed for every ESM consumer; the CommonJS build was unaffected. It
imports `createHash` now.

**WebAuthn MFA answered 500 for every refusal its verifier made.** A wrong origin,
challenge or rpID, or a counter rollback, reached `verifyWebauthnMfa` as a thrown
`Error` rather than `false`, and reached `confirmWebauthnMfaEnrollment` as an unmapped
error rather than `AUTH_PASSKEY_MISMATCH`. Both now answer as their other refusals do.
The rollback check also read only the new count, so a count falling back to zero, the
cloned authenticator, passed it and was refused only by the bundled verifier; it reads
the pair now, as the passkey provider does.

**A cloned passkey or WebAuthn MFA key was refused but never reported.** The bundled
verifier checks the signature count itself, and throws before it checks the signature,
so the `passkey-counter-rollback` and `webauthn-mfa-counter-rollback` `suspicious`
events fired only when two assertions raced. The providers now make that check
themselves, once the signature is verified: a signed count that goes backwards is
refused and reported, and a forged assertion is refused without a report, so the
signal cannot be raised by someone who does not hold the key.

**Another account could lock a user out of their passkey.** A passkey's credential id
is chosen by the authenticator and offered to anyone who starts a sign-in with the
owner's address, and nothing refused registering one that was already registered. A
second account that did became the credential sign-in found, so the owner's passkey was
refused from then on; WebAuthn MFA had the same flaw. Registering a credential id that
is already registered now fails with `AUTH_PASSKEY_MISMATCH` on both paths. Rows that
already collide are not repaired. WebAuthn MFA enrollment also lists the identity's
enrolled authenticators in `excludeCredentials` now, as passkey registration does.

**An idempotency window past a day was cut to one.** Both idempotency stores cut
`ttlMs` to 24 hours, so a key configured for 48 was released after 24 and a retry on
the second day ran the operation again; the configured window is now kept. `ttlMs` and
`pollTimeoutMs` are checked when the facet is built and refused with
`AUTH_MISCONFIGURED` unless finite: a NaN poll timeout answered every concurrent retry
409 without waiting, and an infinite one never answered once the first request's
process had died. Breaking: `IdempotencyImpl` no longer takes a `null` store and
`enabled()` is gone; the engine always wires a store, and no adapter read it.

**WebAuthn registration accepted key algorithms it never offered.** Passkey
registration and WebAuthn MFA enrollment offered Ed25519, ES256 and RS256, but the
response verifier fell back to its own wider list, RSA with SHA-1 among it, so MFA's
`supportedAlgorithmIDs` narrowed what the browser was asked for and not what was
accepted. Both now refuse a key under an algorithm they did not offer, with
`AUTH_PASSKEY_MISMATCH`. `confirmWebauthnMfaEnrollment` takes `supportedAlgorithmIDs`;
pass it the list given to `beginWebauthnMfaEnrollment`.

WebAuthn MFA loads `@simplewebauthn/server` through the passkey loader and is typed against
`Passkey.SimpleWebAuthnServerModule`, so its options objects are checked. Breaking (types): `Mfa.WebauthnLibrary`
is removed; pass a `Passkey.SimpleWebAuthnServerModule` as `webauthnModule`.

**BREAKING (types): `'indirect'` attestation is gone.** `Passkey.SimpleWebAuthnServerModule` is now checked
against the library where it is loaded, and `@simplewebauthn/server` has no `'indirect'`; passkey's
`attestationType` and MFA's `attestation` take `'none' | 'direct' | 'enterprise'`. Its `rp.id` and `rpId` are
optional, as the library answers them, and `Passkey.CredentialMetadata.transports` is `Passkey.Transport[]`.
Registration stores only the transports WebAuthn names, once each: the library passes on whatever the client
sent, and that was stored verbatim. WebAuthn MFA refuses a credential whose stored count is not a number, as
passkey sign-in does; it read one as 0, which let any count through.

Passkey sign-in refuses a null or missing `response` as `AUTH_PASSKEY_MISMATCH`, where it threw a TypeError.
Passkeys and WebAuthn MFA take a credential id up to the 1023 bytes WebAuthn allows: sign-in refused one past
768 bytes that registration had stored, and registration now refuses a longer one.

Passkey sign-in opens an AAL 2 session only when the authenticator verified the user. A presence-only
assertion, which the default `userVerification: 'preferred'` accepts from a security key with no PIN, opens
an AAL 1 session that `checkStepUp({ aal: 2 })` refuses; set `userVerification: 'required'` to refuse it
outright. Breaking: `MfaImpl.eligibleAal` is removed; read `session.aal`. Two TOTP enrollment confirms
racing on one code enroll once, with one set of backup codes.

**A revoked TOTP enrollment could still be confirmed.** `confirmTotpEnrollment` took the pending row whether or not it
was revoked or expired, so an enrollment an operator revoked still confirmed and minted backup codes good for a
step-up. It now refuses with `AUTH_MFA_REQUIRED`.

**BREAKING: one backup-code implementation.** `BackupCodesFacet`, `backupCodesFacet`, `AuthBackupCodesFacet` and
`DEFAULT_BACKUP_CODES_CONFIG` are removed. The facet hashed its codes in a form `auth.mfa` never computes, so
no code it minted could satisfy a step-up, and minting deleted the codes `auth.mfa` had issued. Its count and
wipe move to `auth.mfa.remainingBackupCodes` and `auth.mfa.removeBackupCodes`, which emits `mfa.removed`.
`verifyBackupCode` now forgives the spaces and hyphens a user types as well as case, and a code minted at
`backupCodeLen: 64`, which `verifyBackupCode` and `completeStepUp` both refused at 65 characters, verifies and
steps up. Codes already issued keep working.

**BREAKING: an `ApiKeysFacet` built by hand could make the bare prefix a key.** Only `apiKeyProvider`
checked the config, so `new ApiKeysFacet(...)` or `apiKeysFacet(...)` with `randomBytes: 0` minted the prefix
alone as every key, and `verify` accepted it as the owner. The constructor now takes `ApiKeys.CfgInput` and
refuses what the provider refuses. A `prefix` and `randomBytes` that make a key longer than the 512
characters `verify` accepts are refused as `AUTH_MISCONFIGURED`; such keys were minted and then never
verified. `authApiKeyImpl`, a second name for `authApiKey`, is removed.

**Rotating a revoked or expired API key handed back a working one.** `apiKeys.rotate`
checked only that the id named an API key, so a key revoked because it leaked, or
past its expiry, came back live under a new secret. It now refuses with
`AUTH_APIKEY_REVOKED`, as `verify` does.

**Revoking an API key left the sessions it signed in live.** A session `authApiKey`
opened outlived the key, and was opened as `kind: 'user'`, so nothing could tell it
from the owner's own. It is now `kind: 'apikey'`, as an `m2m` one is, and `revoke`,
`revokeAll` and `rotate` end every `apikey` session of the identity, in any tenant:
a session does not record which key opened it, so revoking one key signs out the
sessions its sibling keys opened too. `apiKeysFacet` takes the sessions store as a
new last argument; `apiKeyProvider()` passes it. An `m2m` access token is a JWT and
stays valid until its `exp`, as before.

**Impersonating left the operator's own session behind.** `impersonate` kept the
operator's session live beside the impersonating one, whose cookie replaces it, and
`releaseImpersonation` minted the operator a new one, so each impersonation left a
signed-in session nobody held. `impersonate` now ends the session it replaces.
Breaking for a bearer client that kept the operator's token to fall back to: it
uses the session `releaseImpersonation` returns.

**`promoteGuest` promoted any session.** Handed a signed-in session's sid, it signed
that session out and gave its device baseline to the identity being promoted. It now
refuses a session that is not a guest with `AUTH_INVALID_PARAMETERS` and leaves it
signed in.

**An idempotency key replayed another request's response.** A key reused with a
different body was answered with the first request's cached response. `handle` takes
`fingerprint`, a hash of the method, path and body; a repeat with another answers 422
`idempotency-key-reused`, as the IETF idempotency-key draft has it, instead of
replaying. Without it `handle` behaves as before.

**An older magic link kept working after a newer one was sent.** Every link stayed
live until its own expiry. Requesting one now retires the account's earlier links,
as a password reset does.

**Org membership and role changes left no audit trail.** `addMember`, `removeMember`
and `setRoles` emitted nothing. They now emit `org.member.added`,
`org.member.removed` and `org.roles.set`, audited like the other events and
delivered to webhooks subscribed to `'*'`. Breaking for a host that maps every
event name exhaustively.

**A resource server could not read the scopes an `m2m` token was granted.** The
token carries them, but `JwtTransport.verify` rebuilt the session without them.
`resolveSession` now answers `scope` for a token that carries one, and a transport's
`verify` answers `Transport.Verified`, a session with an optional `scope`.

**A remembered device could be issued as a password-reset token.** `RememberMeFacet.issue` let a `purpose`
key in the caller's metadata replace the row's, so the device token became whatever purpose it named, and
"forget every device" could not remove it. The purpose is now always `trusted-device`.

**A KMS that wrapped the data key in nothing stored values nobody could read.** `AuthKmsEnvelopeDataAtRest`
sealed the value anyway, so the write succeeded and the value was lost, which showed only on the first read.
`AuthAwsKmsProvider` did this over any client that answers a base64 string, as KMS's JSON protocol does. The
envelope now refuses an empty wrapped key as `AUTH_MISCONFIGURED`, and the provider refuses a key field that
is not bytes as `AUTH_PROVIDER_FAILED`. Breaking (types): `AuthAwsKmsProvider.IGenerateDataKeyOutput` and
`IDecryptOutput` are removed.

**BREAKING: the engine no longer holds an idempotency facet, so production boots without one.** Nothing in
the package called `auth.idempotency`, yet the engine built a `MemoryIdempotency` when none was configured, and
that constructor refuses under `NODE_ENV=production`, so every production deploy had to configure a shared store
it might never use, and `strict()` demanded one. `auth.idempotency`, the `idempotency` key on `createAuth` and
`AuthEngine`, `resolveIdempotency` and `IdempotencyInput` are removed. Build the facet yourself and call it in the
routes that need it: `const idem = redisIdempotency({ prefix: 'auth:idem', redis })`, then
`idem.handle(key, ctx, executor, { identityId })`. `createAuth` refuses a leftover `idempotency` key by name.

**The Hono and Next routes stop reading a request body past 100 KiB.** They read every body whole, so a
streamed upload to a public route like `/signin` was buffered to its end before anything refused it; the OAuth
form_post callback claimed an 8 KB cap and cut the body only after reading it. Past 100 KiB, the size Express's
body parser caps at, the read stops and the rest is cancelled, and a declared `Content-Length` over it is refused
before any read. The route answers as it does for a malformed body. `readBodyText` and `readBodyJson` in
`@gentleduck/auth/server/generic` are the reader, for a host writing its own Fetch-API routes.
`HonoAdapter.Context` and `MountHono.HonoCtx` no longer have `req.json`, which nothing reads now.

**A misspelled `hijack` reaction was enforced as nothing.** The policy's values
were never checked, so a config read from JSON or written in plain JavaScript with
`onUserAgentChange: 'MFA'` came back from `evaluate` as a reaction `applyReaction`
does not know, and the request went through where a step-up was configured; an
unknown `onMissingSignal` quietly meant `'soften'`. Both now throw
`AUTH_MISCONFIGURED` when the engine is built, as `anomaly.reactions` already did.

**BREAKING: `scan` is gone from the Redis client contract, and `eval` is optional.** Neither
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

`orgs.listMembers` no longer lists a member who left. On a host store answering every row it listed the departed
member and their roles, while `resolveMembership` refused them.

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

**BREAKING: `'link-if-verified'` no longer hands an account to whoever squatted its address.**
The policy linked an IdP sign-in to the local account holding the same email whenever the IdP
said the address was verified, and never asked whether the local account had verified it. So
anyone could sign up with a victim's address and a password, leave it unverified, and wait: the
victim's first Google sign-in landed in the squatter's account, squatter's password still on it.
Both sides must now have verified the address, and a callback policy receives
`existingEmailVerified` to decide the same way. Three ways round it are closed with it.
`identities.updateProfile` and `updateProfileMany` clear `emailVerified` in the same write when
a patch moves the address. `advanceSignUp` refuses a `profilePatch` that moves the email the flow
began with (`AUTH_INVALID_PARAMETERS`), which carried an `email-verified` stage onto an address
nobody proved. And `identities.markEmailVerified(id, email)` now takes the address being verified
and refuses with `AUTH_INVALID_PARAMETERS` once the identity no longer holds it; verification
links carry the address they were mailed to, so one clicked after the address changed answers
`AUTH_RECOVERY_TOKEN_INVALID`. Links issued before this release carry no address and are refused
the same way; the user requests a new one.

**A signup completion refused for its staged profile no longer spends the flow token.**
`completeSignUp` burnt the token and then wrote the profile the stages had staged, so a
`profilePatch` with a blank username was refused after the burn and the flow could not be
advanced to fix it. The staged profile is now checked first; a refused completion leaves the
token usable. `advanceSignUp` also refuses `profilePatch: { email: undefined }`, which slipped
past the fixed-email check.

**A password reset refused for a weak new password no longer signs the user out everywhere.**
`completePasswordReset` burnt the link and revoked every session before `passwords.set` checked
the new password, so a too-short one answered `AUTH_INVALID_CREDENTIALS` with the old password
kept, every device signed out and the link dead. The password is now checked first, and a refusal
spends nothing. The check is public as `passwords.assertStrength(plaintext)`, and a non-string
password is `AUTH_INVALID_CREDENTIALS` rather than a `TypeError`.

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

**A request the anomaly verdict refuses still has its drift audited.** `requestSecurity` acted on
the verdict before running the hijack check, so a `deny`, or an `onAnomaly` that throws to refuse
a step-up, left before an ip or user-agent change was looked at, and the `suspicious` event that
records one was never written — on exactly the requests most worth auditing. The hijack check now
runs first; which refusal wins is unchanged.

**BREAKING: a denied device stays new, on the retry too.** The device-fingerprint detector
remembered a device while scoring it, before any verdict existed, so whatever it added to a
`deny` was spent on the first attempt: the retry, or a request racing the first, passed as a
known device. A `new-device: 'deny'` reaction refused one request and allowed the next. Devices
are now remembered once the verdict is in, and never for a `deny`.
`AuthDeviceFingerprint.IStore` replaces `checkAndRemember` with `has` (read-only) and
`remember`; a store still written against `checkAndRemember` is refused at construction.
`Anomaly.Detector` gains an optional `record(ctx, decision)`, called after the verdict under the
same deadline, a failure logged and the verdict kept. It is skipped for a detector whose `evaluate`
threw or overran, or a store too slow to answer `has` made the device known without it ever being
scored. A `step-up` is still remembered, since the default lets it through: a host that refuses
one passes the signal's `evidence.fingerprint` to `store.forget`.

**Sign in with Apple now works, and `stateCookie` is no longer ignored.** Apple could
not complete a flow at three independent layers: the authorize request omitted
`response_mode=form_post`, which Apple requires as soon as *any* scope is requested
and the default scopes are `['name', 'email']`; no adapter mounted a POST that could
receive the resulting form post; and the pre-auth cookie was `SameSite=Lax`, which a
browser withholds on a cross-site POST, so the binding check failed even once the
first two were fixed. One new flag carries all three — `OAuth.Options.responseMode`,
set by the provider module rather than the host — so only Apple gets `SameSite=None`
and the other five providers keep `Lax`. `mountHono` now mounts the oauth callback on
POST as well as GET, reading `code`/`state` from a urlencoded body, and
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

**Sign in with Apple keeps the user's name.** Apple sends the name once, in the form post's `user`
field on the first authorization, and never again; nothing read it, so the `name` scope Apple asks the
user to share was thrown away for good. `mountHono` now forwards the field as `OAuth.CompleteInput.user`
and `apple()` reads its `firstName` and `lastName` into `Profile.name`. The field's `email` is not read;
the id_token's is the one Apple signs. A callback route you wrote yourself should pass `user` through.
`OAuth.Options.fetchProfile` receives the callback input as a third argument.

**Every framework adapter has the OAuth callback route.** Only `mountHono` mounted one, so on Express,
Fastify, Koa, Next, Elysia and NestJS the route an IdP returns the browser to was yours to write, and
Apple's form post with it. Each adapter now has one handler for GET and POST: `mountProviderCallback`,
`fastifyProviderCallback` (mounted by `registerFastify`), `koaProviderCallback`, `nextProviderCallback`
(routed by `mountNext`, which takes `providerCallback: false` to leave it out), `elysiaProviderCallback`
and `nestProviderCallback`, all over `oauthCallback` in `server/generic`. A form post needs your
framework's urlencoded body parser: `express.urlencoded()`, `@fastify/formbody`, `koa-bodyparser`.
The route is not CSRF-guarded, since the IdP's page posts it cross-site, so it now drives only a
provider of kind `oauth`: `mountHono`'s callback answers 400 for any other id, where it used to call
`signIn` with whatever id the path named.

**`mountHono` takes the caller's address.** Hono resolves none, and `mountHono` gave the app nowhere to
supply one, so no route it mounted stamped an address on the session row or gave the hijack and
anomaly checks one to compare. Pass `ip`, typed against your app's context:
`mountHono<Context>(app, auth, { ip: (c) => getConnInfo(c).remote.address })`.

**`client.beginProvider` begins OAuth and SAML sign-ins.** The begin route answered with a redirect to the
IdP, which `fetch` followed as a cross-origin request and failed, so neither the client nor
`useBeginProvider` could start one. A request accepting `application/json` now gets `{ url }` and the
pre-auth cookie, and the client, which sends that Accept, navigates there. A browser navigation still gets
the redirect. If you call the route with your own `fetch`, send the Accept header and assign the URL.

**Any OAuth 2.0 IdP can be added.** `@gentleduck/auth/providers/oauth/core` exports `oProvider`, the builder
the six shipped providers are made from, with `OAuthClient`, the `OAuth` types and the `getUserinfo*`
readers. **BREAKING:** `OAuth.Options.endpoints` is gone. Nothing read it; the endpoints belong to the
`OAuthClient` you pass as `client`.

**BREAKING: OAuth sign-in stores no refresh-token row.** Each sign-in whose token response carried a
refresh token wrote a new `oauth` credential row holding its hash, with no expiry. They were for a
refresh-rotation helper no entrypoint exported, and which could never run, since the token it needed was
the one that had been hashed away. The helper is gone, and with it `Credential.Store.revokeFamily`, which
a custom store no longer implements, `AUTH_OAUTH_REUSE_DETECTED`, `OAuth.CredentialMetadata` and
`OAuth.FamilyMetadata`. Rows of kind `oauth` already stored are read by nothing and can be deleted.

**BREAKING: a `replace` import no longer erases a user it cannot re-create.** `identities.bulkCreate(rows,
{ mode: 'replace' })` erased the identity holding a row's address, then created the row, and counted a refused
create as `failed` — so a profile over the size cap, a provider subject another identity holds or a username
already taken left the user, their credentials and their sessions gone behind a report that read as
untouched. The cap is now checked before the erase, where it is still a failed row. A refusal only the store
can raise is raised instead of counted, so the call throws; run a replace inside `withTransaction` for the
erase to roll back with it. A row's `providers` are now `ProviderLinkInput`, what `create` takes: drop the
`addedBy` the old type demanded, which nothing read.

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

One lost `EXPIRE` no longer locks a Redis rate-limit key out for good. `redisLimiter` sent `INCRBY` and
then `EXPIRE` on the window's first hit, so a timeout, a dropped connection or a crash between the two left
a counter with no TTL: it never reset, and once it passed `max` every later attempt on that key was refused
until someone deleted it by hand. With `eval` on the client, the increment and the TTL are now one script,
which also restores a TTL on a counter already left without one. The same script reads the remaining TTL,
so `resetAt`, and the `Retry-After` built from it, is the window's real end rather than a full window from
now. A client without `eval` keeps the two-command path.

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

**BREAKING for a custom `Credential.Store`: credentials revoke in bulk, as sessions do.**
`auth.apiKeys.revokeAll(identityId)` revokes every key an identity holds in one write and answers them revoked.
Before, a host revoked them one at a time, and a key minted meanwhile survived, or deleted them, after which a replayed
key answered `AUTH_APIKEY_INVALID` rather than `AUTH_APIKEY_REVOKED`. It sits on the new
`Credential.Store.revokeByKind(identityId, kind, ctx)`, which a hand-written store must implement;
`auth.passkeys` lists an identity's passkeys and revokes one or all of them, without the secret;
`revoke(identityId, credentialId, credentials)` refuses a row that is not a passkey that identity holds, so an id
read off another account revokes nothing.
`rememberMe.revokeAll` is one statement. `revoke` now records its actor in `updatedBy`, and revoking a revoked row
changes nothing on every adapter, where pg, MySQL and sqlite rewrote its `revokedAt` and version.

**An erasure's operator was recorded nowhere, and a transaction lost the actor of any narrower scope.**
`identities.erase` and `eraseMany` took `operatorId` and bound it around a store call no adapter reads it from. They
now emit a new audited event, `identity.erased` (`{ identityId, reason }`, one per row), with the operator as
`audit.actorId`. Inside `withTransaction`, audited events were stamped when `pending.flush()` ran, outside the actor
scope each call ran under; they are stamped as they are emitted now. A `'*'` subscriber or webhook endpoint receives
the new event.

**BREAKING: the hijack facet's `suspicious` event no longer carries the addresses and user agents it compared.**
Its `meta` was `{ from, to }`, the session's recorded ip or user agent and the request's, which every sink the bus
reaches then stored. The anomaly facet already kept raw request values off the same event. `meta` is now
`{ sessionId }`, the stored session id `session.revoked` also carries; `evaluate` still answers `from` and `to` to the
adapter and `onHijack`, in-process.

**Under `JwtTransport` the hijack policy could never refuse a drift.** `verify` rebuilt the session with no ip or
User-Agent, so every request read as a missing baseline, which the policy softens to `'rotate'` whatever it is set
to. Tokens now carry the session's `ip` and `ua` claims, readable by anyone holding the token, and `verify` restores
them. A deployment with `onIpChange: 'revoke'` starts revoking on drift under JWT; a token minted before this carries
neither and reads as before until it expires.

**A hijack rotation handed a drifted session freshness and a new absolute deadline.** The documented re-issue for
`'rotate'` was `rotateOrCreate({ purpose: 're-auth' })`, which is for a person who just authenticated: the new row
was fresh, so a stolen AAL2 session moved to a new address passed `checkStepUp` without a factor, and one that kept
moving never reached its absolute cap. Use the new purpose `'drift'`: the row is issued stale, keeps the previous
row's `absoluteExpiresAt` and `actingAs`, the previous row is revoked, and it refuses without a live previous
session. `Sessions.MintInput` takes `fresh: false` to issue any row stale.

**BREAKING: a request the hijack policy refused could still teach the device detector a new device.** The detectors'
`record` ran inside `anomaly.evaluate`, before `onSession`, so a stolen cookie replayed from another browser was
stepped up, had that browser remembered for the victim, and only then was refused on the User-Agent change. Records
now run from `Anomaly.Result.admit()`, which the actor wrappers call after `onSession` passes: a request refused by
the verdict, the hijack policy or `onAnomaly` records nothing. A host calling `resolveSession` with a
`requestSnapshot` itself calls `anomaly.admit()` once it serves the request, or no device is ever remembered.

**BREAKING: on Nest, duck-auth no longer writes `req.session`.** `makeGuard` and `nestActorContext` filled it when
empty, and express-session skips itself when it finds `req.session` filled, so an app mounting express-session after
duck-auth had its own sessions off for every signed-in request. Read the session with `@CurrentSession()`;
`req.identity` is still set, and `NestAdapter.Request` no longer has a `session` field.

A password reset, and removing TOTP or WebAuthn MFA, now revoke every remembered device (`RememberMeFacet`) the
identity holds in that tenant. A device token skips the second factor for whoever holds it, so one trusted before a
reset, or to skip a factor since removed, stayed good for its 90-day TTL unless the host wired `revokeAll` into both
itself. Removing backup codes leaves devices alone.

`session.maxSessionsPerIdentity` caps how many sessions one identity may hold, revoking the oldest to make
room. Set it on `createAuth` or `AuthEngine`; it holds inside `withTransaction` too. Unset by default, which is the
existing behaviour; guest sessions are not counted. Setting it puts one extra read on the sign-in path.

**Your captcha's timeout now covers the whole call, not just the handshake.** The
deadline was cleared as soon as the provider's headers arrived, so a provider that
answered `200` and then stalled the body parked the sign-in path indefinitely — the
outage the timeout exists to bound. It now stays armed across the body read and
reports `timeout` either way. A body the connection drops partway through is now
`network-error`, with the reason on `detail`, rather than a `malformed-response`,
which is kept for an answer that arrived whole and is not a siteverify body.

**A captcha `timeoutMs` past 2^31-1 no longer refuses every token.** Node's
`setTimeout` fires a longer delay after 1ms, so a large value meant as "no ceiling"
answered `timeout` to every challenge, humans included. It is now refused at
construction, as the anomaly detector timeout already was.

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

**A per-call `expectedHostname` or `expectedAction` of `''` no longer disables its check.** The
constructor already refused both empty; the per-call overrides got no validation. An empty
hostname matched a response that carried none at all, and an empty action replaced the
configured one and matched a widget mounted without an action — so the value a caller passes
to tighten one call was the one that removed the check. They are now `invalid-expected-hostname`
and `invalid-expected-action`, refused before the token is posted so a caller's mistake does not
spend the user's single-use token, and a non-string hostname no longer throws out of a `verify`
documented never to throw. A refusal also carries the provider's `action` and `score` now,
which were being dropped on the way out.

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

**`issue()` always writes `abs`, and a ceiling it cannot read makes a token nothing accepts.**
A session whose `absoluteExpiresAt` was an `Invalid Date` used to mint a token with no
ceiling, bounded only by `ttlMs` and the sliding deadline. The sessions facet reads the same
session as expired. `checkStepUp` now weighs `freshness` with the predicate the sessions
facet and `verify()` use, so a session exactly `freshness` old reads as stale there too.

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

**BREAKING: a DPoP proof's `alg` must match its key.** `DPoPVerifier` checked `alg`
against `acceptedAlgs` and then verified the signature under whatever key the header
carried. With the default `['ES256', 'EdDSA']`, a proof labelled `EdDSA` verified under
a P-256 key or a 1024-bit RSA key, and with `RS256` enabled a 512-bit key passed, so a
client could bind its tokens to a key anyone can factor. `ES256` now requires P-256 (not
secp256k1), `EdDSA` Ed25519 or Ed448, and `RS256`/`PS256` an RSA key of at least 2048
bits (RFC 7518 3.3). Anything else is `AUTH_DPOP_INVALID` with reason
`jwk does not fit alg <alg>`.

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

**The OAuth PKCE verifier no longer travels in the `state`.** The signed `state` carried
the verifier in plain base64url, and the IdP round-trips `state` in the authorize URL and
again beside `code` in the callback URL. Whoever could read a callback URL (a log, a
referrer, browser history) held both the code and its verifier, which is the interception
PKCE exists to stop; with no `clientSecret` (a public client) that alone redeemed the code
at the token endpoint. The state-binding cookie `begin` sets is now the verifier, and the
state carries only its digest. A flow begun before you deploy this fails at its callback.

**An OAuth sign-in can be begun through the mounted routes.** Every router refused the id
before the provider saw it: the begin route allowed letters, digits, `_` and `-`, and every
OAuth provider registers as `oauth:<vendor>`, so `POST /auth/providers/oauth:google/begin`
answered 400 on Hono, Express, Next, Fastify, Koa, Elysia and NestJS alike, and the only way
in was calling `auth.flows.beginProvider` yourself. The route now accepts exactly the ids the
engine registers. Express and Next also decode the id, which `client.beginProvider` escapes;
Express reads it from `req.params.id`, so mount `mountProviderBegin` on a route whose param is
`:id`, as its docs show.

**BREAKING: the OAuth vendors register as `oauth:google`, not `oauth:authGoogle`.** The rename
that prefixed every export with `Auth` also renamed the ids inside the vendor factories, so
Google, GitHub, Microsoft, Discord, LinkedIn and Apple have registered as `oauth:authGoogle`,
`oauth:authGithub` and so on. Those ids are what identity links and oauth refresh credentials
store, and what every begin and callback URL names. They are `oauth:google`, `oauth:github`,
`oauth:microsoft`, `oauth:discord`, `oauth:linkedin` and `oauth:apple` again. If you stored
links under the old ids, rewrite each identity link's `providerId` and each `oauth`
credential's metadata `provider` from `oauth:authGoogle` to `oauth:google` (and so on per
vendor), and the same prefix of its `familyId`. Until then a returning user's sign-in finds
no link: the default `onFederationConflict: 'reject'` refuses it when their email already has
an identity, and without an email match it creates a second one. A redirect URI that names
the id, as `mountHono`'s callback route does, changes with it at each IdP.

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

**BREAKING: `extractSetCookies` is removed from `@gentleduck/auth/server/generic`.** It read
`getSetCookie` defensively and answered `[]` on a runtime without it, and Node 22, the package's floor,
and Bun both have it. Call `response.headers.getSetCookie()`.

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
`vars` is typed by `kind`: every message carries the signed `url` and its lifetime `ttlMin`, a password
reset adds `requiresMfa` and the undo link `restorableUntil` (epoch ms), so `vars.url` is a `string`
without a cast.

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
no runtime export changed — but the names did: `ActorResolvable` is `Actor.Resolvable` and
`RequestActorOptions` is `Actor.RequestOptions`. Import `Actor` from
`@gentleduck/auth` or `@gentleduck/auth/core` and reach through it. `Engine.Cfg.resolveActor` is now
`Actor.Resolver` rather than a second copy of the same signature, and `src/core/actor/README.md`
documents the precedence ladder, the `withActor(undefined)` fence and what the scope does not do.

**`Events.IBus` declares an optional `listenerCount`, and `Events.Stampable` is gone.** Type-only. A bus
of your own type-checks without `listenerCount` as before, and `strict()` still skips its `lockout` check
on one that lacks it. `Stampable` existed for one cast inside the audit stamper, which no longer makes it.

**`NestAdapter.NestExecutionContextLike.getRequest` is no longer generic.** Type-only. It returns
`NestAdapter.Request`, so a context you build by hand returns the request as it is, where it had to be
cast to `T`. Nest's own `ExecutionContext` satisfies it as before, and a test now pins both guards to
Nest's `CanActivate`.

**`withGrpc` now compiles where grpc-js takes it.** Type-only. `GrpcAdapter.UnaryCall` required `session`
and `identity`, which grpc-js's `ServerUnaryCall` does not have, and the callback's error carried a
`metadata` of the adapter's own shape rather than grpc-js's `Metadata` class, so
`server.addService(def, { method: withGrpc(auth, handler) })` failed with TS2322 and every TypeScript
host needed a cast. Both slots are optional now, set once a session resolves; the callback's error is
`{ code, message }`, and `Metadata` asks only for `get`. Verified against @grpc/grpc-js 1.14.5, which a
test now pins it to.

**`withGrpc` no longer labels a failure it did not raise as `AUTH_MISCONFIGURED`.** A handler that threw, or
a `getCaller`, `onAnomaly` or `onHijack` hook that threw anything but an `AuthError`, was answered `INTERNAL`
with `AUTH_MISCONFIGURED`, pointing whoever read it at the auth configuration. It is answered `UNKNOWN` with
`Unknown error`, what grpc-js answers for the same handler unwrapped. An `AuthError` maps as before.

**The Fastify adapter now compiles where Fastify takes it, and the per-handler actor wrappers keep the
framework's types.** `FastifyAdapter.Request.params` was `Record<string, string>`, where Fastify types it
`unknown`, so `registerFastify(app, auth)`, `addHook('preHandler', fastifyCsrf(auth))` and every handler
failed to type-check against Fastify 5 and no TypeScript host could mount one without a cast. It is
`unknown` now, so a handler typed with `FastifyAdapter.Request` narrows `params` before reading it.
`fastifyWithActor`, `elysiaWithActor` and `nextWithActor` are generic over the handler they wrap: one
typed with Fastify's request and reply, Elysia's `Context` or Next's `NextRequest` keeps those types and
returns what its framework takes, and an untyped one gets the adapter's shapes as before.
`nextWithActor` called the handler with the request alone, so a dynamic route never received its
`{ params }`; every argument is passed on now. Verified against Fastify 5.12.5, Elysia 1.4.30, Express
5.2.1, Koa 3.2.1 and Next 16.3.3.

**BREAKING: the hijack policy's `'revoke'` now ends the session.** `applyReaction('revoke')` threw
`AUTH_SESSION_REVOKED` and did nothing else, so a host that set `onIpChange: 'revoke'` had the drifted
request refused while the session stayed live: no `session.revoked` was emitted, and the same cookie was
served again from the address that signed in. The session is now revoked before the refusal, and a store
outage during the revocation is raised rather than read as done. `HijackFacet` and `hijackFacet` take the
sessions as their second argument, and `applyReaction(reaction, session)` answers a promise, so a host
calling it directly passes the session and awaits it.

**An event sink that rejected decided the hijack reaction.** `hijack.evaluate` awaited each `suspicious`
emit bare, so a bus whose `emit` rejected failed the request with the sink's own error: `'revoke'`
refused without revoking, leaving the session live, and `'ignore'` refused a request the policy lets
through. The rejection is now logged and the configured reaction applies, as the anomaly facet already
did for its own emit.

**A User-Agent longer than the session column stepped up every request.** `SessionsImpl.create` keeps
the first 512 characters of a User-Agent, and `hijack.evaluate` compared that with the request's value
as given. The shipped `<name>Caller` helpers cut it to the same length first; a `getCaller` of the host's
own, reading the header directly, did not, so the browser that signed in read as a changed one on every
request, and under the default policy was asked for a step-up it could never clear. `evaluate` now reads
the request as the row was written: cut to the column, and an empty value as an absent one.

**BREAKING: a stepped-up, impersonating or post-reset session is now checked for drift.**
`completeStepUp`, `impersonate`, `releaseImpersonation` and a password reset made while signed in each
minted their session with no IP or User-Agent, and the hijack policy softens a missing baseline to
`'rotate'` whatever it is set to. So once a user stepped up to AAL2 their session could be replayed from
any browser, `onUserAgentChange: 'revoke'` included, and so could every impersonation. `rotateOrCreate`
now carries the previous session's `ip`, `userAgent` and `fingerprint` wherever the caller passes none.
`completeStepUp` takes the request's `ip` and `userAgent`, as `signIn` does; pass them
(`...expressCaller(req)`) so the browser that proved the factor becomes the one compared against. Without
them the session keeps the old values, and an `'mfa'` reaction on a changed browser is asked again rather
than cleared. `'mfa'` refuses every request an actor wrapper covers, so mount the route that completes the
step-up outside it. The `'rotate'` recipe on `applyReaction` now says to pass the session's `actingAs`:
`purpose: 're-auth'` drops it, which turned an impersonation into an unmarked session as the target. Under
`JwtTransport` the token carries no baseline at all, so the policy answers `'rotate'` at most there.

**BREAKING (MySQL): the session `ip` and `fingerprint` columns are wider.** `SessionsImpl.create` keeps up
to 64 characters of an address and 256 of a fingerprint, and the MySQL schema declared `varchar(45)` and
`varchar(128)`. Under MySQL's default strict mode a longer value refused the sign-in with
`AUTH_ADAPTER_FAILED`; a server without strict mode truncates instead, leaving a baseline shorter than the
value the hijack check compares against it. The columns are now `varchar(64)` and `varchar(256)`, and an
existing database needs `ALTER TABLE auth_sessions MODIFY ip varchar(64), MODIFY fingerprint varchar(256)`.

**A session store that was merely unwell turned the hijack check off.** `withRequestActor` — which seven
of the eight framework adapters mount — wrapped its `resolveSession` in a bare `catch`, so every failure
that was not "no session" fell through to running the handler unbound: no actor on the writes it made, no
audit envelope, and `onSession` never called, which is where `requestSecurity` puts the hijack and anomaly
refusals. The catch is gone. A request with no token, or with an expired, revoked or forged cookie, still
runs as nobody; a store that is down, or a session that outlived its identity, now raises, and
every adapter already has a path for that. `AUTH_SESSION_IDENTITY_ERASED` is kept out of the absent set to
stay loud, and this was silencing it.

**An empty actor id is no longer an actor.** `withActor('')` and a `resolveActor` returning `''` — what a
host's request context answers when it means "no user" — wrote an empty string into `created_by`,
`updated_by` and `deleted_by`, so `where created_by is null` missed those rows. `''` is now the same fence
`undefined` already was, and records NULL. `identities.erase` and `eraseMany` read an `operatorId` of `''`
as no operator too, rather than binding that fence over the request's own actor for a store reading it.

**A request with no session no longer inherits the actor around the server.** `AsyncLocalStorage` hands
a server started inside `withActor('system', ...)` to every request it accepts, and `withRequestActor` —
with nest and gRPC inline — ran the handler bare when no session resolved. An anonymous sign-up wrote
`created_by = 'system'` and audited `signup.completed` as the system's act. The audit envelope had the
same hole on the signed-in path: `runWithAuditEnvelope(undefined, fn)` inherited, and an ambient
envelope's `actorId` outranks `actorId()`, so a user revoking their own session under
`{ actorId: 'system' }` was audited as the system. Both scopes are now bound for every request, with a
session or without, and `runWithAuditEnvelope(undefined, fn)` clears the scope as
`withActor(undefined, fn)` already did. `withResolvedActor` takes `Sessions.Me | null`.

BREAKING: `resolveActor`, `currentActor` and `actorId`'s argument are gone, and `Actor.Context` (formerly
`ActorContext`) with them. Nothing in the package used them, and `actorId({ actorId: x })` answered `x`.
To attribute one call to someone other than the request's actor, wrap it in `withActor`: the innermost
scope wins. `createAuth({ resolveActor })` is unaffected.

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
that was already the suspicious one. Absent or `undefined` reads as `{}`; anything else that is not a
record is refused with the detector's other malformed output. `RequestSnapshot.geo`'s fields are `readonly`, matching the deep
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

**A device-fingerprint detector can no longer be registered without a store.** `deviceFingerprintDetector`
refused a missing `authSha256` at construction — so the detector could not end up registered, listed and
silent — but took `store` on trust, where a missing one throws inside `evaluate` and is caught, logged
and skipped once per request. It is refused at construction now, with the same check, and so is a
detector `register` could not run: no `evaluate`, an empty id, or a `record` that is not a function. A
`compose` that
returns something other than a non-empty string is skipped rather than passed to the store, where it
would have keyed nothing a hash produces and made every request a first sighting.

**The anomaly module now says when it has been switched off.** A `denyAt` below `stepUpAt` leaves the
step-up rung unreachable, and a `req.now` that is not a finite number — a `Date` where a number belongs —
makes every time-based detector score nothing. Neither is refused, because both fail closed and the
second would cost the whole verdict, but both are logged.

**An explicit `undefined` in the anomaly config now means the default.** `createAuth({ anomaly: {
stepUpAt: undefined } })` type-checks, and the facet spread it over its defaults, so the engine refused to
start with `stepUpAt must be a number between 0 and 1 (got undefined)`. The same held for `threshold`,
`denyAt` and `detectorTimeoutMs`, and for `authImpossibleTravelDetector`'s `maxKmPerHour` and
`minElapsedMs`. Each field now falls back on its own, as the hijack policy and the captcha config already
did; a value that is present and out of range is still refused.

**Impossible-travel evidence carries `intervalMs` alongside `elapsedMs`, and neither position.** The
speed is computed over `max(elapsedMs, minElapsedMs)`, so whenever those differ — a gap under the floor,
or a stored last-seen in the future — the recorded distance over the recorded elapsed did not give the
recorded speed. `from` and `to` are gone: they put the stored last-seen coordinates and the request's own
into every `suspicious` sink, which the device detector's evidence already refuses to do with an
address.

**`isRecord` moved to `@gentleduck/auth/core/predicates`**, replacing the byte-identical private copies the
package kept in eleven places, among them the captcha verifier, the Redis session store, both token
transports and the OAuth client.

**Captcha hostnames are compared case-insensitively.** `expectedHostname: 'App.Example.com'` against a
provider reporting `app.example.com` refused every solve — a hostname is case-insensitive, so the check
meant to stop a widget running on someone else's domain stopped it running on the operator's own.

**A captcha rejection always names a code.** `verify` never throws, so `errorCodes` is the only thing a
caller has to log, and a provider answering `{"success": false}` with no `error-codes` produced a refused
sign-in with no reason in the record. That case is now `provider-rejected`; a provider's own codes are
untouched.

**Captcha has no error vocabulary of its own.** `AuthCaptcha.ErrorCode` was a second set of error kinds
beside `AuthError.Code`, for an array that is mostly the provider's own wire codes passed through
untouched — and being an open union it narrowed nothing anyway. `IVerifyResult.errorCodes` is `string[]`;
the codes this package adds are a table in `src/core/captcha/README.md`. `CAPTCHA_TOKEN_MAX_LENGTH`,
`CAPTCHA_TIMEOUT_DEFAULT_MS` and `CAPTCHA_MAX_AGE_DEFAULT_MS` are exported from `@gentleduck/auth/core`,
where they were previously exported from a barrel no consumer could reach.

**The captcha types are fully documented, and `src/core/captcha/README.md` is new.**

**A malformed server body no longer throws inside the client.** `createAuthClient` treated any JSON body
with an `ok` key as a well-formed envelope and cast it. A server answering `{"ok":false}` with no `error`
— a proxy, an error page, a half-written route — was handed back as one, and the first caller to read
`res.error.code` got a TypeError rather than a failure it could report. The shape is checked now, and a
body that is not an envelope falls through to the by-status wrapper, which also carries `status` for the
first time.

**`Envelope` moved, and now matches what the server sends.** It is not an error type — it is the wire
shape the client bindings read — and it declared `issues`, which nothing has ever written, while omitting
`status`, which `AuthError.toJSON()` always sends. Reading `res.error.status` or `res.error.retryAfter`
was a type error for a field that was right there.

BREAKING: import it from `@gentleduck/auth/client/vanilla`, beside `VanillaClient`, rather than from the
root or `@gentleduck/auth/core`.

**The Vue binding works.** `@gentleduck/auth/client/vue` loaded `vue` through `new Function('return require')()`,
which finds no `require` in Node or Bun under either module system, none in a browser, and is refused outright
under a CSP without `'unsafe-eval'`. Each failure was reported as "`vue` is not installed", so
`app.use(createAuthVuePlugin())` and every composable threw `AUTH_MISCONFIGURED` wherever they ran, `vue`
installed or not. The binding now imports `vue` statically, as the React and Solid bindings import theirs;
`vue` stays an optional peer that only this entry point pulls.

BREAKING (types): `VueClient.Ref`, `VueClient.VueModule` and `VueClient.App` are gone. The composables return
Vue's own `Ref`s, `VueClient.Plugin.install` takes Vue's `App`, and `AUTH_VUE_KEY` is an `InjectionKey`, so
`inject(AUTH_VUE_KEY)` is typed.

**The Solid `Provider` works.** It read `props.children` while building the context provider, which is what
runs the children JSX compiles, so everything inside `<Provider>` was built before the context existed and every
`authUse*` primitive threw `AUTH_MISCONFIGURED`, under solid's browser and server builds alike. The children are
now read inside the provider.

**A destructured client works.** `const { signIn, refresh } = createAuthClient()` reached `getSession` through
`this`, so `signIn` rejected with a TypeError after the server had already signed the user in, and `refresh`
threw every time. Both resolve to an Envelope now, like every other method.

**The database drivers are declared.** Given a connection string, the drizzle adapters load `pg`, `mysql2` or
`better-sqlite3`, and none was declared, so each resolved only where hoisting happened to put it. They are
optional peers now, at the ranges drizzle-orm declares. `svelte` and `@gentleduck/iam` are no longer optional
peers: nothing in the package loads either. `strict()` no longer tells you to use a Prisma adapter, which the
package does not have.

**`@gentleduck/error`'s own exports are no longer republished under this package's name.** `detail` and
`isSecretKey` were re-exported verbatim from `@gentleduck/auth/core/errors`, and `redactSecrets` was a
line-for-line copy of the library's `scrubMeta` walker — same depth cap, same truncation marker, same
`Date` passthrough — differing only in overwriting a secret-bearing key rather than dropping it.

BREAKING: `detail`, `isSecretKey` and `redactSecrets` are gone from `@gentleduck/auth/core/errors`; the
first two are `@gentleduck/error`'s to export. A webhook payload's secret-bearing keys are now absent
rather than present as `'[redacted]'`, since the default redactor is `scrubMeta`. Pass your own `redact`
to `AuthWebhookDeliverer` to keep the marker.

**A failing webhook dead-letter sink is logged, and no longer fails the delivery.** The sink's
rejection was swallowed without a line, under a comment saying "log and drop", so a dead-letter store
that was down lost every failed delivery unseen. A sink that threw synchronously escaped instead, and
`deliverOne` rejected with the sink's error in place of the delivery outcomes. Both now log under
`[@gentleduck/auth]` and answer the outcomes.

**A webhook `resolveHost` lookup that fails is retried, and runs before every attempt.** With
`resolveHost` wired, one failed lookup dead-lettered the event with `attempts: 0`, so a DNS blip lost a
delivery the retry ladder was there to save; without it, the same failure inside `fetch` was retried.
The name was also resolved once, before the first attempt, although `resolveHost` is documented as
checked before each request. Now every attempt resolves and checks the name, a failed lookup takes the
normal backoff, a refusal still stops the ladder, and a lookup answering no address is refused rather
than vetting nothing and leaving `fetch` to resolve the name itself.

**`strict()` refuses a plaintext captcha endpoint.** `allowInsecureEndpoint` was the one dev-only hatch
in the package with no production check — `AuthNullCaptchaVerifier`, `AuthInMemoryEvents`,
`MemoryIdempotency`, `MemoryLimiter` and the weak-key brands are all refused, this was not — so a deploy
posting the provider secret over cleartext HTTP booted without a word, handing the secret to anyone on
the path and letting them answer `success: true` to every call. The check reads the parsed endpoint, so
`HTTP://` or a leading space, which `fetch` sends over http all the same, is refused too.

It is also narrower than it read. The SSRF guard never consulted it, so `http://localhost:8787` was
refused with the flag set just as without it: the only thing the flag permits is cleartext to a public
host. The docs say so now, and the test that claimed to cover loopback — while passing a public name —
pins the refusal it was named for.

**BREAKING: `CookieTransport` refuses a `maxAgeSec` or `sameSite` the browser would drop.** A `maxAgeSec`
of 0 or below set a cookie deleted on arrival, and `NaN` or a fraction set a `Max-Age` browsers ignore,
leaving a browser-session cookie; `sameSite: 'none'` without `secure` is rejected by every current browser.
Each signed the user in and left no session behind. `maxAgeSec` must now be a positive whole number of
seconds and `sameSite: 'none'` needs `secure: true`, both `AUTH_MISCONFIGURED` at construction.

**`strict()` now looks inside `CompositeTransport`.** It read `secure` and the weak-signing-key brand off
the configured transport alone, and a composite carries neither, so a `secure: false` cookie or an HS256
key under 32 bytes passed production once it was wrapped with a bearer transport — the pairing the
composite exists for. Each part, nested composites included, is now checked as if it were configured
alone; `CompositeTransport.transports` is public for that.

**`strict()` judges magic-link by the `deliver` the provider holds.** It checked `cfg.deliver`, which the
provider never reads: it sends through its own `deliver`, and `cfg.deliver` reaches it only when a thunk
passes it on. So `magicLink({ deliver, findIdentityByEmail })` with no `cfg.deliver` was refused in
production though every link went out, and `cfg.deliver` beside a `magicLink({ findIdentityByEmail })`
passed, then refused every link request with `AUTH_MISCONFIGURED`. The provider now publishes whether it
has one, and the refusal reads ``provider 'magic-link' has no `deliver` ``.

**`strict()` counts the providers that registered, not the entries passed.** "No provider registered"
fired only when `providers` was empty, and `providers` drops a falsy entry and a thunk answering nothing,
so `[env.GITHUB_ID && github(...)]` with the variable unset booted production with nothing registered.
It now reads `auth.providers.size`, new, which counts attach-only facets too, so an m2m deployment holding
only `apiKeyProvider()` still passes.

**Production refusals name classes that exist.** `strict()` named `AuthNoopLimiter` and
`AuthMemoryIdempotency`, the redis session store `RedisSessionStore`, none of them exported anywhere; they
are `NoopLimiter`, `MemoryIdempotency` and `RedisSessionImpl`. The compliance `limiterRequired` demand
also said only the Noop limiter did not count, when `MemoryLimiter` is refused as well.

**A captcha network failure reports its message on `detail`, not as an error code.** `errorCodes` had
the thrown message pushed into it as a second entry, which gave the array unbounded cardinality for
anyone metering on it and carried whatever the fetch implementation named — an endpoint, a proxy, an
internal address — into what a caller logs or renders. `IVerifyResult.detail` is new and holds it.

**An empty `remoteIp` is no longer forwarded** as `remoteip=` for the provider to reject, and a
`"error-codes": null` body is read as "none" rather than as a malformed response that refused the solve.

**A captcha token that is not a string is refused unsent.** The size cap read `.length`, and an array's
counts elements, so a parsed body's `["x".repeat(100000)]` passed at length 1 and went out in the
siteverify POST. It now fails with `invalid-input-response`.

**The impossible-travel detector can now be fed.** `authImpossibleTravelDetector` ships, is exported,
documented and tested, and scored nothing on every request any real deployment made: it needs
`req.geo`, and no adapter could put coordinates there. The snapshot is built from
whatever `getCaller` returns, and that type was `{ ip?, userAgent? }` — so the detector sat registered
and permanently silent, which reads exactly like one that finds nothing wrong. Its docs also sent
`getLastSeen` to `Identity.attributes`, which does not exist: the host records positions itself, and
never from a denied request, or "last seen" moves to the attacker.

`CallerFingerprint` now carries an optional `geo`, which the snapshot already spreads through, so no
adapter changed. A host that resolves geolocation returns it alongside the address:

```ts
getCaller: (req) => ({ ...expressCaller(req), geo: lookup(req.ip) }),
```

**A signal you muted is no longer reported as evidence.** An `'allow'` reaction is documented to drop a
signal before the score is computed, and it did — but `Anomaly.Result.signals` and the `suspicious`
event still listed it. The event's `signal` field named kinds that the `score` beside it had never seen,
and a host filtering `result.signals` acted on precisely the signal the operator turned off. Both now
report only what the verdict was computed from.

**Captcha does not front anything on its own, and the docs now say so.** Nothing in this package calls
`auth.captcha.verify` — no flow, provider, route or adapter — and `Provider.Context` carries no verifier,
so the challenge is checked where the host checks it. Three places read the other way, including the
captcha module's own first line. A deployment that set `cfg.captcha` and stopped had a captcha in front
of nothing while every other signal said otherwise.

**`Anomaly.Kind` no longer advertises three kinds nothing emits.** `'high-velocity'`, `'off-hours'` and
`'concurrent-geo'` were listed as "the kinds the shipped detectors emit" by two detectors that emit
neither. The union's `(string & {})` arm still accepts any string a plugin names, so nothing that
compiled stops compiling.

**BREAKING: `mountHono` no longer takes `cors`.** The option was declared and type-checked, and nothing
read it, so `mountHono(app, auth, { cors: { origins } })` looked configured and sent no CORS headers.
Mount `hono/cors` on the app yourself; passing `cors` is now a type error rather than a silent no-op.

**BREAKING: `createAuth` no longer types `plugins` or `oauth`.** Both were in `AuthDefine.Cfg`, `plugins`
documented as installed through the registry, and `createAuth` refused any non-empty value of either:
installing a plugin is async, and each oauth provider takes its own `stateSigningSecret`. They are now
unknown keys, so a type error, and refused at runtime even when empty. `AuthDefine.IPluginEntry` is gone.
Install a plugin with `await auth.use(plugin)` once the engine is built.

**A missing provider's error names a factory that exists.** Reading `auth.passwords` or `auth.apiKeys`
without the provider told you to add `passwordProvider()` or `api-keyProvider()`, neither of which
exists. It now says `passwords()` and `apiKeyProvider()`, on the engine and inside `withTransaction`.

**`memoryDPoPNonceStore()` and `authMemoryDeviceFingerprintStore()` take their class's options.** Both
factories took no arguments, so the DPoP store's `development` escape hatch and the fingerprint store's
`maxPerIdentity` and `ttlMs` were reachable only through `new`, and `memoryDPoPNonceStore()` under
`NODE_ENV=production` refused to construct with no way to say otherwise.

**BREAKING: `callerSnapshot` is gone from `@gentleduck/auth/server/generic`.** It was `{ ...caller, now }`
with one caller, `requestSecurity`, which now builds the snapshot itself. A host resolving a session
outside the adapters passes `{ ...caller, now: Date.now() }` as `requestSnapshot`.

**`new DrizzleMysqlAdapter(pool)` type-checks with a real `mysql2` pool.** The constructor is documented
to take one, but its structural pool type required a `query` that accepts `unknown`, which no mysql2
overload does, so passing `createPool(...)` was a compile error. `DrizzlePgAdapter`'s pool type had the
same shape; both now accept any function there.
