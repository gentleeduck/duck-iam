# Porting scenarios between the two suites

The gap table says *where* we are thin; this file is the work of closing it. One
section per direction, newest last. A scenario only lands here once it has been
written, run, and shown to fail against a mutated version of the code it covers
— a ported test that cannot fail is worse than the gap it claimed to close.

Measured against better-auth **v1.7.2**.

## them → us

### 1. The outbound SSRF guard — ported, 1 test → 93

**Their suite:** `packages/core/src/utils/host.test.ts`, 77 cases, around
`isPublicRoutableHost` and friends: input normalisation, IPv4 and IPv6
classification, IPv4-mapped handling, FQDN classification, and a
`Security: Bypass Prevention` block naming each payload class.

**Ours before:** `core/url-validators/` had 15 cases, 14 of them about
`isSafeCallbackPath` — the open-redirect side. The SSRF side had **one**, through
the name path. Everything else — `parseIpv4`, `parseIpv6`, `isBlockedIpv4`,
`isBlockedIpv6` — was uncovered, and `parseIpv6` is hand-written: `::`
expansion, a dotted-quad in the last two hextets, zone stripping.

**What the port found:** the classifier is right. Every payload class they test
is refused: IPv4-mapped metadata in both spellings, `0.0.0.0` (Oligo
0.0.0.0 Day), `.localhost` suffixes without the substring false-positive, the
absolute-DNS trailing dot, and the 6to4, NAT64, Teredo and IPv4-compatible
tunnel forms. Boundaries are exact — `9.255.255.255` and `11.0.0.0` both pass
either side of `10/8`. Our webhook path is **stronger** than theirs: it resolves
DNS and classifies each answer through `assertResolvedHostIsPublic`, which
catches the wildcard-resolver trick (`127.0.0.1.nip.io`) that no spelling guard
can see.

Two things came out of writing it rather than reading it:

- **A vacuous case.** `refuses('[fe80::1%25eth0]')` passes with the zone-strip
  deleted, because WHATWG `URL` has no syntax for a zone id and fails to parse
  first. The strip is only live on `assertResolvedHostIsPublic`, which takes a
  raw address, so the case moved there. `URL` also rewrites
  `::ffff:169.254.169.254` to `::ffff:a9fe:a9fe` before the classifier sees it,
  so the "hex-encoded bypass" and the dotted one are the same input through a URL
  and different inputs through a resolved address.
- **Six non-routable ranges were missing**, now added: RFC 5737's three
  documentation `/24`s, and on v6 `2001:2::/48` (RFC 5180), `2001:db8::/32`
  (RFC 3849), `3fff::/20` (RFC 9637) and `5f00::/16` (RFC 9602). Not an SSRF
  risk — nothing listens there — so this converts a connect timeout into
  `AUTH_MISCONFIGURED` at config time. Writing `3fff::/20` as a 12-bit mask also
  swallowed `3ffe::/16`, ordinary address space since the 6bone was returned;
  the boundary case caught it, which is the argument for writing boundary cases.

**Landed:** `core/url-validators/__tests__/outbound-host-classification.test.ts`,
93 cases. Non-vacuous against six mutations — zone strip removed, a mask widened
from /16 to /8, the IPv4-mapped check deleted, the trailing-dot strip removed,
`endsWith` loosened to `includes`, and the 6to4 check deleted — 1 to 10 failures
each. The `includes` mutation survived the first draft, which is why
`api.internal.example.com` is in the allowed list.

### 2. Redirect refusal on the fifth outbound path — ported, 2 tests

**Their suite:** `reject-redirects.server.test.ts` asserts that each
server-side OAuth fetch refuses a redirect to an internal host —
`validateAuthorizationCode`, `refreshAccessToken`, `clientCredentialsToken`
and the JWKS fetch — with a sanity case proving a client that *does* follow
redirects reaches the internal endpoint.

**Ours before:** `outbound-redirects.test.ts` opens by claiming "every outbound
request in the library now takes that posture". Four OAuth paths were asserted
there, webhooks in `webhooks-delivery.test.ts`, CAPTCHA in
`captcha-verifiers.test.ts`. The fifth — `authFetchOidcDiscovery` — set
`redirect: 'error'` and nobody checked.

It matters most there: the document that call returns names the `token_endpoint`
and `jwks_uri` the host trusts afterwards, and the RFC 8414 §3.3 issuer check
cannot catch it, because the attacker's document carries an `issuer` matching
whatever host it redirected to.

**Landed:** two cases in `oidc/__tests__/oidc.test.ts`. The first goes red with
`redirect: 'error'` removed from `oidc/index.ts`. The second pins the
host-trust boundary: endpoints *inside* an accepted document are shape-checked
and nothing more, so a document may legitimately name
`http://169.254.169.254/...`. That is correct today — the issuer is host
configuration, loopback is how a local Keycloak is tested, and no code in this
package fetches those endpoints — but it is the assumption that breaks first if
an issuer ever becomes tenant-supplied.

### 3. `client_secret_basic` ignored the encoding RFC 6749 mandates — ported, 26 tests, **found a bug**

Their `packages/core/src/oauth2/basic-credentials.test.ts`, 13 cases on one
function. We had no test for the reading half at all, and the reading half was
wrong.

RFC 6749 section 2.3.1 does not say `base64(id + ':' + secret)`. Each half is
encoded with the `application/x-www-form-urlencoded` algorithm *first*, and the
result of that is base64'd. A conforming client with the secret `s3cr3t key`
sends `s3cr3t+key`; one whose secret contains `+` sends `%2B`.

`parseBasicAuth` in `src/oidc/op/index.ts` base64-decoded, split on the first
colon, and compared the halves raw. So a client that followed the spec
authenticated against the wrong string and was refused — `invalid_client` on a
correct secret.

**Why it never showed.** `registerClient` mints secrets with `randomToken(32)`,
which is base64url: `A-Za-z0-9-_`, every character of which form-encoding leaves
untouched. The round trip is lossless for every secret this library generates.
It breaks only when a host passes its own `client_secret` (or `client_id`) to
`registerClient`, which the signature allows and which any migration from
another OP does. Same shape as
[[duck-auth-peerdep-enforces-what-you-got-wrong]]: the default input hid the
defect.

Fixed by trying the form-decoded spelling first and the raw one second, for both
halves. The raw fallback is deliberate — a non-conforming client that sends
`a+b` literally keeps working, and since both candidates are compared against
the stored hash with `timingSafeEqual`, accepting two spellings does not widen
what a caller has to know. Percent-decoding that throws (`100%zz`) falls back to
raw rather than refusing.

Fails that led here, all in `src/oidc/op/__tests__/client-secret-basic.test.ts`:
7 of 26 — six secrets (space, `+`, `%`, `:`, `&=`, non-ASCII) and one
`client_id` needing encoding.

**Two seam mistakes worth recording.** The first draft asserted on an absent
`error` field from `op.introspect`. That is vacuous: `introspect` answers
`{ active: false }` for a refused client exactly as it does for an unknown
token, so every positive case passed before the fix as well as after. The suite
now introspects a **live** access token, where `active === true` is reachable
only if the client authenticated. Second, the empty-`client_id` guard survived
mutation — `findById('')` returns null anyway, so the guard only changes the
error text. The invariant actually worth pinning is that a Basic header *owns*
the `client_id`: falling back to `req.client_id` when the header's half is empty
would let a caller authenticate as whichever client the body names using a
secret the header carries. That case fails against the fallback mutation.

Mutations run, each in its own `vitest run`:

| Mutation | Result |
| --- | --- |
| candidates collapse to raw only (the shipped behaviour) | 7 failed |
| secret comparison removed | 6 failed |
| empty Basic id falls back to the body | 1 failed |
| drop the empty-`client_id` guard | **survived** — error text only, see above |

### 4. Consumer smoke tier — ported, 0 → 9 checks, no bug found

Their `e2e/smoke` tier was the top recommendation in `FINDINGS.md`: 26 cases
asserting the package imports and type-checks under bun, deno, Cloudflare
Workers, esbuild, vite, ipv6 and five tsconfig permutations. We had none, and
have shipped the class twice.

Ported the part that applies to us as `scripts/smoke-consumer.ts`
(`bun run smoke`). The runtime matrix does not: we are a Node server library
with `@types/node` in `dependencies` and no edge or Deno claim anywhere in
`package.json` or the README, so a Workers fixture would assert a contract we
never offered. What does apply is the type surface a consumer resolves, which
`check-types` cannot see — it reads `src` under our own tsconfig, which turns
`exactOptionalPropertyTypes`, `verbatimModuleSyntax`,
`noPropertyAccessFromIndexSignature` and `noImplicitOverride` **off** and never
opens an emitted `.d.ts`.

Nine checks, all green: the 188 files the `exports` map promises all exist,
every condition declares `types`, and all 47 entrypoints type-check under seven
consumer tsconfigs — nodenext, node16, bundler+isolatedModules,
verbatimModuleSyntax, exactOptionalPropertyTypes, noUncheckedIndexedAccess, and
one with `skipLibCheck` **off**. That last one is stricter than better-auth's
tier, where all five fixtures set `skipLibCheck: true` and so never read the
declarations they ship.

**The declarations are clean, and the entrypoint list is generated from the map
on every run** so adding an export cannot leave the check behind.

**One false finding, worth recording.** With `"types": []` the probe reported
four `Cannot find name 'Buffer'` errors in our emitted `.d.ts`
(`Kms.Cfg.masterKey` is `Buffer | string`, re-exported through the root barrel).
That read like a portability defect. It is not: `@types/node` is a direct
`dependencies` entry, so every consumer gets it transitively, and the fixture's
empty `types` array had removed what the package ships. The premise was mine,
not the package's.

**Sensitivity, established by mutation rather than assumed** — the first draft
claimed to cover the `exports` map and did not:

| Mutation | First draft | Now |
| --- | --- | --- |
| entry points into a directory that does not exist | 7 configs fail | 7 configs fail |
| a broken declaration in `dist` | caught by the no-skipLibCheck config | same |
| `types` condition points at a missing file | **survived** | caught by the target-exists check |
| `types` condition removed, only `default` left | **survived** | caught by the types-declared check |
| an entry deleted from the map | **survives** | **still survives** — see below |

The two survivors shared one cause: TypeScript resolves a missing `types` target
by falling back to a sibling `.d.ts`, so a wrong or absent condition type-checks
clean and ships a package that works by filename coincidence. Two structural
assertions over the map now cover it.

A deleted entry still cannot be caught here, and the reason is worth keeping:
the fixture is generated *from* the map, so a removed entry simply is not
imported — the check pins the map to itself, the same trap as
[[duck-auth-generated-spec-drifted-from-router]]. What catches removal is
`public-surface.test.ts` and `readme-imports.test.ts`, which pin specifiers
against the map from the outside. The two mechanisms are complementary, and
neither alone is enough.

Also filtered: `skipLibCheck: false` surfaces 65 errors from `drizzle-orm`'s own
declarations, including a `TS2307` for the optional `gel` driver. The check
scopes failures to our `dist` and the generated fixture, because a count that
included peer-dep noise would never be green and would say nothing about this
package.

### Checked and already closed

Worth recording so the next sweep does not re-walk them:

- **Provider ID-token forgery** (their `verify-id-token.test.ts`: forged
  signature, `alg:none`, nonce, opaque-token gating). We have no
  client-supplied id_token path at all — no `signInWithIdToken`, no one-tap —
  and `decodeIdToken` is reachable only from a token-endpoint response, which is
  the OIDC Core §3.1.3.7 exemption. `apple.ts:81` says so. `alg:none` and
  alg-confusion are covered on our own JWTs by `jwt-asymmetric.test.ts` under
  RFC 8725 §3.1.
- **Versioned secret rotation** (their `secret-rotation.test.ts`, 38 cases,
  including `Number()` coercion traps: hex versions, scientific notation,
  duplicates after coercion). Does not port — our key ring is keyed by string
  `kid`, not an integer version, and `assertKid` already refuses `''` and any
  `kid` containing the `$` field separator.
- **API-key expiry and quota.** Expiry is enforced in the shared credentials
  layer via `isCredentialExpired`, with the `Date.parse('bad')` → NaN case
  handled in `credentials.constants.ts` and a DB check constraint behind it.
  Their `remaining`/`refillInterval` credit system is a feature we do not have,
  so those ~25 cases describe nothing of ours.

## us → them

Checking duck-auth's own hard-won findings against better-auth. Reported here
rather than filed upstream; none of this has been sent to them.

### 1. `freshSessionMiddleware` fails open on a future or unreadable `createdAt`

**Executed, not inferred** — see the run below. The bug we fixed in
`isSessionFresh`, still present in theirs. Two sites:

- `better-auth/src/api/routes/session.ts:596` — `freshSessionMiddleware`, the
  gate on sensitive operations.
- `better-auth/src/api/routes/update-user.ts:544` — the same check gating
  **account deletion when no password is supplied**.

Both read:

```ts
const createdAt = new Date(session.session.createdAt).getTime();
if (Date.now() - createdAt >= freshAge) throw /* not fresh */;
```

One comparison, two ways past it. A `createdAt` **ahead of the clock** makes the
left side negative, which is under any window, so the session is fresh for ever.
A `createdAt` that **will not parse** makes it `NaN`, and `NaN >= freshAge` is
`false`, so that session is fresh too. A freshness gate should fail closed on
both.

Ours is the same shape with both ends bound, and the comment on it records the
measurement — a session dated a day ahead read fresh, and so did one dated a
century ahead:

```ts
if (session.fresh !== true) return false
const ms = deadlineMs(session.rotatedAt)
return Number.isFinite(ms) && Math.abs(now - ms) < freshnessMs
```

**How reachable:** not attacker-controlled in a default deployment —
`createdAt` is written server-side, and their `session_data` cookie is
HMAC-signed. It is reachable by **clock skew across a fleet**, since whichever
node wrote the row decides the stamp, and by a **custom or secondary-storage
adapter** that returns a `createdAt` their `new Date(...)` cannot read. So:
defence-in-depth and multi-node correctness, not a direct bypass.

**Untested either way.** Their freshness tests use `freshAge` of 1, 60 and
1000 — the fresh path and the expired path. Neither a future stamp nor an
unparseable one appears in the suite.

Their rate limiter at `api/rate-limiter/index.ts:217` has the same
`now - stamp >= window` shape and is **fine**: there a future stamp means the
window never resets, which keeps the caller limited. Fails closed.

#### The run

An earlier draft of this entry rested on reading the code shape and the bypass
arithmetic, which is how a finding gets recorded that is not there. So the
condition was **sliced out of their source file by text and evaluated** —
`scripts/repro-freshness.mjs` takes the file and the line of the `if`, lifts the
three statements the gate is made of, and runs them. Nothing is retyped: if
their bytes said something else, the verdicts would change with them.

Against their default `freshAge` of one hour, both sites answer identically:

| `session.createdAt` | verdict |
| --- | --- |
| created now | accepted as fresh — correct |
| created 2 hours ago | **refused** — the gate does work |
| 1 hour in the future | **accepted as fresh** |
| 100 years in the future | **accepted as fresh** |
| `'not-a-date'` | **accepted as fresh** |
| `''` | **accepted as fresh** |
| `null` | refused — `new Date(null)` is the epoch, so it reads as very stale |

Two distinct causes in one line. A future stamp makes `Date.now() - createdAt`
negative, and a negative is never `>= freshAge`. An unparseable stamp makes it
`NaN`, and `NaN >= x` is false. Both skip the throw, so the session is fresh
forever. The stale case refusing is what proves the harness is wired to
something real rather than answering "accepted" to everything.

Not directly attacker-controlled — `createdAt` is written server-side — so
reachability is a backwards clock correction, a replication or timezone quirk,
or a custom adapter handing back a string that does not parse. That is the same
reachability our own version had, and we hardened it rather than closing it as
theoretical.

Our reference, `src/core/sessions/sessions.ts`, bounds both ends and demands a
readable stamp:

```ts
if (session.fresh !== true) return false
const ms = deadlineMs(session.rotatedAt)
return Number.isFinite(ms) && Math.abs(now - ms) < freshnessMs
```

and `__tests__/freshness-window-parity.test.ts` pins the same table that fails
on their side — `stamped a century ahead` → false, `fails closed on a rotatedAt
nothing can read` → false — across all three places that weigh the window.

### 2. Sweep of our other finding classes against their code

Our own audit history is a list of bug *shapes*. Each was checked against
better-auth rather than assumed to be ours alone. One hit, recorded above; the
rest are clean on their side, and the reasons are worth keeping because most are
structural rather than lucky.

| Our finding class | Their code |
| --- | --- |
| One-sided clock comparison | **FOUND**, two sites — see above |
| CAS single-use claims ([[duck-auth-magic-link-cas-flake]]) | clean |
| Empty key is still a key ([[duck-auth-empty-key-is-still-a-key]]) | unreachable |
| Modulo bias in generated secrets ([[codeql-dismissal-is-a-claim]]) | clean |
| Owner is not kind ([[duck-auth-owner-is-not-kind]]) | structurally prevented |
| WebAuthn counter ([[duck-auth-peerdep-enforces-what-you-got-wrong]]) | check correct, write not atomic |
| Defaulted tenant is unscoped | not applicable, no tenancy |

- **Single-use claims.** `internalAdapter.consumeVerificationValue` burns the row
  *before* the verifier runs, inside `withVerificationConsumeLock` +
  `runWithTransaction`, over a `consumeOne` adapter primitive; the
  secondary-storage path uses an atomic `getAndDelete`. They also carry an
  explicit `FIXME(consume-identifier-atomic)` naming the one gap that remains —
  no primitive that deletes every row for an identifier and returns the latest in
  one operation. This is the class we spent eleven sites on, and they have it.
- **Empty TOTP secret.** `two-factor/index.ts:241` mints
  `generateRandomString(32)` server-side and encrypts it; no path stores a
  caller-supplied secret, so a zero-byte secret is unreachable rather than
  guarded. Our hole was on the write side, which is the side they closed by
  construction.
- **Modulo bias.** `@better-auth/utils`'s generator does correct rejection
  sampling — `maxValid = Math.floor(256 / charSetLength) * charSetLength`, values
  at or above it discarded — over a 64-character set, where no rejection is even
  needed. Uniform. This is the one our CodeQL alert #140 was wrongly dismissed
  over, and theirs is right.
- **Owner is not kind.** Their schema splits what ours keeps in one table:
  `session`, `account`, `passkey`, `twoFactor` and `verification` are separate
  models, so a `userId`-scoped delete cannot cross purposes — the model *is* the
  kind. The one multi-purpose table, `verification`, is namespaced by identifier
  prefix (`2fa-`, `trust-device-`). Our bug needed one table holding six
  purposes to exist at all.
- **WebAuthn counter.** `passkey/src/routes.ts:896` hands
  `counter: passkey.counter` to simplewebauthn, which enforces the regression
  check — the same delegation that hid our own dropped `|| oldCounter !== 0`. The
  write afterwards is a plain `adapter.update` with no compare-and-set, so two
  concurrent authentications can both read counter *N*, both pass the check, and
  both write. Narrow: the challenge is burned atomically before this point, so a
  replay needs a second live challenge. Worth noting, not a reported defect.

### Checked and clean on their side

- **nOAuth / fabricated `emailVerified`.** Their `microsoft-entra-id.ts`
  defaults `emailVerified` to `false` when the claim is absent and says why in a
  comment, falling back to the `verified_primary_email` arrays. They do not
  fabricate it. This was our bug, not theirs. (They type `xms_edov` without
  using it, which is Microsoft's own domain-ownership claim — a hardening
  opportunity, not a defect, given the safe default.)
- **Apple `email_verified`.** Taken at face value, which is correct: it arrives
  on a signature-verified id_token from Apple's token endpoint, and Apple does
  assert the claim, private-relay addresses included.
