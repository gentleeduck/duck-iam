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

### 5. SAML had no audience binding it could not be told to drop — ported, 8 tests, **found a bug**

Ported from their `packages/sso/src/saml/response-binding.test.ts`, which refuses
an assertion whose `AudienceRestriction` names another SP, a bearer `Recipient`
for another SP, and a response `Destination` for another SP.

Only the first of those three is a binding here, and the port proves that by
execution rather than by reading the library. `src/providers/saml/__tests__/
saml-audience-binding.test.ts` builds real RSA-signed assertions through
`@node-saml/node-saml`'s own `signXml` and moves one binding at a time:

| Case | node-saml 5.1.0 | What it means |
| --- | --- | --- |
| audience names another SP | refused | the binding works, by default |
| no `AudienceRestriction` at all | refused | absence is not "unrestricted" |
| bearer `Recipient` names another SP | **accepted** | `Recipient` appears nowhere in its validation path |
| response `Destination` names another SP | **accepted** | only ever set on outbound requests |
| `audience: false` + all three moved | **accepted** | nothing is left |

So `AudienceRestriction` is the whole of what ties an assertion to this Service
Provider. The constructor already refused a client set to verify no signature at
all, and refused a missing `verifyRelayState` or `replayStore` unless the host
opted out by name — but it accepted `audience: false` silently. With that set, any
assertion the IdP ever signed, for any SP it serves, minted a session here.

**Fixed** in `src/providers/saml/saml.ts`: `audience === false` is refused at
construction unless the host passes the new `allowAnyAudience`, matching the
`allowUnsolicited` / `allowReplay` precedent in the same constructor. Both
clauses are mutation-proven, each in its own `vitest run`:

| Mutation | Result |
| --- | --- |
| guard removed entirely | `is refused at construction` fails |
| opt-out clause removed | `is accepted once the host says so` fails |

A second, smaller correction came out of the same read. The comment above the
`callbackUrl` check claimed "the client is what validates `Destination` and
`Recipient` against its own callback". It does not, and the two accepted cases
above are the proof. The check is still worth keeping — it stops the advertised
ACS and the one the client signs with from drifting — but it is not the binding
the comment claimed, and the comment now says what it actually buys.

### 6. A passkey challenge belonged to whichever ceremony asked first — ported, 5 tests, no bug

Their `passkey.test.ts` refuses a registration that reuses an authentication
challenge and an authentication that reuses a registration one. Ours are kept
apart by a key prefix — `reg:${sessionId}` against `auth:${sessionId}` — set in
two functions that never read each other, so nothing failed if one changed.

No bug: the prefixes are right. The port is regression cover for an invariant
that lived in two string literals. The mock verifier answers `verified: true` for
anything, so a shared keyspace would let the wrong ceremony spend the challenge.

Unifying the keyspace fails 4 of the 5 cases. The first draft was worse than that
looks: `refuses an authentication that reuses a registration challenge` **survived**
the mutation, because with no credential enrolled the authentication refused at
the credential lookup instead and would have passed whatever the keyspace did. It
now enrols one under its own session id first, so the keyspace is the only thing
left to refuse it.

### 7. A verify in flight writing the key back as it found it — ported, 4 tests, no bug

Their "verify should not write back stale state" cluster: refuse to re-enable a
key disabled during verification, or recreate one deleted during it.
`ApiKeysFacet.verify` stamps `lastUsedAt` by rotating the row to the secret it
already holds — a write issued after the revoke check has passed, on a row read
before the revoke landed. A `Proxy` on `findByHashedSecret` runs the revoke in
exactly that window.

No bug, and the mutation work is the interesting part. Three independent guards
stop the write resurrecting the key, and **each one alone keeps the cases green**:

| Guard | Mutation | Result |
| --- | --- | --- |
| `revoke` bumps the version, so the stamp loses its CAS | version not bumped | still green |
| `rotate` writes only `lastUsedAt` and `secret` | `rotate` clears `revokedAt` | still green |
| `rotate` refuses an id that is gone | — | delete case green regardless |
| first two together | both removed | **2 of 4 fail — the key is re-enabled** |

The first draft's docstring credited the CAS alone. That was wrong, and the
single mutations are what showed it: the property survives on redundancy, so the
test is only worth keeping because it fails when the redundancy is spent.

### 8. A replayed authorization code kept its tokens — ported, 5 tests, **found a gap**

Ported from their `token.test.ts` ("rejects authorization code replay with
invalid_grant and revokes issued tokens"). RFC 6749 4.1.2 has two halves — deny
the second redemption, and revoke what the first one issued, since which caller
holds the stolen code is not knowable from the server. We denied and kept the
tokens: whoever redeemed first walked away with a 30-day refresh grant off a
10-minute code, and the legitimate client's failure did nothing about it.

PKCE makes this the residual case rather than the main one — a stolen code is
unusable without the verifier or the client secret, and both are mandatory here —
so this is depth behind a door that is already shut, which is what the RFC's
SHOULD is for.

**Fixed** with no change to any store interface: the refresh family id is now
derived from the code (`codeFamily`), so a failed redemption revokes
`family(code)` and reaches every rotation descended from it. A code that never
existed, or simply expired, revokes nothing.

| Mutation | Result |
| --- | --- |
| revoke call removed | 3 of 5 fail |
| family id random again, as before | 3 of 5 fail |

Two things the port pinned that are worth naming. Deriving the family beats
recording tokens against the code, because rotation cannot walk the grant out of
reach of its own revocation — the third refresh in a chain still dies. And the
access token did not die with it: it carried no family. Port 10 adds the column
and inverts that last case.

### 9. XML Signature Wrapping, demonstrated rather than assumed — ported, 6 tests, no bug

`FINDINGS.md` claimed the XSW cluster "belongs to node-saml, which we delegate
to". That is an assumption until something runs, so these cases run it: a validly
signed assertion for the victim, plus a forged one for the attacker in five
positions, through the real client.

| Payload | node-saml 5.1.0 |
| --- | --- |
| forged assertion in `samlp:Extensions` | ignored, victim signs in |
| forged assertion in an arbitrary `<Wrapper>` | ignored, victim signs in |
| forged assertion nested three levels deep | ignored, victim signs in |
| forged assertion as a second top-level sibling | refused |
| forged outer assertion holding the signed one in its `saml:Advice` | refused |

The delegation holds: the subject that lands is always the signed one. Each case
pins which of the two answers it is, so a change in either direction shows up.
Their equivalent refuses all five by counting assertions, which is stricter and
reaches the same place.

Non-vacuity is a harness mutation rather than a product one, since the code under
test is a dependency: signing the attacker's assertion instead of the victim's
fails 4 of the 6, so the cases do read the subject that actually signs in.

### 10. The grant ended but its access tokens did not — ported, 12 tests, **closed two residuals**

Port 8 left two things recorded rather than fixed, and this closes both. Their
`oidc.test.ts` asserts what we were missing on each: that revoking a grant
reaches the access tokens it issued, and that an ID token carries `auth_time`
and `sid` and keeps them across a refresh.

**Access tokens now carry the family of their grant.** Both token kinds are
inserted under one family, so the four paths that end a grant reach both: a
replayed code, a replayed refresh token, a subject since erased, and
RFC 7009 2.1 revocation of a refresh token. Revoking a single access token at
`/revoke` still takes only that token — one leaked token is not a leaked grant,
and a case pins the difference.

**`auth_time` and `sid` reach the ID token.** The OP enforced `max_age` and then
minted a token with no `auth_time`, so the RP could not check the freshness it
had asked for (OIDC Core 3.1.3.6). `authorize` now hands `auth_time` back with
`consent_required`, `completeConsent` takes it, and both claims are stored
against the grant so a refresh repeats the sign-in it descends from rather than
reporting itself as one (12.2). Omitting it omits the claim: a time nobody
measured is not invented.

| Mutation | Result |
| --- | --- |
| `accessTokens.revokeFamily` dropped from `revokeGrant` | 3 of 7 code-replay, 3 of 4 grant-revocation fail |
| access token inserted under its own random family | 3 of 7 code-replay fail |
| `/revoke` widened from `revokeByHash` to the family | the one case that pins the difference fails |
| `auth_time` claim never emitted | 3 of 4 claim cases fail |
| refresh reports `Date.now()` as `auth_time` | 2 of 4 fail |
| refresh rewrites `sid` | 3 of 4 fail |
| `authorize` reports `Date.now()` instead of the last factor | 3 of 4 fail |
| sqlite `accessTokens.revokeFamily` made a no-op | the store-compliance case fails |
| sqlite drops `auth_time` reading a code back | the round-trip case fails |
| sqlite rewrites `sid` reading a refresh token back | the round-trip case fails |

Store compliance earned five cases, which is where the dialects prove the three
new columns rather than the OP proving them once over memory. One of those is
worth naming: the field-fidelity case now **measures** `auth_time` instead of
leaving it null, because a nullable field read back as null proves nothing about
the column it came from — and on Postgres a `bigint` arrives as a string unless
the mapper says otherwise.

`at_hash` stays deliberately absent. It is keyed to the signing algorithm's hash
and `signIdToken` is a host callback that hides the algorithm, so a SHA-256
`at_hash` would be wrong for ES384 — and a wrong `at_hash` is worse than none.
OIDC makes it optional for the code flow.

This is the first port that breaks a host-written store: three columns and
`AccessTokenStore.revokeFamily`. The shipped memory and Drizzle stores are
updated, and the changeset carries the DDL note.

### Coverage of their tree, cluster by cluster

The sweep behind ports 5-7 walked every cluster in `MAP-better-auth.md` rather
than the four with the largest counts, and worked from their **refusal surface**
as well as their tests: 481 `new APIError` and 220 `new BetterAuthError` sites
across 965 source files, reduced to 218 distinct named codes, of which ~130 are
security-relevant. A behaviour of theirs is a candidate here whether or not they
test it.

| Their cluster | Verdict |
| --- | --- |
| SAML + SSO (584) | **bug found**, port 5. XSW delegation now demonstrated, port 9. Algorithm and encryption cases remain node-saml's |
| OIDC OP (791) | two bugs found: `client_secret_basic` (port 3) and code-replay revocation (port 8). PKCE is S256-only and mandatory for public clients; `resource`, `pairwise`, `backchannel`, `private_key_jwt`, `dpop` are feature gaps |
| OAuth2 + social (539) | no client-supplied id_token path, so their `verify-id-token` cluster cannot apply; no JWKS fetch, so their cache-collision and redirect cases cannot either |
| Transport / CSRF / origin (274) | covered. `allowedOrigins` is exact-match, so their wildcard, prefix, subdomain-extension and path-pin-traversal bypasses have no surface |
| API keys (193) | port 7. Their quota/refill credit system is a feature gap |
| Orgs (265) | memberships with opaque roles, no role-creation or invite surface; cross-org boundaries already pinned by `orgs-boundary.test.ts` |
| Admin / impersonation (96) | impersonation covered (self-impersonation, TTL cap, release, tenant). **Ban/disable is a feature gap** — see FINDINGS |
| MFA / 2FA (82) | covered. `requireMfa` throws before any session is minted; step-up shares one per-identity bucket across factors |
| Passkey (41) | port 6 |
| Sessions (120), passwords (76), magic-link (62) | covered; `evictUnproven` exceeds their "clear an unverified account's password when verify adopts it" |
| Rate limiting (29) | covered. No XFF parsing here — the host supplies `ip`, so trusted-proxy handling is theirs |
| CAPTCHA (33) | covered, including `expectedAction` / `expectedHostnames` / `minScore` binding |
| Adapters (408), engine/config (716) | our own store-compliance matrices cover this ground |
| Device grant (118), email/phone OTP (126), multi-session, SCIM (265), MCP (63), CIMD (149) | no surface here at all — feature gaps, no code to fail a test |
| Billing (168), CLI (349), client SDK (248), i18n, telemetry, OpenAPI, browser e2e | out of scope since PR #288, or not a library concern |

### Checked and already closed

Verified by reading the code and finding the case already covered, this round:

- **DPoP proof replay** — `jti` is recorded per proof, and the TTL is measured
  against the far edge of the freshness window rather than the sum, so a proof
  dated ahead of this clock cannot outlive its own record. Ahead of theirs.
- **Login CSRF by cross-site navigation** — their `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`.
  `verifyCsrf` reads `Sec-Fetch-Site` as layer 1, and a missing `Origin` fails
  closed whenever an allowlist is set. They gate theirs behind a flag that can
  turn it off.
- **Account collision from a missing provider subject** — their "rejects sign-in
  when the provider omits an account id". `getUserinfoString` answers `undefined`
  for an empty string, `getUserinfoNumericIdAsString` for anything non-numeric,
  and `provider.ts` refuses an empty `sub` for every provider. `oauth.test.ts`
  pins it with a `no-sub` IdP. Apple returns `{ sub: '' }` and is caught there.
- **Login CSRF by handing over a begun flow** — the signed state is bound to a
  PKCE verifier held in a cookie, so a state completes only in the browser that
  began it; it is burned before the code is spent, and a provider with no
  `nonceStore` is refused at construction unless the host passes
  `allowStateReplay`.
- **Limiter key collisions** — their `ip.test.ts` collision cases. Every key here
  is one fixed namespace plus one value, so there is no second component to shift
  a delimiter into.
- **X-Forwarded-Host and X-Forwarded-For parsing** — absent. The host supplies
  `ip`, and `baseUrl` is configuration, so their traversal, HTML-injection and
  spoofed-hop cases have nothing to reach.
- **Another user's passkey** — `revoke` checks kind *and* owner and answers
  absent, already pinned by `passkey-manage.test.ts`.
- **User enumeration** — covered on all three paths with work counted rather than
  timed: password verify hashes a real reference hash on the no-credential branch,
  and `flows-password-reset-timing-defense.test.ts` plus the magic-link suites
  count store round trips.


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

## their advisories → us

A third axis, added 2026-10-24: not their tests but the **37 security advisories
better-auth has published from its own repository** (`gh api
/repos/better-auth/better-auth/security-advisories`, 3 critical, 22 high, 9
medium, 3 low). Each one is a bug that reached a release and was found by someone
else, which makes the set a better list of what actually goes wrong in an auth
library than any test suite is.

Every row was read for its mechanism and the mechanism looked for here, in the
code rather than in a test name. The tally:

- **17 have no surface here** — duck-auth ships no routes, no multi-session, no
  SCIM, no billing, no device grant, no organization invitations, no OAuth proxy
  and no user-registered identity providers. That is not merit, it is a smaller
  product; the two feature gaps worth naming are the device grant and the
  `resource`/audience parameter.
- **15 were already closed and already pinned** by a test here.
- **4 were closed in the code with nothing pinning them.** Ported, below.
- **1 was half open.** Fixed, below.

| Advisory | Severity | Their package | What it was | Here | Why |
| --- | --- | --- | --- | --- | --- |
| [GHSA-5rr4-8452-hf4v](https://github.com/advisories/GHSA-5rr4-8452-hf4v) | critical | sso | Any signed-in user can make the server fetch and read internal URLs | **closed** | port 1: 93 classification cases plus DNS-resolved checks on the webhook path |
| [GHSA-rjg6-39jm-rgg4](https://github.com/advisories/GHSA-rjg6-39jm-rgg4) | critical | scim | SCIM tokens can take over users they do not own, and deactivation fails | **no surface** | no SCIM |
| [GHSA-965c-763c-88jm](https://github.com/advisories/GHSA-965c-763c-88jm) | critical | core | OAuth state can be used as a Magic Link to sign in as another user | **closed, newly tested** | tokens live in separate `kind`s, and the six redeemers sharing `recovery` each check `metadata.purpose` |
| [GHSA-hjpm-7mrm-26w8](https://github.com/advisories/GHSA-hjpm-7mrm-26w8) | high | core | Callback URLs that start with // can send users to another site | **closed** | `//`, `///` and `/\` refused; `url-validators.test.ts` |
| [GHSA-vp58-j275-797x](https://github.com/advisories/GHSA-vp58-j275-797x) | high | core | Trusted origin check can be bypassed, leading to account takeover | **closed, newly tested** | `allowedOrigins` is an exact match on the parsed Origin, never a pattern |
| [GHSA-99h5-pjcv-gr6v](https://github.com/advisories/GHSA-99h5-pjcv-gr6v) | high | core | Anyone can create or change API keys for another user | **no surface** | `apikeys.create(identityId, …)` takes the subject positionally; no route to fall back from a session |
| [GHSA-4vcf-q4xf-f48m](https://github.com/advisories/GHSA-4vcf-q4xf-f48m) | high | passkey | Any signed-in user can delete other users' passkeys | **closed** | `passkey.revoke` checks owner and kind; 3 tests |
| [GHSA-x732-6j76-qmhm](https://github.com/advisories/GHSA-x732-6j76-qmhm) | high | core | Paths with repeated slashes can bypass disabled paths and rate limits | **no surface** | no router, no `disabledPaths`, no path-keyed limit |
| [GHSA-xg6x-h9c9-2m83](https://github.com/advisories/GHSA-xg6x-h9c9-2m83) | high | core | Session cookie cache can let users skip two-factor authentication | **closed** | no session cache; a `requireMfa` intent throws before any session is minted |
| [GHSA-p6v2-xcpg-h6xw](https://github.com/advisories/GHSA-p6v2-xcpg-h6xw) | high | core | Rate limiter can be bypassed by rotating IPv6 addresses | **closed** | `ipSubnet` expands `::` and groups to /48; limiter keys are the host’s to choose |
| [GHSA-gv74-j8m3-fg5f](https://github.com/advisories/GHSA-gv74-j8m3-fg5f) | high | sso | Regular organization members can register SSO providers | **no surface** | federation is host config; no user- or member-registered providers |
| [GHSA-g38m-r43w-p2q7](https://github.com/advisories/GHSA-g38m-r43w-p2q7) | high | core | OAuth sign-in can link to an account an attacker registered in advance | **closed** | `link-if-verified` needs the address verified on both sides |
| [GHSA-fmh4-wcc4-5jm3](https://github.com/advisories/GHSA-fmh4-wcc4-5jm3) | high | core | Organization invitations can be accepted by an unverified account | **no surface** | no organization invitation flow |
| [GHSA-cq3f-vc6p-68fh](https://github.com/advisories/GHSA-cq3f-vc6p-68fh) | high | core | Any signed-in user can approve or deny another person's device sign-in | **no surface** | no device authorization grant (feature gap) |
| [GHSA-392p-2q2v-4372](https://github.com/advisories/GHSA-392p-2q2v-4372) | high | oauth-provider | Concurrent refreshes can create extra valid refresh tokens | **closed** | the claim is the write; 10-way race on sqlite, pg and mysql |
| [GHSA-7w99-5wm4-3g79](https://github.com/advisories/GHSA-7w99-5wm4-3g79) | high | oauth-provider | Parallel requests can reuse one authorization code | **closed** | `DELETE … RETURNING` / `affectedRows`; plus a provider-level simultaneous redemption |
| [GHSA-j8v8-g9cx-5qf4](https://github.com/advisories/GHSA-j8v8-g9cx-5qf4) | high | scim | Any signed-in user can take over another user's personal SCIM provider | **no surface** | no SCIM |
| [GHSA-9h47-pqcx-hjr4](https://github.com/advisories/GHSA-9h47-pqcx-hjr4) | high | core | OIDC provider allows plain PKCE and lists unsigned tokens as supported | **one half was open — fixed** | PKCE was already S256-only and mandatory for public clients; `none` could reach the discovery document |
| [GHSA-h3rm-78g3-j7cp](https://github.com/advisories/GHSA-h3rm-78g3-j7cp) | high | stripe | Organization billing actions can run on the wrong organization | **no surface** | no billing plugin |
| [GHSA-prpr-5gj3-qqhg](https://github.com/advisories/GHSA-prpr-5gj3-qqhg) | high | sso | Four SSO flaws let an attacker sign in as another user | **closed** | the SAML half: both signature checks default on and turning both off is refused; XSW in port 9 |
| [GHSA-qq9h-g4jm-xgf3](https://github.com/advisories/GHSA-qq9h-g4jm-xgf3) | high | core | Attacker's password keeps working after magic link or email OTP sign-in | **closed** | `evictUnproven` clears an unproven password when a link or code adopts the account |
| [GHSA-8c5h-wx78-2cfg](https://github.com/advisories/GHSA-8c5h-wx78-2cfg) | high | sso | Unproven domain claims can allow account takeover or organization joins | **no surface** | no provider-claimed domains |
| [GHSA-q84f-53jg-9ppm](https://github.com/advisories/GHSA-q84f-53jg-9ppm) | high | core | Device login approval does not show the requesting client or permissions | **no surface** | no device authorization grant (feature gap) |
| [GHSA-mx9r-x6ww-qjw9](https://github.com/advisories/GHSA-mx9r-x6ww-qjw9) | high | sso | Personal SSO providers can sign in as another provider's users | **closed** | a link is keyed `(providerId, providerSub)`, so one provider cannot match another’s |
| [GHSA-r4xp-prcw-77qf](https://github.com/advisories/GHSA-r4xp-prcw-77qf) | high | core | OAuth Proxy lets an attacker sign in as another user | **no surface** | no OAuth proxy, and state carries no profile for one to trust |
| [GHSA-8jhw-6pjj-8723](https://github.com/advisories/GHSA-8jhw-6pjj-8723) | medium | core | Email verification links can redirect users to any website | **closed** | every link flow routes `callbackPath` through `isSafeCallbackPath` and falls back to its own default |
| [GHSA-9x4v-xfq5-m8x5](https://github.com/advisories/GHSA-9x4v-xfq5-m8x5) | medium | core | Error page can run attacker JavaScript from a crafted link | **no surface** | the package renders no HTML and serves no error page |
| [GHSA-36rg-gfq2-3h56](https://github.com/advisories/GHSA-36rg-gfq2-3h56) | medium | core | Trusted-origin check allows redirects to untrusted sites | **closed, newly tested** | no `startsWith`; five look-alike origins pinned |
| [GHSA-569q-mpph-wgww](https://github.com/advisories/GHSA-569q-mpph-wgww) | medium | core | The first request after startup can make every route return 404 | **no surface** | `baseUrl` is required config; nothing reads a Host header |
| [GHSA-xr8f-h2gw-9xh6](https://github.com/advisories/GHSA-xr8f-h2gw-9xh6) | medium | oauth-provider | clientPrivileges does not limit who can create OAuth clients | **closed** | DCR is off by default and takes an initial access token |
| [GHSA-wxw3-q3m9-c3jr](https://github.com/advisories/GHSA-wxw3-q3m9-c3jr) | medium | core | OAuth callback accepts a forged state value when state is kept in a cookie | **no surface** | state is HMAC-signed, nonce-burned and cookie-bound, not a stored row compared for presence |
| [GHSA-pw9m-5jxm-xr6h](https://github.com/advisories/GHSA-pw9m-5jxm-xr6h) | medium | core | OIDC provider and MCP plugins accept refresh tokens without the client secret | **closed, newly tested** | `token()` authenticates the client before the grant switch, both grants |
| [GHSA-86j7-9j95-vpqj](https://github.com/advisories/GHSA-86j7-9j95-vpqj) | medium | core | OIDC and MCP plugins accept javascript: redirect URIs that can run scripts | **closed** | `assertUsableScheme` is a rule, not a denylist; `dcr.test.ts` |
| [GHSA-p2fr-6hmx-4528](https://github.com/advisories/GHSA-p2fr-6hmx-4528) | medium | oauth-provider | Access tokens can target APIs the user did not authorize | **no surface** | no `resource` parameter and no audience to misbind (feature gap) |
| [GHSA-wmjr-v86c-m9jj](https://github.com/advisories/GHSA-wmjr-v86c-m9jj) | low | core | Forged multi-session cookies can make sign-out delete arbitrary sessions | **no surface** | no multi-session; the cookie holds an opaque sid that has to be in the store |
| [GHSA-2vg6-77g8-24mp](https://github.com/advisories/GHSA-2vg6-77g8-24mp) | low | scim | Deleted users stay signed in when sessions live in secondary storage | **closed** | an unreadable identity is refused at resolve on both paths, wherever sessions live |
| [GHSA-44jh-23m7-hpcf](https://github.com/advisories/GHSA-44jh-23m7-hpcf) | low | drizzle-adapter,kysely-adapter | Concurrent requests can exceed rate limits on PostgreSQL | **no surface** | no SQL-backed limiter; memory, redis and valkey increment atomically |

### 11. The advisory sweep — 4 ports, 17 cases, **one fix**

**The fix: `none` could reach the discovery document.** `authBuildOidcDiscovery`
passed `cfg.signingAlgs` into `id_token_signing_alg_values_supported`
unexamined. The union type (`'HS256' | 'ES256' | 'RS256'`) rules `none` out
wherever a compiler reads the call, but the list a host actually has often comes
from a config file or an environment variable, where no compiler reads anything
— and an RP that picks its algorithm from the published list will then accept an
unsigned ID token (OIDC Core 16.18). Refused at build time now, in any casing.
Exactly better-auth's GHSA-9h47-pqcx-hjr4, which shipped `none` as a default.

**And a test that named a guard which did not exist.** `rfc-conformance.test.ts`
had `it('rejects "none" alg (OIDC Core §16.18 ...)')` whose body built the
document with **no** `signingAlgs` at all and asserted `none` was absent from the
default. It tested the default value and read as a rejection; nothing rejected
anything. Its neighbour asserted `.not.toThrow()` for an alg outside the JWA set
through an `as any` cast, under the name `rejects "alg" outside the JWA
registered set`. The first is now three cases that pass `none`, `None` and
`NONE` the way a host would (`JSON.parse`, so no cast), and the second is gone:
its claim was false, its only route in was a cast, and the union type is the
gate it pretended to be.

**The four ports**, each mutation-proven:

| Ported | Advisory | Cases | Mutation |
| --- | --- | --- | --- |
| A recovery token spent at another flow's redeemer | GHSA-965c-763c-88jm (critical) | 6 | each of 5 purpose checks deleted in turn, killing exactly its own case |
| A look-alike Origin against the allowlist | GHSA-36rg-gfq2-3h56, GHSA-vp58-j275-797x | 6 | `includes` → `some(startsWith)` kills exactly the 3 payloads that bypass |
| A confidential client refreshing with no secret | GHSA-pw9m-5jxm-xr6h | 1 | `client_secret_post` accepting an absent secret |
| `signingAlgs: ['none']` | GHSA-9h47-pqcx-hjr4 | 4 | the comparison value changed, so the gate never fires |

The first is the one worth reading. duck-auth keeps seven token families in one
`Credential.kind` of `'recovery'`, told apart only by `metadata.purpose`, and
`findByHashedSecret(hash, 'recovery')` hands back whichever row matches the hash
regardless of purpose — so each of the six redeemers has to check the label
itself. All six did. Only one, `verifyBackupCode`, had a test saying so. The new
file relabels **the redeemer's own row** to each of the other six purposes and
feeds it back, which isolates the label as the only thing that changed, then
accepts the same token again once relabelled correctly — the companion allow,
without which a six-way refusal proves nothing but that something refused.

One case there is deliberately redundant: a real `signup-flow` token, the thing
any caller who merely names an address is handed, spent at
`completePasswordReset`. It survives the purpose check being deleted, because
the address comparison refuses it too, and goes red only when both are spent.
Kept on port 7's reasoning: the property stands on redundancy, so the test is
worth keeping precisely because it fails when the redundancy is gone.

**Two candidates were dropped as already covered**, found by reading before
writing rather than after: the IPv6 rate-limit bypass (GHSA-p6v2-xcpg-h6xw) is
covered by 10 cases in `device-fingerprint.test.ts`, which my first grep missed
by looking in `anomaly.test.ts`; and the deleted-user-stays-signed-in advisory
(GHSA-2vg6-77g8-24mp) by `session-security.e2e.test.ts`'s "a soft-deleted
identity stops resolving without erasing the row". A grep that misses the file
fakes a gap as readily as one anchored wrong fakes a clean sweep.

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
