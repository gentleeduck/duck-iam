# Security Policy

## Supported Versions

We provide security updates for the latest minor release of `@gentleduck/auth`.
Older versions may not receive patches.

| Version | Supported |
| ------- | --------- |
| 5.x     | Yes     |

## Reporting a Vulnerability

`@gentleduck/auth` mediates authentication - the gate every other security
control depends on. A vulnerability here can yield session hijack, credential
disclosure, MFA bypass, or impersonation. Please treat security reports with
the seriousness they deserve.

> [!WARNING]
> **Do not disclose security issues publicly.**
> Do not open a GitHub issue, PR, or discussion describing a vulnerability.

If you discover a vulnerability in `@gentleduck/auth`:

1. Report it privately by emailing **security@gentleduck.org**.
2. Include:
   - A detailed description of the vulnerability.
   - Steps to reproduce, ideally with a minimal repro.
   - The affected version(s).
   - Any known impact (session takeover, credential exposure, MFA bypass,
     fixation, replay, DoS, ReDoS, etc.).
   - Suggested fix, if you have one.
3. We will confirm receipt within **48 hours** and provide a timeline for a
   fix.

## Responsible Disclosure

We ask security researchers to give us **90 days** to address issues before
public disclosure. We will credit you in the release notes unless you prefer
to remain anonymous.

## Scope

In scope:

- The `@gentleduck/auth` core (`AuthEngine`, all facets, transports, errors).
- All shipped adapters: Memory, Drizzle (Postgres, MySQL, SQLite), Redis,
  Valkey.
- All shipped providers: password, magic-link, OAuth (google, github,
  linkedin, microsoft, discord, apple), passkey, api-key, MFA, SAML.
- All shipped server adapters: generic, express, hono, next, fastify, koa,
  elysia, nestjs, grpc.
- All shipped clients: vanilla, react, vue, solid, svelte.
- The CSRF middleware, idempotency store, anomaly detectors, and compliance
  presets.
- OIDC discovery (information-disclosure surface).

Out of scope:

- Vulnerabilities in third-party dependencies (please report upstream first).
- Misconfiguration captured by `AuthEngine.strict()` - the library throws on
  these at boot; ignoring the throw is operator error.
- Issues that require an attacker to already control the identity / session
  / credential store rows directly (those are trusted persistence).
- Social-engineering or physical attacks against contributors.

## What We Care About Most

Pay extra attention to:

- **Session hijack / fixation**: a rotation purpose that fails to revoke
  the prior SID, a guest session promoted without rotation, or any path
  that produces a session without going through `SessionsImpl.rotateOrCreate`.
- **Credential disclosure**: plaintext passwords, recovery codes, or
  api-keys leaking through logs, traces, errors, telemetry, or
  `JSON.stringify(identity)`.
- **MFA bypass**: a session reaching AAL 2 without a verified second factor,
  a `checkStepUp` that passes a stale or AAL 1 session, or a TOTP code or
  backup code accepted twice.
- **JWT key confusion**: alg-none acceptance, mixed-key signing, stale
  kid still on `verifyKeys` after the rollover window.
- **DPoP**: jti replay across the nonce-store TTL, missing nonce enforcement,
  thumbprint mismatch silently accepted.
- **CSRF**: cookie-auth route that mutates state without `__Host-duck-csrf`
  double-submit.
- **OAuth refresh-token reuse**: failure to revoke the rotation family on
  reuse (RFC 6749 §10.4).
- **Magic-link / recovery-token replay**: tokens not single-use, not hashed
  at rest, not rate-limited.
- **Idempotency-key collision**: cross-tenant key reads, missing TTL,
  cached response replayed to a different identity.
- **Delivery disclosure**: PII or a live token
  reaching the events bus payloads a webhook forwards.
- **Anomaly-detector poisoning**: device-fingerprint store corruption that
  marks every new device as "known".
- **Rate-limiter starvation**: a single tenant exhausting the global token
  bucket and locking everyone out.

### Guards deliberately survive a rollback

`withTransaction` binds identity, session and credential writes to your
transaction, but it does **not** bind the layer-2 guards: rate-limiter
counters, idempotency records, and hijack / anomaly scores are written on
the engine's own connection and stand whether or not your transaction
commits. That is the intended behaviour, in both directions:

- an attacker who can force a rollback cannot refund the attempts it cost,
  so a failing transaction is not a way to replay past the limiter; and
- a legitimate caller whose transaction failed cannot clear its idempotency
  record either, so a retry needs a fresh idempotency key rather than
  silently re-running under the old one.

A report that these are "leaking outside the transaction" is working as
designed. A report that a *credential or session* write escaped the
transaction, or that an event published for a rolled-back write, is a bug -
those buffer in `pending` and publish only on `flush()`.

Thank you for helping keep `@gentleduck/auth` and the wider gentleduck
ecosystem secure.

---

## Deployment Hardening Guide

`@gentleduck/auth` is the authentication **engine**. Identity-store
authority, secret storage, TLS termination, and CORS policy are the
operator's responsibility. The library ships safe defaults where it can;
the items below are choices only the operator can make.

### 1. `AuthEngine.strict({ env: 'production' })` at boot

`createAuth` runs `strict()` as it returns. In production it throws one
`AUTH_MISCONFIGURED` listing every footgun at once: a missing or in-memory
limiter, a `secure: false` cookie, a memory store, the in-process event bus
holding a `fleet` handler, an http `baseUrl`, no provider, no `lockout`
listener, and so on. A `lockout` listener cannot exist before `createAuth`
returns, so pass `strict: false`, subscribe, then call it yourself:

```ts
const auth = createAuth({
  // ...
  strict: false,
})
auth.events.on('lockout', page)
auth.strict({ env: 'production' })
```

### 2. Transport selection

`CookieTransport` for browser-only apps (set `secure: true`,
`sameSite: 'lax'`, never expose to a non-`__Host-` cookie scope).
`BearerTransport` for token-auth APIs. `JwtTransport` for stateless edges
(supply rotating keys; never run on a single key forever). `CompositeTransport`
when an app needs both. `strict()` rejects `secure: false` in production.

### 3. JWT signing-key rotation

`JwtTransport` accepts `signKey` (current signer) plus `verifyKeys` (signer
+ retired keys still valid for in-flight tokens). Rotate every 90 days:
mint a new secret, add it as the signer under a new kid, and keep the prior
kid on `verifyKeys`. Once the longest issued-JWT TTL has elapsed (cap +
buffer), drop the previous kid. Never use a single non-rotated key in
production.

### 4. DPoP-bound JWTs (RFC 9449)

Bind JWTs to a client key pair via `DPoPVerifier` when the access-token
audience cannot use cookies (single-page apps, mobile). DPoP-bound tokens
are useless to an attacker without the client's private key. Wire
`MemoryDPoPNonceStore` for dev and `RedisDPoPNonceStore` or
`valkeyDPoPNonceStore` for production so jti replay is detected across
nodes; the memory store refuses to construct in production.

### 5. Rate limiter - a shared one in production

`MemoryLimiter` is fine for tests and single-process dev. Multi-process or
multi-node deployments need `redisLimiter` or `valkeyLimiter` so
credential stuffing across process boundaries hits a real ceiling.
`strict({ env: 'production' })` rejects both `NoopLimiter` and
`MemoryLimiter`.

### 6. Idempotency store

`memoryIdempotency` is per-process. Browser retries behind a load balancer
will reach a different process and double-charge side-effects. Use
`redisIdempotency` or `valkeyIdempotency` in production; set the TTL to the
longest reasonable retry window (default 24h is conservative).

### 7. Password hashing

`Argon2idHasher` (the `@node-rs/argon2` peer) is the default. Where that
native peer cannot install, `scryptHasher()` uses Node's built-in scrypt.
The `fips` compliance preset requires Argon2id with FIPS parameters. Never
roll your own. `passwords.autoRehash` (on by default) upgrades hashes as users sign
in, so a parameter bump rolls out gradually.

### 8. Magic-link / recovery-token delivery

Magic-link and recovery tokens are *bearer credentials*. They reach the
host through the `deliver` callback on the engine config and nowhere else -
never the events bus, which a webhook forwards to external endpoints.
Tokens are hashed at rest with sha-256 and consumed single-use; `deliver`
sees the plaintext for the one delivery. The recipient address is whatever
the identity row holds, so a host that accepts an address from user input
validates it before storing it: the library does not parse it for CR/LF
before handing it over, and a mail transport that interpolates it into a
header would otherwise carry an injection.

### 9. OAuth refresh-token rotation (RFC 6749 §10.4)

The OIDC provider rotates refresh tokens on every use. Presenting a spent
one revokes its whole rotation family and answers `invalid_grant`. This is
always on and emits no event.

### 10. CSRF on cookie-auth routes

`CookieTransport` pairs the session with a `__Host-duck-csrf` double-submit
cookie. The routes each server adapter mounts verify it themselves. Every
state-mutating route you write on a cookie-auth surface MUST verify it too,
with the adapter's middleware (`expressCsrf`, `honoCsrf`, `fastifyCsrf`,
`koaCsrf`, `elysiaCsrf`, `withNextCsrf`, NestJS `makeCsrfGuard`) or with
`csrfGuard` from `@gentleduck/auth/core`:

```ts
import { csrfGuard } from '@gentleduck/auth/core'

export async function POST(req: Request) {
  await csrfGuard(auth, req)
  // ... the mutation
}
```

`csrfGuard` skips safe methods (GET/HEAD/OPTIONS/TRACE) and bearer requests
that carry no session cookie. It throws `AUTH_CSRF` on a mismatch, which
`errorToHttp` maps to 403.

### 11. MFA step-up freshness

`flows.checkStepUp(session, { methods, freshness })` refuses a session
below AAL 2 or older than its fresh window (`session.freshnessMs`, default
5min), and with `freshness`, one whose factor is older than that. Call it
before each privileged operation: token rotation, account deletion,
password change, and impersonation all warrant step-up.

### 12. Impersonation

There is no scope list - `actingAs` carries `realIdentityId`, `startedAt`,
`reason` and `expiresAt` only, so an impersonating session holds the
target's full authority until its window closes. The window *is* the
control: pass the shortest `ttlMs` the task needs, capped at 60min. The
row's own expiry is shortened to match, so it dies with the window rather
than lingering in the target's device list. Nesting is refused.

Wire both events to the audit sink; the pair is what an incident review
needs, not just the start: `identity.impersonated`, whose `audit.actorId`
names the operator, and `identity.impersonation.ended`, whose `endedBy` is
`release`, `revoke` or `expiry`. SOC2 / HIPAA require this.

**Known race, low.** Neither `releaseImpersonation` nor `impersonate` is
single-use against its input sid: two concurrent releases both succeed, and
a release racing a start spends the sid twice. Both read the session before
the rotation deletes it, with no compare-and-delete between. The result is
extra operator sessions, not extra authority - an operator can already sign
in N times - so this is durability for a stolen cookie rather than new
capability. Closing it needs `deleteIfPresent(id): Promise<boolean>` on the
session store contract, which every adapter would have to implement; that
break is not worth it at this severity. Revoke by identity rather than by
sid if you count operator sessions.

### 13. Anomaly detectors

`authImpossibleTravelDetector` and `deviceFingerprintDetector` ship as
detectors. A flagged request emits `suspicious`. Without `onAnomaly` the
server adapters refuse a `deny` with `AUTH_ANOMALY_DENIED` and admit a
`step-up`; the route reads `resolved.anomaly` to decide the rest.
Always wire `suspicious` to the audit sink. The shipped fingerprint store is
process-local, so a multi-process deployment implements
`AuthDeviceFingerprint.IStore` over shared storage, or every node sees a
known device as new.

### 14. PII in events / telemetry

The events bus payloads carry session + identity IDs but never plaintext
secrets. Custom event listeners must respect this. This package ships no
telemetry exporter, so whatever you subscribe to the bus - traces, metrics
or logs - is the layer that has to scrub user input from its attributes.

### 15. SECURITY.md release cadence

When a security fix lands, the version number is bumped, the release notes
list the CVE / advisory ID and reporter (unless they prefer anonymity),
and consumers are notified via the GitHub Security Advisory channel.

