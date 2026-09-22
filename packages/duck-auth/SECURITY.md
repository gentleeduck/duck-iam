# Security Policy

## Supported Versions

We provide security updates for the latest minor release of `@gentleduck/auth`.
Older versions may not receive patches.

| Version | Supported |
| ------- | --------- |
| 0.x     | Yes (current pre-1.0 surface) |

Once `1.0.0` ships, the previous minor will remain supported for **12 months**.

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
- All shipped channels: console, smtp, resend, ses, twilio, webpush.
- The CSRF middleware, idempotency store, anomaly detectors, and compliance
  presets.
- The OpenAPI generator, OIDC discovery, OpenTelemetry wiring, and i18n
  catalog (information-disclosure surface).

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
  that produces a session without going through `SessionsFacet.rotateOrCreate`.
  See DESIGN section 37 + THREAT-MODEL section 2.
- **Credential disclosure**: plaintext passwords, recovery codes, or
  api-keys leaking through logs, traces, errors, telemetry, or
  `JSON.stringify(identity)`.
- **MFA bypass**: a code path that reaches `flows.signIn` success without
  the MFA challenge for a TOTP-enrolled identity. Backup-code reuse,
  step-up not enforced after `freshnessMs` window.
- **JWT key confusion**: alg-none acceptance, mixed-key signing, stale
  kid still on `verifyKeys` after the rollover window.
- **DPoP**: jti replay across the nonce-store TTL, missing nonce enforcement,
  thumbprint mismatch silently accepted.
- **CSRF**: cookie-auth route that mutates state without `__Host-duck-csrf`
  double-submit (DESIGN section 39).
- **OAuth refresh-token reuse**: failure to revoke the rotation family on
  reuse (RFC 6749 §10.4); see DESIGN section 4.
- **Magic-link / recovery-token replay**: tokens not single-use, not hashed
  at rest, not rate-limited.
- **Idempotency-key collision**: cross-tenant key reads, missing TTL,
  cached response replayed to a different identity.
- **Channel disclosure**: PII (email body, SMS body) reaching telemetry or
  events bus payloads.
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

For the full STRIDE-style threat model see
[`THREAT-MODEL.md`](./THREAT-MODEL.md) - every defense the library ships and
every assumption it makes about the operator is enumerated there.

For the dependency audit see [`AUDIT-RESULTS.md`](./AUDIT-RESULTS.md) -
re-runnable via `bun audit`; current advisories are dev-tooling only,
none on the runtime path.

---

## Deployment Hardening Guide

`@gentleduck/auth` is the authentication **engine**. Identity-store
authority, secret storage, TLS termination, and CORS policy are the
operator's responsibility. The library ships safe defaults where it can;
the items below are choices only the operator can make.

### 1. `AuthEngine.strict({ env: 'production' })` at boot

Always call `strict()` at process startup. It throws `AUTH/MISCONFIGURED`
on the highest-impact footguns: NoopLimiter in production, insecure
CookieTransport, memory adapter in production, missing providers, missing
lockout-event listener, and so on. Wire to a failing health-check so a
misconfigured deploy never serves traffic.

```ts
// - Boot-time validation; deployment fails fast.
const auth = new AuthEngine({ /* ... */ })
auth.strict({ env: process.env.NODE_ENV === 'production' ? 'production' : 'development' })
```

### 2. Transport selection

`CookieTransport` for browser-only apps (set `secure: true`,
`sameSite: 'lax'`, never expose to a non-`__Host-` cookie scope).
`BearerTransport` for token-auth APIs. `JwtTransport` for stateless edges
(supply rotating keys; never run on a single key forever). `CompositeTransport`
when an app needs both. `strict()` rejects `secure: false` in production.

### 3. JWT signing-key rotation

`JwtTransport` accepts `signKey` (current signer) plus `verifyKeys` (signer
+ retired keys still valid for in-flight tokens). Rotate every 90 days
using `duck-auth keys rotate hs256` - it emits a new secret plus a config
snippet that adds the new kid as the signer and keeps the prior kid on
`verifyKeys`. Once the longest issued-JWT TTL has elapsed (cap +
buffer), drop the previous kid. Never use a single non-rotated key in
production.

### 4. DPoP-bound JWTs (RFC 9449)

Bind JWTs to a client key pair via `DPoPVerifier` when the access-token
audience cannot use cookies (single-page apps, mobile). DPoP-bound tokens
are useless to an attacker without the client's private key. Wire
`MemoryDPoPNonceStore` for dev and `RedisDPoPNonceStore` for production
so jti replay is detected across nodes.

### 5. Rate limiter - never `NoopLimiter` in production

`MemoryLimiter` is fine for tests and single-process dev. Multi-process or
multi-node deployments need `RedisLimiter` so credentials-stuffing across
process boundaries hits a real ceiling. `strict({ env: 'production' })`
rejects `NoopLimiter`.

### 6. Idempotency store

The default in-memory idempotency store is per-process. Browser retries
behind a load balancer will reach a different process and double-charge
side-effects. Use `RedisIdempotencyStore` in production; set TTL to the
longest reasonable retry window (default 24h is conservative).

### 7. Password hashing

`ScryptHasher` (Node built-in, no peerDep) is the default and is fine for
most deployments. Compliance presets (`fips`, `hipaa`) require Argon2id -
install `@node-rs/argon2` and switch to `Argon2idHasher`. Never roll your
own. `passwords.autoRehash` (on by default) upgrades hashes as users sign
in, so a parameter bump rolls out gradually.

### 8. Magic-link / recovery-token channel

Magic-link and recovery tokens are *bearer credentials*. The bundled
console channel is dev-only. Production must use a real channel
(`Resend`, `SES`, `SMTP`, `Twilio`). Tokens are hashed at rest with
sha-256 and consumed single-use; the channel only sees the plaintext for
the one delivery.

### 9. OAuth refresh-token rotation (RFC 6749 §10.4)

Refresh-token reuse triggers family revocation: the entire rotation family
is invalidated and the user is signed out. This is mandatory and on by
default. Do not disable it. Wire a `lockout` event listener so the
operator is paged when reuse is detected - the user's account may be
compromised.

### 10. CSRF on cookie-auth routes

`CookieTransport` mounts a `__Host-duck-csrf` double-submit cookie (DESIGN
section 39). Every state-mutating route on a cookie-auth surface MUST
verify the CSRF header matches the cookie.

**You wire this - the library does NOT auto-enforce.** The framework
adapter you mount calls into `FlowsFacet.signIn` / `signOut` /
`beginProvider`; the library cannot tell whether your request came from
a same-origin form or a malicious cross-origin fetch without inspecting
the request headers, and the headers are unique to each framework. The
package ships a `csrfGuard(auth, req)` helper in `@gentleduck/AUTH/core`
that does the work - call it before every state-mutating handler:

```ts
import { csrfGuard } from '@gentleduck/AUTH/core'

// Express
app.post('/AUTH/signin', async (req, res, next) => {
  try { await csrfGuard(auth, fetchReqFromExpress(req)) } catch (e) { return next(e) }
  // ... call auth.flows.signIn
})

// Hono
app.post('/AUTH/signin', async (c) => {
  await csrfGuard(auth, c.req.raw)
  // ... call auth.flows.signIn
})

// Next.js (App Router)
export async function POST(req: Request) {
  await csrfGuard(auth, req)
  // ... call auth.flows.signIn
}
```

`csrfGuard` short-circuits for safe methods (GET/HEAD/OPTIONS/TRACE) and
for Bearer/JWT-authenticated requests (browsers cannot CSRF a header
that JS must explicitly set). It throws `AUTH/CSRF` on mismatch - your
adapter's error handler should map that to HTTP 403.

When the request comes in via a Bearer / JWT transport (no ambient
cookie credential), pass `{ isBearer: true }` to bypass - there is
nothing to defend against.

### 11. MFA step-up freshness

`flows.checkStepUp(action)` enforces a fresh re-auth window
(`session.freshnessMs`, default 5min) before privileged operations.
Configure on a per-action basis: token rotation, account deletion,
password change, and impersonation all warrant step-up.

### 12. Impersonation (DESIGN section 38)

Operators acting as a tenant inherit *only* the explicit `actingAs.scopes`
list. Never grant `*` here. Every impersonation start emits
`session.impersonate-start` - wire an audit log listener; SOC2 / HIPAA
require this.

### 13. Anomaly detectors

`impossibleTravel` + `deviceFingerprint` ship as detectors. They emit
`anomaly` events; they do *not* block by default - the operator's policy
decides (step-up, deny, log only). Always wire `anomaly` to the audit
sink. For multi-process deployments, back `DeviceFingerprintStore` with
Redis so a fresh device is not "first-sight" on every node.

### 14. PII in events / telemetry

The events bus payloads carry session + identity IDs but never plaintext
secrets. Custom event listeners must respect this. OpenTelemetry wiring
(`src/telemetry/otel`) auto-redacts known PII keys; if you add custom
spans, scrub user input from attributes.

### 15. SECURITY.md release cadence

When a security fix lands, the version number is bumped, the release notes
list the CVE / advisory ID and reporter (unless they prefer anonymity),
and consumers are notified via the GitHub Security Advisory channel.

For full threat-model coverage (STRIDE per asset), see
[`THREAT-MODEL.md`](./THREAT-MODEL.md).

