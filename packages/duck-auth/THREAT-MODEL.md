# THREAT-MODEL.md

Threat model for `@gentleduck/auth`. Aligned to **OWASP ASVS 4.0** (Application
Security Verification Standard) and uses the **STRIDE** taxonomy
(Spoofing / Tampering / Repudiation / Information disclosure / Denial of
service / Elevation of privilege) for classification.

This document is a contract: every section names the threat, the
mitigation the library ships, the configuration required to keep the
mitigation effective, and what residual risk remains for the host app to
own.

---

## Trust boundaries

```
+----------------+      +------------------+      +-----------------+
|  User browser  |<---->|  Framework       |<---->| @gentleduck/    |
|  / Mobile app  |      |  adapter         |      |  auth core      |
+----------------+      +------------------+      +-----------------+
                                |                          |
                                |                          v
                                |                  +-----------------+
                                |                  |  Stores         |
                                |                  |  (Redis/SQL)    |
                                |                  +-----------------+
                                v
                        +-----------------+
                        | Outbound        |
                        | channels        |
                        | (email/SMS)     |
                        +-----------------+
```

Three boundaries:

1. **Public network <-> framework adapter**: untrusted input crosses this
   line; every authentication / mutation route lives here.
2. **Adapter <-> AuthRoot facets**: trusted internal API. Inputs are
   validated by the facets; adapters MUST pass typed inputs (no
   pass-through of raw HTTP bodies).
3. **AuthRoot <-> stores + channels**: trusted backend boundary. The lib
   assumes Redis / database / SMTP relay are operated by the same team
   that operates the auth service.

---

## 1. Spoofing

### S1. Stolen session cookie or bearer token

| Attribute | Value |
|----|----|
| ASVS | V3.4.1, V3.7.1 |
| Surface | `CookieTransport` + `BearerTransport` + `JwtTransport` |

**Mitigations shipped:**

- Session IDs hashed with sha-256 before persistence; the cookie /
  bearer carries the plaintext; the store row key is the hash. A
  database exfiltrator cannot resume sessions without the live cookies.
- `__Host-` prefix on the default cookie name (browser enforces Secure +
  Path=/ + no Domain).
- `HttpOnly` + `SameSite=Lax` defaults.
- DPoP (`DPoPVerifier`) cryptographically binds bearer tokens to a
  client-held EC / Ed25519 keypair. A stolen bearer cannot be replayed
  without the matching private key.
- Per-request DPoP proof carries `htm` (method), `htu` (URL), `jti`
  (anti-replay nonce), `iat` (freshness window), and optional `ath`
  (access-token hash). All five are verified.

**Required config:**

- `transport: new CookieTransport({ secure: true })` in production
  (`strict()` rejects `secure:false` outside `env:'dev'`).
- For bearer tokens, wire `DPoPVerifier` into the framework adapter
  middleware and require the `DPoP` header on every authenticated
  request.

**Residual risk:** an attacker with same-origin XSS can exfiltrate
DPoP-bound tokens by minting their own proofs. Mitigation lives outside
this library (CSP, Trusted Types, app-side input sanitization).

### S2. CSRF (forged state-changing request from another origin)

| Attribute | Value |
|----|----|
| ASVS | V4.2.2 |
| Surface | `CsrfFacet` |

**Mitigations shipped:**

- Per-session CSRF token (`csrfHash` on `Session.ISession`); cookie
  carries plaintext, request carries it via `X-CSRF-Token` header or
  `csrf_token` form field; server compares against sha-256 of the
  cookie.
- `SameSite=Lax` cookie cuts most CSRF surface before reaching this
  layer.

**Required config:** framework adapter must mount the CSRF middleware
on every mutating route (`POST` / `PUT` / `PATCH` / `DELETE`). The
shipped Express / Hono / Next adapters do this by default.

**Residual risk:** apps that disable the CSRF middleware are on their
own.

### S3. OAuth state spoofing (CSRF on the callback)

| Attribute | Value |
|----|----|
| ASVS | V2.5.1 |
| Surface | `providers/oauth/core` |

**Mitigations shipped:**

- `state` parameter is an HMAC-signed value bound to the initiator's
  session id and the chosen provider id; the callback rejects on
  mismatch (`AUTH/OAUTH_STATE_MISMATCH`).
- PKCE-S256 challenge generated for every flow; verifier persisted
  server-side and checked at token exchange (`AUTH/OAUTH_FAILED`).
- `nonce` (OIDC) recorded in the credential store at start; the
  callback fails closed on replay (`AUTH/OAUTH_NONCE_REPLAY`).

### S4. Magic-link forgery

| Attribute | Value |
|----|----|
| ASVS | V2.4.1, V6.3.1 |
| Surface | `providers/magic-link` |

**Mitigations shipped:**

- Plaintext token is 32 cryptographically random bytes (256 bits of
  entropy); only the sha-256 is persisted in the credential row.
- Single use: row deleted on success.
- TTL default 10 minutes (`AUTH/RECOVERY_TOKEN_EXPIRED` on consumption
  past TTL).
- Per-email rate limit via the configured `Limiter.ILimiter`.

---

## 2. Tampering

### T1. JWT alg confusion / key swap

| Attribute | Value |
|----|----|
| ASVS | V3.5.3 |
| Surface | `JwtTransport` |

**Mitigations shipped:**

- Library only signs + verifies HS256 (v0.1); the verifier rejects any
  other `alg` header field. ES256 / RS256 / EdDSA scheduled for v0.2
  via `jose`.
- `kid` header looked up against the configured `verifyKeys` map.
  Unknown `kid` -> `AUTH/JWT_KEY_UNKNOWN`.
- Rotated keys retained for an overlap window via `notAfter` so
  already-issued tokens keep verifying through a rotation.

### T2. Session fixation

| Attribute | Value |
|----|----|
| ASVS | V3.2.3 |
| Surface | `SessionsFacet.rotateOrCreate` |

**Mitigations shipped:**

- Every sign-in, MFA pass, password change, and impersonation start
  rotates the session id (see DESIGN section 37 - the 7-row rotation
  matrix). The pre-auth session is revoked atomically.

### T3. DPoP proof tampering

| Attribute | Value |
|----|----|
| ASVS | V3.4.1 |
| Surface | `DPoPVerifier` |

**Mitigations shipped:**

- DPoP proofs verified end-to-end (signature against embedded JWK,
  thumbprint match against access-token `cnf.jkt`, htm/htu/iat/jti/ath
  claims all enforced).
- Allowed-alg set defaults to `['ES256', 'EdDSA']`; symmetric algorithms
  forbidden per RFC 9449 section 4.2.
- `jwk` field rejected if it carries a `d` (private key) component.

---

## 3. Repudiation

### R1. "I never signed in / impersonated / consented"

| Attribute | Value |
|----|----|
| ASVS | V7.1.1, V7.2.1 |
| Surface | `Events` bus |

**Mitigations shipped:**

- Every state transition emits a typed event via the configured
  `Events.IBus`: `session.created`, `session.rotated`,
  `session.revoked`, `identity.impersonated`, `mfa.completed`,
  `password.changed`, `oauth.bound`, etc.
- Impersonation sessions carry an `actingAs` envelope on the session
  itself (real identity id + reason + start time + cap).
- 1-hour hard cap on impersonation TTL regardless of caller request.

**Required config:** wire a durable event sink (Kafka, Datadog,
file-based audit log) into the events bus. The default `InMemoryEvents`
is lost on restart.

### R2. Lost lockout audit trail

| Attribute | Value |
|----|----|
| ASVS | V7.2.1 |
| Surface | `Limiter` + `lockout` event |

**Mitigations shipped:**

- `AuthRoot.strict()` refuses production boot when no listener is
  attached to the `lockout` event.

---

## 4. Information disclosure

### I1. Password / token leakage via logs or response bodies

| Attribute | Value |
|----|----|
| ASVS | V8.3.1, V8.3.4 |
| Surface | `errors` + channels |

**Mitigations shipped:**

- `AuthErrorObject.toJSON()` returns a wire-safe envelope. Sensitive
  meta keys never leak; the only fields are `code`, `status`, and the
  whitelisted extras (`missing`, `until`, `retryAfter`, `kid`).
- Channel implementations receive the identity + variables only; never
  the raw plaintext password or magic-link secret. Magic-link URLs are
  pre-signed by the library before reaching the channel.
- Password hashes use Argon2id (v1 default) or scrypt (built-in
  fallback) with constant-time verify via `crypto.timingSafeEqual`.

### I2. User enumeration via response timing or content

| Attribute | Value |
|----|----|
| ASVS | V2.2.7 |
| Surface | `password` + `magic-link` providers |

**Mitigations shipped:**

- `password.complete` returns `AUTH/INVALID_CREDENTIALS` for both
  "unknown email" and "wrong password"; no separate signal.
- `magic-link.begin` does not vary the response shape on whether the
  email is registered (consumer wires `autoCreateIdentity:true` to
  homogenize fully).
- Per-email + per-IP rate limits applied uniformly (`AUTH/RATE_LIMITED`).

**Residual risk:** timing-side-channel via Argon2id parameter
mismatches if the caller wires different `memoryCost` values per
tenant. `strict()` does not catch this; document for operators.

### I3. Session record leakage from a stolen Redis dump

| Attribute | Value |
|----|----|
| ASVS | V3.7.1 |
| Surface | `RedisSessionStore` + `AdminFacet.dataAtRest` |

**Mitigations shipped:**

- Stored session records contain only the sha-256 of the SID; the
  plaintext lives in the cookie / Authorization header.
- `dataAtRest.encrypt` / `.decrypt` envelopes can wrap PII fields in
  the identity profile (AES-256-GCM by default). Disabled out-of-the-
  box; ops choose.

---

## 5. Denial of service

### D1. Brute force against password / magic-link

| Attribute | Value |
|----|----|
| ASVS | V11.1.1 |
| Surface | `Limiter` |

**Mitigations shipped:**

- Per-identity + per-IP token-bucket via `Limiter.ILimiter`. Memory
  + Redis impls ship in-tree.
- `strict()` refuses production boot when no limiter is wired.
- `AuthErrorObject('AUTH/RATE_LIMITED')` carries a `retryAfter` field
  for `Retry-After` header derivation.
- Hashed-password verification uses argon2id at OWASP-2024 minimums so
  per-attempt CPU cost is enforced server-side.

### D2. Memory exhaustion via unbounded session listing

| Attribute | Value |
|----|----|
| ASVS | V12.4.2 |
| Surface | `SessionsFacet.listByIdentity` |

**Mitigations shipped:**

- `Session.IStore.listByIdentity` is documented as bounded by the live
  TTL window; Redis impl SREMs stale members on read so an old identity
  cannot accumulate millions of orphaned entries.

### D3. Idempotency replay flood

| Attribute | Value |
|----|----|
| ASVS | V11.1.5 |
| Surface | `IdempotencyFacet` |

**Mitigations shipped:**

- `RedisIdempotencyStore.claim` is atomic via `SET NX EX`; a flood of
  duplicate idempotency keys triggers at most one executor invocation.
- Per-tenant key prefix prevents cross-tenant collision.

---

## 6. Elevation of privilege

### E1. AAL downgrade after MFA

| Attribute | Value |
|----|----|
| ASVS | V2.10.1 |
| Surface | `Session.AAL` field |

**Mitigations shipped:**

- `aal` (1 / 2 / 3) and `factors[]` (method + completedAt) are first-
  class on every `Session.ISession`. `AdminFacet.requireAAL(level)`
  throws `AUTH/AAL_INSUFFICIENT` when called inside a downgraded
  context.
- `factors[]` is append-only across rotations; the rotation matrix
  preserves the AAL ceiling unless the rotation reason explicitly
  resets it (sign-out, recovery).

### E2. Impersonation escape

| Attribute | Value |
|----|----|
| ASVS | V2.5.6 |
| Surface | `FlowsFacet.impersonate` |

**Mitigations shipped:**

- `authorize` callback required on every `impersonate()` call; the
  facet refuses self-impersonation regardless of return value
  (`AUTH/IMPERSONATE_FORBIDDEN`).
- `actingAs` envelope persisted on the issued session so audit /
  rate-limiting / authz layers can see "this user is acting as".
- 1-hour TTL cap, enforced even when the caller passes a longer
  `ttlMs`.
- `releaseImpersonation(sid)` refuses non-impersonation sessions
  (`AUTH/IMPERSONATE_EXPIRED`).

### E3. OAuth token reuse after refresh

| Attribute | Value |
|----|----|
| ASVS | V2.4.6 |
| Surface | `providers/oauth/core` |

**Mitigations shipped:**

- Refresh tokens stored hashed with a family-id grouping per
  RFC 6749 section 10.4. Reuse of a previously-rotated refresh token
  revokes the entire family + emits `AUTH/OAUTH_REUSE_DETECTED`.

### E4. Compliance preset bypass

| Attribute | Value |
|----|----|
| ASVS | V1.14.6 |
| Surface | `CompliancePreset` |

**Mitigations shipped:**

- Compliance presets (`gdpr` / `hipaa` / `soc2` / `fips`) layered with
  strictest-wins merge. Caller overrides cannot weaken a preset
  (`AuthRoot.strict()` refuses).
- Each preset documented separately; e.g. `fips` requires Argon2id +
  HS256 + JWT transport + no cookie fallback.

---

## Out of scope

Threats the library deliberately does NOT mitigate; the host app owns
them:

- **XSS in the host app**: a same-origin script can exfiltrate any
  token the browser holds; the library cannot defend against this.
- **Network-level interception**: TLS termination is the host's
  responsibility.
- **Operational secrets management**: the library accepts secrets
  via config; the host wires its secrets manager.
- **Email / SMS deliverability**: channel adapters relay; spam-filter
  decisions are out of band.
- **Phishing of users by the app itself**: outside the library's
  threat surface.

---

## Verification checklist

A deployment is considered baseline-compliant when every item passes:

- [ ] `AuthRoot.strict()` succeeds at boot
- [ ] Cookie transport carries `secure: true`
- [ ] A non-memory `Limiter` is wired
- [ ] A non-memory `Session.IStore` is wired (Redis or SQL)
- [ ] An events listener is attached to `lockout`, `session.revoked`,
      and `identity.impersonated`
- [ ] Compliance preset matches the regulatory scope
- [ ] Idempotency store is non-memory in multi-process deploys
- [ ] CSRF middleware is mounted on every mutating route
- [ ] DPoP verifier is wired when bearer tokens are issued
- [ ] OAuth refresh-token reuse-detection event monitored
