# Security Policy

## Supported Versions

We provide security updates for the latest major release of `@gentleduck/iam`.
Older versions may not receive patches.

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| 1.x     | No        |

## Reporting a Vulnerability

`@gentleduck/iam` is an authorization engine. Vulnerabilities in an
authorization library can result in privilege escalation, data exposure,
or bypassed access controls in any application using it. Please treat
security reports with the seriousness they deserve.

> [!WARNING]
> **Do not disclose security issues publicly.**
> Do not open a GitHub issue, PR, or discussion describing a vulnerability.

If you discover a vulnerability in `@gentleduck/iam`:

1. Report it privately by emailing **security@gentleduck.org**.
2. Include:
   - A detailed description of the vulnerability.
   - Steps to reproduce, ideally with a minimal repro.
   - The affected version(s).
   - Any known impact (privilege escalation, denial of service, ReDoS, etc.).
   - Suggested fix, if you have one.
3. We will confirm receipt within **48 hours** and provide a timeline for a fix.

## Responsible Disclosure

We ask security researchers to give us **90 days** to address issues before
public disclosure. We will credit you in the release notes unless you prefer
to remain anonymous.

## Scope

In scope:

- The `@gentleduck/iam` core evaluation engine.
- All shipped adapters: Memory, File, Prisma, Drizzle, Redis, HTTP.
- All shipped server middleware: Express, NestJS, Hono, Next.js, generic.
- All shipped client integrations: React, Vue, Vanilla.
- The condition operators and dollar-path resolution.
- The `explain()` trace builder.

Out of scope:

- Vulnerabilities in third-party dependencies (please report upstream first).
- Issues that require an attacker to already control the policy store or
  role definitions (those are by-design trusted inputs).
- Social-engineering or physical attacks against contributors.

## What We Care About Most

Pay extra attention to:

- **Authorization bypasses**: a request that should be denied returning allow.
- **Privilege escalation**: a user gaining permissions they were not granted.
- **Dollar-path injection**: malformed `$path` references leaking data across
  the request boundary.
- **Prototype pollution**: condition field paths reaching `__proto__`,
  `constructor`, or `prototype`.
- **ReDoS**: regex patterns in the `matches` operator causing pathological
  backtracking.
- **Cache poisoning**: a stale or attacker-controlled value persisting in the
  LRU cache after invalidation should have run.
- **Multi-tenant scope leaks**: a permission granted in one scope leaking into
  another scope.

Thank you for helping keep `@gentleduck/iam` and the wider gentleduck ecosystem
secure.

---

## Deployment Hardening Guide

`@gentleduck/iam` is the authorization **engine**. Authentication, identity
sourcing, CSRF protection, and multi-tenant isolation are the operator's
responsibility. The library ships safe defaults where it can; the items below
are choices only the operator can make.

### 1. Identity sourcing — never trust client-supplied headers

`accessMiddleware` / `withAccess` / `guard` derive a `subjectId` from a
`getUserId(req)` callback. Always derive identity from a **server-verified**
source: a cookie session, a JWT verified by upstream middleware, an mTLS
client certificate, or a session token your auth layer already validated.

```ts
// ✅ Cookie session verified by app middleware
app.use(sessionMiddleware)
const guard = accessMiddleware(engine, {
  getUserId: (req) => req.session?.userId ?? null,
})

// ✅ JWT verified by app middleware → req.user
app.use(jwtMiddleware)
const guard = accessMiddleware(engine, {
  getUserId: (req) => req.user?.sub ?? null,
})

// ❌ Client-supplied header — anyone with curl spoofs admin
getUserId: (req) => req.headers['x-user-id']
// ❌ Request body — attacker-controlled
getUserId: (req) => req.body?.userId
```

The Express/Nest defaults already read from `req.user?.id` (populated by
common auth middleware). The Hono default reads `c.get('userId')` only
(no header fallback — SEC-101). The Next `withAccess` requires
`getUserId` to be supplied explicitly.

### 2. Admin router CSRF

`adminRouter` / `bindAdminRouter` / `createAdminHandlers` /
`createAdminOperations` accept `csrfCheck`. The **built-in default**
(`defaultCsrfCheck`) rejects browser requests whose `Sec-Fetch-Site`
header is `cross-site` or `cross-origin`. This closes the most common
cookie-auth CSRF vector without operator action.

```ts
// ✅ Default — Sec-Fetch-Site check applied automatically
adminRouter(engine, { authorize: (req) => req.user?.role === 'admin' })

// ✅ Bearer-token / mTLS API (no browser) — disable
adminRouter(engine, { authorize, csrfCheck: false })

// ✅ Stricter: Origin allowlist
const ADMIN_ORIGINS = new Set(['https://admin.example.com'])
adminRouter(engine, {
  authorize,
  csrfCheck: (req) => ADMIN_ORIGINS.has(req.headers.origin),
})
```

### 3. Redis invalidator: secret + per-tenant channel

`createRedisInvalidator` defaults to an unsigned envelope on the
default channel `'duck-iam:invalidate'`. Anyone with `PUBLISH` rights
to that channel can wipe caches. **Production deployments must set
`secret`**, and multi-tenant deployments should pass `tenantId` so
tenant A's revoke cannot wipe tenant B's cache.

```ts
const invalidator = createRedisInvalidator({
  client: redisPubSub,
  secret: process.env.IAM_INVALIDATE_SECRET, // HMAC-SHA256
  tenantId: tenant.slug,                     // per-tenant channel
  onPublishError: (err, channel) => log.warn({ err, channel }, 'publish failed'),
})
```

Rotating `IAM_INVALIDATE_SECRET` is HMAC-key rotation: engines with
mismatched secrets silently drop each other's messages, so coordinate
the rotation window.

### 4. Multi-tenant cache scoping

The `matches`-operator regex cache and dot-path segment cache are
process-globals (SEC-050). A hostile tenant flooding distinct
patterns can evict another tenant's hot entries — availability
degradation, not auth bypass. Two mitigations:

- **One Node process per tenant** (recommended): each process gets
  its own globals — no cross-talk.
- **Periodic flush** via `engine.flushSharedCaches()`. Tune the
  interval against your request volume.

```ts
// Periodic flush at 5min interval
setInterval(() => engine.flushSharedCaches(), 5 * 60 * 1000)
```

### 5. `defaultEffect: 'allow'`

Almost always wrong. `defaultEffect: 'allow'` means a request that
matches no policy is allowed — silent fail-open on adapter outages,
mass policy deletion, or any other source of "no applicable rule".
The engine refuses this configuration unless you pass
`allowFailOpen: true` and emits a startup warning. Operators who
opt in should chart the `failOpen` field on `IMetricsEvent` to alert
on silent failures (SEC-044).

### 6. `explain()` output

`engine.explain()` returns full rule contents, condition operands,
and `subject.attributes` for development debugging. It throws in
production mode by default. The `summary` string interpolates
operator- and attacker-influenced IDs verbatim; downstream consumers
that render it as HTML must escape themselves.

### 7. Adapter trust

The library never validates what the adapter stores or returns
beyond shape checks (`validatePolicy`/`validateRole`). Policies and
roles in the store are trusted inputs. Restrict write access to the
store at the storage layer (DB grants, file permissions, Redis
ACLs).

### 8. File adapter `rootDir`

Always pass `rootDir` when the file path can be derived from
request data. The adapter performs textual containment + symlink
realpath checks (SEC-003, SEC-025) only when `rootDir` is set; an
adapter without `rootDir` warns once at construction (SEC-026)
but cannot enforce containment.

### 9. HTTP adapter `allowedHosts`

Set `allowedHosts` to your IAM API hostname allowlist. The default
rejects private/loopback hosts (SEC-001) and refuses redirects
(SEC-042), but a permissive `baseUrl` without `allowedHosts` warns
once at construction.

### 10. Observability

Wire `onPolicyError`, `onError`, and `onMetrics` on the engine —
silent failures in an authorization path either deny everything or
allow everything, both customer-visible outages. Use
`createMetricsAggregator()` to chart `failOpen` rate as a
silent-policy-breakage alarm.

---

## Code-level Security Annotations (SEC-XXX catalog)

DEBT-9: the source carries `// SEC-XXX:` reference comments at each
hardened site. This catalog lists every SEC-ID with a one-line summary
so a reader can browse the catalog without grepping. Full rationale
lives in CHANGELOG.md (2.0.0 + 2.1.0 sections) plus git blame on the
fix commit.

| ID | Class | Summary |
|---|---|---|
| SEC-001 | SSRF / scheme | HTTP adapter `baseUrl` scheme + private-IP + allowedHosts validation |
| SEC-003 | Path traversal | File adapter rejects `..` segments + rootDir containment |
| SEC-007 | Resource match | Literal-only `matchesResource` semantics; `:*` required for hierarchy |
| SEC-010 | Audit | `onAdminMutation` fires across all server adapters |
| SEC-019 | Encoding | Redis assignment separator is NUL byte (not space) |
| SEC-020 / SEC-022 / SEC-034 | ReDoS | `matches` operator regex cap + UTF-8 byte length |
| SEC-021 | Devtools leak | Devtools default-block when no dev-mode signal |
| SEC-024 | Race | Redis `_runSerialised` per assignments key (single-process) |
| SEC-025 | TOCTOU | File `_assertWithinRoot` per-I/O re-check (drops one-shot latch) |
| SEC-026 | Log spam | File rootDir warn module-global once-per-process latch |
| SEC-027 | Path exfil | File warn omits resolved path (request-derived oracle) |
| SEC-028 .. SEC-030 / SEC-035 .. SEC-038 | SSRF v6 | IPv4-mapped, 6to4, NAT64, `::`, `0.0.0.0`, IDN normalisation |
| SEC-031 / SEC-034 | DoS | Redis invalidator pre-auth size + depth + UTF-8 byte cap |
| SEC-032 | Warn silencing | Invalidator per-channel rate-limited warn (replaces one-shot latch) |
| SEC-039 .. SEC-041 | Audit leakage | redactPath / onAuditHookError / err.message sanitisation |
| SEC-042 | SSRF redirect | HTTP adapter `redirect: 'error'` on fetch |
| SEC-043 | Validation | Admin write path runs `validatePolicy` / `validateRole` before persist |
| SEC-044 | Observability | `failOpen` field on `IMetricsEvent` + aggregator counter |
| SEC-045 | Race | `_mergedInFlight` sentinel on `_loadAllPolicies` |
| SEC-046 | Auth bypass | Redis invalidator drops v:1 envelope when secret unset |
| SEC-047 | Audit leakage | `errorToAuditString` non-Error tag + 256-char cap |
| SEC-048 | Namespacing | Devtools localStorage prefix vendor-namespaced |
| SEC-050 | Multi-tenant DoS | Regex + path cache flush via `flushSharedCaches()` |
| SEC-051 | Observability | `permissions()` fires `onMetrics` per check |
| SEC-052 | Error leakage | Validator throw text uses codes, not user values |
| SEC-053 | Symlink bypass | File realpath fallback gated on `code === 'ENOENT'` |
| SEC-054 | Fail-open | File load throws on non-ENOENT instead of silently emptying |
| SEC-055 / SEC-065 / SEC-066 | Hook escape | `_safeHookCall` wraps every operator hook; double-wrapped `console.error` |
| SEC-056 | Decision rewrite | Trailing hooks (`afterEvaluate`/`onDeny`) outside evaluation try |
| SEC-057 | Silent drop | `permissions()` forwards `onPolicyError` to evaluator |
| SEC-058 | Silent ABAC deny | Redis/Drizzle attrs throw on corruption (not silent `{}`) |
| SEC-059 | Cross-backend drift | `getSubjectRoles` unscoped-only across all adapters |
| SEC-063 | Adapter DoS | File `_loadInFlight` cleared on any throw (was stuck-rejection) |
| SEC-064 | Data destruction | File parse-fail throws (was silent `{}` → overwrite on flush) |
| SEC-067 | Admin lockout | `setSubjectAttributes` recovers from corrupt existing blob |
| SEC-068 | HTTP contract | HTTP adapter `getSubjectRoles` documents unscoped-only |
| SEC-069 | Listener swallow | dt/flow.ts notify() console.error on throw |
| SEC-070 | Fail-closed batch | `permissions()` outer try → all-deny map + `onError` |
| SEC-101 | Auth bypass | Hono/Next default `getUserId` no longer trusts `x-user-id` header |
| SEC-103 | CSRF | Admin router default-on `defaultCsrfCheck` (Sec-Fetch-Site) |
| SEC-104 | Key parser | Vanilla `extractAction` escape-aware via `splitPermissionKey` |

`SEC-002 / 004 / 005 / 006 / 008 / 009 / 011..018 / 023 / 033 / 042 (covered above)` —
P0/P1 work from 2.0.0; see CHANGELOG.md 2.0.0 section + the `audit/`
directory in the repo (gitignored; per-commit detail in git log).
