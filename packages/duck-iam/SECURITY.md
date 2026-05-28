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
or bypassed access controls in any application using it.

> [!WARNING]
> Do not disclose security issues publicly.
> Do not open a GitHub issue, PR, or discussion describing a vulnerability.

If you discover a vulnerability in `@gentleduck/iam`:

1. Report it privately by emailing security@gentleduck.org.
2. Include:
   - A description of the vulnerability.
   - Steps to reproduce, ideally with a minimal repro.
   - The affected version(s).
   - Any known impact.
   - Suggested fix, if you have one.
3. We will confirm receipt within 48 hours.

## Responsible Disclosure

We ask security researchers to give us 90 days to address issues before
public disclosure. We will credit you in the release notes unless you prefer
to remain anonymous.

## Scope

In scope:

- The core evaluation engine.
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

- Authorization bypasses: a request that should be denied returning allow.
- Privilege escalation: a user gaining permissions they were not granted.
- Dollar-path injection: malformed `$path` references leaking data across
  the request boundary.
- Prototype pollution: condition field paths reaching `__proto__`,
  `constructor`, or `prototype`.
- ReDoS: regex patterns in the `matches` operator causing pathological
  backtracking.
- Cache poisoning: a stale or attacker-controlled value persisting in the
  LRU cache after invalidation should have run.
- Multi-tenant scope leaks: a permission granted in one scope leaking into
  another scope.

## Deployment Hardening Guide

`@gentleduck/iam` is the authorization engine. Authentication, identity
sourcing, CSRF protection, and multi-tenant isolation are the operator's
responsibility.

### Identity sourcing

`accessMiddleware` / `withAccess` / `guard` derive a `subjectId` from a
`getUserId(req)` callback. Always derive identity from a server-verified
source: a cookie session, a JWT verified by upstream middleware, an mTLS
client certificate, or a session token your auth layer already validated.

```ts
// Cookie session verified by app middleware
app.use(sessionMiddleware)
const guard = accessMiddleware(engine, {
  getUserId: (req) => req.session?.userId ?? null,
})

// JWT verified by app middleware
app.use(jwtMiddleware)
const guard = accessMiddleware(engine, {
  getUserId: (req) => req.user?.sub ?? null,
})
```

Do not derive identity from a client-supplied header or request body.

The Express and Nest defaults read from `req.user?.id`. The Hono default
reads `c.get('userId')` only. The Next `withAccess` requires `getUserId`
to be supplied explicitly.

### Admin router CSRF

`adminRouter` / `bindAdminRouter` / `createAdminHandlers` /
`createAdminOperations` accept `csrfCheck`. The built-in default rejects
browser requests whose `Sec-Fetch-Site` header is `cross-site` or
`cross-origin`.

```ts
// Default
adminRouter(engine, { authorize: (req) => req.user?.role === 'admin' })

// Bearer-token or mTLS API (no browser)
adminRouter(engine, { authorize, csrfCheck: false })

// Origin allowlist
const ADMIN_ORIGINS = new Set(['https://admin.example.com'])
adminRouter(engine, {
  authorize,
  csrfCheck: (req) => ADMIN_ORIGINS.has(req.headers.origin),
})
```

### Redis invalidator

`createRedisInvalidator` defaults to an unsigned envelope on the
default channel `'duck-iam:invalidate'`. Production deployments must set
`secret`, and multi-tenant deployments should pass `tenantId` so
tenant A's revoke cannot wipe tenant B's cache.

```ts
const invalidator = createRedisInvalidator({
  client: redisPubSub,
  secret: process.env.IAM_INVALIDATE_SECRET,
  tenantId: tenant.slug,
  onPublishError: (err, channel) => log.warn({ err, channel }, 'publish failed'),
})
```

Rotating `IAM_INVALIDATE_SECRET` is HMAC-key rotation: engines with
mismatched secrets silently drop each other's messages, so coordinate
the rotation window.

### Multi-tenant cache scoping

The `matches`-operator regex cache and dot-path segment cache are
process-globals. A hostile tenant flooding distinct patterns can evict
another tenant's hot entries. Two mitigations:

- One Node process per tenant.
- Periodic flush via `engine.flushSharedCaches()`.

```ts
setInterval(() => engine.flushSharedCaches(), 5 * 60 * 1000)
```

### `defaultEffect: 'allow'`

Almost always wrong. A request that matches no policy is allowed, which
becomes a silent fail-open on adapter outages, mass policy deletion, or
any other source of "no applicable rule". The engine refuses this
configuration unless you pass `allowFailOpen: true` and emits a startup
warning. Chart the `failOpen` field on `IMetricsEvent` to alert on
silent failures.

### `explain()` output

`engine.explain()` returns full rule contents, condition operands,
and `subject.attributes` for development debugging. It throws in
production mode by default. The `summary` string interpolates
operator- and attacker-influenced IDs verbatim; downstream consumers
that render it as HTML must escape themselves.

### Adapter trust

The library never validates what the adapter stores or returns
beyond shape checks. Policies and roles in the store are trusted
inputs. Restrict write access to the store at the storage layer (DB
grants, file permissions, Redis ACLs).

### File adapter `rootDir`

Always pass `rootDir` when the file path can be derived from
request data. The adapter performs textual containment and symlink
realpath checks only when `rootDir` is set; an adapter without
`rootDir` warns once at construction but cannot enforce containment.

### HTTP adapter `allowedHosts`

Set `allowedHosts` to your IAM API hostname allowlist. The default
rejects private and loopback hosts and refuses redirects, but a
permissive `baseUrl` without `allowedHosts` warns once at construction.

### Observability

Wire `onPolicyError`, `onError`, and `onMetrics` on the engine.
Silent failures in an authorization path either deny everything or
allow everything. Use `createMetricsAggregator()` to chart `failOpen`
rate as a silent-policy-breakage alarm.
