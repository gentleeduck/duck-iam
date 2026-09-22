# Security Policy

## Supported Versions

We provide security updates for the latest major release of `@gentleduck/iam`.
Older versions may not receive patches.

| Version | Supported |
| ------- | --------- |
| 5.x     | Yes       |
| < 5.0   | No        |

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

`iamAccessMiddleware` / `iamGuard` / `iamNestAccessGuard` / `withIamAccess`
derive a `subjectId` from a `getUserId(req)` callback. Always derive identity from a server-verified
source: a cookie session, a JWT verified by upstream middleware, an mTLS
client certificate, or a session token your auth layer already validated.

```ts
// Cookie session verified by app middleware
app.use(sessionMiddleware)
const guard = iamAccessMiddleware(engine, {
  getUserId: (req) => req.session?.userId ?? null,
})

// JWT verified by app middleware
app.use(jwtMiddleware)
const guard = iamAccessMiddleware(engine, {
  getUserId: (req) => req.user?.sub ?? null,
})
```

Do not derive identity from a client-supplied header or request body.

The Express default reads `req.user?.id`; the Nest default falls back to
`req.user?.sub` when `id` is absent. The Hono default
reads `c.get('userId')` only. The Next `withIamAccess` requires `getUserId`
to be supplied explicitly.

### Admin router CSRF

`iamAdminRouter` / `iamBindAdminRouter` / `createIamAdminHandlers` /
`createIamAdminOperations` accept `csrfCheck`. The built-in default rejects
browser requests whose `Sec-Fetch-Site` header is `cross-site` or
`cross-origin`.

```ts
// Default
iamAdminRouter(engine, { authorize: (req) => req.user?.role === 'admin' })

// Bearer-token or mTLS API (no browser)
iamAdminRouter(engine, { authorize, csrfCheck: false })

// Origin allowlist
const ADMIN_ORIGINS = new Set(['https://admin.example.com'])
iamAdminRouter(engine, {
  authorize,
  csrfCheck: (req) => ADMIN_ORIGINS.has(req.headers.origin),
})
```

### Redis invalidator

`createIamRedisInvalidator` defaults to an unsigned envelope on the
default channel `'duck-iam:invalidate'`. Production deployments must set
`secret`, and multi-tenant deployments should pass `tenantId` so
tenant A's revoke cannot wipe tenant B's cache.

```ts
const invalidator = createIamRedisInvalidator({
  client: redisPubSub,
  secret: process.env.IAM_INVALIDATE_SECRET,
  tenantId: tenant.slug,
  onPublishError: (err, channel) => log.warn({ err, channel }, 'publish failed'),
  onMessageDropped: (reason, channel) => log.warn({ reason, channel }, 'invalidation dropped'),
})
```

Rotating `IAM_INVALIDATE_SECRET` is HMAC-key rotation: a half-rolled-out
secret makes both halves of the fleet drop each other's messages, and every
node then serves up to one `cacheTTL` of stale allow. The drops are not
silent if you wire `onMessageDropped` - watch it for
`v:2 envelope received without secret configured` and
`unsigned message with secret configured`, which are the two halves of an
unfinished rotation. Coordinate the rotation window.

### Multi-tenant cache scoping

The `matches`-operator regex cache and the dot-path segment cache are held
**per `IamEngine` instance**, and every `can()` / `permissions()` path passes the
instance's own pair. One tenant flooding cold patterns therefore cannot evict
another tenant's entries, and one engine per tenant is enough to isolate them.
`FAQ.md` §6 describes the same behaviour.

Process-global fallbacks of both caches do still exist, for callers that use
`evaluate()` / the condition operators directly, and for `explain()`, which does
not pass the instance caches. `iamFlushSharedCaches()` clears *those*:

```ts
import { iamFlushSharedCaches } from '@gentleduck/iam/core'
iamFlushSharedCaches()
```

It is not a multi-tenancy mitigation - the per-instance caches it does not touch
are the ones that serve production traffic - so there is no reason to schedule
it on a timer.

### `defaultEffect: 'allow'`

Almost always wrong. A request that matches no policy is allowed, which
becomes a silent fail-open on adapter outages, mass policy deletion, or
any other source of "no applicable rule". The engine constructor throws
unless you also pass `allowFailOpen: true`, and warns at construction even
when you do, so an operator grepping logs for fail-open configurations
always finds one. The gate applies in both modes, and the exported
`iamEvaluate*` wrappers carry it too. Chart the `failOpen` field on
`IMetricsEvent` to alert on silent failures.

### `explain()` output

`engine.explain()` returns full rule contents, condition operands,
and `subject.attributes` for development debugging. `mode` defaults to
`'production'`, and `explain()` throws in that mode - it is available only
under `mode: 'development'`. The `summary` string, and the `actual` /
`expected` strings on every rule trace leaf, interpolate operator- and
attacker-influenced IDs verbatim. The explain pipeline never escapes for
any rendering target; run every value-derived string through
`iamEscapeHtml` (`@gentleduck/iam/core/explain`) before it reaches
`innerHTML` or a non-escaping template.

### Client-side checks are not authorization

`@gentleduck/iam/client/{react,vue,vanilla}` read a permission map that a
server serialised and a browser now holds. Every value in it can be edited
from a devtools console. `can()`, `<Can>` and `allowedActions()` decide what
to render; they decide nothing else. Nothing validates the map on arrival -
it is `JSON.parse` output typed as `IamClient.PartialPermissionMap`, and the
readers test `=== true` precisely because a stringified `"false"` is truthy.
Every request the UI fires must be authorized again on the server, by the
engine, against the live policy set. A report that a client hook returned
the wrong answer for a tampered map is not a vulnerability in this package;
a server middleware honouring a client-supplied verdict is.

### Adapter trust

The library never validates what the adapter stores or returns
beyond shape checks. Policies and roles in the store are trusted
inputs. Restrict write access to the store at the storage layer (DB
grants, file permissions, Redis ACLs).

### File adapter `rootDir`

Always pass `rootDir` when the file path can be derived from
request data. The adapter enforces containment only when `rootDir` is
set: a textual check at construction, plus a `realpath` re-check on the
first read (cache miss) and before every write. The `realpath` half is
skipped when the filesystem driver does not expose one. A cache hit does
not re-check, so a file swapped for an escaping symlink after the first
read is caught by the next write, not by the reads in between. Omitting
`rootDir` warns once per process and accepts any absolute path.

### HTTP adapter `allowedHosts`

Set `allowedHosts` to your IAM API hostname allowlist. Omitting it warns
once per process and accepts any host. The private/loopback refusal and
`redirect: 'error'` are on by default, but the private-range check reads
the literal `baseUrl` hostname - DNS is never resolved, so a public name
pointing at a private address is constrained only by `allowedHosts`.

### Observability

Wire `onPolicyError`, `onError`, and `onMetrics` on the engine.
Silent failures in an authorization path either deny everything or
allow everything. Use `iamCreateMetricsAggregator()`
(`@gentleduck/iam/observability/metrics`) to chart `failOpen` rate as a
silent-policy-breakage alarm.
