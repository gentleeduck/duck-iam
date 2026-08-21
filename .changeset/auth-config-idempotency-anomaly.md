---
'@gentleduck/auth': minor
---

Configure idempotency and anomaly the way the limiter is configured.

`idempotency` accepted only the facet, so the config line read
`idempotency: idempotency(memoryIdempotency())` right next to
`limiter: redisLimiter({ redis, max, windowMs })`. Two spellings for the same idea, and
the wrapping was easy to forget.

The key now takes a bare store as well and the engine normalises it, and
`memoryIdempotency()` / `redisIdempotency()` return a ready facet whose one config
object carries both store knobs and facet knobs. The whole line is
`idempotency: redisIdempotency({ prefix: 'auth:idem', redis })`. `new MemoryIdempotency()`
and `new RedisIdempotency()` still give the bare store, and wrapping an already-wrapped
facet is a no-op rather than an error.

`MemoryIdempotency` refused to construct unless `development: true` was passed, in every
environment rather than only production, which made the no-arg constructor unusable
including in the engine's own dev fallback. Only `NODE_ENV=production` is refused now,
and `development: true` is the escape hatch for it.

`anomaly` had no config key at all: the engine hardcoded `DEFAULT_ANOMALY_CONFIG`, so the
detectors could be registered but their thresholds and per-signal reactions could never
be tuned. `anomaly` is merged over the defaults the same way `hijack` is.

`createAuth` silently dropped two keys its type accepted. `plugins` cannot work because
installation is async and `createAuth` is not; `oauth.stateSigningSecret` cannot work
because the secret has to reach each provider at construction. Both now throw
`AUTH_MISCONFIGURED` naming the call that does work (`await auth.use(plugin)`, and
`github({ stateSigningSecret })`), rather than booting an engine that quietly lacks what
was asked for.
