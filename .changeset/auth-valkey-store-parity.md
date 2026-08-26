---
'@gentleduck/auth': patch
---

Add a `valkeyXxx` wrapper next to every Redis-backed store, so switching between
`redis`/`valkey` clients is a one-line change instead of hand-wiring `valkeyAdapter`
into each store's config: `valkeySessionImpl`, `valkeyDPoPNonceStore`,
`valkeyEvents`, `valkeyIdempotency` (`@gentleduck/auth/core/idempotency`), and
`valkeyLimiter` (new `@gentleduck/auth/limiters/valkey` entry, mirroring
`limiters/redis`).

`valkeyEvents` takes a `{ cmd, sub }` connection pair rather than one client: once
an ioredis/iovalkey connection calls `.subscribe()`, it enters subscriber mode and
can no longer run ordinary commands (including `PUBLISH`), so the publish/command
side and the subscribe side need separate connections. `valkeyPubSubAdapter` is
exported standalone for callers who want to drive `RedisEvents` directly.

Each `valkeyXxx` factory lives in its own sibling file next to the matching
`RedisXxx` implementation, mirroring the `redis.ts`/`valkey.ts` split used
elsewhere: `sessions.redis.ts`/`sessions.valkey.ts`, `dpop-nonce.redis.ts`/
`dpop-nonce.valkey.ts`, `events.redis.ts`/`events.valkey.ts`,
`idempotency.redis.ts`/`idempotency.valkey.ts`, and `limiters/redis`/
`limiters/valkey`. `adapters/valkey` is a re-export barrel, mirroring
`adapters/redis`. Each also has its own real-server e2e suite colocated next to
the matching `redis*.e2e.test.ts` (`sessions.valkey.e2e`, `dpop-nonce.valkey.e2e`,
`events.valkey.e2e`, `idempotency.valkey.e2e`, `valkey-limiter.e2e`).

Also removes three independent hand-rolled copies of the ioredis-to-`RedisLike`
translation that predated `valkeyAdapter` (`test/e2e-redis.ts`'s `toRedisLike`, used
across eleven e2e suites; `events.redis.e2e.test.ts`'s `eventsClient`; and the
revocation worker's `toEventsClient`), replacing all of them with `valkeyAdapter`/
`valkeyPubSubAdapter` so there is exactly one implementation of that translation.
