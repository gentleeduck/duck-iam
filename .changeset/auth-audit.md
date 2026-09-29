---
'@gentleduck/auth': minor
---

**Each event handler picks where it runs.** `on(event, handler, { delivery })` takes `'origin'` or
`'fleet'` (`Events.OnOptions`, `Events.Delivery`). An `origin` handler runs once, on the server that
emitted, inside its async context, and never from a Redis message. A `fleet` handler runs on every
server. The default stays `fleet`, so existing handlers behave as before.

- `RedisEvents` keeps the two kinds apart. `emit` always publishes, then runs this server's `origin`
  and `fleet` handlers; a message from another server runs only the `fleet` ones. A server subscribes
  to an event's channel only while it holds a `fleet` handler for it.
- `InMemoryEvents` runs both kinds and lists the events holding a `fleet` handler in `fleetEvents()`.
  `listenerCount` counts both kinds on either bus.
- `withAuditStamping` and the transaction's buffering bus pass the options through.

**`strict()` checks the handlers, not the bus.** In production it refuses the in-process bus, or no
`events` at all, only while it holds a `fleet` handler, and names those events. A bus holding only
`origin` handlers passes, so a single server no longer needs Redis to boot. It sees only the handlers
registered before it runs. A Redis bus passes as before. The `Event bus required` and
`AuthInMemoryEvents rejected in production` refusals are gone.

**Webhooks go out once per emit.** `WebhookDeliverer.attach` registers as `origin`, so on a Redis fleet
each server posts only what it emitted, where before every server posted every event. An
`authz.revoked` that another service publishes straight to Redis no longer reaches duck-auth's
webhooks; its publisher delivers that one.

A plugin's `events` still register as `fleet`; register from `install` with `{ delivery: 'origin' }` to
run once.
