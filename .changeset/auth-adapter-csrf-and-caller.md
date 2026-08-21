---
'@gentleduck/auth': major
---

Guard every server adapter's routes, and record the caller on the session.

Elysia, Fastify and Koa ran sign-in, sign-out and provider-begin with no CSRF check,
while Next, Hono, Express and Nest guarded theirs. Which adapter an application mounted
decided whether a cookie-authenticated POST could be driven from another origin, and
nothing in the API hinted at the difference. All seven guard now.

Every adapter also gets a guard for the application's own routes. `csrfGuard` was
exported the whole time but no adapter exposed it in its own middleware shape, so
protecting a route outside the mounted set meant hand-rolling the framework glue:

- `app.use(expressCsrf(auth))`
- `app.use(koaCsrf(auth))`
- `app.use('*', honoCsrf(auth))`
- `fastify.addHook('preHandler', fastifyCsrf(auth))`
- `app.onBeforeHandle(elysiaCsrf(auth))`
- `export const POST = withNextCsrf(auth, handler)`, a wrapper because the App Router
  gives the adapter no chain to hook

They share `Csrf.GuardOptions`, and each writes its own 403 rather than delegating to an
error handler the application may not have.

Sign-in dropped the caller's ip and user-agent in every adapter, so every session row
recorded a device it could not name and the anomaly detectors had nothing to compare
against. `callerContext` forwards only what the framework itself resolved: reading a
forwarded header in the library would take the value the caller wrote, and the host is
the only layer that knows how many proxies it trusts. Elysia and Hono resolve no address
themselves, so their context types take an optional `ip` the application sets.

BREAKING: a cookie-authenticated POST to the elysia, fastify or koa sign-in, sign-out or
provider-begin route now requires a CSRF token and gets a 403 without one. Bearer and JWT
transports keep the existing bypass, since they carry auth in the Authorization header
and are not sent ambiently by a browser.
