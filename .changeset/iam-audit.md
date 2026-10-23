---
'@gentleduck/iam': minor
---

Security and correctness fixes from the ongoing audit, grouped by what goes wrong
if you do not take them.

**An async CSRF check could not refuse anything.** The admin router's CSRF
phase (`express`, `hono`, `nest` and `next` all share it) called `csrfCheck(req)`
and tested its return value directly. A synchronous predicate worked; an async
one did not — a `Promise` is always truthy, so a check that would have resolved
to `false` let the mutation through anyway, and one that rejected produced an
unhandled rejection on top of the same bypass. `csrfCheck` is now awaited, and
its type is `(req) => boolean | Promise<boolean>`, matching `authorize`'s
existing shape. If your `csrfCheck` is already synchronous, nothing changes.
