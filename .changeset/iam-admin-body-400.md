---
'@gentleduck/iam': minor
---

A malformed admin request body now answers 400 instead of 500.

`engine.admin.savePolicy` and `saveRole` validate before they write, and signalled
a rejection with a bare `Error`. Every HTTP integration catches whatever a handler
throws and routes it to `onError`, which answers 500 — so a body the validator
refused, which is the client's mistake, was reported as the server's. The write
was correctly refused either way, so this was never a way past validation; but a
500 tells a caller to retry a request that can never succeed, and hides a client
bug behind an apparent outage.

Rejections are now `IamValidationError`, carrying `kind` (`'policy' | 'role'`),
the validator's `issues`, and `status: 400`. It extends `Error`, so existing
`instanceof Error` checks and the exact message text still hold.

- **express, hono and next** answer `400 { error: 'Invalid policy', issues: [...] }`
  and no longer route the failure through `onError`.
- **Nest** hands errors to its own exception filter, which only maps
  `HttpException`, and this package does not depend on `@nestjs/common`. Read
  `status` in a filter of your own:

```ts
if (iamIsValidationError(err)) throw new BadRequestException({ error: `Invalid ${err.kind}`, issues: err.issues })
```

A genuine server fault is still a 500, and the `onAdminMutation` audit event
still fires with `success: false` either way.
