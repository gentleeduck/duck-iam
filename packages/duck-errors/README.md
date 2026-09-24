# @gentleduck/errors

Typed, registry-driven error classes: branded codes, secret-safe `toJSON`, and a construct-or-throw
kit. Framework-agnostic, zero runtime dependencies, ESM + CJS, works anywhere plain `Error` does
(Node, Bun, Deno, browsers, edge runtimes).

## Install

```bash
npm install @gentleduck/errors
# or
bun add @gentleduck/errors
```

## Quick start

```typescript
import { createErrorKit, detail, fault } from '@gentleduck/errors'

// A registry: each code maps to a status. `detail<M>(status)` says the code also
// carries a `meta` of shape M; `fault(status)` marks a code a store/adapter can
// raise itself (vs. one only flow/validation logic raises). A plain `number` is
// a bare code with no required meta.
const USER_ERRORS = {
  USER_NOT_FOUND: detail<{ id: string }>(404),
  USER_EMAIL_TAKEN: detail<{ email: string }>(409),
  VALIDATION_FAILED: 400,
  STORE_UNAVAILABLE: fault(503),
}

const { fail, throwError, asError, hasErrorCode, metaOf } = createErrorKit('UserError', USER_ERRORS)

// Construct without throwing.
const err = fail('USER_NOT_FOUND', { id: 'u_123' })

// Throw directly. A code's declared shape is enforced at the call site: USER_NOT_FOUND's
// `id` can't be omitted, while a bare code like VALIDATION_FAILED takes no meta argument at all.
throwError('USER_EMAIL_TAKEN', { email: 'a@b.com' })

// Wrap an unknown catch value. Already-typed instances pass through unchanged;
// anything else is wrapped under the given code with the original on `.cause`.
try {
  await store.get(id)
} catch (e) {
  throw asError(e, 'STORE_UNAVAILABLE')
}

// Narrow by code rather than `instanceof` — this also matches an instance built
// by a duplicated copy of the package (hoisting, or a dependency installed
// separately from its consumer).
if (hasErrorCode(err, 'USER_NOT_FOUND')) {
  metaOf(err, 'USER_NOT_FOUND').id // typed as string
}
```

## What you get

- **`createErrorKit(name, registry)`** builds a fresh error class plus its helpers. Each call
  declares its own class, never a shared one, so two kits' instances never satisfy each other's
  `instanceof` — the same way two hand-written classes wouldn't.
- **`fail` / `throwError`** construct or throw a typed instance; **`asError` / `rethrowError`** wrap
  an `unknown` catch value, passing already-typed instances through unchanged.
- **`hasErrorCode`** narrows by a `code` property instead of `instanceof`, so it still recognizes an
  instance from a duplicated copy of the package.
- **`.toJSON()`** returns `{ ok: false, error: { code, status, ...meta } }` with every key matching
  `/secret|password|passphrase|plaintext|token|hash|salt|signature|credential|private|apikey|api_key/i`
  dropped at any depth — safe to send straight over the wire. `isSecretKey` and `scrubMeta` are
  exported standalone if you need the same redaction elsewhere.
- **`.status`** and **`.statusCode`** (an alias, under the name Nest's base exception filter reads)
  come straight from the registry.
- **A bare code takes no meta argument at all** — not `{}`, not `undefined`, nothing — so
  `fail('SOME_BARE_CODE', { anything })` is a compile error rather than a silently-accepted value
  that never reaches `.meta`.
- **A `detail(status)` that forgot its `<M>` fails the same way** — not `object`, nothing — so a
  registry entry declared without the type argument can't be given meta either, rather than
  silently accepting any shape at all.

## Design notes

- Zero runtime dependencies, `sideEffects: false`, built with `platform: 'neutral'` — nothing here
  assumes Node, a browser, or any other host.
- Ships both ESM and CommonJS (`exports` map with `import`/`require` conditions, each carrying its
  own `.d.ts`/`.d.cts`), verified against node10, node16, and bundler module resolution.
- Brand types (`Carries`, `Fault`) are plain, string-keyed property brands rather than
  `unique symbol` — safe to reference from a consuming package's own declaration output.

## License

[MIT](./LICENSE)
