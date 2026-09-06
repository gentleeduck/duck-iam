---
'@gentleduck/auth': major
---

The public surface now names what it returns, and a post-commit drain no longer reports a committed write as a failure.

**`pending.flush()` never rejects.** It resolves with `{ published, failed: Error[] }`.

`flush` runs after the caller's transaction has committed and empties the buffer whether or not a listener threw, so a rejection asked the caller to handle a failure with nothing left to retry — and the natural handling, letting it propagate, answered a committed write with a 500 whose one promise, that the write did not happen, was false. The write happened; some announcement of it did not. Those are different facts and callers need to tell them apart, log the second, and still answer 200. A thrown non-`Error` arrives as an `Error` with the original on `cause`, so `failed` is always loggable.

Callers who want the old behaviour can write `if (failed.length) throw new AggregateError(failed)`. The reverse was not available, which is why this changed.

**`identities.restore()` returns `Me | null`.** One rule now covers all three lifecycle writes: `null` means the id matched nothing — the same outcome `softDelete` and `erase` already reported that way — and a throw means a row *was* matched and a named rule refused it (`AUTH_GRACE_EXPIRED`, `AUTH_EMAIL_TAKEN`). `restore` was typed as though it could not miss, which told you which outcome the author remembered rather than which outcomes exist. It threw `AUTH_UNAUTHENTICATED` for an absent id; that path is now `null`.

`flows.cancelAccountDeletion` is unchanged and still throws `AUTH_UNAUTHENTICATED`: at a flow boundary there is no account whose deletion could be cancelled, which is an error rather than data.

**The root barrel re-exports the domain types.** `@gentleduck/auth` exported the engine and none of the types the engine returns, so naming the type of any return value meant a second import from `@gentleduck/auth/core`. `Identities`, `Sessions`, `Credential`, `Org`, `Events`, `Batch`, `Pending`, `Flows`, `Engine`, `Bound`, `Provider`, `Transport`, `TenantContext`, `Envelope`, `Anomaly`, `Compliance`, `Hijack`, `M2m`, `Operations`, `Kms` and `DataAtRest` are now reachable from the root. These are types only — the runtime surface is unchanged and still deliberately narrow.

**`Identities` is exported under its own name, and `Identity` is gone.** `@gentleduck/auth/core` exported the namespace as `Identity`, so it read as `Identities` in every declaration, doc comment, internal signature and error message, and as `Identity` at the import site. There is now one name. Replace `import type { Identity } from '@gentleduck/auth/core'` with `Identities`; the members are unchanged, so the rest of each reference stays as it is.

**`CHANGELOG.md` ships in the package.** The README links it and `files` did not include it, so on npm the link 404'd and the only way to see what a release contained was to diff two tarballs. `@gentleduck/iam` had the same gap and is fixed too.
