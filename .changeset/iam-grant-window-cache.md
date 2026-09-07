---
'@gentleduck/iam': patch
---

Time-boxed grants stop granting when they expire, not up to a `cacheTTL` later.

**The subject cache now respects the grant's own window.** `IamLRUCache` gave every entry the engine's full `cacheTTL` (60s by default) with nothing tying it to the bounds the drizzle adapter filters on, so a grant with `expiresAt` kept answering *allow* for up to a minute after it ended, and a grant with a future `startsAt` kept answering *deny* for up to a minute after it opened. A 30-second break-glass grant was live for sixty. `IamLRUCache.set` takes an optional `notAfter`, caps the entry at the earlier of the two, stores nothing when the bound has already passed, and expires on `>=` so it agrees with the adapter's exclusive upper bound.

**New optional adapter method: `getSubjectGrantBoundary(subjectId, opts?)`.** Returns the earliest *future* `startsAt` or `expiresAt` among the subject's grants, or `null` when none has a bound. The engine asks for it alongside the reads it describes — no extra round trip — and caps the cache entry there. It is implemented by the drizzle adapter, the only one that stores the bounds; the other five omit it and continue to refuse the options outright. Custom adapters need no change, and gain the shortened cache by implementing it. A failure in the method costs caching only: the subject is not cached, the answer still comes from the store, and a warning names the method and subject.

**`assignRole` refuses a window that can never be active.** `startsAt >= expiresAt` is an empty interval — the grant is stored and never live, while the call resolves and `engine.admin.assignRoles` reports `ok: true, applied: 1`. An `Invalid Date` in either field was passed to the driver rather than refused. Both are now rejected at the adapter boundary, on `assignRole` and on every row of `assignRoleMany`; the error names the fields and never the instants. The shipped pg/mysql/sqlite schemas already carried `ch_iam_assignments_starts_before_expires`, but the adapter can be pointed at a caller's own table, where the code is the only guard.
