---
'@gentleduck/auth': major
---

The Redis session store: a parser that threw instead of failing closed, a create that could leave a session no revocation could reach, and a `gc` that never took the lease its contract promised.

**`parseStoredSession` never throws now — and stops losing factors quietly.**

Its whole contract is that a corrupt or tampered row reads as "no session" rather than taking a request down. It did not hold. `Array.isArray` narrowed `factors` to `any[]`, so the filter read `.method` off whatever was in the array; a single `null` element threw, outside the `try/catch` that guards only `JSON.parse`. `getByHash` is on the path of every authed request for that session, so one bad blob was a permanent 500 — and `listByIdentity`, which parses in a loop, went down with it.

Every *other* malformed shape was the quieter half and the more dangerous one: it was dropped. A row claiming `aal: 2` came back carrying no factors at all, and step-up logic reads that list as authoritative.

- A structurally broken entry — `null`, a primitive, no `method` — now rejects the whole row. That is corruption, and a session we cannot read is not a session we should serve.
- An unknown but well-formed method is still skipped, not rejected: that is what a newer writer adding a factor method produces, and an older reader must not choke on it.
- The 16-element `factors` cap that `sessions.create` and `parseJwtPayload` both apply is now enforced here too. This reader was the one door in that had no cap.
- A malformed `actingAs` envelope is refused rather than degraded to `null`. Degrading it lost both halves of what the envelope is for — the audit trail naming the real actor, and the expiry bounding the impersonation window — and left the row reading as an ordinary session belonging to the person being impersonated.

**`create` writes the index before the record.** The two writes are separate round-trips. A failure between them used to leave a session that authenticates fine but sits in no identity index: `listByIdentity` cannot see it and `deleteAllForIdentity` cannot delete it, so it survives the password change or ban that was supposed to end it. Reversing the order alone is not enough and would have made things worse — a concurrent `listByIdentity` pruned the entry inside the gap, and a record no index names is unreachable forever. So `listByIdentity` no longer prunes: a missing record may be a create still in flight, and only that create knows. A failed record write compensates its index entry, but only when `sadd` reports it actually added one — otherwise a duplicate `create` would unindex whichever session won the race.

**`gc` is driven by an expiry index instead of walking every session.** The sweep used to `SCAN` every `{prefix}:idx:identity:*` key, read every member's record, parse it, and compare two dates — O(every session that exists) per cycle, on a schedule, with a `get` and a `JSON.parse` for each one. It also could not sweep guest sessions at all: they carry no `identityId`, sit in no index, and so were reachable only by their key TTL, which tracks `absoluteExpiresAt` and therefore never enforced the sliding `expiresAt` on them.

There is now a single deployment-wide sorted set, `{prefix}:exp`, whose members are `sessionId:identityId` scored by whichever deadline comes first. `gc` pages it with `ZRANGEBYSCORE -inf <now> LIMIT`, so a cycle costs one range query plus the rows that are genuinely due — nothing proportional to the sessions that are still live. Because the member carries the owning identity, a row is deleted and dropped from its identity index **without its body ever being read**, and a guest session is swept like any other.

The write paths keep the index in step: `create` adds the member after the record lands (an `nx` collision must not re-score the live session already under that id, and a create that cannot be scheduled unwinds itself), `update` re-scores before writing so a renewal is never swept on its old deadline and moves the member when the session changes identity, and `delete` / `deleteAllForIdentity` retire members directly rather than leaving them to come due.

This also closes the race the index walk could only narrow. That sweep met index entries naming records that had not landed yet and had to re-read to guess whether they were orphans; a session earns an expiry member only once its record exists, so a create in flight is invisible to `gc` by construction. The confirming second read is gone with it. `create` now refuses a session id containing `:`, since that is where the member splits.

**`gc` takes a distributed lease.** `Sessions.Store.gc` has been documented as "acquires distributed lease before running" since 5.x, and no implementation acquired anything — every instance in a fleet swept concurrently. Worse than the waste, an operator reading that line would reasonably conclude they did not need their own locking. `RedisSessionImpl` now takes `{prefix}:gc:lease` with SET NX and returns `{ deleted: 0 }` when it loses. The lease is left to expire rather than released in a `finally`: a sweep that outruns the window has already lost it, and deleting it then frees a lease the run no longer holds. New `gcLeaseSec` config, default 300s. The SQL store's `gc` is unaudited and was left alone; the contract's docstring now says what it actually guarantees instead of over-promising.

**`_ttlFor` fails closed.** It assumed anything that was not a `Date` was a number, so an `absoluteExpiresAt` that arrived as an ISO string — what a JSON round-trip produces — made every step downstream `NaN`, and `{ ex: NaN }` reached the client. Some clients write that as a key with no expiry at all: an immortal session. It now parses through the same `parseStoredDate` the read path uses, so a serialised date yields the session's real TTL rather than the 30-day ceiling, and only a genuinely unparseable value falls back to the cap.

**`listByIdentity` reads concurrently.** It awaited one `get` per session id in a loop. It backs the active-devices view and runs inside `revokeAllForIdentity`, so those were N sequential round-trips on a request path. Now `Promise.all` over the same `get` — no new client methods, since widening `RedisLike.Client` would force every adapter to implement more.

**Also fixed here:**

- The parser's `kind` and `aal` gates were written with `as` casts; they are `isSessionKind` / `isAal` predicates now, along with `isRecord` and `isFactorMethod` for the new checks.
- A session-security e2e case read the clock four separate times to build one row, so `absoluteExpiresAt` and `expiresAt` could straddle a millisecond tick and invert — tripping `chk_auth_sessions_absolute_expires_after_expires` and reporting a working constraint as a broken write. Both such cases now take a single reading.
- The identity compliance suite gave `restoreMany` a one-second grace window and then spent it on a create-and-erase round-trip against the real database. On a loaded MySQL container the window closed first, and correct behaviour was reported as a failure. The round-trip now happens before the clock starts, on the minute-long window the rest of the suite uses.

**Breaking:**

- Stored session rows that are structurally malformed — a broken `factors` entry, more than 16 factors, a partial `actingAs` — now resolve as `null` instead of resolving with the bad part silently removed. Sessions affected by this were already carrying data the library could not vouch for; they will need to sign in again.
- `Sessions.Store.gc` implementations that can run on more than one instance are now required to serialise themselves. Nothing enforced this before because nothing did it.
- **`RedisLike.Client` gains `zadd`, `zrem` and `zrangebyscore`.** A custom client implementing this interface by hand will not compile until it has them; `FakeRedis` and the bundled valkey/ioredis adapter already do. `@upstash/redis` and node-redis expose all three under those names.
- **`RedisSessionImpl` claims a new key, `{prefix}:exp`.** A deployment that namespaces by prefix is unaffected; one sharing a database with other data should confirm that key is free.
- **Sessions created before this release have no expiry member**, so `gc` will not sweep them — they fall back to their key TTL, which is what bounded them before this index existed, and their identity-index entries are cleared when that index key's own TTL lapses. They are otherwise fully usable, and any `update` schedules them. To sweep them promptly instead, backfill from the existing records once after deploying, or accept that they age out.
- `RedisSessionImpl.create` now rejects a `session.id` containing `:` with `AUTH_MISCONFIGURED`. The sha-256 hashes the library generates never contain one; a deployment substituting its own id scheme must not use that character.
