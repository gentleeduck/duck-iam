# What actually ran

Built 2026-10-21, duck-auth counts re-measured 2026-10-24 (port 11). macOS arm64,
Docker 29.6.2. Logs in `out/`. Regenerate with `bun run coverage-gap:run`.

These are the only counts worth quoting. The static per-cluster numbers in
`out/GAP-TABLE.md` undercount by ~25% (see `README.md`), so they show shape, not
size.

## duck-auth — 5453 executed, 5453 passed

| Tier | Command | Files | Tests | Result |
| --- | --- | --- | --- | --- |
| unit (hermetic) | `vitest run --project unit` | 252 | 4487 | all passed |
| sqlite store-compliance | `bun test …/compliance.bun.ts` | 1 | 111 | all passed, 0.8s |
| e2e (real pg, mysql, redis, valkey) | `DUCKAUTH_E2E_REQUIRE=1 vitest run --project e2e` | 40 | 855 | all passed |
| **total** | | **293** | **5453** | **0 failed, 0 skipped** |

Plus `bun run smoke`, which is a script rather than a vitest tier: 9 checks over
the built package — 188 `exports` targets present, every condition typed, and 47
entrypoints type-checked under 7 consumer tsconfigs.

The unit tier was 4308 when this folder was built. The +179 are the ported
scenarios in `PORT-LOG.md`: 43 from the security sweep (ports 5-10) and 17 more
from the advisory sweep (port 11), which read better-auth's 37 published
advisories rather than its tests. Port 10 also added 5 store-compliance cases,
which is why the e2e tier moved: each runs again on Postgres and MySQL.

## better-auth v1.7.2 — 6274 executed, 6 failed

`pnpm test` (turbo, per package). Full per-package breakdown in
`out/ba-summary.txt`.

| | Files | Tests | Failed | Skipped |
| --- | --- | --- | --- | --- |
| reported by 19 packages | 297 | 6274 | 6 | 12 |

Three packages did not contribute, none of it their fault as a library:

- **`@better-auth/api-key`** — `src/api-key.test.ts` (183 cases) failed to load:
  `password authentication failed for user "user"`. Their unit tier calls
  `getTestInstance` → `getPostgres`, which dials
  `postgres://user:password@localhost:5433/better_auth`.
- **`@better-auth/release-tooling`** (107 static) — hung at 0% CPU and was killed.
- **`@better-auth/telemetry`** (6 static) — never reported.

The 6 failures are the same cause: `db.test.ts` "preserve a forced UUID on
postgres", `oauth-proxy` "database mode + UUID", and four
`sso/providers.test.ts` cases about Postgres provider-deletion locking. All need
their docker-compose stack (postgres ×4, mysql ×3, mssql, mongo, redis on fixed
host ports), which was not started.

Their `e2e/adapter` (94 static), `e2e/integration` (Playwright, 16) and
`e2e/smoke` (26) tiers were not run at all for the same reason.

So better-auth's achievable total is roughly **6570 unit** plus ~136 e2e, against
duck-auth's 5453. We execute about 83% of their test count.

## The architectural difference this exposed

**duck-auth's unit tier is hermetic and better-auth's is not.** Ours runs 4308
tests in 12 seconds with no external service, and every test that needs real
infrastructure lives in a separate vitest project. Theirs mixes them: a plain
`pnpm test` on a machine without their Postgres loses 189 tests, one of them an
entire 183-case file, and reports failures that say nothing about the code.

That is worth keeping. It is also the thing that makes our e2e tier easy to skip
by accident, which is the trade — see the skips section in `FINDINGS.md`.
