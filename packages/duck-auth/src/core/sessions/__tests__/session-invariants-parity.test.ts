/**
 * `assertSessionAllowed` is documented as "the session rules every dialect carries as table constraints,
 * applied by the stores that have no schema to carry them". It carried three of the seven: kind, aal and
 * the blank tenant. A session id that was not a hash, a deadline before the row's own creation, a rotation
 * before it, an absolute cap below the sliding one — pg, mysql and sqlite each refuse all four, and memory,
 * redis and valkey took every one of them.
 *
 * The case list is keyed by the dialect's own constraint names and checked against the schema, so a CHECK
 * added to SQL with no in-process counterpart fails here rather than going unnoticed.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { sha256 } from '~/core/crypto'
import { FakeRedis } from '~/core/drivers/redis-like'
import { RedisSessionImpl } from '~/core/sessions/sessions.redis'
import type { Sessions } from '~/core/sessions/sessions.types'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

const BORN = new Date(Date.now() - 86_400_000)

function legal(overrides: Partial<Sessions.Me> = {}): Sessions.Me {
  const now = new Date()
  const exp = new Date(now.getTime() + 60_000)
  return {
    aal: 1,
    absoluteExpiresAt: exp,
    actingAs: null,
    createdAt: BORN,
    csrfHash: null,
    expiresAt: exp,
    factors: [],
    fingerprint: null,
    fresh: true,
    id: sha256('a-session'),
    identityId: 'ident-1',
    ip: null,
    kind: 'user',
    rotatedAt: now,
    tenantId: null,
    updatedAt: now,
    userAgent: null,
    ...overrides,
  }
}

/** One violation per dialect constraint, each the smallest departure from {@link legal} that trips it. */
const VIOLATIONS: Record<string, Partial<Sessions.Me>> = {
  chk_auth_sessions_aal: { aal: 4 as Sessions.Me['aal'] },
  chk_auth_sessions_absolute_expires_after_expires: {
    absoluteExpiresAt: new Date(Date.now() + 1000),
    expiresAt: new Date(Date.now() + 60_000),
  },
  chk_auth_sessions_expires_after_created: { expiresAt: new Date(BORN.getTime() - 1000) },
  chk_auth_sessions_id_length: { id: 'sid-1' },
  chk_auth_sessions_kind: { kind: 'robot' as Sessions.Me['kind'] },
  chk_auth_sessions_rotated_after_created: { rotatedAt: new Date(BORN.getTime() - 1000) },
  chk_auth_sessions_tenant_not_blank: { tenantId: '' },
}

describe('the in-process session stores enforce what every dialect CHECKs', () => {
  it('has a case for every session constraint the schema declares', () => {
    const declared = [
      ...new Set(readFileSync(join(SRC, 'adapters/drizzle/pg/pg.schema.ts'), 'utf8').match(/chk_auth_sessions_\w+/g)),
    ]
    expect(declared.sort()).toEqual(Object.keys(VIOLATIONS).sort())
  })

  for (const dialect of ['pg', 'mysql', 'sqlite'] as const) {
    it(`${dialect} declares exactly those, so the list describes all three`, () => {
      const schema = readFileSync(join(SRC, `adapters/drizzle/${dialect}/${dialect}.schema.ts`), 'utf8')
      expect([...new Set(schema.match(/chk_auth_sessions_\w+/g))].sort()).toEqual(Object.keys(VIOLATIONS).sort())
    })
  }

  describe.each([
    ['memory', () => new MemoryAdapter().sessions],
    ['redis', () => new RedisSessionImpl({ prefix: 'test', redis: new FakeRedis() })],
  ])('%s', (_name, build) => {
    let store: ReturnType<typeof build>

    beforeEach(() => {
      store = build()
    })

    it('accepts a row that breaks none of them', async () => {
      const row = legal()
      await store.create(row)
      await expect(store.getByHash(row.id)).resolves.toMatchObject({ id: row.id })
    })

    for (const [name, violation] of Object.entries(VIOLATIONS)) {
      it(`create refuses ${name}`, async () => {
        await expect(store.create(legal(violation))).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      })

      it(`update refuses ${name}`, async () => {
        const row = legal()
        await store.create(row)
        // `id` is pinned to the key, so the one constraint an update cannot reach is the id's own width.
        const patch = name === 'chk_auth_sessions_id_length' ? { aal: 4 as Sessions.Me['aal'] } : violation
        await expect(store.update(row.id, patch)).rejects.toMatchObject({ code: 'AUTH_INVALID_PARAMETERS' })
      })
    }
  })
})
