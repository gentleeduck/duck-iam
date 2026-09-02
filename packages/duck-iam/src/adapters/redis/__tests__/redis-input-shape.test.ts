import { describe, expect, it } from 'vitest'
import type { IamPrimitives } from '../../../core/types'
import { type IamRedis, IamRedisAdapter } from '../index'

/** Minimal in-memory ILike: only the string commands setSubjectAttributes touches. */
function fakeRedis(): IamRedis.ILike {
  const strings = new Map<string, string>()
  const unused = async () => {
    throw new Error('not exercised')
  }
  return {
    get: async (k) => strings.get(k) ?? null,
    set: async (k, v) => {
      strings.set(k, v)
      return 'OK'
    },
    del: async (...ks) => ks.reduce((n, k) => n + (strings.delete(k) ? 1 : 0), 0),
    hset: unused,
    hget: unused,
    hdel: unused,
    hkeys: unused,
    hvals: unused,
    hgetall: unused,
    sadd: unused,
    srem: unused,
    smembers: unused,
  }
}

describe('IamRedisAdapter direct-call input shape', () => {
  it('rejects a string attrs value (the spread-to-chars class)', async () => {
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: fakeRedis() })
    await expect(
      adapter.setSubjectAttributes('user-1', 'admin=true' as unknown as IamPrimitives.Attributes),
    ).rejects.toThrow(/attributes for "user-1" must be a plain object \(got string\)/)
  })

  it('does not corrupt existing attributes on a rejected call', async () => {
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: fakeRedis() })
    await adapter.setSubjectAttributes('user-1', { tier: 'gold' })
    await expect(adapter.setSubjectAttributes('user-1', [1] as unknown as IamPrimitives.Attributes)).rejects.toThrow()
    expect(await adapter.getSubjectAttributes('user-1')).toEqual({ tier: 'gold' })
  })
})

describe('an empty scope is refused rather than stored as a global assignment', () => {
  function setRedis(): IamRedis.ILike {
    const sets = new Map<string, Set<string>>()
    const unused = async () => {
      throw new Error('not exercised')
    }
    return {
      del: async () => 0,
      get: unused,
      hdel: unused,
      hget: unused,
      hgetall: unused,
      hkeys: unused,
      hset: unused,
      hvals: unused,
      sadd: async (k, ...members) => {
        const set = sets.get(k) ?? new Set<string>()
        sets.set(k, set)
        let added = 0
        for (const m of members) if (!set.has(m)) set.add(m), added++
        return added
      },
      set: unused,
      smembers: async (k) => [...(sets.get(k) ?? [])],
      srem: async () => 0,
    }
  }

  it('assignRole with scope "" throws instead of granting globally', async () => {
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: setRedis() })
    await expect(adapter.assignRole('user-1', 'editor', '')).rejects.toThrow(/must not be an empty string/)
  })

  it('an omitted scope is still a global assignment', async () => {
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: setRedis() })
    await adapter.assignRole('user-1', 'editor')
    expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
  })

  it('a real scope stays scoped', async () => {
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: setRedis() })
    await adapter.assignRole('user-1', 'editor', 'org-1')
    expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    expect(await adapter.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
  })
})
