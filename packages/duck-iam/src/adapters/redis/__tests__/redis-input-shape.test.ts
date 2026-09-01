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
