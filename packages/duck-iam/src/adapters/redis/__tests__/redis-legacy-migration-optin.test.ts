import { describe, expect, it } from 'vitest'
import type { IamRedis } from '../index'
import { IamRedisAdapter } from '../index'

/** Only the set operations are real; every other command returns an empty default. */
class SetOnlyRedis implements IamRedis.ILike {
  readonly sets = new Map<string, Set<string>>()

  async get(): Promise<string | null> {
    return null
  }
  async set(): Promise<unknown> {
    return 'OK'
  }
  async del(): Promise<number> {
    return 0
  }
  async hset(): Promise<number> {
    return 0
  }
  async hget(): Promise<string | null> {
    return null
  }
  async hdel(): Promise<number> {
    return 0
  }
  async hkeys(): Promise<string[]> {
    return []
  }
  async hvals(): Promise<string[]> {
    return []
  }
  async hgetall(): Promise<Record<string, string>> {
    return {}
  }
  async sadd(key: string, ...members: string[]): Promise<number> {
    const set = this.sets.get(key) ?? new Set<string>()
    this.sets.set(key, set)
    let added = 0
    for (const m of members) if (!set.has(m)) set.add(m), added++
    return added
  }
  async srem(key: string, ...members: string[]): Promise<number> {
    const set = this.sets.get(key)
    if (!set) return 0
    let removed = 0
    for (const m of members) if (set.delete(m)) removed++
    return removed
  }
  async smembers(key: string): Promise<string[]> {
    return Array.from(this.sets.get(key) ?? [])
  }
}

// "Exactly one space, no NUL" is a guess: a global grant of role `admin org1` reads as `admin` in `org1`, and the
// migration would rewrite it that way.
describe('redis legacy assignment migration is opt-in', () => {
  async function seeded(migrateLegacyAssignments: boolean, member = 'admin org1') {
    const client = new SetOnlyRedis()
    await client.sadd('assignments:u1', member)
    const adapter = new IamRedisAdapter<string, string, string, string>({ client, migrateLegacyAssignments })
    return { adapter, client }
  }

  it('does not reinterpret a spaced role id as a scoped grant by default', async () => {
    const { adapter } = await seeded(false)
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('does not grant the prefix role by default', async () => {
    const { adapter } = await seeded(false)
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin org1'])
    expect(await adapter.getSubjectRoles('u1')).not.toContain('admin')
  })

  it('does not rewrite the set as a side effect of a read', async () => {
    const { adapter, client } = await seeded(false)
    await adapter.getSubjectScopedRoles('u1')
    expect(Array.from(client.sets.get('assignments:u1') ?? [])).toEqual(['admin org1'])
  })

  it('still reinterprets and rewrites when the operator opts in', async () => {
    const { adapter, client } = await seeded(true)
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org1' }])
    expect(Array.from(client.sets.get('assignments:u1') ?? [])).toEqual([`admin${String.fromCharCode(0)}org1`])
  })

  // Control: the flag must not change how a NUL-encoded member decodes.
  it.each([false, true])('decodes a NUL-separated member the same with migrate=%s', async (flag) => {
    const { adapter } = await seeded(flag, `editor${String.fromCharCode(0)}org-1`)
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'editor', scope: 'org-1' }])
  })

  // Control: a member with no separator at all is a global grant either way.
  it.each([false, true])('decodes a bare role id as global with migrate=%s', async (flag) => {
    const { adapter } = await seeded(flag, 'viewer')
    expect(await adapter.getSubjectRoles('u1')).toEqual(['viewer'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })
})
