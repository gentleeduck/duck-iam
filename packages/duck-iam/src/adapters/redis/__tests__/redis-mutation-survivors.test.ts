import { describe, expect, it, vi } from 'vitest'
import type { IamRedis } from '../index'
import { IamRedisAdapter } from '../index'

// Pins checks in `redis/index.ts` that mutation testing could delete or invert with the suite still green.
// Each block names the mutant it kills.

/** The adapter's member separator, spelled as an escape so it stays visible. */
const NUL = '\u0000'

class FakeRedis implements IamRedis.ILike {
  readonly sets = new Map<string, Set<string>>()
  readonly strings = new Map<string, string>()
  readonly calls: Array<{ op: string; args: string[] }> = []

  async get(key: string): Promise<string | null> {
    return this.strings.get(key) ?? null
  }
  async set(key: string, value: string): Promise<unknown> {
    this.strings.set(key, value)
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
    this.calls.push({ args: members, op: 'sadd' })
    const set = this.sets.get(key) ?? new Set<string>()
    this.sets.set(key, set)
    let added = 0
    for (const m of members) {
      if (!set.has(m)) {
        set.add(m)
        added++
      }
    }
    return added
  }
  async srem(key: string, ...members: string[]): Promise<number> {
    this.calls.push({ args: members, op: 'srem' })
    // INFO: real Redis rejects a zero-member `SREM` ("wrong number of arguments"); modelled so `revokeRole`'s
    // guard is tested.
    if (members.length === 0) throw new Error("ERR wrong number of arguments for 'srem' command")
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

function make(members: string[], migrateLegacyAssignments = true) {
  const client = new FakeRedis()
  client.sets.set('assignments:u1', new Set(members))
  const adapter = new IamRedisAdapter<string, string, string, string>({ client, migrateLegacyAssignments })
  return { adapter, client }
}

// `_isLegacyEncoded` decides whether a member is a role or a role plus scope; each of its conditions is pinned.
describe('M-1: the legacy-encoding heuristic', () => {
  it('does not treat a NUL-encoded member as legacy, even when its scope contains a space', async () => {
    // Decode finds the NUL either way. The guard keeps this member out of migration, whose SADD-then-SREM of the
    // identical member would delete the grant.
    const { adapter, client } = make([`admin${NUL}my org`])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'my org' }])
    expect(await adapter.getSubjectRoles('u1')).toEqual([])
    expect(client.calls).toEqual([])
    expect(Array.from(client.sets.get('assignments:u1') ?? [])).toEqual([`admin${NUL}my org`])
  })

  it('does not treat a member with no space as legacy', async () => {
    // Kills the `first === -1` mutants (deletion, and `=== +1`).
    const { adapter, client } = make(['admin'])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
    expect(client.calls).toEqual([])
  })

  it('does not treat a member with two spaces as legacy', async () => {
    // Kills `indexOf(' ', first + 1) === -1` -> `true`, which splits `admin org 1` into scope `org 1`.
    const { adapter } = make(['admin org 1'])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin org 1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('control: exactly one space and no NUL is legacy', async () => {
    const { adapter } = make(['admin org-1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org-1' }])
  })
})

describe('M-2: the decode gate and its empty-tail arm', () => {
  it('does not decode a spaced member as role+scope when migration is off', async () => {
    // Kills the `if (this._isLegacyEncoded(member))` -> `if (true)` mutant.
    const { adapter } = make(['admin org-1'], false)
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin org-1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('decodes an empty legacy tail as a GLOBAL grant, not one scoped to the empty string', async () => {
    // Kills `scope === '' ? { role } : ...` -> `false ? ...`, which yields a grant scoped to `''`.
    const { adapter } = make(['admin '])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('decodes an empty NUL tail as a global grant too', async () => {
    const { adapter } = make([`admin${NUL}`])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })
})

// Without the migration's `filter` calls it would rewrite every member of the set, not only legacy ones.
describe('M-3: the migration touches only legacy members', () => {
  it('rewrites the legacy member and leaves an already-migrated one alone', async () => {
    const { adapter, client } = make(['admin org-1', `viewer${NUL}org-2`])
    await adapter.getSubjectRoles('u1')
    // Kills both `.filter(...)` deletions, which would re-encode and re-add the migrated member too.
    const srem = client.calls.filter((c) => c.op === 'srem').flatMap((c) => c.args)
    const sadd = client.calls.filter((c) => c.op === 'sadd').flatMap((c) => c.args)
    expect(srem).toEqual(['admin org-1'])
    expect(sadd).toEqual([`admin${NUL}org-1`])
    expect(Array.from(client.sets.get('assignments:u1') ?? [])).toEqual([`viewer${NUL}org-2`, `admin${NUL}org-1`])
  })

  it('does not reach EVAL at all when nothing is legacy', async () => {
    // Kills `const legacy = members`: the Lua path has no second filter, so it would rewrite a migrated set.
    const client = new FakeRedis()
    client.sets.set('assignments:u1', new Set([`viewer${NUL}org-2`]))
    const evalFn = vi.fn(async () => 'OK')
    const adapter = new IamRedisAdapter<string, string, string, string>({
      client: Object.assign(client, { eval: evalFn }),
      migrateLegacyAssignments: true,
    })
    await adapter.getSubjectRoles('u1')
    expect(evalFn).not.toHaveBeenCalled()
  })

  it('re-checks under the lock and writes nothing when another writer got there first', async () => {
    // Kills `if (stillLegacy.length === 0) return` -> `if (false) return`: another writer migrates the set between
    // the first read and the locked re-read, so no empty SADD/SREM may follow.
    const client = new FakeRedis()
    client.sets.set('assignments:u1', new Set(['admin org-1']))
    let reads = 0
    const racing = Object.assign(client, {
      async smembers(key: string): Promise<string[]> {
        reads++
        // The first read (by `getSubjectRoles`) sees legacy; by the second, a concurrent writer has migrated it.
        if (reads > 1) client.sets.set(key, new Set([`admin${NUL}org-1`]))
        return Array.from(client.sets.get(key) ?? [])
      },
    })
    const adapter = new IamRedisAdapter<string, string, string, string>({
      client: racing,
      migrateLegacyAssignments: true,
    })
    await adapter.getSubjectRoles('u1')
    expect(client.calls).toEqual([])
  })

  it('does not write at all when nothing is legacy', async () => {
    // Nothing is legacy, so neither SADD nor SREM may be issued.
    const { adapter, client } = make([`viewer${NUL}org-2`])
    await adapter.getSubjectRoles('u1')
    expect(client.calls).toEqual([])
  })

  it('passes the migrated/legacy pair to EVAL when the client has one', async () => {
    // Kills the emptied `for (const m of legacy) {...}` body: EVAL must receive the `[migrated, legacy]` pair.
    const client = new FakeRedis()
    client.sets.set('assignments:u1', new Set(['admin org-1']))
    const evalFn = vi.fn(async () => 'OK')
    const adapter = new IamRedisAdapter<string, string, string, string>({
      client: Object.assign(client, { eval: evalFn }),
      migrateLegacyAssignments: true,
    })
    await adapter.getSubjectRoles('u1')
    expect(evalFn).toHaveBeenCalledTimes(1)
    expect(evalFn.mock.calls[0]?.slice(-3)).toEqual(['assignments:u1', `admin${NUL}org-1`, 'admin org-1'])
  })
})

describe('M-4: revoking a role the subject never held', () => {
  it('issues no SREM at all', async () => {
    // Kills `if (targets.length > 0)` -> `if (true)` / `>= 0`; the fake errors on a zero-member SREM as Redis does.
    const { adapter, client } = make([`viewer${NUL}org-1`])
    await expect(adapter.revokeRole('u1', 'never-held')).resolves.toBeUndefined()
    expect(client.calls.filter((c) => c.op === 'srem')).toEqual([])
  })

  it('control: revoking a role the subject does hold issues one SREM', async () => {
    const { adapter, client } = make([`viewer${NUL}org-1`])
    await adapter.revokeRole('u1', 'viewer')
    expect(client.calls.filter((c) => c.op === 'srem')).toEqual([{ args: [`viewer${NUL}org-1`], op: 'srem' }])
  })
})

// Inverting the lock's `=== settled` check deletes a lock a later writer installed, dropping its serialisation.
describe('M-5: writes to one key stay serialised', () => {
  it('does not start a write until the previous one has finished', async () => {
    const order: string[] = []
    const gate = new Map<string, () => void>()
    const client = new FakeRedis()
    client.sets.set('assignments:u1', new Set())
    // Each SREM parks until released, so any overlap is observable.
    const slow = Object.assign(client, {
      async srem(_key: string, ...members: string[]): Promise<number> {
        const tag = (members[0] ?? '?').split(NUL)[0] ?? '?'
        order.push(`start:${tag}`)
        await new Promise<void>((resolve) => gate.set(tag, resolve))
        order.push(`end:${tag}`)
        return 1
      },
    })
    const adapter = new IamRedisAdapter<string, string, string, string>({ client: slow })

    // Chaining alone orders `a` and `b`. `c` starts after `a` settles while `b` is in flight, which is when an
    // inverted check has already dropped `b`'s lock.
    const a = adapter.revokeRole('u1', 'a', 'org-1')
    const b = adapter.revokeRole('u1', 'b', 'org-1')

    await vi.waitFor(() => expect(gate.has('a')).toBe(true))
    gate.get('a')?.()
    await a
    await new Promise((resolve) => setTimeout(resolve, 0))

    const c = adapter.revokeRole('u1', 'c', 'org-1')
    await new Promise((resolve) => setTimeout(resolve, 0))

    await vi.waitFor(() => expect(gate.has('b')).toBe(true))
    gate.get('b')?.()
    await b
    await vi.waitFor(() => expect(gate.has('c')).toBe(true))
    gate.get('c')?.()
    await c

    // Strict alternation - no write starts before its predecessor ended.
    expect(order).toEqual(['start:a', 'end:a', 'start:b', 'end:b', 'start:c', 'end:c'])
  })
})

// An emptied `catch` falls through to the shape-check throw, so these assert the parse-failure branch by message.
describe('M-6: corrupted attributes throw from the parse branch', () => {
  it('names the JSON parse failure, not the shape check', async () => {
    const client = new FakeRedis()
    client.strings.set('attrs:u1', '{not json')
    const adapter = new IamRedisAdapter<string, string, string, string>({ client })
    await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/JSON parse failed/)
  })

  it('reports the underlying SyntaxError to onPolicyError', async () => {
    const client = new FakeRedis()
    client.strings.set('attrs:u1', '{not json')
    const onPolicyError = vi.fn()
    const adapter = new IamRedisAdapter<string, string, string, string>({ client, onPolicyError })
    await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow()
    expect(onPolicyError).toHaveBeenCalledTimes(1)
    expect(onPolicyError.mock.calls[0]?.[0]).toBeInstanceOf(SyntaxError)
  })

  // Control: the shape-check branch, so the two throws are told apart by more than their shared prefix.
  it('control: valid JSON of the wrong shape names the shape check', async () => {
    const client = new FakeRedis()
    client.strings.set('attrs:u1', '[1,2]')
    const adapter = new IamRedisAdapter<string, string, string, string>({ client })
    await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/not a JSON object/)
  })
})
