import { describe, expect, it, vi } from 'vitest'
import type { IamRedis } from '../index'
import { IamRedisAdapter } from '../index'

/**
 * Stryker on `redis/index.ts` scored 79.71% with 34 survivors. Most sat on
 * error-message strings, but six sat on real checks - the legacy-migration
 * heuristic, the migration's two filters, `revokeRole`'s empty-target guard,
 * the write-lock identity test, and the corrupt-attributes throw. Every one of
 * them could be deleted or inverted with the suite still green.
 *
 * Each block below names the mutant it kills.
 */

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
    // Real Redis answers `SREM key` with no members with a "wrong number of
    // arguments" error, not a no-op. `revokeRole`'s guard exists for exactly
    // this; without modelling it here the guard's mutant survives.
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

/**
 * M-1: all four conditions in `_isLegacyEncoded` survived. The heuristic decides
 * whether a stored string is a role, or a role plus a scope; not one of its
 * conditions was pinned.
 */
describe('M-1: the legacy-encoding heuristic', () => {
  it('does not treat a NUL-encoded member as legacy, even when its scope contains a space', async () => {
    // `_decodeAssignment` finds the NUL first, so the decode is right either
    // way. The guard's real job is to keep this member out of the MIGRATION:
    // without it, `admin\u0000my org` is "migrated" to itself and the SREM that
    // follows the SADD deletes the grant outright.
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
    // Kills the `indexOf(' ', first + 1) === -1` -> `true` mutant: with it,
    // `admin org 1` splits at the first space and silently mints scope `org 1`.
    const { adapter } = make(['admin org 1'])
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin org 1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('control: exactly one space and no NUL is legacy', async () => {
    const { adapter } = make(['admin org-1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org-1' }])
  })
})

/** M-2: the legacy branch gate and its empty-scope arm. */
describe('M-2: the decode gate and its empty-tail arm', () => {
  it('does not decode a spaced member as role+scope when migration is off', async () => {
    // Kills the `if (this._isLegacyEncoded(member))` -> `if (true)` mutant.
    const { adapter } = make(['admin org-1'], false)
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin org-1'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
  })

  it('decodes an empty legacy tail as a GLOBAL grant, not one scoped to the empty string', async () => {
    // Kills the `scope === '' ? { role } : ...` -> `false ? ...` mutant, which
    // yields `{ role, scope: '' }` - I-1's empty-string-scope confusion arriving
    // at the adapter's own decode boundary.
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

/**
 * M-3: the migration's two `filter` calls and its re-check. Deleting either
 * makes the migration rewrite EVERY member of the set - a destructive rewrite
 * of live assignment data - and no test caught it.
 */
describe('M-3: the migration touches only legacy members', () => {
  it('rewrites the legacy member and leaves an already-migrated one alone', async () => {
    const { adapter, client } = make(['admin org-1', `viewer${NUL}org-2`])
    await adapter.getSubjectRoles('u1')
    // Kills both `.filter(...)` deletions: with either gone, the
    // already-migrated member is re-encoded and re-added too.
    const srem = client.calls.filter((c) => c.op === 'srem').flatMap((c) => c.args)
    const sadd = client.calls.filter((c) => c.op === 'sadd').flatMap((c) => c.args)
    expect(srem).toEqual(['admin org-1'])
    expect(sadd).toEqual([`admin${NUL}org-1`])
    expect(Array.from(client.sets.get('assignments:u1') ?? [])).toEqual([`viewer${NUL}org-2`, `admin${NUL}org-1`])
  })

  it('does not reach EVAL at all when nothing is legacy', async () => {
    // Kills `const legacy = members`: the outer filter is what decides whether
    // the migration runs. On the Lua path there is no second filter to save it,
    // so an already-migrated set would be rewritten wholesale.
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
    // Kills `if (stillLegacy.length === 0) return` -> `if (false) return`.
    // The re-check only shows through the race it defends against: the set is
    // legacy at the first read and already migrated by the time the lock is
    // held. Without it, SADD/SREM are called with no members - which real Redis
    // answers with an error, not a no-op.
    const client = new FakeRedis()
    client.sets.set('assignments:u1', new Set(['admin org-1']))
    let reads = 0
    const racing = Object.assign(client, {
      async smembers(key: string): Promise<string[]> {
        reads++
        // The first read (the one `getSubjectRoles` does) still sees legacy;
        // by the second, a concurrent writer has migrated it.
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
    // Kills `if (stillLegacy.length === 0) return` -> `if (false) return`,
    // which reaches `sadd`/`srem` with an empty list.
    const { adapter, client } = make([`viewer${NUL}org-2`])
    await adapter.getSubjectRoles('u1')
    expect(client.calls).toEqual([])
  })

  it('passes the migrated/legacy pair to EVAL when the client has one', async () => {
    // Kills the emptied `for (const m of legacy) {...}` body: the Lua path was
    // called with no ARGV and the two tests exercising it still passed, so
    // "the Lua migration re-encodes something" was asserted nowhere.
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

/** M-4: `revokeRole`'s empty-target guard. */
describe('M-4: revoking a role the subject never held', () => {
  it('issues no SREM at all', async () => {
    // Kills `if (targets.length > 0)` -> `if (true)` / `>= 0`: real Redis
    // answers a zero-member SREM with an error, which the fake now models.
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

/**
 * M-5: the write-lock identity check. Inverting `=== settled` deletes the lock
 * a *concurrent* writer installed, dropping serialisation for an in-flight
 * write to the same key - and 33 tests still passed.
 */
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

    // The identity check matters for a writer that arrives AFTER an earlier one
    // has settled but while a later one is still in flight. Chaining alone
    // covers `a`/`b`, so `c` is started only once `a` has finished - at which
    // point the inverted check has already dropped `b`'s lock and `c` runs
    // straight into `b`.
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

/**
 * M-6: the corrupt-attributes throw. Emptying the `catch` leaves `parsed`
 * undefined, which falls through to the *second* throw - so a test asserting
 * only `/corrupted attributes/` cannot tell the two apart, and the mutant
 * survived. These assert the parse-failure branch specifically.
 */
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

  // Control: the OTHER branch, so the two throws are told apart by the suite
  // and not merely by their shared prefix.
  it('control: valid JSON of the wrong shape names the shape check', async () => {
    const client = new FakeRedis()
    client.strings.set('attrs:u1', '[1,2]')
    const adapter = new IamRedisAdapter<string, string, string, string>({ client })
    await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/not a JSON object/)
  })
})
