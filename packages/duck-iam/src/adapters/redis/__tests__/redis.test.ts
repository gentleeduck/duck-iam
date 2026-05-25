import { beforeEach, describe, expect, it } from 'vitest'
import type { Engine } from '../../../core'
import type { AccessControl, Adapter } from '../../../core/types'
import { runAdapterCompliance } from '../../__compliance__/compliance'
import { type Redis, RedisAdapter } from '../index'

type A = 'read' | 'write'
type R = 'post' | 'comment'
type Ro = 'viewer' | 'editor'
type S = 'org-1' | 'org-2'

class FakeRedis implements Redis.ILike {
  private strings = new Map<string, string>()
  private hashes = new Map<string, Map<string, string>>()
  private sets = new Map<string, Set<string>>()

  async get(key: string): Promise<string | null> {
    return this.strings.get(key) ?? null
  }
  async set(key: string, value: string): Promise<unknown> {
    this.strings.set(key, value)
    return 'OK'
  }
  async del(...keys: string[]): Promise<number> {
    let n = 0
    for (const k of keys) {
      if (this.strings.delete(k)) n++
      if (this.hashes.delete(k)) n++
      if (this.sets.delete(k)) n++
    }
    return n
  }
  async hset(key: string, field: string, value: string): Promise<number> {
    if (!this.hashes.has(key)) this.hashes.set(key, new Map())
    const h = this.hashes.get(key)!
    const fresh = !h.has(field)
    h.set(field, value)
    return fresh ? 1 : 0
  }
  async hget(key: string, field: string): Promise<string | null> {
    return this.hashes.get(key)?.get(field) ?? null
  }
  async hdel(key: string, ...fields: string[]): Promise<number> {
    const h = this.hashes.get(key)
    if (!h) return 0
    let n = 0
    for (const f of fields) if (h.delete(f)) n++
    return n
  }
  async hkeys(key: string): Promise<string[]> {
    return Array.from(this.hashes.get(key)?.keys() ?? [])
  }
  async hvals(key: string): Promise<string[]> {
    return Array.from(this.hashes.get(key)?.values() ?? [])
  }
  async hgetall(key: string): Promise<Record<string, string>> {
    const out: Record<string, string> = {}
    for (const [k, v] of this.hashes.get(key)?.entries() ?? []) out[k] = v
    return out
  }
  async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.sets.has(key)) this.sets.set(key, new Set())
    const s = this.sets.get(key)!
    let n = 0
    for (const m of members) {
      if (!s.has(m)) {
        s.add(m)
        n++
      }
    }
    return n
  }
  async srem(key: string, ...members: string[]): Promise<number> {
    const s = this.sets.get(key)
    if (!s) return 0
    let n = 0
    for (const m of members) if (s.delete(m)) n++
    return n
  }
  async smembers(key: string): Promise<string[]> {
    return Array.from(this.sets.get(key) ?? [])
  }

  // helpers for assertions
  rawHash(key: string): Map<string, string> | undefined {
    return this.hashes.get(key)
  }
  rawSet(key: string): Set<string> | undefined {
    return this.sets.get(key)
  }
}

// Adapter compliance — fresh FakeRedis per call.
runAdapterCompliance('RedisAdapter', () => new RedisAdapter({ client: new FakeRedis() }) as never)

describe('RedisAdapter', () => {
  let redis: FakeRedis
  let adapter: RedisAdapter<A, R, Ro, S>

  beforeEach(() => {
    redis = new FakeRedis()
    adapter = new RedisAdapter<A, R, Ro, S>({ client: redis })
  })

  describe('Adapter.IPolicyStore', () => {
    const policy: AccessControl.IPolicy<A, R, Ro> = {
      id: 'p1',
      name: 'Test',
      description: 'desc',
      version: 2,
      algorithm: 'deny-overrides',
      rules: [],
      targets: { actions: ['read'] },
    }

    it('listPolicies starts empty', async () => {
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('savePolicy + listPolicies roundtrip', async () => {
      await adapter.savePolicy(policy)
      const list = await adapter.listPolicies()
      expect(list).toEqual([policy])
    })

    it('getPolicy returns null when missing', async () => {
      expect(await adapter.getPolicy('nope')).toBeNull()
    })

    it('getPolicy returns saved policy', async () => {
      await adapter.savePolicy(policy)
      expect(await adapter.getPolicy('p1')).toEqual(policy)
    })

    it('savePolicy overwrites existing', async () => {
      await adapter.savePolicy(policy)
      await adapter.savePolicy({ ...policy, name: 'Updated' })
      const got = await adapter.getPolicy('p1')
      expect(got?.name).toBe('Updated')
      expect(redis.rawHash('policies')?.size).toBe(1)
    })

    it('deletePolicy removes', async () => {
      await adapter.savePolicy(policy)
      await adapter.deletePolicy('p1')
      expect(await adapter.listPolicies()).toEqual([])
    })

    it('stores under prefixed key when keyPrefix set', async () => {
      const prefixed = new RedisAdapter<A, R, Ro, S>({ client: redis, keyPrefix: 'iam:' })
      await prefixed.savePolicy(policy)
      expect(redis.rawHash('iam:policies')).toBeDefined()
      expect(redis.rawHash('policies')).toBeUndefined()
    })
  })

  describe('Adapter.IRoleStore', () => {
    const role: AccessControl.IRole<A, R, Ro, S> = {
      id: 'editor',
      name: 'Editor',
      description: 'Can edit',
      permissions: [{ action: 'write', resource: 'post' }],
      inherits: ['viewer'] as Ro[],
      scope: 'org-1',
      metadata: { color: 'blue' },
    }

    it('listRoles empty', async () => {
      expect(await adapter.listRoles()).toEqual([])
    })

    it('saveRole + getRole roundtrip', async () => {
      await adapter.saveRole(role)
      expect(await adapter.getRole('editor')).toEqual(role)
    })

    it('getRole null when missing', async () => {
      expect(await adapter.getRole('nope')).toBeNull()
    })

    it('saveRole overwrites', async () => {
      await adapter.saveRole(role)
      await adapter.saveRole({ ...role, name: 'New' })
      const got = await adapter.getRole('editor')
      expect(got?.name).toBe('New')
      expect(redis.rawHash('roles')?.size).toBe(1)
    })

    it('deleteRole removes', async () => {
      await adapter.saveRole(role)
      await adapter.deleteRole('editor')
      expect(await adapter.listRoles()).toEqual([])
    })

    it('listRoles returns multiple', async () => {
      await adapter.saveRole(role)
      await adapter.saveRole({ id: 'viewer', name: 'V', permissions: [] })
      const list = await adapter.listRoles()
      expect(list).toHaveLength(2)
    })
  })

  describe('Adapter.ISubjectStore', () => {
    it('getSubjectRoles empty when none assigned', async () => {
      expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    })

    it('assignRole + getSubjectRoles', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('assignRole is idempotent (set semantics)', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('getSubjectRoles dedups across scopes', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-2')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('getSubjectScopedRoles only returns scoped', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'viewer' as Ro, 'org-2')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toHaveLength(2)
      expect(scoped).toContainEqual({ role: 'editor', scope: 'org-1' })
      expect(scoped).toContainEqual({ role: 'viewer', scope: 'org-2' })
    })

    it('revokeRole without scope removes all matching role assignments', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-2')
      await adapter.assignRole('user-1', 'viewer' as Ro)
      await adapter.revokeRole('user-1', 'editor' as Ro)
      const remaining = await adapter.getSubjectRoles('user-1')
      expect(remaining).toEqual(['viewer'])
    })

    it('revokeRole with scope only clears matching scoped assignment', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      await adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([])
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
    })

    it('revokeRole no-op when role not assigned', async () => {
      await adapter.revokeRole('user-1', 'editor' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual([])
    })

    it('getSubjectAttributes returns {} when missing', async () => {
      expect(await adapter.getSubjectAttributes('nobody')).toEqual({})
    })

    it('setSubjectAttributes stores and merges', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { plan: 'pro' })
      expect(await adapter.getSubjectAttributes('user-1')).toEqual({ team: 'A', plan: 'pro' })
    })

    it('setSubjectAttributes overwrites existing keys', async () => {
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      await adapter.setSubjectAttributes('user-1', { team: 'B' })
      expect((await adapter.getSubjectAttributes('user-1')).team).toBe('B')
    })

    it('getSubjectRoles returns ONLY unscoped roles, not scoped (SEC-059)', async () => {
      // Aligns redis with file/memory contract: scoped roles go through
      // getSubjectScopedRoles only.
      await adapter.assignRole('user-1', 'viewer' as Ro)
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['viewer'])
      expect(await adapter.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
    })

    it('throws on corrupted attributes JSON instead of returning {} (SEC-058)', async () => {
      await redis.set('attrs:user-1', '{not-valid-json')
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
    })

    it('setSubjectAttributes recovers from corrupt existing blob (SEC-067)', async () => {
      // Admin overwrite is the only recovery path: the read throws on
      // corruption, which would otherwise lock the operator out forever.
      // Setter catches the throw, logs, and uses `{}` as the merge base.
      await redis.set('attrs:user-1', 'not-json{')
      await adapter.setSubjectAttributes('user-1', { team: 'A' })
      // Read now returns the freshly-written value (no longer corrupt).
      expect(await adapter.getSubjectAttributes('user-1')).toEqual({ team: 'A' })
    })

    it('throws on non-object attributes JSON (SEC-058)', async () => {
      await redis.set('attrs:user-1', '"a-string"')
      await expect(adapter.getSubjectAttributes('user-1')).rejects.toThrow(/corrupted attributes/)
    })

    it('keys are isolated per subject', async () => {
      await adapter.assignRole('user-1', 'editor' as Ro)
      await adapter.assignRole('user-2', 'viewer' as Ro)
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['editor'])
      expect(await adapter.getSubjectRoles('user-2')).toEqual(['viewer'])
    })
  })

  describe('keyPrefix', () => {
    it('namespaces all storage keys', async () => {
      const prefixed = new RedisAdapter<A, R, Ro, S>({ client: redis, keyPrefix: 'app1:' })
      await prefixed.savePolicy({ id: 'p1', name: 'P', algorithm: 'deny-overrides', rules: [] })
      await prefixed.saveRole({ id: 'r1' as Ro, name: 'R', permissions: [] })
      await prefixed.assignRole('user-1', 'r1' as Ro)
      await prefixed.setSubjectAttributes('user-1', { x: 1 })

      expect(redis.rawHash('app1:policies')).toBeDefined()
      expect(redis.rawHash('app1:roles')).toBeDefined()
      expect(redis.rawSet('app1:assignments:user-1')).toBeDefined()
      // Default (unprefixed) keys stay empty
      expect(redis.rawHash('policies')).toBeUndefined()
    })

    it('two adapters with different prefixes do not collide', async () => {
      const a1 = new RedisAdapter<A, R, Ro, S>({ client: redis, keyPrefix: 'app1:' })
      const a2 = new RedisAdapter<A, R, Ro, S>({ client: redis, keyPrefix: 'app2:' })
      await a1.savePolicy({ id: 'p1', name: 'P1', algorithm: 'deny-overrides', rules: [] })
      await a2.savePolicy({ id: 'p1', name: 'P2', algorithm: 'deny-overrides', rules: [] })
      expect((await a1.getPolicy('p1'))?.name).toBe('P1')
      expect((await a2.getPolicy('p1'))?.name).toBe('P2')
    })
  })

  describe('integration with engine', () => {
    it('adapter contract satisfies Engine when used end-to-end', async () => {
      const { Engine } = await import('../../../core/engine')
      const engine = new Engine<A, R, Ro, S>({ adapter, cacheTTL: 0 })

      await adapter.saveRole({
        id: 'editor' as Ro,
        name: 'Editor',
        permissions: [{ action: 'write', resource: 'post' }],
      })
      await adapter.assignRole('user-1', 'editor' as Ro)

      const allowed = await engine.can('user-1', 'write', { type: 'post', attributes: {} })
      expect(allowed).toBe(true)

      const denied = await engine.can('user-1', 'read', { type: 'post', attributes: {} })
      expect(denied).toBe(false)
    })
  })

  describe('malformed-row drop (P0)', () => {
    // Round-trip guard: corrupt rows must NOT reach the engine. Adapter drops
    // them and routes the failure through onPolicyError. Without this, a
    // tampered Redis hash entry would parse as garbage and silently strip
    // deny rules from the decision pipeline.
    it('listPolicies drops a row whose JSON cannot be parsed', async () => {
      const errors: Array<{ msg: string; ctx: { adapter: string; rowId: string } }> = []
      const adapter = new RedisAdapter<A, R, Ro, S>({
        client: redis,
        onPolicyError: (err, ctx) => errors.push({ msg: err.message, ctx }),
      })
      // Seed one valid row + one corrupt row directly into the fake store.
      await redis.hset(
        'policies',
        'good',
        JSON.stringify({
          id: 'good',
          name: 'good',
          algorithm: 'deny-overrides',
          rules: [],
        }),
      )
      await redis.hset('policies', 'bad', '{not valid json')

      const list = await adapter.listPolicies()
      expect(list.map((p) => p.id)).toEqual(['good'])
      expect(errors).toHaveLength(1)
      expect(errors[0]?.ctx.rowId).toBe('bad')
    })

    it('listPolicies drops a row that parses but fails shape validation', async () => {
      const errors: Array<{ rowId: string }> = []
      const adapter = new RedisAdapter<A, R, Ro, S>({
        client: redis,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      // Missing required fields (no `rules`, no `algorithm`).
      await redis.hset('policies', 'shape-bad', JSON.stringify({ id: 'shape-bad', name: 'x' }))

      const list = await adapter.listPolicies()
      expect(list).toEqual([])
      expect(errors[0]?.rowId).toBe('shape-bad')
    })

    it('getPolicy returns null and calls onPolicyError on malformed row', async () => {
      const errors: Array<{ rowId: string }> = []
      const adapter = new RedisAdapter<A, R, Ro, S>({
        client: redis,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      await redis.hset('policies', 'bad', 'definitely not json')
      const got = await adapter.getPolicy('bad')
      expect(got).toBeNull()
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('listRoles drops malformed rows and continues', async () => {
      const errors: Array<{ rowId: string }> = []
      const adapter = new RedisAdapter<A, R, Ro, S>({
        client: redis,
        onPolicyError: (_err, ctx) => errors.push({ rowId: ctx.rowId }),
      })
      await redis.hset('roles', 'good', JSON.stringify({ id: 'good', name: 'g', permissions: [] }))
      await redis.hset('roles', 'bad', JSON.stringify({ name: 'no id' }))
      const list = await adapter.listRoles()
      expect(list.map((r) => r.id)).toEqual(['good'])
      expect(errors[0]?.rowId).toBe('bad')
    })

    it('falls back to console.warn when no onPolicyError is configured', async () => {
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: redis })
      await redis.hset('policies', 'bad', '{not json')
      const warnings: string[] = []
      const orig = console.warn
      console.warn = (...args: unknown[]) => warnings.push(args.map(String).join(' '))
      try {
        const list = await adapter.listPolicies()
        expect(list).toEqual([])
      } finally {
        console.warn = orig
      }
      expect(warnings.some((w) => /duck-iam:redis/.test(w) && /bad/.test(w))).toBe(true)
    })
  })

  describe('NUL byte guard on role/scope', () => {
    // The encoded set member uses `\0` as separator. A caller smuggling a NUL
    // through `as TRole` would corrupt the assignment silently - the guard
    // throws instead.
    it('assignRole rejects roleId containing NUL', async () => {
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: new FakeRedis() })
      await expect(adapter.assignRole('user-1', 'view\0er' as Ro)).rejects.toThrow(/NUL/)
    })

    it('assignRole rejects scope containing NUL', async () => {
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: new FakeRedis() })
      await expect(adapter.assignRole('user-1', 'viewer' as Ro, 'org\0-1' as S)).rejects.toThrow(/NUL/)
    })
  })

  describe('SEC-019: assignment separator is NUL, not space', () => {
    // Repro of the original bug: encoded member used a literal space (0x20)
    // as the role/scope separator despite the comment claiming NUL. Any
    // role or scope containing whitespace would silently collide on decode.
    // Fix uses a real NUL byte; tests pin down both encode and decode.
    it('encodes role+scope with a NUL separator byte (not space)', async () => {
      const r = new FakeRedis()
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: r })
      await adapter.assignRole('user-1', 'editor' as Ro, 'org-1')
      const set = r.rawSet('assignments:user-1')
      expect(set).toBeDefined()
      const [member] = Array.from(set!)
      expect(member).toBeDefined()
      // Must contain a literal NUL byte, not the previous space separator.
      expect(member!.includes('\0')).toBe(true)
      // No raw space-separator fallback for fresh writes.
      expect(member).toBe(`editor\0org-1`)
    })

    it('round-trips a role and scope that both contain spaces', async () => {
      // Before the fix this case silently collapsed:
      //   `role with space` + `scope:with:colons` -> set member `role with space scope:with:colons`
      //   -> decoded as { role: 'role', scope: 'with space scope:with:colons' }
      // After the fix the NUL separator keeps the boundary unambiguous.
      const r = new FakeRedis()
      const adapter = new RedisAdapter<string, string, string, string>({ client: r })
      await adapter.assignRole('user-1', 'role with space', 'scope:with:colons')
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([{ role: 'role with space', scope: 'scope:with:colons' }])
    })

    it('a value containing only a space round-trips correctly (original SEC-019 repro)', async () => {
      const r = new FakeRedis()
      const adapter = new RedisAdapter<string, string, string, string>({ client: r })
      await adapter.assignRole('user-1', 'admin user')
      expect(await adapter.getSubjectRoles('user-1')).toEqual(['admin user'])
    })

    it('rejects an assignment where roleId contains a literal NUL', async () => {
      const adapter = new RedisAdapter<string, string, string, string>({ client: new FakeRedis() })
      await expect(adapter.assignRole('user-1', 'evil\0role')).rejects.toThrow(/NUL/)
    })

    it('migrates legacy space-separated entries on first read', async () => {
      // Seed an entry written by the old (buggy) encoder: literal space.
      const r = new FakeRedis()
      await r.sadd('assignments:user-1', 'editor org-1')
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: r })

      // Reading scoped roles must decode the legacy entry correctly...
      const scoped = await adapter.getSubjectScopedRoles('user-1')
      expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])

      // ...and the migration must have re-encoded it under the NUL form,
      // removing the legacy entry from the set.
      const members = Array.from(r.rawSet('assignments:user-1') ?? [])
      expect(members).toContain('editor\0org-1')
      expect(members).not.toContain('editor org-1')
    })
  })

  describe('SEC-024: migrate-vs-revoke serialisation', () => {
    it('uses Lua EVAL when client supports it (DEBT-10)', async () => {
      // Cross-process atomic migration via EVAL: confirm the adapter
      // dispatches to the Lua path when client.eval exists.
      const r = new FakeRedis()
      await r.sadd('assignments:user-1', 'editor org-1')
      const evalCalls: Array<[string, number, string[]]> = []
      const clientWithEval = {
        ...r,
        get: r.get.bind(r),
        set: r.set.bind(r),
        del: r.del.bind(r),
        hset: r.hset.bind(r),
        hget: r.hget.bind(r),
        hdel: r.hdel.bind(r),
        hkeys: r.hkeys.bind(r),
        hvals: r.hvals.bind(r),
        hgetall: r.hgetall.bind(r),
        sadd: r.sadd.bind(r),
        srem: r.srem.bind(r),
        smembers: r.smembers.bind(r),
        async eval(script: string, numkeys: number, ...keysAndArgs: string[]): Promise<unknown> {
          evalCalls.push([script, numkeys, keysAndArgs])
          // Simulate Lua execution: read ARGV pairs, SADD migrated, SREM legacy.
          const key = keysAndArgs[0]!
          for (let i = 1; i < keysAndArgs.length; i += 2) {
            await r.sadd(key, keysAndArgs[i]!)
            await r.srem(key, keysAndArgs[i + 1]!)
          }
          return 'OK'
        },
      }
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: clientWithEval })
      await adapter.getSubjectScopedRoles('user-1')
      expect(evalCalls).toHaveLength(1)
      expect(evalCalls[0]?.[1]).toBe(1)
      expect(evalCalls[0]?.[2][0]).toBe('assignments:user-1')
    })

    it('concurrent migration + revoke leaves no resurrected assignment', async () => {
      // Seed a legacy entry that migration would re-encode.
      const r = new FakeRedis()
      await r.sadd('assignments:user-1', 'editor org-1')
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: r })

      // Kick off a read that triggers migration, race-fired with a revoke.
      // Without per-key serialisation the migrator's SADD could land after
      // the revoker's SREM, resurrecting `editor\0org-1`. Serialised, the
      // operations are ordered and the set ends empty.
      const migration = adapter.getSubjectScopedRoles('user-1')
      const revoke = adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')
      await Promise.all([migration, revoke])

      const members = Array.from(r.rawSet('assignments:user-1') ?? [])
      expect(members).not.toContain('editor\0org-1')
      expect(members).not.toContain('editor org-1')
    })

    it('revoke with scope clears both encodings in one call', async () => {
      // Pre-existing partial state: one entry in each encoding for the same
      // role+scope pair. revoke({scope:...}) must drain both, not just one.
      const r = new FakeRedis()
      await r.sadd('assignments:user-1', 'editor org-1', 'editor\0org-1')
      const adapter = new RedisAdapter<A, R, Ro, S>({ client: r })

      await adapter.revokeRole('user-1', 'editor' as Ro, 'org-1')

      const members = Array.from(r.rawSet('assignments:user-1') ?? [])
      expect(members).toHaveLength(0)
    })
  })
})
