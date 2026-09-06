import { describe, expect, it } from 'vitest'
import type { AccessControl, IamAdapter } from '../../core/types'

/**
 * Shared adapter compliance suite.
 *
 * Every shipped adapter (`IamMemoryAdapter`, `IamFileAdapter`, `IamRedisAdapter`,
 * `IamDrizzleAdapter`, `IamPrismaAdapter`, `IamHttpAdapter`) and every third-party
 * adapter must pass this matrix. The suite pins the cross-backend contract
 * so the same scenarios produce identical results regardless of storage.
 *
 * Usage in an adapter test file:
 * ```ts
 * import { runAdapterCompliance } from '../../__compliance__/compliance'
 * runAdapterCompliance('MyAdapter', () => new MyAdapter({ ... }))
 * ```
 *
 * The factory MUST return a fresh, empty adapter on each call.
 */

type AnyAdapter = IamAdapter.IAdapter<string, string, string, string>

const samplePolicy: AccessControl.IPolicy = {
  id: 'p-compliance',
  name: 'Compliance Test Policy',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r1',
      effect: 'allow',
      priority: 10,
      actions: ['read'],
      resources: ['post'],
      conditions: { all: [] },
    },
  ],
}

const sampleRole: AccessControl.IRole = {
  id: 'editor',
  name: 'Editor',
  permissions: [{ action: 'read', resource: 'post' }],
}

/**
 * Parses a row the way one actually arrives - from an HTTP body, a config
 * file, a migration - so this suite can hand an adapter the shapes its guards
 * exist to refuse. `JSON.parse` is the real provenance of every malformed row
 * these tests pin, not a way around the declared signatures: at runtime the
 * adapter is handed exactly this value, and the compile-time type it claims to
 * have is the fiction the guards are there to catch.
 */
function fromJson(json: string) {
  return JSON.parse(json)
}

/**
 * Run the compliance matrix against any adapter implementation.
 *
 * @param adapterName - Human-readable name used in describe blocks.
 * @param factory - Async factory that returns a FRESH adapter per call. Must
 *   not share state across factory invocations (each test runs against a
 *   clean slate).
 */
export function runAdapterCompliance(adapterName: string, factory: () => AnyAdapter | Promise<AnyAdapter>): void {
  describe(`IamAdapter compliance: ${adapterName}`, () => {
    describe('IPolicyStore', () => {
      it('listPolicies returns [] on empty store', async () => {
        const a = await factory()
        expect(await a.listPolicies()).toEqual([])
      })

      it('getPolicy returns null on miss', async () => {
        const a = await factory()
        expect(await a.getPolicy('missing')).toBeNull()
      })

      it('savePolicy + getPolicy round-trips', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const got = await a.getPolicy(samplePolicy.id)
        expect(got?.id).toBe(samplePolicy.id)
        expect(got?.name).toBe(samplePolicy.name)
        expect(got?.algorithm).toBe(samplePolicy.algorithm)
        expect(got?.rules.length).toBe(1)
      })

      /**
       * One write, six backends, one shape. `samplePolicy` omits `version`,
       * `description` and `targets`; the SQL adapters used to normalise it
       * through their column set and hand back `version: 1` plus
       * present-but-undefined `description`/`targets` keys, while the other
       * four returned the caller's object untouched. A consumer reading
       * `policy.version` got `1` on prisma/drizzle and `undefined` elsewhere.
       *
       * `version` is asserted as `1` rather than `undefined` because the SQL
       * column cannot express "absent" without a migration - so the default
       * moved to the write path, where all six adopt it.
       */
      it('savePolicy + getPolicy returns the same shape on every backend', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const got = await a.getPolicy(samplePolicy.id)
        expect(got).not.toBeNull()
        expect(Object.keys(got ?? {}).sort()).toEqual(['algorithm', 'id', 'name', 'rules', 'version'])
        expect(got?.version).toBe(1)
      })

      // The optional fields survive the trip when they ARE supplied - the
      // normaliser drops absent keys, not populated ones.
      // Seeded and written rows must be indistinguishable. The memory adapter
      // seeded its constructor policies raw while `savePolicy` normalised them,
      // so `export()` on a seeded store emitted a snapshot whose shape
      // `import()` did not reproduce - a round trip that changed its own input.
      it('a saved policy and the same policy re-saved are identical', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const once = await a.getPolicy(samplePolicy.id)
        const b = await factory()
        if (once !== null) await b.savePolicy(once)
        expect(await b.getPolicy(samplePolicy.id)).toEqual(once)
      })

      it('savePolicy + getPolicy preserves supplied optional fields', async () => {
        const a = await factory()
        const full = { ...samplePolicy, description: 'D', targets: { actions: ['read'] }, version: 7 }
        await a.savePolicy(full)
        const got = await a.getPolicy(full.id)
        expect(Object.keys(got ?? {}).sort()).toEqual([
          'algorithm',
          'description',
          'id',
          'name',
          'rules',
          'targets',
          'version',
        ])
        expect(got?.version).toBe(7)
        expect(got?.description).toBe('D')
        expect(got?.targets).toEqual({ actions: ['read'] })
      })

      // A field outside `IPolicy` used to be *silently dropped* by the two SQL
      // adapters and *kept* by the other four. Both halves are wrong: a typo in
      // a field name should not be a write that half the fleet honours. Every
      // adapter now refuses it, so the divergence is closed by rejection rather
      // than by picking one of the two old behaviours.
      it('savePolicy refuses a field outside the policy type', async () => {
        const a = await factory()
        // Bound to a variable rather than passed as a literal: the excess
        // property check is a compile-time courtesy, and the row this pins is
        // the one that arrives from JSON at runtime, where no check applies.
        const withExtra = { ...samplePolicy, wat: 'extra' }
        await expect(a.savePolicy(withExtra)).rejects.toThrow(/Unknown field "wat"/)
        expect(await a.getPolicy(samplePolicy.id)).toBeNull()
      })

      it('savePolicy overwrites existing entry (upsert semantics)', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        await a.savePolicy({ ...samplePolicy, name: 'Renamed' })
        const got = await a.getPolicy(samplePolicy.id)
        expect(got?.name).toBe('Renamed')
      })

      it('deletePolicy removes the entry', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        await a.deletePolicy(samplePolicy.id)
        expect(await a.getPolicy(samplePolicy.id)).toBeNull()
      })

      it('listPolicies returns every saved policy', async () => {
        const a = await factory()
        await a.savePolicy({ ...samplePolicy, id: 'p1' })
        await a.savePolicy({ ...samplePolicy, id: 'p2' })
        const list = await a.listPolicies()
        expect(list.map((p) => p.id).sort()).toEqual(['p1', 'p2'])
      })
    })

    describe('IRoleStore', () => {
      it('listRoles returns [] on empty store', async () => {
        const a = await factory()
        expect(await a.listRoles()).toEqual([])
      })

      it('saveRole + getRole round-trips', async () => {
        const a = await factory()
        await a.saveRole(sampleRole)
        const got = await a.getRole(sampleRole.id)
        expect(got?.id).toBe(sampleRole.id)
        expect(got?.name).toBe(sampleRole.name)
        expect(got?.permissions.length).toBe(1)
      })

      it('deleteRole removes the entry', async () => {
        const a = await factory()
        await a.saveRole(sampleRole)
        await a.deleteRole(sampleRole.id)
        expect(await a.getRole(sampleRole.id)).toBeNull()
      })
    })

    /**
     * The cells the matrix used to leave to per-adapter files, or to nothing.
     *
     * Every assertion below pins a case where the six adapters were measured
     * disagreeing. They live here, not in six near-identical suites, because
     * the two adapters missing the `setSubjectAttributes` guard were exactly
     * the two with no `*-input-shape.test.ts` - a per-adapter test proves one
     * adapter and silently exempts the next one somebody writes.
     */
    describe('cross-adapter edge cases', () => {
      it('deleting a row that is not there is a no-op, not a throw', async () => {
        const a = await factory()
        await expect(a.deletePolicy('never-existed')).resolves.toBeUndefined()
        await expect(a.deleteRole('never-existed')).resolves.toBeUndefined()
      })

      it('deleting twice is a no-op the second time', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        await a.deletePolicy(samplePolicy.id)
        await expect(a.deletePolicy(samplePolicy.id)).resolves.toBeUndefined()
      })

      it('assigning the same role twice does not duplicate it', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      it('assigning the same scoped role twice does not duplicate it', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-1')
        if (a.getSubjectScopedRoles) {
          expect(await a.getSubjectScopedRoles('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
        }
      })

      // An empty scope is refused everywhere: redis spells "no scope" as the
      // empty string, so storing a literal one decodes as a *global* grant -
      // strictly more power than was asked for.
      it('an empty-string scope is refused on assign and on revoke', async () => {
        const a = await factory()
        await expect(a.assignRole('user-1', 'editor', '')).rejects.toThrow(/empty string/)
        await expect(a.revokeRole('user-1', 'editor', '')).rejects.toThrow(/empty string/)
      })

      it('an empty-string id is not a readable row', async () => {
        const a = await factory()
        expect(await a.getPolicy('')).toBeNull()
        expect(await a.getRole('')).toBeNull()
        expect(await a.getSubjectRoles('')).toEqual([])
        expect(await a.getSubjectAttributes('')).toEqual({})
      })

      /**
       * Ids that collide with an encoding: redis joins fields with a
       * separator, http puts the id in a URL path, the SQL pair pass it as a
       * bind parameter.
       *
       * The contract is not "every adapter accepts every id" - http refuses a
       * path separator on purpose, and that refusal is a security property, not
       * a gap. The contract is that an adapter never *silently* loses one: it
       * either round-trips the id or rejects the write with a named error. A
       * store that accepts `a/b` and then cannot find it is the failure mode.
       */
      it.each([
        ['a key separator', 'a:b'],
        ['a slash', 'a/b'],
        ['an at sign', 'a@b'],
        ['a newline', 'a\nb'],
        ['a percent-encoded slash', 'a%2Fb'],
        ['unicode', 'ロール-✓'],
      ])('either round-trips or refuses a role id containing %s', async (_label, id) => {
        const a = await factory()
        const refusal = await a.saveRole({ ...sampleRole, id }).then(
          () => null,
          (err: unknown) => String(err),
        )
        if (refusal !== null) {
          expect(refusal).toMatch(/@gentleduck\/iam:/)
          // The matching read must not produce a row. It may throw instead of
          // answering `null` - http does, deliberately, because a silent empty
          // result for an unusable id was retiring deny rules - but it must
          // never hand back something for an id the write refused.
          const read = await a.getRole(id).catch(() => null)
          expect(read).toBeNull()
          return
        }
        expect((await a.getRole(id))?.id).toBe(id)
        await a.assignRole('user-1', id)
        expect(await a.getSubjectRoles('user-1')).toEqual([id])
        await a.revokeRole('user-1', id)
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      // `__proto__` as a key is the prototype-pollution shape. Reading it back
      // must give the row, and must not have changed `Object.prototype`.
      it('treats `__proto__` as an ordinary id', async () => {
        const a = await factory()
        await a.saveRole({ ...sampleRole, id: '__proto__' })
        expect((await a.getRole('__proto__'))?.id).toBe('__proto__')
        expect(Object.hasOwn(Object.prototype, 'id')).toBe(false)
      })

      it('treats `__proto__` as an ordinary attribute key', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { __proto__: 'x' })
        expect(({} as Record<string, unknown>).polluted).toBeUndefined()
      })

      /**
       * Only the drizzle schemas carry `starts_at` / `expires_at`; prisma has
       * no such columns at all. Five adapters used to take `expiresAt` and drop
       * it, so a break-glass grant issued with an expiry was permanent and the
       * batch API still reported `ok: true, applied: 1`.
       *
       * As with ids, the contract is honour-or-refuse, never accept-and-drop.
       * An adapter that takes an already-elapsed `expiresAt` must not then
       * report the grant as live.
       */
      it('either honours an expiresAt or refuses it by name', async () => {
        const a = await factory()
        const past = new Date(Date.now() - 60_000)
        const refusal = await a.assignRole('user-1', 'editor', undefined, { expiresAt: past }).then(
          () => null,
          (err: unknown) => String(err),
        )
        if (refusal !== null) {
          expect(refusal).toMatch(/expiresAt/)
          expect(await a.getSubjectRoles('user-1')).toEqual([])
          return
        }
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('either honours a future startsAt or refuses it by name', async () => {
        const a = await factory()
        const future = new Date(Date.now() + 3_600_000)
        const refusal = await a.assignRole('user-1', 'editor', undefined, { startsAt: future }).then(
          () => null,
          (err: unknown) => String(err),
        )
        if (refusal !== null) expect(refusal).toMatch(/startsAt/)
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('either stores assignment attributes or refuses them by name', async () => {
        const a = await factory()
        const refusal = await a.assignRole('user-1', 'editor', undefined, { attributes: { tier: 'gold' } }).then(
          () => null,
          (err: unknown) => String(err),
        )
        if (refusal !== null) {
          expect(refusal).toMatch(/attributes/)
          expect(await a.getSubjectRoles('user-1')).toEqual([])
          return
        }
        // Accepted: the grant itself must still be live and readable.
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      // A non-object `attrs` used to spread into per-character keys on the two
      // SQL adapters and throw on the other four.
      it.each([
        ['a string', '"abc"'],
        ['an array', '[1, 2]'],
        ['null', 'null'],
        ['a number', '7'],
      ])('refuses %s as an attributes payload', async (_label, json) => {
        const a = await factory()
        await expect(a.setSubjectAttributes('user-1', fromJson(json))).rejects.toThrow(/must be a plain object/)
        expect(await a.getSubjectAttributes('user-1')).toEqual({})
      })

      // The read path dropped a malformed row on four adapters, kept it on
      // memory, and changed its mind across a restart on file. The write is
      // refused everywhere now, so all six agree at the moment of the mistake.
      it('refuses to save a policy whose rules are not an array', async () => {
        const a = await factory()
        const malformed = fromJson(JSON.stringify({ ...samplePolicy, rules: 'nope' }))
        await expect(a.savePolicy(malformed)).rejects.toThrow(/refusing to save invalid policy/)
        expect(await a.getPolicy(samplePolicy.id)).toBeNull()
      })

      it('refuses to save a role whose permissions are not an array', async () => {
        const a = await factory()
        const malformed = fromJson(JSON.stringify({ ...sampleRole, permissions: 'nope' }))
        await expect(a.saveRole(malformed)).rejects.toThrow(/refusing to save invalid role/)
        expect(await a.getRole(sampleRole.id)).toBeNull()
      })
    })

    describe('ISubjectStore', () => {
      it('getSubjectRoles returns [] when no assignments', async () => {
        const a = await factory()
        expect(await a.getSubjectRoles('nobody')).toEqual([])
      })

      it('assignRole + getSubjectRoles returns the role', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      it('revokeRole removes the assignment', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('getSubjectRoles returns ONLY unscoped (global) roles', async () => {
        // Every adapter must honour this contract. Returning scoped+unscoped
        // collapsed means the same subject decides differently across backends.
        const a = await factory()
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-1', 'editor', 'org-1')
        expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['viewer'])
      })

      it('getSubjectScopedRoles returns ONLY scoped assignments', async () => {
        const a = await factory()
        if (!a.getSubjectScopedRoles) return // optional method
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-1', 'editor', 'org-1')
        const scoped = await a.getSubjectScopedRoles('user-1')
        expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
      })

      it('revokeRole with scope removes only the scoped assignment', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.revokeRole('user-1', 'editor', 'org-1')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        if (a.getSubjectScopedRoles) {
          expect(await a.getSubjectScopedRoles('user-1')).toEqual([])
        }
      })

      it('revokeRole without scope removes ALL matching assignments', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-2')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
        if (a.getSubjectScopedRoles) {
          expect(await a.getSubjectScopedRoles('user-1')).toEqual([])
        }
      })

      it('getSubjectAttributes returns {} when none recorded', async () => {
        const a = await factory()
        expect(await a.getSubjectAttributes('nobody')).toEqual({})
      })

      it('setSubjectAttributes merges (does not replace)', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-1', { plan: 'pro' })
        expect(await a.getSubjectAttributes('user-1')).toEqual({ team: 'A', plan: 'pro' })
      })

      it('setSubjectAttributes overwrites existing key on second call', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-1', { team: 'B' })
        expect((await a.getSubjectAttributes('user-1')).team).toBe('B')
      })

      it('assignments are isolated per subject', async () => {
        const a = await factory()
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-2', 'viewer')
        expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['editor'])
        expect((await a.getSubjectRoles('user-2')).sort()).toEqual(['viewer'])
      })

      it('attributes are isolated per subject', async () => {
        const a = await factory()
        await a.setSubjectAttributes('user-1', { team: 'A' })
        await a.setSubjectAttributes('user-2', { team: 'B' })
        expect((await a.getSubjectAttributes('user-1')).team).toBe('A')
        expect((await a.getSubjectAttributes('user-2')).team).toBe('B')
      })
    })
  })
}
