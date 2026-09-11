import { describe, expect, it } from 'vitest'
import type { AccessControl, IamAdapter } from '../../core/types'
import type { OptionalSupport } from './optional-support'

// Adapter compliance suite: every adapter, shipped or third-party, must give the same results for these scenarios.

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

/** Parses a row as one arrives at runtime (HTTP body, config file), so tests can pass shapes the types forbid. */
function fromJson(json: string) {
  return JSON.parse(json)
}

/** A fresh adapter with `editor` and `viewer` stored, since `assignRole` refuses a role that is not stored. */
async function seeded(factory: () => AnyAdapter | Promise<AnyAdapter>): Promise<AnyAdapter> {
  const a = await factory()
  await a.saveRole(sampleRole)
  await a.saveRole({ id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] })
  return a
}

/**
 * Declared support and waivers for adapters that cannot meet a clause for a structural reason.
 * NOTE: a waiver covers the wording of a refusal, never the refusal itself.
 */
export interface IComplianceOptions {
  /**
   * Which optional methods the adapter implements; the only input deciding which clauses are registered.
   * NOTE: declared, not probed, so a method that disappears fails `optional-method-matrix.test.ts` instead of skipping.
   */
  readonly supports: OptionalSupport

  /**
   * The adapter's server owns role storage, so the unknown-role refusal is the server's text. Only `IamHttpAdapter`.
   * The assign must still reject; only the wording clauses are waived.
   */
  readonly delegatesRoleExistence?: boolean
}

/**
 * Registers the compliance suite for one adapter.
 *
 * @param adapterName - Name used in describe blocks.
 * @param factory - Returns a fresh, empty adapter per call; no state may be shared between calls.
 * @param opts - Declared support and structural waivers; see {@link IComplianceOptions}.
 * @example
 * ```ts
 * import { runAdapterCompliance } from '../../__compliance__/compliance'
 * runAdapterCompliance('MyAdapter', () => new MyAdapter({ ... }), { supports: { ... } })
 * ```
 */
export function runAdapterCompliance(
  adapterName: string,
  factory: () => AnyAdapter | Promise<AnyAdapter>,
  opts: IComplianceOptions,
): void {
  const { supports } = opts
  // Bound scoped-role reader that throws when the declared method is missing, rather than skipping the read-back.
  const requireScoped = (
    a: AnyAdapter,
  ): ((subjectId: string) => Promise<readonly { role: string; scope?: string }[]>) => {
    const read = a.getSubjectScopedRoles
    if (!read) throw new Error(`${adapterName} is recorded as implementing getSubjectScopedRoles`)
    return (subjectId) => read.call(a, subjectId)
  }
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

      // Same keys back on every backend. `version` reads as 1 because the SQL column cannot store "absent", so every
      // adapter defaults it on write.
      it('savePolicy + getPolicy returns the same shape on every backend', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const got = await a.getPolicy(samplePolicy.id)
        expect(got).not.toBeNull()
        expect(Object.keys(got ?? {}).sort()).toEqual(['algorithm', 'id', 'name', 'rules', 'version'])
        expect(got?.version).toBe(1)
      })

      // Saving a read-back row must not change it, or an export/import round trip would alter its own input.
      it('a saved policy and the same policy re-saved are identical', async () => {
        const a = await factory()
        await a.savePolicy(samplePolicy)
        const once = await a.getPolicy(samplePolicy.id)
        const b = await factory()
        if (once !== null) await b.savePolicy(once)
        expect(await b.getPolicy(samplePolicy.id)).toEqual(once)
      })

      // The normaliser drops absent optional keys, not populated ones.
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

      // A misspelled field is refused on every adapter, not dropped by some and kept by others.
      it('savePolicy refuses a field outside the policy type', async () => {
        const a = await factory()
        // A variable, not a literal, so no excess-property check applies, as for a row parsed from JSON.
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

    // Cases where adapters were measured disagreeing. Kept here, not per adapter, so a new adapter cannot miss them.
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
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      it('assigning the same scoped role twice does not duplicate it', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-1')
        if (supports.getSubjectScopedRoles) {
          expect(await requireScoped(a)('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
        }
      })

      // An unstored role is refused, not stored as a grant that `resolveSubject` would then drop.
      it('assigning a role that does not exist is refused', async () => {
        const a = await factory()
        await expect(a.assignRole('user-1', 'no-such-role')).rejects.toThrow()
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      // The same sentence on every adapter, not a driver error. SECURITY: it omits the role id, which is
      // caller-controlled and reaches operator logs.
      it('the unknown-role refusal reads the same on every adapter that owns its roles', async () => {
        if (opts.delegatesRoleExistence) return
        const a = await factory()
        await expect(a.assignRole('user-1', 'no-such-role')).rejects.toThrow(
          /^\[@gentleduck\/iam:[a-z]+\] cannot assign a role that is not stored; save the role before granting it$/,
        )
      })

      it('the refusal never echoes the role id back', async () => {
        // A catch, not `toThrow`, because this asserts what the message must not contain. Waived when delegating:
        // that text is the server's response body (the reference server quotes the id), not this package's.
        if (opts.delegatesRoleExistence) return
        const a = await factory()
        const caught = await a.assignRole('user-1', 'no-such-role').then(
          () => null,
          (err: unknown) => err,
        )
        expect(caught).not.toBeNull()
        expect(String(caught)).not.toContain('no-such-role')
      })

      it('a role deleted after the grant does not make a new grant assignable', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.deleteRole('editor')
        await expect(a.assignRole('user-2', 'editor')).rejects.toThrow()
      })

      // Grants go with their role, as SQL's `ON DELETE CASCADE` does.
      // SECURITY: an orphan grant would be held again if a role were recreated under the same id.
      it('deleting a role revokes the grants that named it', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-2', 'editor', 'team-a')
        await a.deleteRole('editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['viewer'])
        if (supports.getSubjectScopedRoles) expect(await requireScoped(a)('user-2')).toEqual([])
      })

      // SECURITY: redis spells "no scope" as "", so an empty scope would be stored as a global grant.
      it('an empty-string scope is refused on assign and on revoke', async () => {
        const a = await seeded(factory)
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

      // Ids that clash with an encoding (redis separator, http URL path): an adapter may refuse one with a named
      // error, but must never accept it and then fail to find it.
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
          // The read may throw instead of returning `null` (http does), but must never return a row the write refused.
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

      // SECURITY: `__proto__` is the prototype-pollution key; the row must read back and `Object.prototype` stay clean.
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

      // Only drizzle stores a validity window. Honour or refuse, never accept and drop: an elapsed grant is not live.
      it('either honours an expiresAt or refuses it by name', async () => {
        const a = await seeded(factory)
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
        const a = await seeded(factory)
        const future = new Date(Date.now() + 3_600_000)
        const refusal = await a.assignRole('user-1', 'editor', undefined, { startsAt: future }).then(
          () => null,
          (err: unknown) => String(err),
        )
        if (refusal !== null) expect(refusal).toMatch(/startsAt/)
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('either stores assignment attributes or refuses them by name', async () => {
        const a = await seeded(factory)
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

      // A non-object `attrs` is refused everywhere, never spread into per-character keys.
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

      // A malformed row is refused on write, so no adapter has to decide what to do with it on read.
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
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
      })

      it('revokeRole removes the assignment', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
      })

      it('getSubjectRoles returns ONLY unscoped (global) roles', async () => {
        // Returning scoped roles too would make the same subject decide differently across backends.
        const a = await seeded(factory)
        await a.assignRole('user-1', 'viewer')
        await a.assignRole('user-1', 'editor', 'org-1')
        expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['viewer'])
      })

      // Optional-method clauses are registered off the support matrix, not the instance, so the run has no skips.
      // Inside them, a missing method means the matrix is wrong, so it throws rather than asserting nothing.
      if (supports.getSubjectScopedRoles) {
        it('getSubjectScopedRoles returns ONLY scoped assignments', async () => {
          const a = await seeded(factory)
          const readScoped = a.getSubjectScopedRoles
          if (!readScoped) throw new Error(`${adapterName} is recorded as implementing getSubjectScopedRoles`)
          await a.assignRole('user-1', 'viewer')
          await a.assignRole('user-1', 'editor', 'org-1')
          const scoped = await readScoped.call(a, 'user-1')
          expect(scoped).toEqual([{ role: 'editor', scope: 'org-1' }])
        })
      }

      it('revokeRole with scope removes only the scoped assignment', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.revokeRole('user-1', 'editor', 'org-1')
        expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        if (supports.getSubjectScopedRoles) {
          expect(await requireScoped(a)('user-1')).toEqual([])
        }
      })

      it('revokeRole without scope removes ALL matching assignments', async () => {
        const a = await seeded(factory)
        await a.assignRole('user-1', 'editor')
        await a.assignRole('user-1', 'editor', 'org-1')
        await a.assignRole('user-1', 'editor', 'org-2')
        await a.revokeRole('user-1', 'editor')
        expect(await a.getSubjectRoles('user-1')).toEqual([])
        if (supports.getSubjectScopedRoles) {
          expect(await requireScoped(a)('user-1')).toEqual([])
        }
      })

      // Adapter-level only: the engine falls back to revoke + assign, so `runEngineCapabilityCompliance` pins these
      // scenarios on all six.
      if (supports.updateAssignmentScope) {
        // A move must neither leave the old row nor lose the new one, and its boolean must be true to what happened.
        it('updateAssignmentScope moves a scoped assignment and reports that it did', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor', 'org-1')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(true)
          if (supports.getSubjectScopedRoles) {
            // Exactly one row: the old scope is gone and no second grant sits beside the new one.
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
          }
          expect(await a.getSubjectRoles('user-1')).toEqual([])
        })

        it('updateAssignmentScope reports false for an assignment that is not there', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(false)
        })

        it('a false report is not a write - the move must not create the grant', async () => {
          // An upserting implementation would answer `false` and still grant `org-2`.
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')

          expect(await a.getSubjectRoles('user-1')).toEqual([])
          if (supports.getSubjectScopedRoles) expect(await requireScoped(a)('user-1')).toEqual([])
        })

        it('the from-scope has to match - a row in another scope is not moved', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor', 'org-9')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(false)
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'editor', scope: 'org-9' }])
          }
        })

        it('the role has to match - another role in the same scope is not moved', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'viewer', 'org-1')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(false)
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'viewer', scope: 'org-1' }])
          }
        })

        it('the subject has to match - another subject holding the same grant is untouched', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-2', 'editor', 'org-1')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(false)
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-2')).toEqual([{ role: 'editor', scope: 'org-1' }])
          }
        })

        it('undefined as the to-scope promotes a scoped grant to a global one', async () => {
          // The widening direction: afterwards the subject holds the role everywhere, not only in `org-1`.
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor', 'org-1')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', undefined)).toBe(true)
          expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
          if (supports.getSubjectScopedRoles) expect(await requireScoped(a)('user-1')).toEqual([])
        })

        it('undefined as the from-scope narrows a global grant into a scope', async () => {
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor')

          expect(await move.call(a, 'user-1', 'editor', undefined, 'org-1')).toBe(true)
          // The global grant must be gone, or the narrowing kept the broader access.
          expect(await a.getSubjectRoles('user-1')).toEqual([])
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
          }
        })

        it('an unscoped row is not what a scoped move is looking for', async () => {
          // `undefined` and `'org-1'` are different rows; a from-scope of `org-1` must not match the global grant.
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor')

          expect(await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')).toBe(false)
          expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        })

        it('moving onto a scope the subject already holds does not leave two rows', async () => {
          // A merge, not a refusal, but a duplicate `org-2` row would survive a later single revoke.
          const a = await seeded(factory)
          const move = a.updateAssignmentScope
          if (!move) throw new Error(`${adapterName} is recorded as implementing updateAssignmentScope`)
          await a.assignRole('user-1', 'editor', 'org-1')
          await a.assignRole('user-1', 'editor', 'org-2')

          await move.call(a, 'user-1', 'editor', 'org-1', 'org-2')
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
          }
        })
      }

      // Batch writes only optimise the per-row loop, so the engine suite pins the behaviour where they are absent.
      if (supports.assignRoleMany) {
        // Same rows as the loop, and any returned index names a write that actually happened, credited once.
        it('assignRoleMany stores the same rows the loop would have', async () => {
          const a = await seeded(factory)
          const assignMany = a.assignRoleMany
          if (!assignMany) throw new Error(`${adapterName} is recorded as implementing assignRoleMany`)

          const written = await assignMany.call(a, [
            { roleId: 'editor', subjectId: 'user-1' },
            { roleId: 'viewer', scope: 'org-1', subjectId: 'user-1' },
            { roleId: 'editor', subjectId: 'user-2' },
          ])

          expect((await a.getSubjectRoles('user-1')).sort()).toEqual(['editor'])
          expect(await a.getSubjectRoles('user-2')).toEqual(['editor'])
          if (supports.getSubjectScopedRoles) {
            expect(await requireScoped(a)('user-1')).toEqual([{ role: 'viewer', scope: 'org-1' }])
          }
          // `null` is an honest "the driver cannot say"; indices must be real.
          if (written !== null) expect(written.every((i) => Number.isInteger(i) && i >= 0 && i < 3)).toBe(true)
        })

        it('assignRoleMany does not credit a write for a grant that was already there', async () => {
          const a = await seeded(factory)
          const assignMany = a.assignRoleMany
          if (!assignMany) throw new Error(`${adapterName} is recorded as implementing assignRoleMany`)
          await a.assignRole('user-1', 'editor')

          const written = await assignMany.call(a, [{ roleId: 'editor', subjectId: 'user-1' }])
          if (written !== null) expect(written).toEqual([])
          // Either way the grant is held exactly once.
          expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        })

        it('assignRoleMany credits a duplicated row once, not twice', async () => {
          // Two rows, one write: at most one index may name it (`creditWrites` credits the first).
          const a = await seeded(factory)
          const assignMany = a.assignRoleMany
          if (!assignMany) throw new Error(`${adapterName} is recorded as implementing assignRoleMany`)

          const written = await assignMany.call(a, [
            { roleId: 'editor', subjectId: 'user-1' },
            { roleId: 'editor', subjectId: 'user-1' },
          ])
          if (written !== null) expect(written.length).toBeLessThanOrEqual(1)
          expect(await a.getSubjectRoles('user-1')).toEqual(['editor'])
        })
      }

      if (supports.revokeRoleMany) {
        it('revokeRoleMany removes the same rows the loop would have', async () => {
          const a = await seeded(factory)
          const revokeMany = a.revokeRoleMany
          if (!revokeMany) throw new Error(`${adapterName} is recorded as implementing revokeRoleMany`)
          await a.assignRole('user-1', 'editor')
          await a.assignRole('user-1', 'viewer', 'org-1')
          await a.assignRole('user-2', 'editor')

          await revokeMany.call(a, [
            { roleId: 'editor', subjectId: 'user-1' },
            { roleId: 'viewer', scope: 'org-1', subjectId: 'user-1' },
          ])

          expect(await a.getSubjectRoles('user-1')).toEqual([])
          if (supports.getSubjectScopedRoles) expect(await requireScoped(a)('user-1')).toEqual([])
          // The row nobody asked about survives - a batch revoke is not a purge.
          expect(await a.getSubjectRoles('user-2')).toEqual(['editor'])
        })

        it('revokeRoleMany does not credit a write for a grant that was not there', async () => {
          const a = await seeded(factory)
          const revokeMany = a.revokeRoleMany
          if (!revokeMany) throw new Error(`${adapterName} is recorded as implementing revokeRoleMany`)

          const removed = await revokeMany.call(a, [{ roleId: 'editor', subjectId: 'user-1' }])
          if (removed !== null) expect(removed).toEqual([])
        })
      }

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
        const a = await seeded(factory)
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
