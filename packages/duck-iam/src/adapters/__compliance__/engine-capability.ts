import { describe, expect, it } from 'vitest'
import { IamEngine } from '../../core/engine/engine'
import type { IamEngineTypes } from '../../core/engine/engine.types'
import type { AccessControl, IamAdapter } from '../../core/types'

// Pins scope moves and batch writes through `engine.admin`, where the engine's fallbacks for optional adapter
// methods make them universal, so every clause runs on every adapter.
type AnyAdapter = IamAdapter.IAdapter<string, string, string, string>

const GRANTABLE: readonly AccessControl.IRole[] = [
  { id: 'editor', name: 'Editor', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
]

/** The adapter, the engine over it, and the events that engine emitted. */
interface IHarness {
  readonly adapter: AnyAdapter
  readonly engine: IamEngine<string, string, string, string>
  readonly events: IamEngineTypes.IMutationEvent[]
}

/** A fresh adapter with `GRANTABLE` saved through it (only memory takes a seed), wrapped in an engine. */
async function harness(factory: () => AnyAdapter | Promise<AnyAdapter>): Promise<IHarness> {
  const adapter = await factory()
  for (const role of GRANTABLE) await adapter.saveRole(role)
  const events: IamEngineTypes.IMutationEvent[] = []
  const engine = new IamEngine<string, string, string, string>({
    adapter,
    hooks: { onMutation: (e) => void events.push(e) },
  })
  return { adapter, engine, events }
}

/** The subject's scoped rows, sorted; throws a named error if the adapter has no `getSubjectScopedRoles`. */
async function scopedRows(a: AnyAdapter, subjectId: string): Promise<Array<{ role: string; scope?: string }>> {
  const read = a.getSubjectScopedRoles
  if (!read) throw new Error('runEngineCapabilityCompliance requires an adapter that implements getSubjectScopedRoles')
  const rows = await read.call(a, subjectId)
  // `scope` is not defaulted: a scoped row without one is an adapter bug and must show in the assertion.
  return [...rows]
    .map((r) => ({ role: r.role, scope: r.scope }))
    .sort((x, y) => x.role.localeCompare(y.role) || (x.scope ?? '').localeCompare(y.scope ?? ''))
}

/** Both halves of a subject's holdings, for the cases that assert on each. */
async function holdings(a: AnyAdapter, subjectId: string) {
  return { global: (await a.getSubjectRoles(subjectId)).slice().sort(), scoped: await scopedRows(a, subjectId) }
}

/**
 * Registers the engine-level capability suite for one adapter.
 * NOTE: the adapter must implement `getSubjectScopedRoles`; every scope assertion reads back through it.
 *
 * @param adapterName - Name used in describe blocks.
 * @param factory - Returns a fresh, empty adapter per call.
 * @example
 * ```ts
 * runEngineCapabilityCompliance('MyAdapter', () => new MyAdapter({ ... }))
 * ```
 */
export function runEngineCapabilityCompliance(
  adapterName: string,
  factory: () => AnyAdapter | Promise<AnyAdapter>,
): void {
  describe(`IamEngine capability compliance: ${adapterName}`, () => {
    describe('admin.updateAssignmentScope', () => {
      it('moves a scoped assignment, leaving exactly one row', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        // One row, not two - the destination must not sit beside the source.
        expect(await holdings(adapter, 'user-1')).toEqual({ global: [], scoped: [{ role: 'editor', scope: 'org-2' }] })
      })

      it('creates nothing when the subject holds no such grant', async () => {
        // A move is not an upsert: with no row at `org-1` there is nothing to move.
        const { adapter, engine } = await harness(factory)

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await holdings(adapter, 'user-1')).toEqual({ global: [], scoped: [] })
      })

      it('emits no scope-changed event when nothing moved', async () => {
        // A downstream replicator would otherwise create the grant this engine declined to create.
        const { engine, events } = await harness(factory)

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(events.filter((e) => e.type === 'role.scope-changed')).toEqual([])
      })

      it('emits exactly one scope-changed event carrying both ends and the actor', async () => {
        const { adapter, engine, events } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2', 'ops@example.com')

        const moved = events.filter((e) => e.type === 'role.scope-changed')
        expect(moved).toHaveLength(1)
        expect(moved[0]).toMatchObject({
          actor: 'ops@example.com',
          fromScope: 'org-1',
          roleId: 'editor',
          subjectId: 'user-1',
          toScope: 'org-2',
        })
      })

      it('the from-scope has to match - a row in another scope is not moved', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-3')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'editor', scope: 'org-3' }])
      })

      it('the role has to match - another role in the same scope is not moved', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'viewer', 'org-1')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'viewer', scope: 'org-1' }])
      })

      it('the subject has to match - another subject holding the same grant is untouched', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-2', 'editor', 'org-1')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await holdings(adapter, 'user-1')).toEqual({ global: [], scoped: [] })
        expect(await scopedRows(adapter, 'user-2')).toEqual([{ role: 'editor', scope: 'org-1' }])
      })

      it('undefined as the to-scope promotes a scoped grant to a global one', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', undefined)

        expect(await holdings(adapter, 'user-1')).toEqual({ global: ['editor'], scoped: [] })
      })

      it('undefined as the from-scope narrows a global grant into a scope', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor')

        await engine.admin.updateAssignmentScope('user-1', 'editor', undefined, 'org-1')

        expect(await holdings(adapter, 'user-1')).toEqual({ global: [], scoped: [{ role: 'editor', scope: 'org-1' }] })
      })

      it('an unscoped row is not what a scoped move is looking for', async () => {
        // Matching the global row would widen every scoped move to "or the global grant".
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await holdings(adapter, 'user-1')).toEqual({ global: ['editor'], scoped: [] })
      })

      it('moving onto a scope the subject already holds does not leave two rows', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')
        await adapter.assignRole('user-1', 'editor', 'org-2')

        await engine.admin.updateAssignmentScope('user-1', 'editor', 'org-1', 'org-2')

        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
      })

      it('moveRoleScopes applies every row and reports one outcome each', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')
        await adapter.assignRole('user-2', 'viewer', 'org-1')

        const result = await engine.admin.moveRoleScopes([
          { fromScope: 'org-1', roleId: 'editor', subjectId: 'user-1', toScope: 'org-2' },
          { fromScope: 'org-1', roleId: 'viewer', subjectId: 'user-2', toScope: 'org-2' },
        ])

        expect(result.applied).toBe(2)
        expect(result.outcomes.every((o) => o.ok)).toBe(true)
        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
        expect(await scopedRows(adapter, 'user-2')).toEqual([{ role: 'viewer', scope: 'org-2' }])
      })

      it('a batch is not all-or-nothing about matching - a missing row moves nothing of its own', async () => {
        // Row two names a missing grant: it must not be created, and must not stop row one.
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor', 'org-1')

        await engine.admin.moveRoleScopes([
          { fromScope: 'org-1', roleId: 'editor', subjectId: 'user-1', toScope: 'org-2' },
          { fromScope: 'org-1', roleId: 'viewer', subjectId: 'user-2', toScope: 'org-2' },
        ])

        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'editor', scope: 'org-2' }])
        expect(await holdings(adapter, 'user-2')).toEqual({ global: [], scoped: [] })
      })
    })

    describe('admin.assignRoles', () => {
      it('stores the same rows the loop would have', async () => {
        const { adapter, engine } = await harness(factory)

        const result = await engine.admin.assignRoles([
          { roleId: 'editor', subjectId: 'user-1' },
          { roleId: 'viewer', scope: 'org-1', subjectId: 'user-1' },
        ])

        expect(result.applied).toBe(2)
        expect(await holdings(adapter, 'user-1')).toEqual({
          global: ['editor'],
          scoped: [{ role: 'viewer', scope: 'org-1' }],
        })
      })

      it('an already-granted row is still applied - the postcondition holds either way', async () => {
        // `applied` counts rows whose postcondition holds, not statements run, as single-row `assignRole` does.
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor')

        const result = await engine.admin.assignRoles([{ roleId: 'editor', subjectId: 'user-1' }])

        expect(result.applied).toBe(1)
        expect(result.outcomes.every((o) => o.ok)).toBe(true)
        expect((await adapter.getSubjectRoles('user-1')).filter((r) => r === 'editor')).toEqual(['editor'])
      })

      it('the identical triple listed twice leaves one row, not two', async () => {
        const { adapter, engine } = await harness(factory)

        await engine.admin.assignRoles([
          { roleId: 'editor', scope: 'org-1', subjectId: 'user-1' },
          { roleId: 'editor', scope: 'org-1', subjectId: 'user-1' },
        ])

        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'editor', scope: 'org-1' }])
      })
    })

    describe('admin.revokeRoles', () => {
      it('removes the same rows the loop would have', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'editor')
        await adapter.assignRole('user-1', 'viewer', 'org-1')

        const result = await engine.admin.revokeRoles([
          { roleId: 'editor', subjectId: 'user-1' },
          { roleId: 'viewer', scope: 'org-1', subjectId: 'user-1' },
        ])

        expect(result.applied).toBe(2)
        expect(await holdings(adapter, 'user-1')).toEqual({ global: [], scoped: [] })
      })

      it('revoking a grant that was never there changes nothing and creates nothing', async () => {
        const { adapter, engine } = await harness(factory)
        await adapter.assignRole('user-1', 'viewer', 'org-1')

        const result = await engine.admin.revokeRoles([{ roleId: 'editor', scope: 'org-9', subjectId: 'user-1' }])

        expect(result.outcomes.every((o) => o.ok)).toBe(true)
        expect(await scopedRows(adapter, 'user-1')).toEqual([{ role: 'viewer', scope: 'org-1' }])
      })
    })
  })
}
