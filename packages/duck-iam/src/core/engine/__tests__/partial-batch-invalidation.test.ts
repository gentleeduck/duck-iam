import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { withoutInPlaceUpdate } from '../../../test/adapter-capabilities'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

// The per-row batch loop is not atomic, so a batch that throws part-way must still invalidate and announce
// the rows that landed. SECURITY: otherwise a revoked grant keeps answering allow until the TTL.
type Action = 'read'
type Res = 'post'
const POST = { attributes: {}, type: 'post' as const }
const ADMIN = { id: 'admin', name: 'admin', permissions: [{ action: 'read' as const, resource: 'post' as const }] }

/** A memory adapter whose Nth single-row write throws, mid-loop. */
class FlakyRow extends IamMemoryAdapter<Action, Res, string, string> {
  assignCalls = 0
  failAssignOn = -1
  revokeCalls = 0
  failRevokeOn = -1

  override async assignRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    this.assignCalls++
    if (this.assignCalls === this.failAssignOn) throw new Error('connection reset')
    await super.assignRole(subjectId, roleId, scope)
  }

  override async revokeRole(subjectId: string, roleId: string, scope?: string): Promise<void> {
    this.revokeCalls++
    if (this.revokeCalls === this.failRevokeOn) throw new Error('connection reset')
    await super.revokeRole(subjectId, roleId, scope)
  }
}

/** A memory adapter with a set-based revoke that half-writes and then throws. */
class HalfWritingMany extends IamMemoryAdapter<Action, Res, string, string> {
  async revokeRoleMany(
    rows: readonly { subjectId: string; roleId: string; scope?: string }[],
  ): Promise<readonly number[] | null> {
    // Writes the first row, then fails: a statement abandoned halfway, so the engine cannot know how far it got.
    const first = rows[0]
    if (first) await super.revokeRole(first.subjectId, first.roleId, first.scope)
    throw new Error('connection reset')
  }
}

async function harness(adapter: IamMemoryAdapter<Action, Res, string, string>) {
  const events: string[] = []
  const engine = new IamEngine<Action, Res, string, string>({
    adapter,
    cacheTTL: 60_000,
    hooks: {
      onMutation: (e: IamEngineTypes.IMutationEvent<string, string>) => {
        events.push('subjectId' in e ? `${e.type}:${e.subjectId}` : e.type)
      },
    },
  })
  await adapter.saveRole(ADMIN)
  return { engine, events }
}

const THREE = ['u1', 'u2', 'u3'] as const

describe('a batch that fails part-way still settles the rows that landed', () => {
  it('the batch really does stop at the failing row', async () => {
    // Control: the tests below assume a partial write; an all-or-nothing batch would pass them for the wrong reason.
    const adapter = new FlakyRow()
    const { engine } = await harness(adapter)
    for (const u of THREE) await adapter.assignRole(u, 'admin')
    for (const u of THREE) expect(await engine.can(u, 'read', POST), `${u} not warmed`).toBe(true)

    adapter.failRevokeOn = adapter.revokeCalls + 2
    await expect(engine.admin.revokeRoles(THREE.map((u) => ({ roleId: 'admin', subjectId: u })))).rejects.toThrow(
      'connection reset',
    )
    expect(await adapter.getSubjectRoles('u1'), 'row one did not land').toEqual([])
    expect(await adapter.getSubjectRoles('u3'), 'row three ran anyway').toEqual(['admin'])
  })

  it('the engine denies the subject whose revoke landed', async () => {
    const adapter = new FlakyRow()
    const { engine } = await harness(adapter)
    for (const u of THREE) await adapter.assignRole(u, 'admin')
    for (const u of THREE) await engine.can(u, 'read', POST)

    adapter.failRevokeOn = adapter.revokeCalls + 2
    await expect(engine.admin.revokeRoles(THREE.map((u) => ({ roleId: 'admin', subjectId: u })))).rejects.toThrow()

    expect(await engine.can('u1', 'read', POST)).toBe(false)
    // The unreached row still allows, so this does not pass by denying everything.
    expect(await engine.can('u3', 'read', POST)).toBe(true)
  })

  it('the rows that landed are announced, and only those', async () => {
    const adapter = new FlakyRow()
    const { engine, events } = await harness(adapter)
    for (const u of THREE) await adapter.assignRole(u, 'admin')

    adapter.failRevokeOn = adapter.revokeCalls + 2
    await expect(engine.admin.revokeRoles(THREE.map((u) => ({ roleId: 'admin', subjectId: u })))).rejects.toThrow()

    expect(events).toEqual(['role.revoked:u1'])
  })

  it('the same holds for a partial assign', async () => {
    const adapter = new FlakyRow()
    const { engine, events } = await harness(adapter)
    // Warm a deny for each, so a stale cache would show as a lingering deny.
    for (const u of THREE) expect(await engine.can(u, 'read', POST)).toBe(false)

    adapter.failAssignOn = adapter.assignCalls + 2
    await expect(engine.admin.assignRoles(THREE.map((u) => ({ roleId: 'admin', subjectId: u })))).rejects.toThrow()

    expect(await engine.can('u1', 'read', POST)).toBe(true)
    expect(await engine.can('u3', 'read', POST)).toBe(false)
    expect(events).toEqual(['role.assigned:u1'])
  })

  it('a set-based write that fails invalidates every subject it named', async () => {
    // The adapter cannot say how far it got, so every named subject is dropped: over-invalidating only costs a reload.
    const adapter = new HalfWritingMany()
    const { engine, events } = await harness(adapter)
    for (const u of THREE) await adapter.assignRole(u, 'admin')
    for (const u of THREE) expect(await engine.can(u, 'read', POST)).toBe(true)

    await expect(engine.admin.revokeRoles(THREE.map((u) => ({ roleId: 'admin', subjectId: u })))).rejects.toThrow(
      'connection reset',
    )

    expect(await engine.can('u1', 'read', POST)).toBe(false)
    // Still granted in the store, and re-read rather than served stale.
    expect(await engine.can('u2', 'read', POST)).toBe(true)
    // Nothing is announced: the adapter cannot say which rows landed.
    expect(events).toEqual([])
  })

  it('a move whose re-grant fails does not leave the old scope cached', async () => {
    // `moveOne` emulates the move as revoke + assign; a failed assign leaves nothing held but the old scope cached.
    const adapter = withoutInPlaceUpdate(new FlakyRow())
    const { engine } = await harness(adapter)
    await adapter.assignRole('u1', 'admin', 'org-1')
    expect(await engine.can('u1', 'read', POST, undefined, 'org-1')).toBe(true)

    adapter.failAssignOn = adapter.assignCalls + 1
    await expect(engine.admin.updateAssignmentScope('u1', 'admin', 'org-1', 'org-2')).rejects.toThrow(
      'connection reset',
    )

    expect(await adapter.getSubjectRoles('u1'), 'the revoke half did not land').toEqual([])
    expect(await engine.can('u1', 'read', POST, undefined, 'org-1')).toBe(false)
  })
})
