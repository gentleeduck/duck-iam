import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import type { AccessControl } from '../../types'

/**
 * `scopeMode: 'hierarchical'` meant two different things depending on where the
 * scope was written. A scoped *assignment* at `org-1` reached
 * `org-1.team-a`, because `scopeAncestors` walked the request's scope up to it.
 * A semantically identical role-declared `scope: 'org-1'` did not:
 * `rolesToPolicy` emitted a flat `scope eq 'org-1'` with no awareness of the
 * flag, and the compiled table compared `g.scope !== req.scope` outright. A
 * hierarchical deployment silently lost every role-declared grant below the
 * exact level, and the obvious workaround is to widen the role to `'*'`.
 */
const roles: AccessControl.IRole[] = [
  { id: 'org-editor', name: 'Org Editor', permissions: [{ action: 'write', resource: 'doc' }], scope: 'org-1' },
  { id: 'plain-editor', name: 'Plain Editor', permissions: [{ action: 'write', resource: 'doc' }] },
]

const resource = { attributes: {}, type: 'doc' }

/** `check()` returns a decision in development and a bare boolean in production. */
function allowedOf(result: unknown): boolean {
  if (typeof result === 'boolean') return result
  if (result !== null && typeof result === 'object' && 'allowed' in result) return result.allowed === true
  throw new Error(`unrecognised check() result: ${JSON.stringify(result)}`)
}

type AnyModeEngine = IamEngine<string, string, string, string, 'development' | 'production'>

async function engineWith(
  mode: 'development' | 'production',
  scopeMode: 'flat' | 'hierarchical',
): Promise<AnyModeEngine> {
  const adapter = new IamMemoryAdapter({ assignments: {}, policies: [], roles })
  // Held at the exact scope the role declares, so only the role's own scope
  // condition decides whether the request at a descendant is granted.
  await adapter.assignRole('u1', 'org-editor')
  await adapter.assignRole('u2', 'plain-editor', 'org-1')
  return new IamEngine({ adapter, mode, scopeMode })
}

const MODES = ['development', 'production'] as const

describe.each(MODES)('%s: a role-declared scope under hierarchical', (mode) => {
  it('grants at the exact scope', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-1'))).toBe(true)
  })

  it('grants at a descendant scope', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-1.team-a'))).toBe(true)
  })

  it('grants two levels down', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-1.team-a.repo-b'))).toBe(true)
  })

  // The prefix is a path segment, not a string prefix: `org-10` is a different
  // organisation, and `org-1x` is not below `org-1`.
  it('does not grant a sibling scope that merely shares the prefix', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-10'))).toBe(false)
  })

  it('does not grant an unrelated scope', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-2'))).toBe(false)
  })

  it('does not grant an ancestor of the declared scope', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org'))).toBe(false)
  })

  // The two kinds of scope now agree, which is the whole point: this is the
  // scoped-assignment case that already worked.
  it('agrees with the same grant expressed as a scoped assignment', async () => {
    const engine = await engineWith(mode, 'hierarchical')
    expect(allowedOf(await engine.check('u2', 'write', resource, {}, 'org-1.team-a'))).toBe(true)
  })
})

describe.each(MODES)('%s: flat is still exact', (mode) => {
  it('grants at the exact scope', async () => {
    const engine = await engineWith(mode, 'flat')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-1'))).toBe(true)
  })

  it('does not grant a descendant', async () => {
    const engine = await engineWith(mode, 'flat')
    expect(allowedOf(await engine.check('u1', 'write', resource, {}, 'org-1.team-a'))).toBe(false)
  })

  // Control: the scoped assignment is exact under `'flat'` too, so the two
  // kinds of scope agree in this direction as well.
  it('does not grant a descendant for the scoped assignment either', async () => {
    const engine = await engineWith(mode, 'flat')
    expect(allowedOf(await engine.check('u2', 'write', resource, {}, 'org-1.team-a'))).toBe(false)
  })
})
