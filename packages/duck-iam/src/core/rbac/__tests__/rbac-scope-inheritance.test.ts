import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../engine/engine'
import type { AccessControl } from '../../types'
import { rolesToPolicy } from '../rbac'

/**
 * The suite tested inheritance and scope as strictly separate axes: a role that
 * inherits, or a role that is scoped, never one that does both. That is exactly
 * the cell the cross-scope mistagging bug lived in - an inherited permission
 * was attributed to the *inheriting* role and so picked up the wrong scope,
 * which the two engines then disagreed about. Nothing in
 * `compiled.differential.test.ts` compiled such a graph either, so the
 * differential suite that exists to catch dev/prod splits could not see it.
 *
 * The rule is: a permission's scope belongs to the role that **declared** it,
 * never to whoever inherits it. All four cells are below.
 */
type Cell = {
  readonly childScope?: string
  readonly expected: string | undefined
  readonly label: string
  readonly parentScope?: string
}

const CELLS: Cell[] = [
  { expected: 'org-1', label: 'scoped parent, unscoped child', parentScope: 'org-1' },
  { childScope: 'org-2', expected: 'org-1', label: 'both scoped, different', parentScope: 'org-1' },
  { childScope: 'org-1', expected: 'org-1', label: 'both scoped, same', parentScope: 'org-1' },
  { childScope: 'org-2', expected: undefined, label: 'unscoped parent, scoped child' },
  { expected: undefined, label: 'neither scoped' },
]

function graph(cell: Cell): AccessControl.IRole[] {
  return [
    { id: 'parent', name: 'Parent', permissions: [{ action: 'read', resource: 'post' }], scope: cell.parentScope },
    { id: 'child', name: 'Child', inherits: ['parent'], permissions: [], scope: cell.childScope },
  ]
}

/**
 * The `value` of the `scope` condition on one rule, if it has one. The base
 * conditions sit directly in the rule's `all` for a permission with no
 * conditions of its own, and one level down when the author supplied a group.
 */
function scopeConditionOf(policy: AccessControl.IPolicy, ruleDescription: RegExp): string | undefined {
  const rule = policy.rules.find((r) => r.description !== undefined && ruleDescription.test(r.description))
  if (rule === undefined) throw new Error(`no rule matching ${ruleDescription}`)
  const group = rule.conditions
  if (!('all' in group)) throw new Error('expected an `all` group')
  const first = group.all[0]
  const base = first !== undefined && !('field' in first) && 'all' in first ? first.all : group.all
  for (const item of base) {
    if ('field' in item && item.field === 'scope') return typeof item.value === 'string' ? item.value : undefined
  }
  return undefined
}

describe('a permission inherited across a scope boundary keeps its declarer scope', () => {
  it.each(CELLS)('$label', (cell) => {
    const policy = rolesToPolicy(graph(cell))
    expect(scopeConditionOf(policy, /^Child: read on post \(via Parent\)$/)).toBe(cell.expected)
  })

  // Control: the parent's own rule always carries the parent's scope, so the
  // assertions above are about the inherited copy and not about the emission
  // being scope-blind altogether.
  it.each(CELLS)('$label: the parent own rule is unaffected', (cell) => {
    const policy = rolesToPolicy(graph(cell))
    expect(scopeConditionOf(policy, /^Parent: read on post$/)).toBe(cell.parentScope)
  })
})

const resource = { attributes: {}, type: 'post' }

/** `check()` returns a decision in development and a bare boolean in production. */
function allowedOf(result: unknown): boolean {
  if (typeof result === 'boolean') return result
  if (result !== null && typeof result === 'object' && 'allowed' in result) return result.allowed === true
  throw new Error(`unrecognised check() result: ${JSON.stringify(result)}`)
}

async function check(mode: 'development' | 'production', cell: Cell, scope: string | undefined): Promise<boolean> {
  const adapter = new IamMemoryAdapter({ assignments: {}, policies: [], roles: graph(cell) })
  await adapter.assignRole('u1', 'child')
  const engine: IamEngine<string, string, string, string, 'development' | 'production'> = new IamEngine({
    adapter,
    mode,
  })
  return allowedOf(await engine.check('u1', 'read', resource, {}, scope))
}

const SCOPES = [undefined, 'org-1', 'org-2'] as const

describe('the two engines agree on every scope x inheritance cell', () => {
  for (const cell of CELLS) {
    for (const scope of SCOPES) {
      it(`${cell.label}, request scope ${scope ?? '(none)'}`, async () => {
        expect(await check('production', cell, scope)).toBe(await check('development', cell, scope))
      })
    }
  }

  // Controls: the grant is real at the scope it was declared for, and absent at
  // the one it was not - without these the agreement above could be "everything
  // denies in both engines".
  it('control: a scoped-parent grant fires at the declared scope', async () => {
    const cell = CELLS[0]
    if (cell === undefined) throw new Error('missing cell')
    expect(await check('development', cell, 'org-1')).toBe(true)
    expect(await check('production', cell, 'org-1')).toBe(true)
  })

  it("control: it does not fire at the child's own scope", async () => {
    const cell = CELLS[1]
    if (cell === undefined) throw new Error('missing cell')
    expect(await check('development', cell, 'org-2')).toBe(false)
    expect(await check('production', cell, 'org-2')).toBe(false)
  })
})
