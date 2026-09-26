import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// reportUnmatchableRules and reportDeadConditionPaths dedupe independently, but both were once handed the same
// "already reported" set. reportUnmatchableRules's key is the fixed string "<policy>\0<rule>\0unmatchable"; a
// condition whose field is literally that word makes reportDeadConditionPaths compute the identical key for the
// same rule. Sharing one set meant whichever ran first (the condition-path check) silently swallowed the other's
// distinct, unrelated warning about the same rule - including one about a deny that can never fire.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [{ id: 'writer', name: 'W', permissions: [] }]

describe('a rule dead for two unrelated reasons at once reports both', () => {
  it('reports the empty "actions" list and the dead condition path, not just one', async () => {
    const reported: string[] = []
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'P',
      rules: [
        {
          actions: ['delete'],
          conditions: { all: [] },
          effect: 'allow',
          id: 'allow',
          priority: 1,
          resources: ['post'],
        },
        {
          // Empty actions alone makes reportUnmatchableRules key this "p\0deny\0unmatchable".
          actions: [],
          // A field literally named "unmatchable" makes reportDeadConditionPaths key this rule the same way.
          conditions: { all: [{ field: 'unmatchable', operator: 'eq', value: true }] },
          effect: 'deny',
          id: 'deny',
          priority: 10,
          resources: ['post'],
        },
      ],
    }
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [policy], roles: ROLES }),
      hooks: { onPolicyError: (e: Error) => reported.push(e.message) },
      mode: 'production',
    })

    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(2)
    expect(reported.some((m) => m.includes('empty "actions" list'))).toBe(true)
    expect(reported.some((m) => m.includes('resolves to null on every request'))).toBe(true)
  })
})
