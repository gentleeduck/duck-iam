import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../../adapters/memory'
import type { AccessControl, IamPrimitives } from '../../../types'
import { IamEngine } from '../../engine'

// Both `policyCombine` modes this engine supports ('and', 'allow-overrides') are defined
// as commutative: the combined decision must not depend on the order policies/roles were
// declared, loaded, or iterated in. Unlike 'first-applicable' (excluded from `mode:
// 'production'` entirely), neither mode should ever short-circuit on iteration order - a
// bug that accidentally introduced order-sensitivity (e.g. a stray `.find()` instead of
// `.every()`/`.some()`, or a Map-iteration-order dependency) would be invisible to every
// other test in this suite, since they all use one fixed declaration order. This file
// holds that fixed input constant and permutes only the declaration order.

const basePolicies: AccessControl.IPolicy[] = [
  {
    id: 'allow-read',
    name: 'Allow read',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r1', effect: 'allow', priority: 0, actions: ['read'], resources: ['post'], conditions: { all: [] } },
    ],
  },
  {
    id: 'allow-update-owned',
    name: 'Allow update if owned',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'r2',
        effect: 'allow',
        priority: 0,
        actions: ['update'],
        resources: ['post'],
        conditions: {
          all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }],
        },
      },
    ],
  },
  {
    id: 'deny-delete',
    name: 'Deny delete',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r3', effect: 'deny', priority: 0, actions: ['delete'], resources: ['post'], conditions: { all: [] } },
    ],
  },
  {
    id: 'wildcard-admin',
    name: 'Wildcard admin actions',
    algorithm: 'allow-overrides',
    rules: [
      { id: 'r4', effect: 'allow', priority: 0, actions: ['admin:*'], resources: ['post'], conditions: { all: [] } },
    ],
  },
]

const baseRoles: AccessControl.IRole[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'comment' }] },
  {
    id: 'editor',
    name: 'Editor',
    inherits: ['viewer'],
    permissions: [{ action: 'update', resource: 'comment', scope: 'org-1' }],
  },
  { id: 'admin', name: 'Admin', inherits: ['editor'], permissions: [{ action: 'delete', resource: 'comment' }] },
]

const assignments = { u1: ['editor'], u2: ['admin'], u3: [] }
const attributes = { u1: {}, u2: {}, u3: {} }

/** Deterministic array shuffle (Fisher-Yates over a fixed permutation index list, no Math.random). */
function permute<T>(arr: readonly T[], perm: readonly number[]): T[] {
  return perm.map((i) => arr[i]!)
}

// A handful of fixed, distinct permutations of [0,1,2,3] - covers reversed, rotated, and
// swapped-pairs orderings without needing a full 24-permutation exhaustive sweep.
const POLICY_PERMS: readonly number[][] = [
  [0, 1, 2, 3],
  [3, 2, 1, 0],
  [1, 3, 0, 2],
  [2, 0, 3, 1],
]
const ROLE_PERMS: readonly number[][] = [
  [0, 1, 2],
  [2, 1, 0],
  [1, 2, 0],
]

const REQUESTS: readonly {
  subjectId: string
  action: string
  resource: { type: string; attributes: IamPrimitives.Attributes }
}[] = [
  { subjectId: 'u1', action: 'read', resource: { type: 'post', attributes: {} } },
  { subjectId: 'u1', action: 'update', resource: { type: 'post', attributes: { ownerId: 'u1' } } },
  { subjectId: 'u1', action: 'update', resource: { type: 'post', attributes: { ownerId: 'someone-else' } } },
  { subjectId: 'u2', action: 'delete', resource: { type: 'post', attributes: {} } },
  { subjectId: 'u2', action: 'admin:ban', resource: { type: 'post', attributes: {} } },
  { subjectId: 'u1', action: 'read', resource: { type: 'comment', attributes: {} } },
  { subjectId: 'u2', action: 'update', resource: { type: 'comment', attributes: {} } },
  { subjectId: 'u2', action: 'delete', resource: { type: 'comment', attributes: {} } },
  { subjectId: 'u3', action: 'read', resource: { type: 'post', attributes: {} } },
]

describe.each([
  'and',
  'allow-overrides',
] as const)('combine-order invariance (policyCombine: %s) - declaration order must not change any decision', (policyCombine) => {
  it('every policy-array permutation × role-array permutation agrees with the canonical order', async () => {
    const canonical = new IamEngine({
      adapter: new IamMemoryAdapter({ roles: baseRoles, policies: basePolicies, assignments, attributes }),
      defaultEffect: 'deny',
      mode: 'production',
      policyCombine,
    })
    const canonicalResults = await Promise.all(REQUESTS.map((r) => canonical.can(r.subjectId, r.action, r.resource)))

    for (const pperm of POLICY_PERMS) {
      for (const rperm of ROLE_PERMS) {
        const engine = new IamEngine({
          adapter: new IamMemoryAdapter({
            roles: permute(baseRoles, rperm),
            policies: permute(basePolicies, pperm),
            assignments,
            attributes,
          }),
          defaultEffect: 'deny',
          mode: 'production',
          policyCombine,
        })
        for (let i = 0; i < REQUESTS.length; i++) {
          const r = REQUESTS[i]!
          const got = await engine.can(r.subjectId, r.action, r.resource)
          expect(
            got,
            `policyCombine=${policyCombine} pperm=${pperm.join(',')} rperm=${rperm.join(',')} request#${i}=${JSON.stringify(r)}`,
          ).toBe(canonicalResults[i])
        }
      }
    }
  })
})

describe('wildcard action/resource patterns are separator-bound, not raw substring prefixes (confirmation)', () => {
  it("'admin:*' does not match an action that merely starts with the same letters without the separator", async () => {
    const policies: AccessControl.IPolicy[] = [
      {
        id: 'wild',
        name: 'Wild',
        algorithm: 'deny-overrides',
        rules: [
          {
            id: 'w',
            effect: 'allow',
            priority: 0,
            actions: ['admin:*'],
            resources: ['post'],
            conditions: { all: [] },
          },
        ],
      },
    ]
    const adapter = new IamMemoryAdapter({ roles: [], policies, assignments: { u1: [] }, attributes: { u1: {} } })
    const engine = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    // Matches: shares the 'admin:' separator-bound prefix.
    expect(await engine.can('u1', 'admin:ban', { type: 'post', attributes: {} })).toBe(true)
    // Must NOT match: 'adminX' shares the raw substring 'admin' but not the 'admin:' prefix
    // (a naive `action.startsWith('admin')` check, instead of `startsWith('admin:')`, would
    // wrongly allow this).
    expect(await engine.can('u1', 'adminXban', { type: 'post', attributes: {} })).toBe(false)
    expect(await engine.can('u1', 'administer', { type: 'post', attributes: {} })).toBe(false)
  })

  it("'org.*' resource wildcard does not match a hyphen-joined lookalike", async () => {
    const policies: AccessControl.IPolicy[] = [
      {
        id: 'wild',
        name: 'Wild',
        algorithm: 'deny-overrides',
        rules: [
          {
            id: 'w',
            effect: 'allow',
            priority: 0,
            actions: ['read'],
            resources: ['org.*'],
            conditions: { all: [] },
          },
        ],
      },
    ]
    const adapter = new IamMemoryAdapter({ roles: [], policies, assignments: { u1: [] }, attributes: { u1: {} } })
    const engine = new IamEngine({ adapter, defaultEffect: 'deny', mode: 'production' })
    expect(await engine.can('u1', 'read', { type: 'org.settings', attributes: {} })).toBe(true)
    expect(await engine.can('u1', 'read', { type: 'org-settings', attributes: {} })).toBe(false)
    expect(await engine.can('u1', 'read', { type: 'organization', attributes: {} })).toBe(false)
  })
})
