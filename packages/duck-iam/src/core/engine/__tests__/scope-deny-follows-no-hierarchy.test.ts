import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// In hierarchical mode a grant at `org-1` reaches `org-1.team-a`, because `rolesToPolicy` emits
// `any: [eq org-1, starts_with "org-1."]` for it. An author writing their own scope condition gets no such help:
// each of the three obvious spellings is wrong in a different direction, and two of them fail open.

const POST = { attributes: {}, id: 'p1', type: 'post' } as const
const ROLES: AccessControl.IRole[] = [
  { id: 'editor', name: 'E', permissions: [{ action: 'delete', resource: 'post' }] },
]

/** Allow and deny in one policy, so the verdict distinguishes a deny that fired from one that did not. */
function policyWith(condition: unknown): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: 'guard',
    name: 'frozen org',
    rules: [
      { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
      {
        actions: ['delete'],
        conditions: { all: [condition] } as AccessControl.IRule['conditions'],
        effect: 'deny',
        id: 'd',
        priority: 10,
        resources: ['post'],
      },
    ],
  }
}

async function can(condition: unknown, reqScope: string, grantScope = 'org-1') {
  const adapter = new IamMemoryAdapter({ policies: [policyWith(condition)], roles: ROLES })
  await adapter.assignRole('u1', 'editor', grantScope)
  const engine = new IamEngine({ adapter, mode: 'production', scopeMode: 'hierarchical' })
  return engine.can('u1', 'delete', POST, undefined, reqScope)
}

const EQ = { field: 'scope', operator: 'eq', value: 'org-1' }
const PREFIX_BARE = { field: 'scope', operator: 'starts_with', value: 'org-1' }
const PREFIX_DOTTED = { field: 'scope', operator: 'starts_with', value: 'org-1.' }
const CORRECT = { any: [EQ, PREFIX_DOTTED] }

describe('a scope condition does not inherit the hierarchy a grant has', () => {
  it('CONTROL: the grant itself is hierarchical, and a deny that cannot match leaves it alone', async () => {
    const never = { field: 'scope', operator: 'eq', value: 'nowhere' }
    expect(await can(never, 'org-1')).toBe(true)
    expect(await can(never, 'org-1.team-a')).toBe(true)
    // No grant reaches here, so this is the floor: a `false` below must come from the deny, not from a missing grant.
    expect(await can(never, 'org-10')).toBe(false)
  })

  it('`eq` denies the node and leaves the whole subtree allowed', async () => {
    expect(await can(EQ, 'org-1')).toBe(false)
    expect(await can(EQ, 'org-1.team-a')).toBe(true)
  })

  it('a bare `starts_with` denies the subtree but also catches a sibling sharing the prefix', async () => {
    expect(await can(PREFIX_BARE, 'org-1')).toBe(false)
    expect(await can(PREFIX_BARE, 'org-1.team-a')).toBe(false)
    // Granted at `org-10` so the request is authorised; only the over-broad deny can refuse it.
    expect(await can(PREFIX_BARE, 'org-10', 'org-10')).toBe(false)
  })

  it('a dotted `starts_with` denies the subtree and misses the node itself', async () => {
    expect(await can(PREFIX_DOTTED, 'org-1')).toBe(true)
    expect(await can(PREFIX_DOTTED, 'org-1.team-a')).toBe(false)
  })

  it('the spelling that works is the one `rolesToPolicy` uses for grants', async () => {
    expect(await can(CORRECT, 'org-1')).toBe(false)
    expect(await can(CORRECT, 'org-1.team-a')).toBe(false)
    expect(await can(CORRECT, 'org-1.team-a.repo-1')).toBe(false)
    // And it does not reach the sibling, which is what separates it from the bare prefix.
    expect(await can(CORRECT, 'org-10', 'org-10')).toBe(true)
  })

  it('flat mode has no trap: `eq` is the whole contract there', async () => {
    const adapter = new IamMemoryAdapter({ policies: [policyWith(EQ)], roles: ROLES })
    await adapter.assignRole('u1', 'editor', 'org-1')
    const engine = new IamEngine({ adapter, mode: 'production', scopeMode: 'flat' })
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(false)
    // The grant does not reach the child in flat mode either, so there is nothing for a deny to miss.
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1.team-a')).toBe(false)
  })
})
