import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// The inward turn of the dead-target checks. Round 61 compared a policy's targets to its rules' vocabulary and
// round 63 compared a rule to its own policy's targets; both need a second thing to compare against. A rule can
// also be unreachable on its own - an empty list matches nothing, an empty `any` is false, nothing is a member of
// the empty set - and then there is nothing to compare it with and nothing said so.

const POST = { attributes: { tags: ['x'] }, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
]

function build(deny: Partial<AccessControl.IRule>, targets?: AccessControl.IPolicy['targets']) {
  const reported: string[] = []
  const policy: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'P',
    rules: [
      { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'allow', priority: 1, resources: ['post'] },
      {
        actions: ['delete'],
        conditions: { all: [] },
        effect: 'deny',
        id: 'deny',
        priority: 10,
        resources: ['post'],
        ...deny,
      },
    ],
    targets,
  }
  const engine = new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [policy], roles: ROLES }),
    hooks: { onPolicyError: (e: Error) => reported.push(e.message) },
    mode: 'production',
  })
  return { engine, reported }
}

describe('a rule no request can reach, for reasons wholly inside the rule', () => {
  // The allow in each policy is the companion that makes the verdict readable: `false` proves the deny fired,
  // `true` proves it did not. A deny-only policy answers deny either way.
  it('fires the deny when nothing is wrong, so `true` below means the deny was lost', async () => {
    const { engine, reported } = build({})
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toEqual([])
  })

  it('reports an empty "actions" list and shows the deny gone', async () => {
    const { engine, reported } = build({ actions: [] })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('rule "deny" has an empty "actions" list, which matches no action')
    expect(reported[0]).toContain('a deny written this way never fires')
  })

  it('reports an empty "resources" list', async () => {
    const { engine, reported } = build({ resources: [] })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported[0]).toContain('has an empty "resources" list, which matches no resource')
  })

  it('reports an empty "any" group, which `validatePolicy` does not reject even at write time', async () => {
    const { engine, reported } = build({ conditions: { any: [] } })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported[0]).toContain('has an empty "any" condition group, which is false for every request')
  })

  it('reports "in" against an empty list and names the field', async () => {
    const { engine, reported } = build({
      conditions: { all: [{ field: 'subject.id', operator: 'in', value: [] }] },
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported[0]).toContain('tests "subject.id" with "in" against an empty list')
  })

  it('reports a "none" group holding an item true for every request', async () => {
    const { engine, reported } = build({ conditions: { none: [{ all: [] }] } })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported[0]).toContain('holding an item that is true for every request')
  })

  it('follows an "all" chain down to the dead item', async () => {
    const { engine, reported } = build({
      conditions: { all: [{ all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }, { any: [] }] }] },
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported[0]).toContain('has an empty "any" condition group')
  })

  it('stays quiet for a dead disjunct under a live "any", because the rule still fires', async () => {
    const { engine, reported } = build({
      conditions: { any: [{ any: [] }, { field: 'subject.id', operator: 'eq', value: 'u1' }] },
    })
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toEqual([])
  })

  it('stays quiet for a false item under "none", which helps the rule apply', async () => {
    const { engine, reported } = build({ conditions: { none: [{ any: [] }] } })
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toEqual([])
  })

  it('stays quiet for "subset_of" against an empty list, which a request can still satisfy', async () => {
    const conditions: AccessControl.IConditionGroup = {
      all: [{ field: 'resource.attributes.tags', operator: 'subset_of', value: [] }],
    }
    const untagged = build({ conditions })
    expect(await untagged.engine.can('u1', 'delete', { attributes: { tags: [] }, id: 'p2', type: 'post' })).toBe(false)
    expect(untagged.reported).toEqual([])

    const tagged = build({ conditions })
    expect(await tagged.engine.can('u1', 'delete', POST)).toBe(true)
    expect(tagged.reported).toEqual([])
  })

  it('names the rule’s own list, not the policy targets that also exclude it', async () => {
    const { engine, reported } = build({ actions: [] }, { actions: ['delete'] })
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('has an empty "actions" list')
    expect(reported[0]).not.toContain('targets.actions')
  })

  it('says "an allow" for a dead allow, and reports it once however often it is evaluated', async () => {
    const reported: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({
        assignments: { u1: ['writer'] },
        policies: [
          {
            algorithm: 'deny-overrides',
            id: 'p',
            name: 'P',
            rules: [
              { actions: [], conditions: { all: [] }, effect: 'allow', id: 'dead', priority: 1, resources: ['post'] },
            ],
          },
        ],
        roles: ROLES,
      }),
      hooks: { onPolicyError: (e: Error) => reported.push(e.message) },
      mode: 'production',
    })
    await engine.can('u1', 'delete', POST)
    await engine.can('u1', 'read', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('an allow written this way never fires')
  })
})
