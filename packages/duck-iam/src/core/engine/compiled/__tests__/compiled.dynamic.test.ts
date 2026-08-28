import { describe, expect, it } from 'vitest'
import { evaluateFast } from '../../../evaluate'
import type { AccessControl, IamRequest } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'

const policies: AccessControl.IPolicy[] = [
  {
    id: 'ownership',
    name: 'Ownership',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'owner-update',
        effect: 'allow',
        priority: 0,
        actions: ['update'],
        resources: ['post'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
      },
    ],
  },
]

describe('compileTable: DYNAMIC cells', () => {
  it('a conditional rule compiles to a DYNAMIC cell, not CONST_ALLOW', () => {
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)
  })

  it('groups the candidate rule under its owning policy, with the policy algorithm', () => {
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    const groups = t.dynamic[idx]!
    expect(groups).toHaveLength(1)
    expect(groups[0]!.policyId).toBe('ownership')
    expect(groups[0]!.algorithm).toBe('deny-overrides')
    expect(groups[0]!.rules[0]!.id).toBe('owner-update')
  })

  it('a policy with targets is excluded entirely (falls through)', () => {
    const targeted: AccessControl.IPolicy[] = [{ ...policies[0]!, id: 'targeted', targets: { actions: ['update'] } }]
    const t = compileTable([], targeted)
    expect(t.actionId.has('update')).toBe(false) // never entered the action universe
  })

  it('differential: DYNAMIC classification is not short-circuited to always-allow by evaluateFast', () => {
    const t = compileTable([], policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('post')!
    expect(t.kind[idx]).toBe(CellKind.DYNAMIC)

    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }

    // Condition fails: subject.id !== resource.attributes.ownerId. If the
    // interpreter agreed with a naive CONST_ALLOW classification, this
    // would incorrectly return true. It must return false, proving the
    // rule's condition is actually evaluated - never short-circuited.
    const denyingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'someone-else' } }
    const denyingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: denyingResource }
    expect(evaluateFast(policies, denyingRequest)).toBe(false)

    // Condition holds: subject.id === resource.attributes.ownerId.
    const allowingResource: IamRequest.IResource = { type: 'post', attributes: { ownerId: 'user1' } }
    const allowingRequest: IamRequest.IAccessRequest = { subject, action: 'update', resource: allowingResource }
    expect(evaluateFast(policies, allowingRequest)).toBe(true)
  })
})
