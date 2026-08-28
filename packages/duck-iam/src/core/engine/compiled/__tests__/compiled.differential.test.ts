import { describe, expect, it } from 'vitest'
import { evaluateFast } from '../../../evaluate'
import type { AccessControl, IamRequest } from '../../../types'
import { CellKind, compileTable } from '../compiled.compile'

/**
 * Differential tests: verify compiled table agrees with the real interpreter (evaluateFast)
 * for all touched cells. Every code path in compilation must match the oracle.
 */

const roles: AccessControl.IRole[] = [
  { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [{ action: 'update', resource: 'post' }] },
]

const policies: AccessControl.IPolicy[] = [
  {
    id: 'public',
    name: 'Public',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'pub-read',
        effect: 'allow',
        priority: 0,
        actions: ['read'],
        resources: ['comment'],
        conditions: { all: [] },
      },
    ],
  },
]

const conflictPolicies: AccessControl.IPolicy[] = [
  {
    id: 'conflict',
    name: 'Conflict',
    algorithm: 'deny-overrides',
    rules: [
      { id: 'r1', effect: 'allow', priority: 0, actions: ['read'], resources: ['secret'], conditions: { all: [] } },
      { id: 'r2', effect: 'deny', priority: 0, actions: ['read'], resources: ['secret'], conditions: { all: [] } },
    ],
  },
]

describe('compiled differential tests (vs evaluateFast)', () => {
  it('ROLE_MASK: compiled correctly marks role permission cell as touched and populated', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!

    // ROLE_MASK cells are populated from roles (not policies), so verify structure
    expect(t.kind[idx]).toBe(CellKind.ROLE_MASK)
    expect(t.touched[idx]).toBe(1)

    // Verify viewer role has the grant
    const viewerBit = 1 << t.roleId.get('viewer')!
    expect(t.allow[idx]! & viewerBit).not.toBe(0)
  })

  it('ROLE_MASK: compiled inheritance closure correctly sets editor bit from viewer grant', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('post')!

    // Editor inherits viewer, so should also have read grant
    const editorBit = 1 << t.roleId.get('editor')!
    expect(t.allow[idx]! & editorBit).not.toBe(0)
  })

  it('CONST_ALLOW: unconditional allow rule agrees with evaluateFast', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('comment')!
    expect(t.kind[idx]).toBe(CellKind.CONST_ALLOW)

    // Any subject (no roles needed for unconditional allow)
    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }
    const resource: IamRequest.IResource = { type: 'comment', attributes: {} }
    const request: IamRequest.IAccessRequest = { subject, action: 'read', resource }

    // Compiled says CONST_ALLOW, evaluateFast should agree
    const evaluateResult = evaluateFast(policies, request)
    expect(evaluateResult).toBe(true)
  })

  it('conflicted allow/deny: falls through to evaluateFast (not claimed by compiled)', () => {
    const t = compileTable(roles, conflictPolicies)
    const idx = t.actionId.get('read')! * t.nResources + t.resourceId.get('secret')!

    // Conflicted cell should be untouched (fall through)
    expect(t.touched[idx]).toBe(0)

    // Any subject on conflicted cell
    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }
    const resource: IamRequest.IResource = { type: 'secret', attributes: {} }
    const request: IamRequest.IAccessRequest = { subject, action: 'read', resource }

    // Evaluator must resolve via policy algorithm (deny-overrides)
    const evaluateResult = evaluateFast(conflictPolicies, request)
    // With deny-overrides, the deny rule wins
    expect(evaluateResult).toBe(false)
  })

  it('untouched cell: compiled skips it, evaluateFast returns default (both agree on fallthrough)', () => {
    const t = compileTable(roles, policies)
    const idx = t.actionId.get('update')! * t.nResources + t.resourceId.get('comment')!
    expect(t.touched[idx]).toBe(0)

    // Untouched cell: no role, no policy rule
    const subject: IamRequest.ISubject = { id: 'user1', roles: [], attributes: {} }
    const resource: IamRequest.IResource = { type: 'comment', attributes: {} }
    const request: IamRequest.IAccessRequest = { subject, action: 'update', resource }

    // Both compiled and evaluateFast fall through (no coverage), default deny
    const evaluateResult = evaluateFast(policies, request)
    expect(evaluateResult).toBe(false)
  })
})
