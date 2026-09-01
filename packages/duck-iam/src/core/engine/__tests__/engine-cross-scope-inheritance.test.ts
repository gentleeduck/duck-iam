import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// Regression coverage for cross-scope role inheritance (see `resolveSubject` in engine.loaders.ts).

type Action = 'read' | 'manageRoles'
type ResourceType = 'post' | 'users'
type RoleId = 'marketplace-guest' | 'marketplace-owner' | 'company-superadmin' | 'unscoped-reader' | 'company-lead'
type Scope = 'company' | 'marketplace' | 'unrelated'

const marketplaceGuestRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'marketplace-guest',
  name: 'Marketplace Guest',
  scope: 'marketplace',
  permissions: [{ action: 'read', resource: 'post' }],
}

const marketplaceOwnerRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'marketplace-owner',
  name: 'Marketplace Owner',
  scope: 'marketplace',
  permissions: [{ action: 'manageRoles', resource: 'users' }],
}

// Inherits marketplace-owner on purpose; declares no permissions of its own.
const companySuperadminRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'company-superadmin',
  name: 'Company Superadmin',
  scope: 'company',
  inherits: ['marketplace-owner'],
  permissions: [],
}

// Declares no scope of its own - an inherited copy must fall back to the assignment row's scope.
const unscopedReaderRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'unscoped-reader',
  name: 'Unscoped Reader',
  permissions: [{ action: 'read', resource: 'post' }],
}

const companyLeadRole: AccessControl.IRole<Action, ResourceType, RoleId, Scope> = {
  id: 'company-lead',
  name: 'Company Lead',
  scope: 'company',
  inherits: ['unscoped-reader'],
  permissions: [],
}

function createEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId, Scope>({
    roles: [marketplaceGuestRole, marketplaceOwnerRole, companySuperadminRole, unscopedReaderRole, companyLeadRole],
  })
  return { adapter, engine: new IamEngine<Action, ResourceType, RoleId, Scope>({ adapter, cacheTTL: 0 }) }
}

describe('Engine.can() - cross-scope role inheritance', () => {
  it('sees inherited authority at the inherited-into scope, even when a literal low-privilege role is also assigned there', async () => {
    const { adapter, engine } = createEngine()

    await adapter.assignRole('user-1', 'company-superadmin', 'company')
    await adapter.assignRole('user-1', 'marketplace-guest', 'marketplace')

    expect(await engine.can('user-1', 'manageRoles', { type: 'users', attributes: {} }, undefined, 'marketplace')).toBe(
      true,
    )
    expect(await engine.can('user-1', 'read', { type: 'post', attributes: {} }, undefined, 'marketplace')).toBe(true)
  })

  it('sees inherited authority at the inherited-into scope purely from inheritance, with no literal assignment at that scope at all', async () => {
    const { adapter, engine } = createEngine()

    await adapter.assignRole('user-2', 'company-superadmin', 'company')

    expect(await engine.can('user-2', 'manageRoles', { type: 'users', attributes: {} }, undefined, 'marketplace')).toBe(
      true,
    )
  })

  it('does not leak the inherited authority into a scope unrelated to either role', async () => {
    const { adapter, engine } = createEngine()

    await adapter.assignRole('user-4', 'company-superadmin', 'company')

    expect(await engine.can('user-4', 'manageRoles', { type: 'users', attributes: {} }, undefined, 'unrelated')).toBe(
      false,
    )
  })

  it("does not drift a direct assignment into the role's own default scope when it was explicitly assigned elsewhere", async () => {
    const { adapter, engine } = createEngine()

    // marketplace-guest declares scope: 'marketplace', but is assigned directly at 'company'.
    // Retagging the assignment with the role's own scope would silently grant authority at
    // 'marketplace' - a scope this assignment never recorded.
    await adapter.assignRole('user-5', 'marketplace-guest', 'company')

    expect(await engine.can('user-5', 'read', { type: 'post', attributes: {} }, undefined, 'marketplace')).toBe(false)
    expect(await engine.can('user-5', 'read', { type: 'post', attributes: {} }, undefined, 'company')).toBe(false)
  })

  it("tags an inherited role that declares no scope with the assignment row's scope", async () => {
    const { adapter, engine } = createEngine()

    await adapter.assignRole('user-6', 'company-lead', 'company')

    // unscoped-reader declares no scope of its own, so the inherited copy has to carry the
    // row's scope ('company') - otherwise it is dropped by the scope filter and never
    // reaches the effective role set.
    expect(await engine.getEffectiveRoles('user-6', 'company')).toEqual(['company-lead', 'unscoped-reader'])
    expect(await engine.getEffectiveRoles('user-6', 'unrelated')).toEqual([])
    expect(await engine.can('user-6', 'read', { type: 'post', attributes: {} }, undefined, 'company')).toBe(true)
    expect(await engine.can('user-6', 'read', { type: 'post', attributes: {} }, undefined, 'unrelated')).toBe(false)
  })

  it('does not regress a same-scope check with no cross-scope inheritance involved', async () => {
    const { adapter, engine } = createEngine()

    await adapter.assignRole('user-3', 'marketplace-guest', 'marketplace')

    expect(await engine.can('user-3', 'read', { type: 'post', attributes: {} }, undefined, 'marketplace')).toBe(true)
    expect(await engine.can('user-3', 'manageRoles', { type: 'users', attributes: {} }, undefined, 'marketplace')).toBe(
      false,
    )
  })
})
