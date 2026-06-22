import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

describe('Engine subject.roles type-confusion defense', () => {
  it('refuses to substring-match string-typed subject.roles against policy.targets.roles', async () => {
    const adapter = new IamMemoryAdapter<string, string, string, string>({
      policies: [
        {
          id: 'p1',
          name: 'admin-only',
          algorithm: 'allow-overrides',
          targets: { roles: ['admin'] },
          rules: [
            {
              id: 'r1',
              effect: 'allow',
              priority: 0,
              actions: ['*'],
              resources: ['*'],
              conditions: { all: [] },
            },
          ],
        },
      ],
    })
    const engine = new IamEngine<string, string, string, string, 'production'>({
      adapter,
      mode: 'production',
      defaultEffect: 'deny',
    })
    const subjectWithStringRoles = {
      id: 'u1',
      roles: 'admin-extra' as unknown as string[],
      attributes: {},
    }
    const allowed = await engine.authorize({
      subject: subjectWithStringRoles,
      action: 'read',
      resource: { type: 'post', attributes: {} },
    })
    expect(allowed).toBe(false)
  })

  it('refuses to substring-match via the RBAC-generated contains condition', async () => {
    const adapter = new IamMemoryAdapter({
      roles: [
        {
          id: 'admin',
          name: 'admin',
          permissions: [{ action: '*', resource: '*' }],
          inherits: [],
        },
      ],
    })
    const engine = new IamEngine<string, string, string, string, 'production'>({
      adapter,
      mode: 'production',
      defaultEffect: 'deny',
    })
    const subjectWithStringRoles = {
      id: 'u1',
      roles: 'admin-extra' as unknown as string[],
      attributes: {},
    }
    const allowed = await engine.authorize({
      subject: subjectWithStringRoles,
      action: 'read',
      resource: { type: 'post', attributes: {} },
    })
    expect(allowed).toBe(false)
  })

  it('non-array subject.roles ({}, null) is normalised to [] (no crash)', async () => {
    const adapter = new IamMemoryAdapter()
    const engine = new IamEngine<string, string, string, string, 'production'>({
      adapter,
      mode: 'production',
      defaultEffect: 'deny',
    })
    const subjectNull = {
      id: 'u1',
      roles: null as unknown as string[],
      attributes: {},
    }
    await expect(
      engine.authorize({ subject: subjectNull, action: 'read', resource: { type: 'post', attributes: {} } }),
    ).resolves.toBe(false)
    const subjectObj = {
      id: 'u1',
      roles: { 0: 'admin' } as unknown as string[],
      attributes: {},
    }
    await expect(
      engine.authorize({ subject: subjectObj, action: 'read', resource: { type: 'post', attributes: {} } }),
    ).resolves.toBe(false)
  })

  it('legitimate array-typed roles still match policies correctly (no regression)', async () => {
    const adapter = new IamMemoryAdapter<string, string, string, string>({
      policies: [
        {
          id: 'p1',
          name: 'admin-only',
          algorithm: 'allow-overrides',
          targets: { roles: ['admin'] },
          rules: [
            {
              id: 'r1',
              effect: 'allow',
              priority: 0,
              actions: ['*'],
              resources: ['*'],
              conditions: { all: [] },
            },
          ],
        },
      ],
    })
    const engine = new IamEngine<string, string, string, string, 'production'>({
      adapter,
      mode: 'production',
      defaultEffect: 'deny',
    })
    expect(
      await engine.authorize({
        subject: { id: 'u1', roles: ['admin'], attributes: {} },
        action: 'read',
        resource: { type: 'post', attributes: {} },
      }),
    ).toBe(true)
  })

  it('development mode also refuses substring-match (returns deny decision)', async () => {
    const adapter = new IamMemoryAdapter<string, string, string, string>({
      policies: [
        {
          id: 'p1',
          name: 'admin-only',
          algorithm: 'allow-overrides',
          targets: { roles: ['admin'] },
          rules: [
            {
              id: 'r1',
              effect: 'allow',
              priority: 0,
              actions: ['*'],
              resources: ['*'],
              conditions: { all: [] },
            },
          ],
        },
      ],
    })
    const engine = new IamEngine<string, string, string, string, 'development'>({
      adapter,
      mode: 'development',
      defaultEffect: 'deny',
    })
    const decision = await engine.authorize({
      subject: { id: 'u1', roles: 'admin-extra' as unknown as string[], attributes: {} },
      action: 'read',
      resource: { type: 'post', attributes: {} },
    })
    // The policy must NOT have applied via substring match.
    expect(decision.allowed).toBe(false)
  })
})
