import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { hasIamErrorCode, type IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

function buildEngine() {
  // Holds `editor` since `assignRole` refuses unknown role ids; these cases test the argument checks in front.
  const adapter = new IamMemoryAdapter<string, string, string, string>({
    roles: [{ id: 'editor', name: 'Editor', permissions: [] }],
  })
  const engine = new IamEngine<string, string, string, string, 'production'>({
    adapter,
    mode: 'production',
    defaultEffect: 'deny',
  })
  return { adapter, engine }
}

async function paramInvalid(promise: Promise<unknown>) {
  const err = await promise.then(
    () => {
      throw new Error('expected to throw')
    },
    (e: unknown) => e,
  )
  expect(hasIamErrorCode(err, 'IAM_ENGINE_PARAM_INVALID')).toBe(true)
  return metaOf(err as IamError<'IAM_ENGINE_PARAM_INVALID'>, 'IAM_ENGINE_PARAM_INVALID')
}

async function attributesParamInvalid(promise: Promise<unknown>) {
  const err = await promise.then(
    () => {
      throw new Error('expected to throw')
    },
    (e: unknown) => e,
  )
  expect(hasIamErrorCode(err, 'IAM_ENGINE_ATTRIBUTES_PARAM_INVALID')).toBe(true)
  return metaOf(err as IamError<'IAM_ENGINE_ATTRIBUTES_PARAM_INVALID'>, 'IAM_ENGINE_ATTRIBUTES_PARAM_INVALID')
}

describe('engine.admin input validation', () => {
  describe('assignRole', () => {
    it('rejects null subjectId without touching the adapter', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.assignRole(null as unknown as string, 'editor'))
      expect(meta).toMatchObject({ name: 'subjectId', reason: 'empty', got: 'null' })
    })

    it('rejects numeric subjectId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.assignRole(42 as unknown as string, 'editor'))
      expect(meta).toMatchObject({ name: 'subjectId', reason: 'empty', got: 'number' })
    })

    it('rejects empty-string roleId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.assignRole('user-1', ''))
      expect(meta).toMatchObject({ name: 'roleId', reason: 'empty' })
    })

    it('rejects object roleId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.assignRole('user-1', { id: 'editor' } as unknown as string))
      expect(meta).toMatchObject({ name: 'roleId', reason: 'empty', got: 'object' })
    })

    it('rejects array scope', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.assignRole('user-1', 'editor', [] as unknown as string))
      expect(meta).toMatchObject({ name: 'scope', reason: 'empty' })
    })

    it('accepts undefined scope (unscoped assignment)', async () => {
      const { adapter, engine } = buildEngine()
      await engine.admin.assignRole('user-1', 'editor')
      const roles = await adapter.getSubjectRoles('user-1')
      expect(roles).toContain('editor')
    })

    it('error text never echoes the offending value', async () => {
      const { engine } = buildEngine()
      const secret = 'attacker-controlled-secret-marker'
      try {
        await engine.admin.assignRole(secret as unknown as string, '<bad>')
      } catch (err) {
        expect(String(err)).not.toContain(secret)
        expect(String(err)).not.toContain('<bad>')
      }
    })

    it('does not touch the adapter when validation fails', async () => {
      const { adapter, engine } = buildEngine()
      await engine.admin.assignRole('user-1', 'editor')
      const before = await adapter.getSubjectRoles('user-1')
      await expect(engine.admin.assignRole('user-1', null as unknown as string)).rejects.toThrow()
      const after = await adapter.getSubjectRoles('user-1')
      expect(after).toEqual(before)
    })
  })

  describe('revokeRole', () => {
    it('rejects non-string subjectId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.revokeRole({} as unknown as string, 'editor'))
      expect(meta).toMatchObject({ name: 'subjectId', reason: 'empty', got: 'object' })
    })

    it('rejects non-string roleId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.revokeRole('user-1', undefined as unknown as string))
      expect(meta).toMatchObject({ name: 'roleId', reason: 'empty', got: 'undefined' })
    })

    it('rejects empty-string scope', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.revokeRole('user-1', 'editor', ''))
      expect(meta).toMatchObject({ name: 'scope', reason: 'empty' })
    })
  })

  describe('setAttributes', () => {
    it('rejects array attrs', async () => {
      const { engine } = buildEngine()
      const meta = await attributesParamInvalid(
        engine.admin.setAttributes('user-1', [] as unknown as Parameters<typeof engine.admin.setAttributes>[1]),
      )
      expect(meta).toMatchObject({ reason: 'not-object', got: 'array' })
    })

    it('rejects null attrs', async () => {
      const { engine } = buildEngine()
      const meta = await attributesParamInvalid(
        engine.admin.setAttributes('user-1', null as unknown as Parameters<typeof engine.admin.setAttributes>[1]),
      )
      expect(meta).toMatchObject({ reason: 'not-object', got: 'null' })
    })

    it('rejects primitive attrs', async () => {
      const { engine } = buildEngine()
      const meta = await attributesParamInvalid(
        engine.admin.setAttributes(
          'user-1',
          'admin=true' as unknown as Parameters<typeof engine.admin.setAttributes>[1],
        ),
      )
      expect(meta).toMatchObject({ reason: 'not-object', got: 'string' })
    })

    it('rejects non-string subjectId before checking attrs', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.setAttributes(null as unknown as string, { admin: true }))
      expect(meta).toMatchObject({ name: 'subjectId', reason: 'empty', got: 'null' })
    })

    it('accepts a plain object', async () => {
      const { adapter, engine } = buildEngine()
      await engine.admin.setAttributes('user-1', { tier: 'gold' })
      const attrs = await adapter.getSubjectAttributes('user-1')
      expect(attrs).toEqual({ tier: 'gold' })
    })
  })

  describe('actor', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      description: '',
      id: 'p1',
      name: 'p1',
      rules: [
        {
          actions: ['read'],
          conditions: { all: [{ field: 'action', operator: 'eq', value: 'read' }] },
          effect: 'allow',
          id: 'r1',
          priority: 1,
          resources: ['post'],
        },
      ],
      version: 1,
    }
    // `string & number` is `never`, so the off-contract actor type-checks without a cast.
    const opts = Object.assign({ actor: 'x' }, { actor: 42 })
    type Admin = ReturnType<typeof buildEngine>['engine']['admin']
    const writes: [string, (admin: Admin) => Promise<unknown>][] = [
      ['savePolicy', (a) => a.savePolicy({ ...policy, id: 'p2' }, opts)],
      ['deletePolicy', (a) => a.deletePolicy('p1', opts)],
      ['saveRole', (a) => a.saveRole({ id: 'viewer', name: 'Viewer', permissions: [] }, opts)],
      ['deleteRole', (a) => a.deleteRole('editor', opts)],
      ['assignRole', (a) => a.assignRole('user-2', 'editor', undefined, opts)],
      ['revokeRole', (a) => a.revokeRole('user-1', 'editor', undefined, opts)],
      ['updateAssignmentScope', (a) => a.updateAssignmentScope('user-1', 'editor', undefined, 'org-1', opts.actor)],
      ['assignRoles', (a) => a.assignRoles([{ opts, roleId: 'editor', subjectId: 'user-2' }])],
      ['revokeRoles', (a) => a.revokeRoles([{ opts, roleId: 'editor', subjectId: 'user-1' }])],
      [
        'moveRoleScopes',
        (a) => a.moveRoleScopes([{ actor: opts.actor, roleId: 'editor', subjectId: 'user-1', toScope: 'org-1' }]),
      ],
      ['setAttributes', (a) => a.setAttributes('user-1', { plan: 'pro' }, opts)],
      [
        'import',
        (a) => a.import({ exportedAt: '', policies: [{ ...policy, id: 'p2' }], roles: [], schemaVersion: 1 }, {}, opts),
      ],
    ]

    it.each(writes)('%s rejects a non-string actor before writing', async (_, write) => {
      const { adapter, engine } = buildEngine()
      await engine.admin.savePolicy(policy)
      await engine.admin.assignRole('user-1', 'editor')
      const state = async () => [
        await adapter.listPolicies(),
        await adapter.listRoles(),
        await adapter.getSubjectScopedRoles('user-1'),
        await adapter.getSubjectRoles('user-2'),
        await adapter.getSubjectAttributes('user-1'),
      ]
      const before = await state()
      const meta = await paramInvalid(write(engine.admin))
      expect(meta).toMatchObject({ name: 'actor', reason: 'empty', got: 'number' })
      expect(await state()).toEqual(before)
    })
  })

  describe('getAttributes / getRole / getPolicy / deleteRole / deletePolicy', () => {
    it('getAttributes rejects non-string subjectId', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.getAttributes(''))
      expect(meta).toMatchObject({ name: 'subjectId', reason: 'empty' })
    })

    it('getRole rejects non-string id', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.getRole(0 as unknown as string))
      expect(meta).toMatchObject({ name: 'id', reason: 'empty', got: 'number' })
    })

    it('getPolicy rejects non-string id', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.getPolicy(false as unknown as string))
      expect(meta).toMatchObject({ name: 'id', reason: 'empty', got: 'boolean' })
    })

    it('deleteRole rejects empty id', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.deleteRole(''))
      expect(meta).toMatchObject({ name: 'id', reason: 'empty' })
    })

    it('deletePolicy rejects empty id', async () => {
      const { engine } = buildEngine()
      const meta = await paramInvalid(engine.admin.deletePolicy(''))
      expect(meta).toMatchObject({ name: 'id', reason: 'empty' })
    })
  })
})
