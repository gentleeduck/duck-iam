import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { VALID_SCOPE_COMBINES, VALID_SCOPE_MODES } from '../engine.libs'
import { IamEngine } from '../index'

const POST = { attributes: {}, type: 'post' } as const

async function seeded() {
  const adapter = new IamMemoryAdapter()
  for (const [id, action] of [
    ['admin', 'delete'],
    ['viewer', 'read'],
  ] as const) {
    await adapter.saveRole({
      description: '',
      id,
      inherits: [],
      name: id,
      permissions: [{ action, resource: 'post' }],
    })
  }
  await adapter.assignRole('u1', 'admin', 'org-1')
  await adapter.assignRole('u1', 'viewer', 'org-1.team-a')
  return adapter
}

const engineWith = async (config: { scopeCombine?: string; scopeMode?: string }) =>
  new IamEngine({
    adapter: await seeded(),
    cacheTTL: 0,
    mode: 'production',
    ...(config as { scopeCombine?: 'union' | 'override'; scopeMode?: 'flat' | 'hierarchical' }),
  })

describe('scopeMode and scopeCombine are checked at boot, like policyCombine', () => {
  it('CONTROL: override keeps only the most specific level, union takes every ancestor', async () => {
    const override = await engineWith({ scopeCombine: 'override', scopeMode: 'hierarchical' })
    const union = await engineWith({ scopeCombine: 'union', scopeMode: 'hierarchical' })
    expect(await override.getEffectiveRoles('u1', 'org-1.team-a')).toEqual(['viewer'])
    expect(await union.getEffectiveRoles('u1', 'org-1.team-a')).toEqual(['admin', 'viewer'])
    expect(await override.can('u1', 'delete', POST, undefined, 'org-1.team-a')).toBe(false)
    expect(await union.can('u1', 'delete', POST, undefined, 'org-1.team-a')).toBe(true)
  })

  it.each(['overide', 'OVERRIDE', '', 'or'])('refuses scopeCombine %o instead of widening to union', async (bad) => {
    await expect(engineWith({ scopeCombine: bad, scopeMode: 'hierarchical' })).rejects.toThrow(
      'IAM_ENGINE_INVALID_CONFIG',
    )
  })

  it.each(['heirarchical', 'Hierarchical', '', 'nested'])(
    'refuses scopeMode %o instead of falling back to flat',
    async (bad) => {
      await expect(engineWith({ scopeMode: bad })).rejects.toThrow('IAM_ENGINE_INVALID_CONFIG')
    },
  )

  it.each(VALID_SCOPE_MODES)('accepts scopeMode %s', async (mode) => {
    await expect(engineWith({ scopeMode: mode })).resolves.toBeInstanceOf(IamEngine)
  })

  it.each(VALID_SCOPE_COMBINES)('accepts scopeCombine %s', async (combine) => {
    await expect(engineWith({ scopeCombine: combine })).resolves.toBeInstanceOf(IamEngine)
  })

  it('omitting both still builds, at flat/union', async () => {
    const engine = await engineWith({})
    expect(await engine.getEffectiveRoles('u1', 'org-1.team-a')).toEqual(['viewer'])
  })
})
