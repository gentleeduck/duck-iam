import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { createIam } from '../../config/config'
import { IamError, metaOf } from '../../errors'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../validate'

const NUL = String.fromCharCode(0)

/** Allow everything, then deny a locked resource: a retired deny shows up as `can()` flipping to `true`. */
function policyWithTargets(targets: unknown): Record<string, unknown> {
  return {
    algorithm: 'deny-overrides',
    id: 'p-lock',
    name: 'p-lock',
    rules: [
      { actions: ['*'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['*'] },
      {
        actions: ['*'],
        conditions: { all: [{ field: 'resource.attributes.locked', operator: 'eq', value: true }] },
        effect: 'deny',
        id: 'r-deny',
        priority: 10,
        resources: ['*'],
      },
    ],
    targets,
  }
}

function errorPaths(result: { issues: readonly { type: string; path?: string }[] }): string[] {
  return result.issues.filter((i) => i.type === 'error').map((i) => i.path ?? '')
}

const access = createIam({
  actions: ['read', 'delete'] as const,
  resources: ['post'] as const,
  roles: ['editor'] as const,
})

/**
 * A store already holding the row: `listPolicies` is never re-validated, so this is how a pre-existing
 * or hand-written row reaches the engine once the write-path gate is in place.
 */
type Row = AccessControl.IPolicy<'delete' | 'read', 'post', 'editor'>

class SeededAdapter extends IamMemoryAdapter<'delete' | 'read', 'post', 'editor'> {
  constructor(private readonly seeded: unknown) {
    super()
  }
  override async listPolicies(): Promise<Row[]> {
    const row = this.seeded
    return isPolicyRow(row) ? [row] : []
  }
}

function isPolicyRow(value: unknown): value is Row {
  return typeof value === 'object' && value !== null && 'rules' in value
}

/** Runs the policy through a real engine; `locked` is the request the policy's deny rule targets. */
async function ask(targets: unknown, locked: boolean, mode: 'development' | 'production'): Promise<boolean | string> {
  const adapter = new SeededAdapter(policyWithTargets(targets))
  await adapter.saveRole({ id: 'editor', name: 'editor', permissions: [{ action: '*', resource: '*' }] })
  await adapter.assignRole('u1', 'editor')
  const engine = access.createEngine({ adapter, mode, policyCombine: 'and' })
  try {
    return await engine.can('u1', 'read', { attributes: { locked }, type: 'post' })
  } catch (err) {
    return `THREW: ${err instanceof Error ? err.message : String(err)}`
  }
}

/** What the write path now answers for the same row: `IAM_VALIDATION_FAILED`'s issues (joined), or `'saved'`. */
async function save(targets: unknown): Promise<string> {
  try {
    await new IamMemoryAdapter().savePolicy(policyWithTargets(targets) as never)
    return 'saved'
  } catch (err) {
    if (err instanceof IamError && err.code === 'IAM_VALIDATION_FAILED') {
      return metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED').issues.join('; ')
    }
    throw err
  }
}

describe('a non-string target entry is what the engine cannot survive', () => {
  it.each(['development', 'production'] as const)('a well-formed target decides normally in %s', async (mode) => {
    expect({
      locked: await ask({ actions: ['read'] }, true, mode),
      unlocked: await ask({ actions: ['read'] }, false, mode),
    }).toEqual({
      locked: false,
      unlocked: true,
    })
  })

  it.each(['development', 'production'] as const)('a non-string role target retires the deny in %s', async (mode) => {
    // The policy is applicable to nobody, so its deny never runs and the RBAC allow is the only vote left.
    expect(await ask({ roles: [42] }, true, mode)).toBe(true)
  })

  it.each(['development', 'production'] as const)(
    'a non-string action target denies everything in %s',
    async (mode) => {
      // `matchesAction` calls `.endsWith` on the pattern, so the compiled table cannot be built at all.
      expect(await ask({ actions: [42] }, false, mode)).toBe(false)
    },
  )

  it('a control-char role target retires the deny the same way', async () => {
    expect(await ask({ roles: [`editor${NUL}`] }, true, 'production')).toBe(true)
  })

  it('the write path refuses every row the engine could not survive', async () => {
    expect({
      controlCharRole: await save({ roles: [`editor${NUL}`] }),
      numberAction: await save({ actions: [42] }),
      numberRole: await save({ roles: [42] }),
      wellFormed: await save({ actions: ['read'] }),
    }).toEqual({
      controlCharRole: expect.stringContaining('targets.roles[0] must not contain control characters'),
      numberAction: expect.stringContaining('targets.actions[0] must be a string'),
      numberRole: expect.stringContaining('targets.roles[0] must be a string'),
      wellFormed: 'saved',
    })
  })
})

describe('validatePolicy reports a target entry it cannot match', () => {
  it.each([
    ['actions', 'targets.actions[0]'],
    ['resources', 'targets.resources[0]'],
    ['roles', 'targets.roles[0]'],
  ])('a non-string %s entry is an error', (key, path) => {
    expect(errorPaths(validatePolicy(policyWithTargets({ [key]: [42] })))).toEqual([path])
  })

  it.each([
    ['actions', 'targets.actions[0]'],
    ['resources', 'targets.resources[0]'],
    ['roles', 'targets.roles[0]'],
  ])('a control character in a %s entry is an error', (key, path) => {
    expect(errorPaths(validatePolicy(policyWithTargets({ [key]: [`read${NUL}`] })))).toEqual([path])
  })

  it('reports the offending index, not the first one', () => {
    expect(errorPaths(validatePolicy(policyWithTargets({ resources: ['post', {}, 'doc'] })))).toEqual([
      'targets.resources[1]',
    ])
  })

  it('reports every bad entry across every axis', () => {
    expect(errorPaths(validatePolicy(policyWithTargets({ actions: [1], resources: [2], roles: [3] })))).toEqual([
      'targets.actions[0]',
      'targets.resources[0]',
      'targets.roles[0]',
    ])
  })

  it('a non-array axis still reports once, not per character', () => {
    expect(errorPaths(validatePolicy(policyWithTargets({ actions: 'read' })))).toEqual(['targets.actions'])
  })

  it.each([
    ['a plain string target', { actions: ['read'], resources: ['post'], roles: ['editor'] }],
    ['a wildcard target', { actions: ['*'], resources: ['*'] }],
    ['an empty axis', { actions: [], roles: [] }],
    ['an absent targets block', undefined],
  ])('%s stays valid', (_label, targets) => {
    expect(errorPaths(validatePolicy(policyWithTargets(targets)))).toEqual([])
  })

  // `IPolicy` has no `null` here and `POLICY_JSON_SCHEMA` refuses it; the engine still reads a stored one as absent.
  it('a null targets block is refused on the way in and ignored on the way out', async () => {
    expect(errorPaths(validatePolicy(policyWithTargets(null)))).toEqual(['targets'])
    expect({ locked: await ask(null, true, 'production'), unlocked: await ask(null, false, 'production') }).toEqual({
      locked: false,
      unlocked: true,
    })
  })

  it('the typed validator reports it too', () => {
    expect(errorPaths(access.validatePolicy(policyWithTargets({ roles: [42] })))).toEqual(['targets.roles[0]'])
  })
})
