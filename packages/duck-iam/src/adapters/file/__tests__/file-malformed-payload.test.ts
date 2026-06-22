import { describe, expect, it, vi } from 'vitest'
import { IamFile, IamFileAdapter } from '../index'

type Action = 'read' | 'write'
type Resource = 'post'
type Role = 'viewer' | 'editor'
type Scope = 'org-1'

function makeFs(initial: string): IamFile.IFS {
  const files = new Map<string, string>([['/store.json', initial]])
  return {
    async readFile(p: string) {
      const v = files.get(p)
      if (v == null) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    async writeFile(p: string, d: string) {
      files.set(p, d)
    },
    async mkdir() {},
  }
}

async function makeAdapter(
  raw: unknown,
): Promise<{ adapter: IamFileAdapter<Action, Resource, Role, Scope>; errors: string[] }> {
  const errors: string[] = []
  const fs = makeFs(JSON.stringify(raw))
  const adapter = new IamFileAdapter<Action, Resource, Role, Scope>({
    path: '/store.json',
    fs,
    rootDir: '/',
    onPolicyError: (err) => {
      errors.push(err.message)
    },
  })
  return { adapter, errors }
}

describe('IamFileAdapter malformed assignments/attributes', () => {
  it('drops assignments when the whole field is a string', async () => {
    const { adapter, errors } = await makeAdapter({ assignments: 'oops' })
    const roles = await adapter.getSubjectRoles('user-1')
    expect(roles).toEqual([])
    expect(errors.some((e) => e.includes('expected object'))).toBe(true)
  })

  it('drops an individual assignment row whose value is a string', async () => {
    const { adapter, errors } = await makeAdapter({
      assignments: {
        'user-good': [{ role: 'editor' }],
        'user-bad': 'admin', // <- string, not array
      },
    })
    expect(await adapter.getSubjectRoles('user-good')).toEqual(['editor'])
    expect(await adapter.getSubjectRoles('user-bad')).toEqual([])
    expect(errors.some((e) => e.includes('user-bad'))).toBe(true)
  })

  it('drops an entire row when any inner entry is malformed', async () => {
    const { adapter, errors } = await makeAdapter({
      assignments: {
        'user-bad': [{ role: 'editor' }, null, { role: 'viewer' }],
      },
    })
    // One bad entry -> drop the whole row (fail-closed; partial
    // assignments could grant unintended access).
    expect(await adapter.getSubjectRoles('user-bad')).toEqual([])
    expect(errors.some((e) => e.includes('user-bad'))).toBe(true)
  })

  it('drops entries with non-string role', async () => {
    const { adapter, errors } = await makeAdapter({
      assignments: {
        'user-bad': [{ role: 42 }],
      },
    })
    expect(await adapter.getSubjectRoles('user-bad')).toEqual([])
    expect(errors.some((e) => e.includes('missing/non-string role'))).toBe(true)
  })

  it('accepts well-formed assignments with + without scope', async () => {
    const { adapter, errors } = await makeAdapter({
      assignments: {
        u1: [{ role: 'editor' }, { role: 'viewer', scope: 'org-1' }],
      },
    })
    // getSubjectRoles is unscoped-only; scoped assignments surface
    // via getScopedAssignments.
    expect(await adapter.getSubjectRoles('u1')).toEqual(['editor'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'viewer', scope: 'org-1' }])
    expect(errors).toHaveLength(0)
  })

  it('drops attributes when the whole field is a string', async () => {
    const { adapter, errors } = await makeAdapter({ attributes: 'oops' })
    const attrs = await adapter.getSubjectAttributes('user-1')
    expect(attrs).toEqual({})
    expect(errors.some((e) => e.includes('expected object'))).toBe(true)
  })

  it('drops an individual attributes row that is a string', async () => {
    const { adapter, errors } = await makeAdapter({
      attributes: {
        'user-good': { tier: 'pro' },
        'user-bad': 'evil',
      },
    })
    expect(await adapter.getSubjectAttributes('user-good')).toEqual({ tier: 'pro' })
    expect(await adapter.getSubjectAttributes('user-bad')).toEqual({})
    expect(errors.some((e) => e.includes('user-bad'))).toBe(true)
  })

  it('accepts well-formed attributes rows', async () => {
    const { adapter, errors } = await makeAdapter({
      attributes: {
        u1: { tier: 'pro', verified: true, level: 5 },
      },
    })
    expect(await adapter.getSubjectAttributes('u1')).toEqual({ tier: 'pro', verified: true, level: 5 })
    expect(errors).toHaveLength(0)
  })

  it('drops array as the root assignments value', async () => {
    const { adapter, errors } = await makeAdapter({ assignments: ['not-an-object'] })
    expect(await adapter.getSubjectRoles('any')).toEqual([])
    expect(errors.some((e) => e.includes('expected object'))).toBe(true)
  })

  it('drops array as an inner attributes row', async () => {
    const { adapter, errors } = await makeAdapter({
      attributes: {
        'user-bad': ['tier', 'pro'],
      },
    })
    expect(await adapter.getSubjectAttributes('user-bad')).toEqual({})
    expect(errors.some((e) => e.includes('user-bad'))).toBe(true)
  })

  it('missing fields default to {} (forward-compat-friendly)', async () => {
    const { adapter, errors } = await makeAdapter({ policies: {}, roles: {} })
    expect(await adapter.getSubjectRoles('any')).toEqual([])
    expect(await adapter.getSubjectAttributes('any')).toEqual({})
    expect(errors).toHaveLength(0)
  })

  describe('prototype-pollution defense', () => {
    it('returns empty roles for subjectId="__proto__" (no Object.prototype leak)', async () => {
      const { adapter, errors } = await makeAdapter({
        assignments: { u1: [{ role: 'editor' }] },
      })
      expect(await adapter.getSubjectRoles('__proto__')).toEqual([])
      expect(await adapter.getSubjectScopedRoles('__proto__')).toEqual([])
      expect(errors).toHaveLength(0)
    })

    it('returns empty attributes for subjectId="__proto__"', async () => {
      const { adapter, errors } = await makeAdapter({
        attributes: { u1: { tier: 'pro' } },
      })
      expect(await adapter.getSubjectAttributes('__proto__')).toEqual({})
      expect(await adapter.getSubjectAttributes('constructor')).toEqual({})
      expect(errors).toHaveLength(0)
    })

    it('setSubjectAttributes with id="__proto__" does not pollute Object.prototype', async () => {
      const { adapter } = await makeAdapter({})
      await adapter.setSubjectAttributes('__proto__', { polluted: true })
      const probe: Record<string, unknown> = {}
      expect((probe as { polluted?: unknown }).polluted).toBeUndefined()
    })

    it('returns null policy for id="__proto__"', async () => {
      const { adapter } = await makeAdapter({
        policies: { 'p-real': { id: 'p-real', rules: [] } },
      })
      expect(await adapter.getPolicy('__proto__')).toBeNull()
      expect(await adapter.getPolicy('constructor')).toBeNull()
    })
  })
})
