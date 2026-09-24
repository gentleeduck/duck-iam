import { describe, expect, it } from 'vitest'
import { IamEngine } from '../../../core/engine/engine'
import { IamMemoryAdapter } from '../index'

// Pins that the memory adapter's seed and write paths agree about what the store can hold,
// so a fixture cannot reach a state `assignRole` forbids.
describe('the memory adapter seed agrees with the equivalent write', () => {
  const VIEWER = { id: 'viewer', name: 'Viewer', permissions: [] }
  const DOC = { attributes: {}, type: 'doc' } as const

  describe('a seeded assignment naming a role that is not stored', () => {
    it('is refused, the way assignRole refuses it', () => {
      expect(() => new IamMemoryAdapter({ assignments: { u1: ['ghost'] } })).toThrow('IAM_ROLE_NOT_FOUND')
    })

    it('is worded identically to the write-path refusal', async () => {
      const adapter = new IamMemoryAdapter({ roles: [VIEWER] })
      const fromWrite = await adapter.assignRole('u1', 'ghost').catch((e: unknown) => (e as Error).message)
      let fromSeed = ''
      try {
        new IamMemoryAdapter({ assignments: { u1: ['ghost'] } })
      } catch (e) {
        fromSeed = (e as Error).message
      }
      expect(fromSeed).toBe(fromWrite)
    })

    it('would otherwise have produced an ALLOW from a role that does not exist', async () => {
      // NOTE: `resolveEffectiveRoles` keeps a directly assigned role id; only the seed refusal stops a phantom grant.
      const adapter = new IamMemoryAdapter({
        assignments: { u1: ['ghost'] },
        // `ghost` is declared only so the seed is legal; the rule keys on the role ID, not its permissions.
        policies: [
          {
            algorithm: 'allow-overrides',
            id: 'p',
            name: 'p',
            rules: [
              {
                actions: ['admin'],
                conditions: { all: [{ field: 'subject.roles', operator: 'contains', value: 'ghost' }] },
                effect: 'allow',
                id: 'g',
                priority: 10,
                resources: ['doc'],
              },
            ],
          },
        ],
        roles: [{ id: 'ghost', name: 'Ghost', permissions: [] }],
      })
      const engine = new IamEngine({ adapter, mode: 'production' })
      // With `ghost` genuinely stored, the allow is correct and expected.
      expect(await engine.can('u1', 'admin', DOC)).toBe(true)

      // Deleting it takes the grant with it, and the refusal above stops a seed bringing it back.
      await engine.admin.deleteRole('ghost')
      expect(await engine.can('u1', 'admin', DOC)).toBe(false)
    })

    it('accepts an assignment whose role the same init declares', async () => {
      const adapter = new IamMemoryAdapter({ assignments: { u1: ['viewer'] }, roles: [VIEWER] })
      expect(await adapter.getSubjectRoles('u1')).toEqual(['viewer'])
    })

    it('accepts an empty assignment list and an absent assignments map', () => {
      expect(() => new IamMemoryAdapter({ assignments: { u1: [] } })).not.toThrow()
      expect(() => new IamMemoryAdapter({ roles: [VIEWER] })).not.toThrow()
    })

    it('refuses before recording ANY of that subject’s roles', () => {
      // One bad id rejects the whole seed rather than storing the good ones.
      let adapter: IamMemoryAdapter | undefined
      try {
        adapter = new IamMemoryAdapter({ assignments: { u1: ['viewer', 'ghost'] }, roles: [VIEWER] })
      } catch {
        /* expected */
      }
      expect(adapter).toBeUndefined()
    })
  })

  describe('getSubjectAttributes hands back a copy', () => {
    it('an edit to the returned bag does not reach the store', async () => {
      const adapter = new IamMemoryAdapter({ attributes: { u1: { dept: 'eng' } } })
      const got = await adapter.getSubjectAttributes('u1')
      // An out-of-contract edit on purpose: the mistake the copy exists to contain.
      ;(got as Record<string, unknown>).isAdmin = true
      expect(await adapter.getSubjectAttributes('u1')).toEqual({ dept: 'eng' })
    })

    it('two reads are independent of each other', async () => {
      const adapter = new IamMemoryAdapter({ attributes: { u1: { dept: 'eng' } } })
      const a = await adapter.getSubjectAttributes('u1')
      const b = await adapter.getSubjectAttributes('u1')
      expect(a).not.toBe(b)
      expect(a).toEqual(b)
    })

    it('an edit to the seed object does not reach the store either', async () => {
      const seed = { dept: 'eng' }
      const adapter = new IamMemoryAdapter({ attributes: { u1: seed } })
      seed.dept = 'legal'
      expect(await adapter.getSubjectAttributes('u1')).toEqual({ dept: 'eng' })
    })

    it('still answers {} for a subject with no attributes, and that copy is inert', async () => {
      const adapter = new IamMemoryAdapter({})
      const got = await adapter.getSubjectAttributes('nobody')
      ;(got as Record<string, unknown>).injected = true
      expect(await adapter.getSubjectAttributes('nobody')).toEqual({})
    })

    it('a write still lands, so the copy did not break setSubjectAttributes', async () => {
      const adapter = new IamMemoryAdapter({ attributes: { u1: { dept: 'eng' } } })
      await adapter.setSubjectAttributes('u1', { level: 3 })
      expect(await adapter.getSubjectAttributes('u1')).toEqual({ dept: 'eng', level: 3 })
    })
  })
})
