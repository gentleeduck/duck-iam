import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { Engine } from '../engine'

function buildEngine() {
  const adapter = new MemoryAdapter<string, string, string, string>()
  const engine = new Engine<string, string, string, string, 'production'>({
    adapter,
    mode: 'production',
    defaultEffect: 'deny',
  })
  return { adapter, engine }
}

describe('engine.admin input validation', () => {
  describe('assignRole', () => {
    it('rejects null subjectId without touching the adapter', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.assignRole(null as unknown as string, 'editor')).rejects.toThrow(
        /subjectId must be a non-empty string \(got null\)/,
      )
    })

    it('rejects numeric subjectId', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.assignRole(42 as unknown as string, 'editor')).rejects.toThrow(
        /subjectId must be a non-empty string \(got number\)/,
      )
    })

    it('rejects empty-string roleId', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.assignRole('user-1', '')).rejects.toThrow(/roleId must be a non-empty string/)
    })

    it('rejects object roleId', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.assignRole('user-1', { id: 'editor' } as unknown as string)).rejects.toThrow(
        /roleId must be a non-empty string \(got object\)/,
      )
    })

    it('rejects array scope', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.assignRole('user-1', 'editor', [] as unknown as string)).rejects.toThrow(
        /scope must be a non-empty string/,
      )
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
      await expect(engine.admin.revokeRole({} as unknown as string, 'editor')).rejects.toThrow(
        /subjectId must be a non-empty string \(got object\)/,
      )
    })

    it('rejects non-string roleId', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.revokeRole('user-1', undefined as unknown as string)).rejects.toThrow(
        /roleId must be a non-empty string \(got undefined\)/,
      )
    })

    it('rejects empty-string scope', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.revokeRole('user-1', 'editor', '')).rejects.toThrow(/scope must be a non-empty string/)
    })
  })

  describe('setAttributes', () => {
    it('rejects array attrs', async () => {
      const { engine } = buildEngine()
      await expect(
        engine.admin.setAttributes('user-1', [] as unknown as Parameters<typeof engine.admin.setAttributes>[1]),
      ).rejects.toThrow(/attributes must be a plain object \(got array\)/)
    })

    it('rejects null attrs', async () => {
      const { engine } = buildEngine()
      await expect(
        engine.admin.setAttributes('user-1', null as unknown as Parameters<typeof engine.admin.setAttributes>[1]),
      ).rejects.toThrow(/attributes must be a plain object \(got null\)/)
    })

    it('rejects primitive attrs', async () => {
      const { engine } = buildEngine()
      await expect(
        engine.admin.setAttributes(
          'user-1',
          'admin=true' as unknown as Parameters<typeof engine.admin.setAttributes>[1],
        ),
      ).rejects.toThrow(/attributes must be a plain object \(got string\)/)
    })

    it('rejects non-string subjectId before checking attrs', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.setAttributes(null as unknown as string, { admin: true })).rejects.toThrow(
        /subjectId must be a non-empty string \(got null\)/,
      )
    })

    it('accepts a plain object', async () => {
      const { adapter, engine } = buildEngine()
      await engine.admin.setAttributes('user-1', { tier: 'gold' })
      const attrs = await adapter.getSubjectAttributes('user-1')
      expect(attrs).toEqual({ tier: 'gold' })
    })
  })

  describe('getAttributes / getRole / getPolicy / deleteRole / deletePolicy', () => {
    it('getAttributes rejects non-string subjectId', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.getAttributes('')).rejects.toThrow(/subjectId must be a non-empty string/)
    })

    it('getRole rejects non-string id', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.getRole(0 as unknown as string)).rejects.toThrow(
        /id must be a non-empty string \(got number\)/,
      )
    })

    it('getPolicy rejects non-string id', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.getPolicy(false as unknown as string)).rejects.toThrow(
        /id must be a non-empty string \(got boolean\)/,
      )
    })

    it('deleteRole rejects empty id', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.deleteRole('')).rejects.toThrow(/id must be a non-empty string/)
    })

    it('deletePolicy rejects empty id', async () => {
      const { engine } = buildEngine()
      await expect(engine.admin.deletePolicy('')).rejects.toThrow(/id must be a non-empty string/)
    })
  })
})
