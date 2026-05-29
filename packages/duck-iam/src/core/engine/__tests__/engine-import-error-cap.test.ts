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
  return engine
}

describe('engine.admin.import schemaVersion error interpolation cap', () => {
  it('caps a multi-MB attacker-controlled schemaVersion string', async () => {
    const engine = buildEngine()
    const evil = 'X'.repeat(10 * 1024 * 1024)
    try {
      await engine.admin.import({ schemaVersion: evil } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg.length).toBeLessThan(500)
      expect(msg).toMatch(/length 10485760/)
      expect(msg).toContain('...')
      expect(msg).toContain('unsupported snapshot schemaVersion')
    }
  })

  it('preserves short string values verbatim (no false truncation)', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: 'v2-beta' } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain(`string 'v2-beta'`)
      expect(msg).not.toContain('...')
      expect(msg).not.toMatch(/length \d+/)
    }
  })

  it('labels a numeric schemaVersion with its typeof prefix', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: 2 } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('number 2')
    }
  })

  it('labels a boolean schemaVersion', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: true } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('boolean true')
    }
  })

  it('labels a null schemaVersion', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: null } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('null')
    }
  })

  it('labels an object schemaVersion as `object` (no recursive expansion)', async () => {
    const engine = buildEngine()
    const huge = { embedded: 'Y'.repeat(5_000_000) }
    try {
      await engine.admin.import({ schemaVersion: huge } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).not.toContain('Y'.repeat(100))
      expect(msg.length).toBeLessThan(500)
      expect(msg).toContain('object')
    }
  })

  it('labels an array schemaVersion with its length, not its contents', async () => {
    const engine = buildEngine()
    const arr = Array(1_000_000).fill('payload')
    try {
      await engine.admin.import({ schemaVersion: arr } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toContain('array (length 1000000)')
      expect(msg.length).toBeLessThan(500)
    }
  })

  it('survives a non-object snapshot without crashing on Reflect.get', async () => {
    const engine = buildEngine()
    await expect(
      engine.admin.import('not-a-snapshot' as unknown as Parameters<typeof engine.admin.import>[0]),
    ).rejects.toThrow(/unsupported snapshot schemaVersion/)
  })
})
