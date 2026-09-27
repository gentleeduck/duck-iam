import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { hasIamErrorCode, type IamError, metaOf } from '../../errors'
import { IamEngine } from '../engine'

function buildEngine() {
  const adapter = new IamMemoryAdapter<string, string, string, string>()
  const engine = new IamEngine<string, string, string, string, 'production'>({
    adapter,
    mode: 'production',
    defaultEffect: 'deny',
  })
  return engine
}

function snapshotFieldGot(err: unknown): string {
  return metaOf(err as IamError<'IAM_ENGINE_SNAPSHOT_VERSION_UNSUPPORTED'>, 'IAM_ENGINE_SNAPSHOT_VERSION_UNSUPPORTED')
    .got
}

describe('engine.admin.import schemaVersion error interpolation cap', () => {
  it('caps a multi-MB attacker-controlled schemaVersion string', async () => {
    const engine = buildEngine()
    const evil = 'X'.repeat(10 * 1024 * 1024)
    try {
      await engine.admin.import({ schemaVersion: evil } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      expect(hasIamErrorCode(err, 'IAM_ENGINE_SNAPSHOT_VERSION_UNSUPPORTED')).toBe(true)
      const got = snapshotFieldGot(err)
      expect(got.length).toBeLessThan(500)
      expect(got).toMatch(/length 10485760/)
      expect(got).toContain('...')
    }
  })

  it('preserves short string values verbatim (no false truncation)', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: 'v2-beta' } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const got = snapshotFieldGot(err)
      expect(got).toContain(`string 'v2-beta'`)
      expect(got).not.toContain('...')
      expect(got).not.toMatch(/length \d+/)
    }
  })

  it('labels a numeric schemaVersion with its typeof prefix', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: 2 } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      expect(snapshotFieldGot(err)).toContain('number 2')
    }
  })

  it('labels a boolean schemaVersion', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: true } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      expect(snapshotFieldGot(err)).toContain('boolean true')
    }
  })

  it('labels a null schemaVersion', async () => {
    const engine = buildEngine()
    try {
      await engine.admin.import({ schemaVersion: null } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      expect(snapshotFieldGot(err)).toContain('null')
    }
  })

  it('labels an object schemaVersion as `object` (no recursive expansion)', async () => {
    const engine = buildEngine()
    const huge = { embedded: 'Y'.repeat(5_000_000) }
    try {
      await engine.admin.import({ schemaVersion: huge } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const got = snapshotFieldGot(err)
      expect(got).not.toContain('Y'.repeat(100))
      expect(got.length).toBeLessThan(500)
      expect(got).toContain('object')
    }
  })

  it('labels an array schemaVersion with its length, not its contents', async () => {
    const engine = buildEngine()
    const arr = Array(1_000_000).fill('payload')
    try {
      await engine.admin.import({ schemaVersion: arr } as unknown as Parameters<typeof engine.admin.import>[0])
      throw new Error('expected throw')
    } catch (err) {
      const got = snapshotFieldGot(err)
      expect(got).toContain('array (length 1000000)')
      expect(got.length).toBeLessThan(500)
    }
  })

  it('survives a non-object snapshot without crashing on Reflect.get', async () => {
    const engine = buildEngine()
    const err = await engine.admin
      .import('not-a-snapshot' as unknown as Parameters<typeof engine.admin.import>[0])
      .then(
        () => {
          throw new Error('expected import() to throw')
        },
        (e: unknown) => e,
      )
    expect(hasIamErrorCode(err, 'IAM_ENGINE_SNAPSHOT_VERSION_UNSUPPORTED')).toBe(true)
  })
})
