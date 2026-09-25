import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { type IamError, metaOf } from '../../errors'
import { VALID_MODES } from '../engine.libs'
import { IamEngine } from '../index'

const POST = { attributes: {}, type: 'post' } as const

async function seeded() {
  const adapter = new IamMemoryAdapter()
  await adapter.savePolicy({
    algorithm: 'deny-overrides',
    description: '',
    id: 'p1',
    name: 'p1',
    rules: [
      { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 0, resources: ['post'] },
    ],
    version: 1,
  })
  return adapter
}

type Bad = { mode?: string; policyCombine?: string }

/** Builds the engine through a cast, the only way to hand the constructor a value the type forbids. */
const build = (adapter: IamMemoryAdapter, config: Bad) => () =>
  new IamEngine({
    adapter,
    cacheTTL: 0,
    ...(config as {
      mode?: 'development' | 'production'
      policyCombine?: 'and' | 'allow-overrides' | 'first-applicable'
    }),
  })

describe('mode is checked at boot, like policyCombine', () => {
  it('CONTROL: production answers a boolean, development answers a decision object that is truthy when denied', async () => {
    const adapter = await seeded()
    const prod = new IamEngine({ adapter, cacheTTL: 0, mode: 'production' })
    const dev = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })

    const prodDeny = await prod.check('u1', 'delete', POST)
    const devDeny = await dev.check('u1', 'delete', POST)

    expect(prodDeny).toBe(false)
    expect(devDeny).toMatchObject({ allowed: false, effect: 'deny' })
    // The consequence of the typo: `if (await engine.check(...))` admits the deny.
    expect(Boolean(prodDeny)).toBe(false)
    expect(Boolean(devDeny)).toBe(true)
  })

  it('CONTROL: explain() is refused in production and answers a trace in development', async () => {
    const adapter = await seeded()
    const prod = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })
    const dev = new IamEngine({ adapter, cacheTTL: 0, mode: 'development' })
    // The signature forbids `explain()` on a production engine, so the runtime guard is only reachable this way.
    Object.assign(prod, { _mode: 'production' })

    await expect(prod.explain('u1', 'read', POST)).rejects.toThrow(/not available in production/)
    await expect(dev.explain('u1', 'read', POST)).resolves.toMatchObject({ decision: { allowed: true } })
  })

  it.each(['prodution', 'Production', 'PRODUCTION', 'prod', '', 'develoment', 'dev'])(
    'refuses mode %o instead of silently running development',
    async (bad) => {
      const adapter = await seeded()
      expect(build(adapter, { mode: bad })).toThrow('IAM_ENGINE_INVALID_CONFIG')
    },
  )

  it('names the offending value verbatim, so whitespace is visible', async () => {
    const adapter = await seeded()
    try {
      build(adapter, { mode: ' production' })()
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_ENGINE_INVALID_CONFIG'>, 'IAM_ENGINE_INVALID_CONFIG')
      expect(meta.got).toBe(' production')
    }
  })

  it.each(VALID_MODES)('accepts mode %s', async (mode) => {
    const adapter = await seeded()
    expect(build(adapter, { mode })).not.toThrow()
  })

  it('still defaults to production when mode is omitted', async () => {
    const adapter = await seeded()
    const engine = new IamEngine({ adapter, cacheTTL: 0 })
    expect(await engine.check('u1', 'delete', POST)).toBe(false)
    expect(await engine.check('u1', 'read', POST)).toBe(true)
  })

  it('closes the first-applicable bypass: a mistyped production mode no longer accepts it', async () => {
    const adapter = await seeded()
    expect(build(adapter, { mode: 'prodution', policyCombine: 'first-applicable' })).toThrow(
      'IAM_ENGINE_INVALID_CONFIG',
    )
  })

  it('still refuses first-applicable under a correctly spelled production', async () => {
    const adapter = await seeded()
    expect(build(adapter, { mode: 'production', policyCombine: 'first-applicable' })).toThrow(
      'IAM_ENGINE_POLICY_COMBINE_INCOMPATIBLE',
    )
  })

  it('still accepts first-applicable under development', async () => {
    const adapter = await seeded()
    expect(build(adapter, { mode: 'development', policyCombine: 'first-applicable' })).not.toThrow()
  })

  it('refuses at construction, so no engine with a bad mode ever answers a check', async () => {
    const adapter = await seeded()
    let engine: unknown
    expect(() => {
      engine = build(adapter, { mode: 'prodution' })()
    }).toThrow('IAM_ENGINE_INVALID_CONFIG')
    expect(engine).toBeUndefined()
  })
})
