import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine, iamEngine } from '../engine'

// Naming `TMode` does not set the optional `IConfig.mode`: the engine runs in production, `check()` returns a
// boolean, and `.allowed` is `undefined`, so a `toBeFalsy()` assertion checks nothing.
describe('the mode type argument does not set the mode', () => {
  const adapter = new IamMemoryAdapter({ roles: [] })

  it('omitting `mode` runs in production however `TMode` is written', async () => {
    const engine = new IamEngine<string, string, string, string, 'development'>({ adapter, cacheTTL: 0 })
    const verdict = await engine.check('u1', 'read', { attributes: {}, type: 'doc' })
    expect(typeof verdict, 'a production engine answers with a boolean, whatever TMode claims').toBe('boolean')
  })

  it('passing `mode` is what produces a decision object', async () => {
    const engine = new IamEngine<string, string, string, string, 'development'>({
      adapter,
      cacheTTL: 0,
      mode: 'development',
    })
    const verdict = await engine.check('u1', 'read', { attributes: {}, type: 'doc' })
    expect(typeof verdict).toBe('object')
    expect(verdict.allowed).toBe(false)
  })

  // `iamEngine` and `access.createEngine` must default `TMode` to the runtime default, `'production'`.
  it('the factory defaults TMode to the mode the runtime is actually in', async () => {
    const verdict = await iamEngine({ adapter, cacheTTL: 0 }).check('u1', 'read', { attributes: {}, type: 'doc' })
    expect(typeof verdict).toBe('boolean')
  })
})
