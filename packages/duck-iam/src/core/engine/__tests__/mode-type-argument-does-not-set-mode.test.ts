import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine, iamEngine } from '../engine'

/**
 * `IConfig.mode` is optional, so naming `TMode` in the type arguments does not
 * set it. The engine then runs in production while `check()` is *typed* to
 * return an `IDecision`, and reading `.allowed` off the boolean it returns
 * yields `undefined` - falsy, so an assertion like `expect(d.allowed).toBe(false)`
 * fails only because `undefined !== false`, and one written as
 * `expect(d.allowed).toBeFalsy()` passes while checking nothing.
 *
 * Four E2E suites were written against this mistake. These tests pin the two
 * halves of it: the runtime ignores the type argument, and the factories no
 * longer default `TMode` to a mode the runtime will not be in.
 */
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

  // `iamEngine` and `access.createEngine` defaulted `TMode` to `'development'`
  // while the class and the runtime default to `'production'`, so the bare
  // `iamEngine({ adapter })` call in the README returned an engine typed to
  // hand back `IDecision` objects it never produces.
  it('the factory defaults TMode to the mode the runtime is actually in', async () => {
    const verdict = await iamEngine({ adapter, cacheTTL: 0 }).check('u1', 'read', { attributes: {}, type: 'doc' })
    expect(typeof verdict).toBe('boolean')
  })
})
