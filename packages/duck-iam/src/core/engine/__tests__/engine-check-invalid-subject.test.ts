import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'

/**
 * An invalid `subjectId` short-circuits before evaluation. In development mode
 * the synthesized deny must still be a complete `IDecision` - callers read
 * `effect`/`timestamp` off it like any other decision.
 */
describe('engine.check() with an invalid subjectId', () => {
  const adapter = new IamMemoryAdapter<'read', 'post', 'viewer', 'org'>({ roles: [], assignments: {}, policies: [] })
  const resource = { type: 'post' as const, attributes: {} }

  it('development: returns a full deny decision', async () => {
    const engine = new IamEngine<'read', 'post', 'viewer', 'org', 'development'>({
      adapter,
      cacheTTL: 0,
      mode: 'development',
    })
    const decision = await engine.check('', 'read', resource)
    expect(decision).toMatchObject({ allowed: false, effect: 'deny', reason: 'invalid subjectId', duration: 0 })
    expect(typeof decision.timestamp).toBe('number')
  })

  it('production: returns false', async () => {
    const engine = new IamEngine<'read', 'post', 'viewer', 'org', 'production'>({
      adapter,
      cacheTTL: 0,
      mode: 'production',
    })
    expect(await engine.check('', 'read', resource)).toBe(false)
  })
})
