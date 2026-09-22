/**
 * The gate is only worth having if a host can reach it. `operations-gating.test.ts` covers what
 * `assertOperationsForRoute` decides; this covers whether anyone outside the package can get one to
 * ask, which is the half a suite that constructs `new OperationsImpl()` directly cannot see.
 */
import { describe, expect, it } from 'vitest'
import * as core from '~/core'
import { InMemoryEvents } from '~/core/events'

describe('operations reachability', () => {
  it('ships the factory and the class as values, not only the type', () => {
    expect(typeof core.operations).toBe('function')
    expect(typeof core.OperationsImpl).toBe('function')
  })

  it('the instance a host builds through the barrel gates its own routes', async () => {
    const ops = core.operations(new InMemoryEvents())
    await ops.readOnly(true)
    expect(() => ops.assertOperationsForRoute('GET')).not.toThrow()
    expect(() => ops.assertOperationsForRoute('POST')).toThrow(expect.objectContaining({ code: 'AUTH_READONLY_MODE' }))
  })
})
