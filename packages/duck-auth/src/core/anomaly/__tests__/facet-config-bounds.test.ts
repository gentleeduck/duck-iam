/** Both detectors in this module refuse a number that is not one. The facet that runs them, and that holds
 *  the four numbers deciding whether anything is reported at all, took them on trust - and every way they
 *  can be wrong fails open. */

import { describe, expect, it } from 'vitest'
import type { Anomaly } from '~/core/anomaly/anomaly.types'
import { InMemoryEvents } from '~/core/events'
import { makeIdentity, makeSession } from '~/test/store-inputs'
import { AnomalyFacet } from '../anomaly.facet'

const identity = makeIdentity({ id: 'u' })
const session = makeSession({ id: 'sid', identityId: 'u' })
const req: Anomaly.RequestSnapshot = { ip: '1.2.3.4', now: 1_760_000_000_000, userAgent: 'ua' }

/** The `detail`, since `AuthError.message` is the bare code and never carries one. */
function refusal(cfg: Partial<Anomaly.Cfg>): string {
  try {
    new AnomalyFacet(new InMemoryEvents(), cfg)
  } catch (err) {
    return err instanceof Error && 'meta' in err ? String((err.meta as { detail?: unknown }).detail) : String(err)
  }
  throw new Error('expected the facet to refuse this config')
}

/** A detector that always fires hard enough to deny under the default ladder. */
const loud: Anomaly.Detector = {
  id: 'loud',
  evaluate: async () => [{ evidence: {}, kind: 'impossible-travel', score: 0.99 }],
}

describe('AnomalyFacet config bounds', () => {
  describe.each(['threshold', 'stepUpAt', 'denyAt'] as const)('%s', (key) => {
    it.each([Number.NaN, Number.POSITIVE_INFINITY, -0.1, 1.1])('refuses %p', (value) => {
      expect(refusal({ [key]: value })).toContain(key)
    })
  })

  describe('detectorTimeoutMs', () => {
    it.each([Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 2 ** 31])('refuses %p', (value) => {
      expect(refusal({ detectorTimeoutMs: value })).toContain('detectorTimeoutMs')
    })
  })

  it('accepts the defaults and a sane custom ladder', () => {
    expect(() => new AnomalyFacet(new InMemoryEvents())).not.toThrow()
    expect(
      () => new AnomalyFacet(new InMemoryEvents(), { denyAt: 1, detectorTimeoutMs: 50, stepUpAt: 0, threshold: 0 }),
    ).not.toThrow()
  })

  it('still denies on the ladder it was given, so the bounds did not replace the arithmetic', async () => {
    const facet = new AnomalyFacet(new InMemoryEvents())
    facet.register(loud)

    await expect(facet.evaluate({ identity, req, session })).resolves.toMatchObject({ decision: 'deny' })
  })

  it('still abandons a detector that hangs past the timeout', async () => {
    const facet = new AnomalyFacet(new InMemoryEvents(), { detectorTimeoutMs: 10 })
    facet.register({ evaluate: () => new Promise(() => {}), id: 'hangs' })

    await expect(facet.evaluate({ identity, req, session })).resolves.toMatchObject({ decision: 'allow', signals: [] })
  })
})
