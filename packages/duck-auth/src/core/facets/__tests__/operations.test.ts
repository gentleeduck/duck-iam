import { beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryEvents } from '~/core/events'
import { OperationsFacet } from '../operations'

describe('OperationsFacet', () => {
  let events: InMemoryEvents
  let ops: OperationsFacet

  beforeEach(() => {
    events = new InMemoryEvents()
    ops = new OperationsFacet(events)
  })

  describe('maintenance', () => {
    it('default state is off', () => {
      expect(ops.snapshot().maintenance.on).toBe(false)
    })

    it('toggle on stores message + retryAfter + emits maintenance.on', async () => {
      const handler = vi.fn()
      events.on('maintenance.on', handler)
      await ops.maintenance(true, { message: 'down 2h', retryAfterSec: 7200 })
      const s = ops.snapshot()
      expect(s.maintenance.on).toBe(true)
      expect(s.maintenance.message).toBe('down 2h')
      expect(s.maintenance.retryAfterSec).toBe(7200)
      expect(handler).toHaveBeenCalledWith({ message: 'down 2h', retryAfter: 7200 })
    })

    it('toggle off clears state + emits maintenance.off', async () => {
      await ops.maintenance(true)
      const handler = vi.fn()
      events.on('maintenance.off', handler)
      await ops.maintenance(false)
      expect(ops.snapshot().maintenance.on).toBe(false)
      expect(handler).toHaveBeenCalledOnce()
    })

    it('assertOperationsForRoute throws AUTH/MAINTENANCE when on', async () => {
      await ops.maintenance(true, { message: 'm', retryAfterSec: 60 })
      expect(() => ops.assertOperationsForRoute('POST')).toThrow()
      try {
        ops.assertOperationsForRoute('POST')
        expect.fail('expected throw')
      } catch (err) {
        expect((err as { code: string }).code).toBe('AUTH_MAINTENANCE')
        expect((err as { meta: { retryAfter: number; message: string } }).meta).toEqual({
          retryAfter: 60,
          message: 'm',
        })
      }
    })

    it('exempt routes pass through during maintenance', async () => {
      await ops.maintenance(true)
      expect(() => ops.assertOperationsForRoute('GET', { healthz: true })).not.toThrow()
      expect(() => ops.assertOperationsForRoute('GET', { session: true })).not.toThrow()
    })
  })

  describe('readOnly', () => {
    it('default state is off', () => {
      expect(ops.snapshot().readOnly.on).toBe(false)
    })

    it('GET / HEAD / OPTIONS pass through in read-only mode', async () => {
      await ops.readOnly(true)
      for (const m of ['GET', 'HEAD', 'OPTIONS']) {
        expect(() => ops.assertOperationsForRoute(m)).not.toThrow()
      }
    })

    it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('%s throws AUTH/READONLY_MODE in read-only', async (method) => {
      await ops.readOnly(true)
      try {
        ops.assertOperationsForRoute(method)
        expect.fail('expected throw')
      } catch (err) {
        expect((err as { code: string }).code).toBe('AUTH_READONLY_MODE')
      }
    })

    it('readOnly off restores mutations', async () => {
      await ops.readOnly(true)
      await ops.readOnly(false)
      expect(() => ops.assertOperationsForRoute('POST')).not.toThrow()
    })
  })

  it('maintenance takes precedence over readOnly when both on', async () => {
    await ops.maintenance(true)
    await ops.readOnly(true)
    try {
      ops.assertOperationsForRoute('POST')
      expect.fail('expected throw')
    } catch (err) {
      expect((err as { code: string }).code).toBe('AUTH_MAINTENANCE')
    }
  })
})
