import { describe, expect, it, vi } from 'vitest'
import type { Request } from '../../types'
import { emitMetrics, safeHookCall } from '../engine.hooks'

describe('safeHookCall', () => {
  it('awaits + returns void on normal completion', async () => {
    const fn = vi.fn(async () => {})
    await safeHookCall(fn, 'onAfter')
    expect(fn).toHaveBeenCalled()
  })

  it('swallows sync throws so the calling decision stays uncorrupted', async () => {
    const fn = () => {
      throw new Error('boom')
    }
    await expect(safeHookCall(fn, 'onError')).resolves.toBeUndefined()
  })

  it('swallows async rejects', async () => {
    const fn = async () => {
      throw new Error('boom')
    }
    await expect(safeHookCall(fn, 'onMetrics')).resolves.toBeUndefined()
  })

  it('survives a console.error that itself throws (closed-stdout case)', async () => {
    const orig = console.error
    console.error = () => {
      throw new Error('stdout closed')
    }
    try {
      const fn = () => {
        throw new Error('boom')
      }
      await expect(safeHookCall(fn, 'onError')).resolves.toBeUndefined()
    } finally {
      console.error = orig
    }
  })
})

describe('emitMetrics', () => {
  it('no-ops when no hook configured', () => {
    expect(() => emitMetrics({}, fakeReq(), true, 0, false, 'production')).not.toThrow()
  })

  it('passes through the request shape', () => {
    const onMetrics = vi.fn()
    emitMetrics({ onMetrics }, fakeReq('alice', 'read', 'post'), true, performance.now() - 10, false, 'development')
    expect(onMetrics).toHaveBeenCalledWith(
      expect.objectContaining({
        subjectId: 'alice',
        action: 'read',
        resource: 'post',
        allowed: true,
        mode: 'development',
        failOpen: false,
      }),
    )
    expect(onMetrics.mock.calls[0]?.[0].durationMs).toBeGreaterThanOrEqual(0)
  })

  it('swallows hook throws (preserves fail-closed deny path)', () => {
    const onMetrics = () => {
      throw new Error('boom')
    }
    expect(() => emitMetrics({ onMetrics }, fakeReq(), false, 0, true, 'production')).not.toThrow()
  })
})

function fakeReq(
  subjectId = 's',
  action = 'a',
  resourceType = 'r',
): Request.IAccessRequest<string, string, string> {
  return {
    subject: { id: subjectId, roles: [], attributes: {} },
    action,
    resource: { type: resourceType, attributes: {} },
  }
}
