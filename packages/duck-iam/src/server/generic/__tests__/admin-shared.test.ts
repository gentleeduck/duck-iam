import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IamAdminAudit } from '../index'
import {
  type IamAdminAuthzAnswer,
  iamDefaultCsrfCheck,
  iamFireAdminMutation,
  iamRunAdminAuthz,
  iamWithAdminAudit,
} from '../index'

function event(overrides: Partial<IamAdminAudit.IEvent> = {}): IamAdminAudit.IEvent {
  return {
    action: 'update',
    method: 'PUT',
    path: '/admin/policies/p-1',
    success: true,
    target: 'policy',
    ts: 1,
    ...overrides,
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('iamDefaultCsrfCheck', () => {
  it('allows a request with no sec-fetch-site header (non-browser caller)', () => {
    expect(iamDefaultCsrfCheck({ headers: {} })).toBe(true)
    expect(iamDefaultCsrfCheck({})).toBe(true)
    expect(iamDefaultCsrfCheck(undefined)).toBe(true)
  })

  it('rejects cross-site and cross-origin on a Record-shaped headers bag (express/nest)', () => {
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': 'cross-site' } })).toBe(false)
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': 'cross-origin' } })).toBe(false)
  })

  it('allows same-origin and same-site on a Record-shaped headers bag', () => {
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': 'same-origin' } })).toBe(true)
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': 'same-site' } })).toBe(true)
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': 'none' } })).toBe(true)
  })

  it('reads the first entry of an array-shaped header value (node req.headers)', () => {
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': ['cross-site', 'same-origin'] } })).toBe(false)
    expect(iamDefaultCsrfCheck({ headers: { 'sec-fetch-site': ['same-origin'] } })).toBe(true)
  })

  it('reads a fetch-API Headers bag via .get() (next)', () => {
    expect(iamDefaultCsrfCheck({ headers: new Headers({ 'sec-fetch-site': 'cross-site' }) })).toBe(false)
    expect(iamDefaultCsrfCheck({ headers: new Headers({ 'sec-fetch-site': 'same-origin' }) })).toBe(true)
    expect(iamDefaultCsrfCheck({ headers: new Headers() })).toBe(true)
  })

  it('reads a hono context via c.req.header()', () => {
    const ctx = (site: string | undefined) => ({
      req: { header: (n: string) => (n === 'sec-fetch-site' ? site : undefined) },
    })
    expect(iamDefaultCsrfCheck(ctx('cross-site'))).toBe(false)
    expect(iamDefaultCsrfCheck(ctx('same-origin'))).toBe(true)
    expect(iamDefaultCsrfCheck(ctx(undefined))).toBe(true)
  })
})

describe('iamRunAdminAuthz', () => {
  it('returns phase:forbidden and never calls authorize when the CSRF check fails', async () => {
    const authorize = vi.fn(() => true)
    const res = await iamRunAdminAuthz({}, () => false, authorize)
    expect(res).toEqual({ phase: 'forbidden' })
    expect(authorize).not.toHaveBeenCalled()
  })

  it('skips the CSRF phase when csrfCheck is null', async () => {
    const res = await iamRunAdminAuthz({}, null, () => ({ id: 'admin' }))
    expect(res).toEqual({ phase: 'ok', actor: { id: 'admin' } })
  })

  it('returns phase:unauthorized for every falsy authorize result', async () => {
    // `0` is outside `IamAdminAuthzAnswer`, but an untyped JavaScript caller can still return it and must be refused.
    for (const falsy of [false, null, undefined, 0, ''] as IamAdminAuthzAnswer[]) {
      expect(await iamRunAdminAuthz({}, null, () => falsy)).toEqual({ phase: 'unauthorized' })
    }
  })

  it('returns phase:ok carrying the authorize return value as actor', async () => {
    const actor = { id: 'u-1', role: 'admin' }
    expect(
      await iamRunAdminAuthz(
        {},
        () => true,
        async () => actor,
      ),
    ).toEqual({ phase: 'ok', actor })
  })

  it('returns phase:error wrapping a thrown Error', async () => {
    const boom = new TypeError('db down')
    const res = await iamRunAdminAuthz({}, null, () => {
      throw boom
    })
    expect(res).toEqual({ phase: 'error', error: boom })
  })

  it('wraps a non-Error throw into an Error for phase:error', async () => {
    const res = await iamRunAdminAuthz({}, null, () => {
      throw 'nope'
    })
    expect(res.phase).toBe('error')
    if (res.phase !== 'error') throw new Error('unreachable')
    expect(res.error).toBeInstanceOf(Error)
    expect(res.error.message).toBe('nope')
  })

  it('passes the request through to both csrfCheck and authorize', async () => {
    const req = { headers: { 'sec-fetch-site': 'same-origin' } }
    const csrf = vi.fn(() => true)
    const authorize = vi.fn(() => true)
    await iamRunAdminAuthz(req, csrf, authorize)
    expect(csrf).toHaveBeenCalledWith(req)
    expect(authorize).toHaveBeenCalledWith(req)
  })
})

describe('iamWithAdminAudit', () => {
  const ctxOf = (over: Partial<Parameters<typeof iamWithAdminAudit>[0]> = {}) => ({
    action: 'update' as const,
    actor: { id: 'admin' },
    method: 'PUT',
    path: '/admin/policies/p-1',
    target: 'policy' as const,
    ...over,
  })

  it('returns the handler value and reports success:true', async () => {
    const hook = vi.fn()
    const out = await iamWithAdminAudit(ctxOf({ onAdminMutation: hook }), async () => 'done')
    expect(out).toBe('done')
    await Promise.resolve()
    expect(hook).toHaveBeenCalledTimes(1)
    expect(hook.mock.calls[0]?.[0]).toMatchObject({
      action: 'update',
      actor: { id: 'admin' },
      error: undefined,
      method: 'PUT',
      path: '/admin/policies/p-1',
      success: true,
      target: 'policy',
    })
  })

  it('re-throws the handler error and reports success:false with the class name', async () => {
    const hook = vi.fn()
    await expect(
      iamWithAdminAudit(ctxOf({ onAdminMutation: hook }), async () => {
        throw new TypeError('secret=hunter2')
      }),
    ).rejects.toThrow('secret=hunter2')
    expect(hook.mock.calls[0]?.[0]).toMatchObject({ error: 'TypeError', success: false })
  })

  it('includeErrorMessage:true swaps the class name for the message', async () => {
    const hook = vi.fn()
    await expect(
      iamWithAdminAudit(ctxOf({ includeErrorMessage: true, onAdminMutation: hook }), async () => {
        throw new TypeError('boom')
      }),
    ).rejects.toThrow('boom')
    expect(hook.mock.calls[0]?.[0]).toMatchObject({ error: 'boom' })
  })

  it('applies redactPath before the hook sees the event', async () => {
    const hook = vi.fn()
    await iamWithAdminAudit(
      ctxOf({ onAdminMutation: hook, redactPath: (p) => p.replace(/\/[^/]+$/, '/:id') }),
      async () => 1,
    )
    expect(hook.mock.calls[0]?.[0]).toMatchObject({ path: '/admin/policies/:id' })
  })

  it('is a no-op-safe wrapper when no hook is supplied', async () => {
    await expect(iamWithAdminAudit(ctxOf(), async () => 42)).resolves.toBe(42)
  })
})

describe('iamWithAdminAudit hook timing', () => {
  const ctxOf = (onAdminMutation: IamAdminAudit.Hook) => ({
    action: 'update' as const,
    actor: { id: 'admin' },
    method: 'PUT',
    onAdminMutation,
    path: '/admin/policies/p-1',
    target: 'policy' as const,
  })

  it('calls the hook before the wrapped call resolves', async () => {
    const order: string[] = []
    await iamWithAdminAudit(
      ctxOf(() => void order.push('hook')),
      async () => 'done',
    )
    order.push('resolved')
    expect(order).toEqual(['hook', 'resolved'])
  })

  it('does not wait for the promise the hook returns', async () => {
    const outcome = await Promise.race([
      iamWithAdminAudit(
        ctxOf(() => new Promise<void>(() => undefined)),
        async () => 'done',
      ),
      new Promise((resolve) => setTimeout(() => resolve('still waiting'), 50)),
    ])
    expect(outcome).toBe('done')
  })

  it('runs work after an await on an already-settled value before the call resolves', async () => {
    const order: string[] = []
    await iamWithAdminAudit(
      ctxOf(async () => {
        await Promise.resolve()
        order.push('after-await')
      }),
      async () => 'done',
    )
    order.push('resolved')
    expect(order).toEqual(['after-await', 'resolved'])
  })

  it('CONTROL: work behind a timer runs after the call resolves', async () => {
    const order: string[] = []
    await iamWithAdminAudit(
      ctxOf(() => {
        setTimeout(() => order.push('after-timer'), 0)
      }),
      async () => 'done',
    )
    order.push('resolved')
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(order).toEqual(['resolved', 'after-timer'])
  })
})

describe('iamFireAdminMutation', () => {
  it('does nothing when no hook is supplied', () => {
    expect(() => iamFireAdminMutation(undefined, event())).not.toThrow()
  })

  it('invokes the hook with the event', () => {
    const hook = vi.fn()
    iamFireAdminMutation(hook, event())
    expect(hook).toHaveBeenCalledTimes(1)
    expect(hook.mock.calls[0]?.[0]).toMatchObject({ path: '/admin/policies/p-1' })
  })

  it('routes a synchronous hook throw to onAuditHookError instead of propagating', () => {
    const boom = new Error('hook exploded')
    const sink = vi.fn()
    expect(() =>
      iamFireAdminMutation(
        () => {
          throw boom
        },
        event(),
        { onAuditHookError: sink },
      ),
    ).not.toThrow()
    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink.mock.calls[0]?.[0]).toBe(boom)
  })

  it('routes an async hook rejection to onAuditHookError', async () => {
    const boom = new Error('async hook exploded')
    const sink = vi.fn()
    iamFireAdminMutation(() => Promise.reject(boom), event(), { onAuditHookError: sink })
    await Promise.resolve()
    await Promise.resolve()
    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink.mock.calls[0]?.[0]).toBe(boom)
  })

  it('falls back to console.error when no onAuditHookError is configured', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    iamFireAdminMutation(() => {
      throw new Error('hook exploded')
    }, event())
    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy.mock.calls[0]?.[0]).toContain('onAdminMutation hook threw')
  })

  it('treats a throwing redactPath as a hook error and never calls the hook', () => {
    const hook = vi.fn()
    const sink = vi.fn()
    const boom = new Error('bad redactor')
    iamFireAdminMutation(hook, event(), {
      onAuditHookError: sink,
      redactPath: () => {
        throw boom
      },
    })
    expect(hook).not.toHaveBeenCalled()
    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink.mock.calls[0]?.[0]).toBe(boom)
  })

  it('last-resort-logs when onAuditHookError itself throws', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() =>
      iamFireAdminMutation(
        () => {
          throw new Error('hook exploded')
        },
        event(),
        {
          onAuditHookError: () => {
            throw new Error('sink exploded')
          },
        },
      ),
    ).not.toThrow()
    expect(spy.mock.calls[0]?.[0]).toContain('onAuditHookError sink threw')
  })
})
