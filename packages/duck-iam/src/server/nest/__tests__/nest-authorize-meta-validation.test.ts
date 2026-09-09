import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import { iamNestAccessGuard } from '../index'

/**
 * `getHandlerMeta` reached into a handler twice without checking anything:
 * `__accessMeta` is a plain property on a function object, and
 * `Reflect.getMetadata` answers `unknown`. Both were asserted straight into
 * `IAuthorizeMeta`, and the very next line of the guard was
 * `if (!meta) return true`.
 *
 * That line cannot tell "this handler has no @IamAuthorize" from "this handler
 * is decorated and the metadata is `null`". The first is a pass by design; the
 * second is a check the author asked for and the guard could not run - and it
 * resolved to the same `true`, so a broken decorator opened the route instead
 * of closing it. `'__accessMeta' in handler` also walks the prototype chain, so
 * an inherited property decided the request.
 *
 * The type-level half matters as well: a `scope` arriving as a number went
 * straight into `engine.can` as the tenant to answer for.
 *
 * Presence and readability are now separate answers. Absent means allow;
 * present-but-unreadable is a denial, reported through `onError` so the broken
 * handler is named rather than producing a silent 403.
 */
function makeEngine() {
  const adapter = new IamMemoryAdapter({
    assignments: { u1: ['viewer'] },
    roles: [{ id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] }],
  })
  return new IamEngine({ adapter, cacheTTL: 0 })
}

/** A handler carrying `value` as `__accessMeta`, however malformed. */
function handlerWith(value: unknown): object {
  const fn = function handler() {
    return null
  }
  Object.defineProperty(fn, '__accessMeta', { configurable: true, value, writable: true })
  return fn
}

function makeCtx(handler: object) {
  return {
    getHandler: () => handler,
    switchToHttp: () => ({
      getRequest: () => ({ headers: {}, method: 'GET', params: {}, path: '/posts', user: { id: 'u1' } }),
    }),
  }
}

describe('a handler decorated with unreadable metadata is denied, not allowed', () => {
  // Every one of these is truthy-or-falsy junk in the `__accessMeta` slot. The
  // falsy ones took `if (!meta) return true` and allowed outright; the truthy
  // ones ran a check against fields nothing had type-checked.
  const UNREADABLE: [string, unknown][] = [
    ['null', null],
    ['false', false],
    ['zero', 0],
    ['empty string', ''],
    ['a string', 'read'],
    ['a number', 42],
    ['an array', ['read']],
    ['action as a number', { action: 1 }],
    ['resource as an object', { resource: {} }],
    ['scope as a number', { scope: 7 }],
    ['infer as a string', { infer: 'true' }],
    ['infer as 1', { infer: 1 }],
  ]

  it.each(UNREADABLE)('%s is refused', async (_label, value) => {
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(handlerWith(value)))).toBe(false)
  })

  it('the refusal reaches onError with a message naming the package', async () => {
    const onError = vi.fn((_err: Error, _request: unknown) => false)
    const guard = iamNestAccessGuard(makeEngine(), { onError })
    await guard(makeCtx(handlerWith(null)))
    expect(onError).toHaveBeenCalledTimes(1)
    expect(String(onError.mock.calls[0]?.[0])).toContain('@gentleduck/iam:nest')
  })

  it('onError cannot be used to turn the refusal back into a pass by accident', async () => {
    // An operator whose `onError` returns true has said so explicitly; this
    // pins that it is *their* decision and not the default.
    const guard = iamNestAccessGuard(makeEngine(), { onError: () => true })
    expect(await guard(makeCtx(handlerWith(null)))).toBe(true)
  })

  it('the engine is never consulted for an unreadable handler', async () => {
    const engine = makeEngine()
    const can = vi.spyOn(engine, 'can')
    const guard = iamNestAccessGuard(engine)
    await guard(makeCtx(handlerWith({ scope: 7 })))
    expect(can).not.toHaveBeenCalled()
  })
})

describe('the pass-through and readable cases are untouched', () => {
  it('a handler with no metadata at all still passes', async () => {
    const guard = iamNestAccessGuard(makeEngine())
    const bare = function handler() {
      return null
    }
    expect(await guard(makeCtx(bare))).toBe(true)
  })

  it('an explicit `undefined` counts as no decorator, not as junk', async () => {
    // What an unset reflect key answers, and indistinguishable from absent.
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(handlerWith(undefined)))).toBe(true)
  })

  it('a valid meta still decides on its merits - allow', async () => {
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(handlerWith({ action: 'read', resource: 'post' })))).toBe(true)
  })

  it('a valid meta still decides on its merits - deny', async () => {
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(handlerWith({ action: 'delete', resource: 'post' })))).toBe(false)
  })

  it('an empty object is readable - every field is optional', async () => {
    const guard = iamNestAccessGuard(makeEngine())
    // Defaults to `read` on `unknown`, which the viewer does not hold.
    expect(await guard(makeCtx(handlerWith({})))).toBe(false)
  })

  it('extra keys alongside valid ones are not a reason to refuse', async () => {
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(handlerWith({ action: 'read', mine: 1, resource: 'post' })))).toBe(true)
  })

  it('a prototype-inherited __accessMeta is read, and validated like any other', async () => {
    // `'__accessMeta' in handler` has always walked the prototype chain. That
    // is not changed here - what changed is that junk arriving this way is
    // refused instead of allowed.
    const proto = { __accessMeta: null }
    const fn = Object.setPrototypeOf(function handler() {
      return null
    }, proto)
    const guard = iamNestAccessGuard(makeEngine())
    expect(await guard(makeCtx(fn))).toBe(false)
  })
})
