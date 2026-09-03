import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { definePolicy } from '../../../core/builder/policy'
import { defineRole } from '../../../core/builder/role'
import { defineRule } from '../../../core/builder/rule'
import { IamEngine } from '../../../core/engine'
import {
  IAM_UNKNOWN_ACTION,
  IAM_UNKNOWN_RESOURCE,
  iamActionForMethod,
  iamDefaultCsrfCheck,
  iamDefaultResource,
  iamIsNameableActor,
  iamPathIsAmbiguous,
  iamRunAdminAuthz,
} from '../index'

/**
 * The HTTP boundary is where an attacker-controlled string becomes the
 * `(action, resource)` a decision is made about. Two things have to hold: the
 * mapping must never name a *different* object than the one the router will
 * serve, and every refusal on this path has to be an actual refusal.
 */

/**
 * `IAM_UNKNOWN_ACTION` and `IAM_UNKNOWN_RESOURCE` are documented as denials -
 * "must match no permission and be denied", "matches no policy target, so the
 * request is denied". A *string* cannot carry that guarantee, because `'*'`
 * exists and matches every string including these two. Any deployment with a
 * wildcard admin rule - the ordinary shape for an admin role - turns both
 * sentinels back into allows, which is precisely the code path built to refuse.
 */
describe('the unknown-action and unknown-resource sentinels are real refusals', () => {
  async function wildcardEngine() {
    const adapter = new IamMemoryAdapter<string, string, string, string>()
    await adapter.saveRole(defineRole<'admin', string, string>('admin').name('Admin').grant('*', '*').build())
    await adapter.assignRole('u1', 'admin')
    await adapter.savePolicy(
      definePolicy<string, string>('wild')
        .name('Wildcard')
        .addRule(defineRule<string, string>('anything').allow().on('*').of('*').build())
        .build(),
    )
    return new IamEngine({ adapter, cacheTTL: 0 })
  }

  it('denies the unknown resource even against a wildcard rule', async () => {
    const engine = await wildcardEngine()
    expect(await engine.can('u1', 'read', { type: IAM_UNKNOWN_RESOURCE, attributes: {} })).toBe(false)
  })

  it('denies the unknown action even against a wildcard rule', async () => {
    const engine = await wildcardEngine()
    expect(await engine.can('u1', IAM_UNKNOWN_ACTION, { type: 'doc', attributes: {} })).toBe(false)
  })

  it('denies a traversal path that the ambiguity guard refused to resolve', async () => {
    const engine = await wildcardEngine()
    const resource = iamDefaultResource('/posts/../admin/secret')
    expect(resource.type).toBe(IAM_UNKNOWN_RESOURCE)
    expect(await engine.can('u1', iamActionForMethod('GET'), resource)).toBe(false)
  })

  it('still allows an ordinary path, so the refusal is not a blanket deny', async () => {
    const engine = await wildcardEngine()
    expect(await engine.can('u1', iamActionForMethod('GET'), iamDefaultResource('/posts/1'))).toBe(true)
  })
})

/**
 * `iamPathIsAmbiguous` already treats a decoded `\` as a separator - `%5C` is
 * refused. A *literal* backslash was not checked, and the WHATWG URL parser
 * converts `\` to `/` in a special-scheme URL before resolving dot segments:
 * `new URL('http://x/posts\\..\\admin').pathname` is `/admin`. So one layer
 * reads the type as `posts\..\admin` and any layer that parses through `URL`
 * reads `/admin` - authorized as one resource, served as another, which is the
 * bypass this function exists to refuse.
 */
describe('a literal backslash is as ambiguous as its encoded twin', () => {
  it.each([['/posts\\..\\admin'], ['/posts\\admin'], ['/a/..\\admin'], ['/a\\b']])('refuses to resolve %s', (raw) => {
    expect(iamPathIsAmbiguous(raw)).toBe(true)
    expect(iamDefaultResource(raw).type).toBe(IAM_UNKNOWN_RESOURCE)
  })

  it('agrees with the encoded form it already refused', () => {
    expect(iamPathIsAmbiguous('/posts%5C..%5Cadmin')).toBe(iamPathIsAmbiguous('/posts\\..\\admin'))
  })

  it('leaves a legitimate path alone', () => {
    expect(iamPathIsAmbiguous('/posts/hello%20world')).toBe(false)
    expect(iamDefaultResource('/posts/1').type).toBe('posts')
  })
})

/**
 * HTTP header names are case-insensitive. Node lowercases what it parses, but
 * this predicate is exported and documented as taking "any object the adapter
 * can extract a header from", and it read exactly one spelling out of a
 * Record. Handed the wire casing, it found no header, concluded "non-browser
 * caller" and returned `true` - the cross-site request it exists to reject was
 * allowed.
 */
describe('the default CSRF check reads the header whatever its case', () => {
  it.each([['sec-fetch-site'], ['Sec-Fetch-Site'], ['SEC-FETCH-SITE'], ['sec-Fetch-Site']])(
    'rejects cross-site sent as %s',
    (name) => {
      expect(iamDefaultCsrfCheck({ headers: { [name]: 'cross-site' } })).toBe(false)
    },
  )

  it.each([['sec-fetch-site'], ['Sec-Fetch-Site']])('allows same-origin sent as %s', (name) => {
    expect(iamDefaultCsrfCheck({ headers: { [name]: 'same-origin' } })).toBe(true)
  })

  it('still allows a caller that sends no such header at all', () => {
    expect(iamDefaultCsrfCheck({ headers: {} })).toBe(true)
    expect(iamDefaultCsrfCheck({})).toBe(true)
    expect(iamDefaultCsrfCheck(undefined)).toBe(true)
  })

  it('reads a fetch-style Headers object, which is already case-insensitive', () => {
    expect(iamDefaultCsrfCheck({ headers: new Headers({ 'Sec-Fetch-Site': 'cross-site' }) })).toBe(false)
    expect(iamDefaultCsrfCheck({ headers: new Headers({ 'Sec-Fetch-Site': 'same-origin' }) })).toBe(true)
  })

  it('reads a hono-style header accessor', () => {
    const c = { req: { header: (n: string) => (n === 'sec-fetch-site' ? 'cross-site' : undefined) } }
    expect(iamDefaultCsrfCheck(c)).toBe(false)
  })
})

/**
 * A throwing `authorize` becomes `phase: 'error'`; a throwing `csrfCheck` used
 * to propagate out of the function entirely, so whether the request was refused
 * depended on the framework adapter's outer catch. A predicate that cannot
 * answer has not said yes.
 */
describe('the admin gate answers for both of its phases', () => {
  it('treats a throwing CSRF predicate as forbidden rather than letting it escape', async () => {
    const result = await iamRunAdminAuthz(
      {},
      () => {
        throw new Error('header store unavailable')
      },
      () => 'admin-1',
    )
    expect(result.phase).toBe('forbidden')
  })

  it('does not call authorize when the CSRF predicate throws', async () => {
    let authorizeCalls = 0
    await iamRunAdminAuthz(
      {},
      () => {
        throw new Error('nope')
      },
      () => {
        authorizeCalls += 1
        return 'admin-1'
      },
    )
    expect(authorizeCalls).toBe(0)
  })

  it('still reports a throwing authorize as an error, not a refusal', async () => {
    const result = await iamRunAdminAuthz({}, null, () => {
      throw new Error('idp down')
    })
    expect(result.phase).toBe('error')
  })
})

/**
 * `actor` is what the admin audit event records as the person who changed a
 * policy, and the gate accepted anything truthy and passed it straight through.
 *
 * `authorize: (req) => req.user?.role === 'admin'` is the *documented* shape -
 * it is the `@example` on `iamAdminRouter` - so a boolean has to keep
 * authorizing the mutation; that is not the bug. The bug is that `true` was
 * then written into the audit event as the actor, and an audit trail naming
 * `true` cannot attribute the change to anybody. A value that names no one is
 * recorded as no one.
 */
describe('the admin gate records an actor only when it has one', () => {
  it.each([[true], [42], [[]], [Symbol.iterator], ['   ']])(
    'still authorizes when authorize returns %s, because truthy means allowed',
    async (actor) => {
      const result = await iamRunAdminAuthz({}, null, () => actor)
      expect(result.phase).toBe('ok')
    },
  )

  it.each([[true], [42], [[]], ['   ']])('does not record %s as the actor', async (actor) => {
    const result = await iamRunAdminAuthz({}, null, () => actor)
    expect(result.phase).toBe('ok')
    if (result.phase === 'ok') expect(result.actor).toBeUndefined()
  })

  it.each([[false], [0], [''], [null], [undefined], [Number.NaN]])(
    'still reports %s as unauthorized',
    async (actor) => {
      const result = await iamRunAdminAuthz({}, null, () => actor)
      expect(result.phase).toBe('unauthorized')
    },
  )

  it.each([['admin-1'], [{ id: 'admin-1' }], [{ id: 'admin-1', email: 'a@b.c' }]])(
    'keeps %s, which does name someone',
    async (actor) => {
      const result = await iamRunAdminAuthz({}, null, () => actor)
      expect(result.phase).toBe('ok')
      if (result.phase === 'ok') expect(result.actor).toEqual(actor)
    },
  )

  it('classifies actors the same way it records them', () => {
    for (const nameable of ['admin-1', { id: 'a' }]) expect(iamIsNameableActor(nameable)).toBe(true)
    for (const not of [true, 42, [], '', '  ', null, undefined]) expect(iamIsNameableActor(not)).toBe(false)
  })
})

/**
 * `IAM_METHOD_ACTION_MAP` is a plain object literal, so `__proto__`,
 * `constructor` and `toString` are reachable through it. `.toUpperCase()` is
 * what currently saves the lookup - every inherited key is lowercase - which
 * makes the uppercase load-bearing for a reason no reader would guess. Pinned
 * here so it cannot be "simplified" into a bypass that returns a function
 * where an action string belongs.
 */
describe('the method map cannot be walked into its prototype', () => {
  it.each([['__proto__'], ['constructor'], ['toString'], ['valueOf'], ['hasOwnProperty']])(
    'maps %s to the unknown action',
    (method) => {
      expect(iamActionForMethod(method)).toBe(IAM_UNKNOWN_ACTION)
    },
  )

  it('returns a string for every input, never an inherited value', () => {
    for (const method of ['__proto__', 'constructor', 'GET', 'get', 'PROPFIND', '']) {
      expect(typeof iamActionForMethod(method)).toBe('string')
    }
  })

  it('still maps the real methods', () => {
    expect(iamActionForMethod('get')).toBe('read')
    expect(iamActionForMethod('DELETE')).toBe('delete')
  })
})

/**
 * `permissions()` does not route through `authorize()` - it has its own
 * evaluation loop - and its own comment says a batch check "must never be able
 * to answer differently from the single check it batches". The refusal is
 * therefore asserted through both entry points, in both engine modes, because
 * one of them granting what the other denies is the bug this package keeps
 * finding.
 */
describe('every entry point refuses the reserved token identically', () => {
  async function wildcardAdapter() {
    const adapter = new IamMemoryAdapter<string, string, string, string>()
    await adapter.saveRole(defineRole<'admin', string, string>('admin').name('Admin').grant('*', '*').build())
    await adapter.assignRole('u1', 'admin')
    await adapter.savePolicy(
      definePolicy<string, string>('wild')
        .name('Wildcard')
        .addRule(defineRule<string, string>('anything').allow().on('*').of('*').build())
        .build(),
    )
    return adapter
  }

  it('permissions() denies the reserved resource and action while allowing the rest', async () => {
    const engine = new IamEngine({ adapter: await wildcardAdapter(), cacheTTL: 0 })
    const map = await engine.permissions('u1', [
      { action: 'read', resource: IAM_UNKNOWN_RESOURCE },
      { action: IAM_UNKNOWN_ACTION, resource: 'doc' },
      { action: 'read', resource: 'doc' },
    ])
    const values = Object.entries(map)
    expect(values.filter(([, allowed]) => allowed)).toHaveLength(1)
    expect(Object.values(map)).toEqual([false, false, true])
  })

  it('can() and permissions() agree, which is the invariant', async () => {
    const engine = new IamEngine({ adapter: await wildcardAdapter(), cacheTTL: 0 })
    const checks = [
      { action: 'read', resource: IAM_UNKNOWN_RESOURCE },
      { action: IAM_UNKNOWN_ACTION, resource: 'doc' },
      { action: 'read', resource: 'doc' },
    ] as const
    const batch = Object.values(await engine.permissions('u1', [...checks]))
    const single = await Promise.all(
      checks.map((c) => engine.can('u1', c.action, { type: c.resource, attributes: {} })),
    )
    expect(batch).toEqual(single)
  })

  it('development mode reports the refusal as an input failure, not an evaluation error', async () => {
    const engine = new IamEngine<string, string, string, string, 'development'>({
      adapter: await wildcardAdapter(),
      cacheTTL: 0,
      mode: 'development',
    })
    const decision = await engine.authorize({
      subject: { id: 'u1', roles: ['admin'], attributes: {} },
      action: 'read',
      resource: { type: IAM_UNKNOWN_RESOURCE, attributes: {} },
    })
    expect(decision.allowed).toBe(false)
    expect(decision.effect).toBe('deny')
    expect(decision.failure).toBe('input')
  })

  it('fires onDeny for the refusal, so it is observable like any other denial', async () => {
    const denials: string[] = []
    const engine = new IamEngine({
      adapter: await wildcardAdapter(),
      cacheTTL: 0,
      hooks: { onDeny: (_req, d) => void denials.push(d.reason ?? '') },
    })
    await engine.can('u1', 'read', { type: IAM_UNKNOWN_RESOURCE, attributes: {} })
    expect(denials).toHaveLength(1)
    expect(denials[0]).toContain('reserved refusal token')
  })
})
