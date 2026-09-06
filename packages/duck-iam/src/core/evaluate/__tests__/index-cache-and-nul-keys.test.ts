import { describe, expect, it } from 'vitest'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

/** An embedded NUL, built rather than written so the file stays greppable. */
const NUL = String.fromCharCode(0)

function rule(
  id: string,
  action: string,
  resource: string,
  effect: AccessControl.Effect = 'allow',
): AccessControl.IRule {
  return { actions: [action], conditions: { all: [] }, effect, id, priority: 1, resources: [resource] }
}

function request(action: string, type: string): IamRequest.IAccessRequest {
  return {
    action,
    environment: {},
    resource: { attributes: {}, type },
    subject: { attributes: {}, id: 'u1', roles: [] },
  }
}

/**
 * `readonly rules` is a compile-time annotation, so the array behind it can be
 * replaced or appended to at runtime - by `admin.import`, a hot reload, or a
 * consumer editing the object it handed in. The interpreter walks `policy.rules`
 * live and sees the change; the fast path reads a memoized index. Keying that
 * memo on the policy object served the stale index for the object's whole
 * lifetime, and the divergence was always prod-allows/dev-denies.
 */
describe('indexPolicy memo tracks the rules array, not the policy object', () => {
  it('rebuilds after the rules array is replaced', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p1',
      name: 'p1',
      rules: [rule('r-allow', 'read', 'post')],
    }
    const req = request('read', 'post')
    expect(evaluateFast([policy], req, 'deny', 'and')).toBe(true)

    Object.assign(policy, { rules: [rule('r-deny', 'read', 'post', 'deny')] })

    const slow = evaluate([policy], req, 'deny', 'and').allowed
    expect(evaluateFast([policy], req, 'deny', 'and')).toBe(slow)
    expect(slow).toBe(false)
  })

  it('rebuilds after a rule is appended to the existing array', () => {
    const rules: AccessControl.IRule[] = [rule('r-allow', 'read', 'post')]
    const policy: AccessControl.IPolicy = { algorithm: 'deny-overrides', id: 'p2', name: 'p2', rules }
    const req = request('read', 'post')
    expect(evaluateFast([policy], req, 'deny', 'and')).toBe(true)

    rules.push(rule('r-deny', 'read', 'post', 'deny'))

    expect(evaluateFast([policy], req, 'deny', 'and')).toBe(evaluate([policy], req, 'deny', 'and').allowed)
    expect(evaluateFast([policy], req, 'deny', 'and')).toBe(false)
  })

  // The precomputed map bakes the combining algorithm into its values, so an
  // index built under one algorithm must not be served after it changes. The
  // verdict is asserted on the index rather than on `evaluateFast`, because for
  // these rules the combine is also re-read live and would mask a stale index.
  it('rebuilds after the combining algorithm changes', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'allow-overrides',
      id: 'p3',
      name: 'p3',
      rules: [rule('r-allow', 'read', 'post'), rule('r-deny', 'read', 'post', 'deny')],
    }
    const before = indexPolicy(policy)

    Object.assign(policy, { algorithm: 'deny-overrides' })

    expect(indexPolicy(policy)).not.toBe(before)
  })

  // Control: an untouched policy must still be served from the memo, otherwise
  // the three tests above would pass on a cache that simply never hits.
  it('still returns the same index object for an untouched policy', () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'p4',
      name: 'p4',
      rules: [rule('r-allow', 'read', 'post')],
    }
    expect(indexPolicy(policy)).toBe(indexPolicy(policy))
  })
})

/**
 * The literal bucket map was keyed on action and resource joined by a NUL,
 * which is not injective: action `read<NUL>post` with resource `x` produces the
 * same key as action `read` with resource `post<NUL>x`. A literal hit is
 * trusted as an exact match and skips the shape check, so the rule answered a
 * request it does not target - in production only.
 */
describe('a NUL in an action or resource name cannot forge a bucket hit', () => {
  const colliding: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p-nul',
    name: 'nul',
    rules: [rule('r-nul', `read${NUL}post`, 'x')],
  }
  const victim = request('read', `post${NUL}x`)

  it('the fast path agrees with the interpreter that nothing applies', () => {
    const slow = evaluate([colliding], victim, 'deny', 'and')
    expect(slow.allowed).toBe(false)
    expect(slow.rule).toBeUndefined()
    expect(evaluateFast([colliding], victim, 'deny', 'and')).toBe(false)
  })

  it('agrees under allow-overrides too', () => {
    const policy: AccessControl.IPolicy = { ...colliding, algorithm: 'allow-overrides' }
    expect(evaluateFast([policy], victim, 'deny', 'allow-overrides')).toBe(
      evaluate([policy], victim, 'deny', 'allow-overrides').allowed,
    )
    expect(evaluateFast([policy], victim, 'deny', 'allow-overrides')).toBe(false)
  })

  // Control: the rule still fires for the request it actually targets, so the
  // assertions above are not passing because the rule fell out of the index.
  it('the rule still matches its own action and resource', () => {
    const own = request(`read${NUL}post`, 'x')
    expect(evaluateFast([colliding], own, 'deny', 'and')).toBe(true)
    expect(evaluate([colliding], own, 'deny', 'and').allowed).toBe(true)
  })

  it('indexes the pair under nested keys, so no delimiter exists to collide on', () => {
    const idx = indexPolicy(colliding)
    expect(idx.byActionResource.get(`read${NUL}post`)?.get('x')).toHaveLength(1)
    expect(idx.byActionResource.get('read')).toBeUndefined()
  })
})
