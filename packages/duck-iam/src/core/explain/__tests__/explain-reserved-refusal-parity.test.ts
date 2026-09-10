import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IAM_RESERVED_REFUSAL } from '../../../shared/reserved'
import { IamEngine } from '../../engine/engine'

/**
 * The reserved refusal token is denied before any policy is consulted, because
 * a sentinel *string* cannot carry a denial - `'*'` matches it, so a wildcard
 * admin grant used to turn the refusal back into an allow.
 *
 * `authorize()` and `permissions()` each enforce that. `explain()` did not: it
 * ran the combine over the policy traces and reported what the policies said,
 * so the tool an operator opens to find out why a request was refused told them
 * it was allowed.
 */
// Generics pinned to `string`: inferring them from the wildcard grant narrows
// `TAction` to `'*'`, and every call below then fails to typecheck against a
// union that has nothing to do with what is being tested.
async function adminEngine() {
  const adapter = new IamMemoryAdapter<string, string, string, string>({
    roles: [{ id: 'admin', name: 'Admin', permissions: [{ action: '*', resource: '*' }] }],
  })
  await adapter.assignRole('u1', 'admin')
  return new IamEngine({ adapter, mode: 'development' })
}

describe('explain() refuses the reserved token the way the decision path does', () => {
  it('denies a reserved action that a wildcard grant would otherwise allow', async () => {
    const engine = await adminEngine()
    const explained = await engine.explain('u1', IAM_RESERVED_REFUSAL, { attributes: {}, type: 'post' })
    expect(explained.decision.allowed).toBe(false)
    expect(explained.decision.effect).toBe('deny')
    expect(explained.decision.failure).toBe('input')
    expect(explained.decision.reason).toContain('reserved refusal token')
  })

  it('denies a reserved resource type as well', async () => {
    const engine = await adminEngine()
    const explained = await engine.explain('u1', 'read', { attributes: {}, type: IAM_RESERVED_REFUSAL })
    expect(explained.decision.allowed).toBe(false)
  })

  it('agrees with can() on both positions', async () => {
    const engine = await adminEngine()
    for (const [action, type] of [
      [IAM_RESERVED_REFUSAL, 'post'],
      ['read', IAM_RESERVED_REFUSAL],
    ] as const) {
      const decided = await engine.can('u1', action, { attributes: {}, type })
      const explained = await engine.explain('u1', action, { attributes: {}, type })
      expect({ action, decided, explained: explained.decision.allowed, type }).toEqual({
        action,
        decided: false,
        explained: false,
        type,
      })
    }
  })

  it('names no deciding policy or rule, because none decided it', async () => {
    const engine = await adminEngine()
    const explained = await engine.explain('u1', IAM_RESERVED_REFUSAL, { attributes: {}, type: 'post' })
    expect(explained.decision.policy).toBeUndefined()
    expect(explained.decision.rule).toBeUndefined()
  })

  // The traces stay. Seeing which wildcard rule *would* have matched is the
  // reason to open explain() on a refused request; only the verdict is fixed.
  it('still traces the policies, and the summary reports the denial', async () => {
    const engine = await adminEngine()
    const explained = await engine.explain('u1', IAM_RESERVED_REFUSAL, { attributes: {}, type: 'post' })
    expect(explained.policies.length).toBeGreaterThan(0)
    expect(explained.summary).toContain('DENIED')
    expect(explained.summary).toContain('reserved refusal token')
  })

  // Control: the same engine, the same wildcard grant, an ordinary action.
  it('control: an ordinary action is still explained as allowed', async () => {
    const engine = await adminEngine()
    const explained = await engine.explain('u1', 'read', { attributes: {}, type: 'post' })
    expect(explained.decision.allowed).toBe(true)
    expect(explained.decision.failure).toBeUndefined()
  })
})
