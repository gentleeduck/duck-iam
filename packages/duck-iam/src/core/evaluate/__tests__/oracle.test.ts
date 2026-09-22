import { describe, expect, it } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast, evaluatePolicyFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

// Seeded fuzz of `evaluate(...).allowed === evaluateFast(...)`. Throwable policies delegate to the interpreter,
// so only iterations without one compare two implementations; those get a floor below.

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const ACTIONS = ['read', 'write', 'delete', 'posts:read', 'posts:write']
const RESOURCES = ['post', 'comment', 'user', 'org', 'org:project', 'dashboard.users']
// Rule-only wildcard patterns (a request is always literal), mixed into makeRule to reach every wildcard bucket.
const WILDCARD_ACTIONS = ['posts:*', 'admin:*']
const WILDCARD_RESOURCES = ['comment:*', 'dashboard.*']
const ROLES = ['viewer', 'editor', 'admin', 'guest']
const SCOPES = ['org-1', 'org-2']
const STATUSES = ['active', 'suspended', 'pending']
const ALGORITHMS: AccessControl.CombiningAlgorithm[] = [
  'deny-overrides',
  'allow-overrides',
  'first-match',
  'highest-priority',
]
const COMBINES: AccessControl.PolicyCombine[] = ['and', 'allow-overrides', 'first-applicable']
const DEFAULTS: AccessControl.Effect[] = ['allow', 'deny']

/** Long enough to make `matches` throw rather than answer. */
const OVERSIZED_USER_AGENT = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')

function pick<T>(rng: () => number, xs: readonly T[]): T {
  return xs[Math.floor(rng() * xs.length)]!
}

function makeCondition(rng: () => number): AccessControl.ICondition {
  // Resolvable field/value pairs. The `matches` arm throws exactly when the user agent is oversized, which keeps
  // the Indeterminate dimension reachable.
  const choice = Math.floor(rng() * 5)
  switch (choice) {
    case 0:
      return { field: 'subject.attributes.status', operator: 'eq', value: pick(rng, STATUSES) }
    case 1:
      return { field: 'resource.attributes.ownerId', operator: 'eq', value: '$subject.id' }
    case 2:
      return { field: 'subject.roles', operator: 'contains', value: pick(rng, ROLES) }
    case 3:
      return { field: 'environment.userAgent', operator: 'matches', value: 'curl' }
    default:
      return { field: 'action', operator: 'in', value: [pick(rng, ACTIONS), pick(rng, ACTIONS)] }
  }
}

function makeConditionGroup(rng: () => number): AccessControl.IConditionGroup {
  const numConds = Math.floor(rng() * 3) // 0..2
  if (numConds === 0) return { all: [] }
  const conds = Array.from({ length: numConds }, () => makeCondition(rng))
  const logic = rng()
  if (logic < 0.5) return { all: conds }
  if (logic < 0.8) return { any: conds }
  return { none: conds }
}

// 20% of picks are a wildcard pattern instead of a literal value.
function pickAction(rng: () => number): string {
  return rng() < 0.2 ? pick(rng, WILDCARD_ACTIONS) : pick(rng, ACTIONS)
}
function pickResource(rng: () => number): string {
  return rng() < 0.2 ? pick(rng, WILDCARD_RESOURCES) : pick(rng, RESOURCES)
}

function makeRule(rng: () => number, idx: number): AccessControl.IRule {
  const numActions = 1 + Math.floor(rng() * 2)
  const numResources = 1 + Math.floor(rng() * 2)
  const actions = Array.from({ length: numActions }, () => pickAction(rng))
  const resources = Array.from({ length: numResources }, () => pickResource(rng))
  // 30% of rules carry conditions - exercises condition evaluation in both paths.
  const withConditions = rng() < 0.3
  return {
    id: `r${idx}`,
    effect: rng() < 0.5 ? 'allow' : 'deny',
    // Narrow, so priority ties (where the interpreter and the indexed fast path can drift) are common.
    priority: Math.floor(rng() * 4),
    actions,
    resources,
    conditions: withConditions ? makeConditionGroup(rng) : { all: [] },
  }
}

/** Random target dimensions; `undefined` when no dimension was drawn. */
function makeTargets(rng: () => number): AccessControl.IPolicy['targets'] {
  const targets: { actions?: string[]; resources?: string[]; roles?: string[] } = {}
  if (rng() < 0.5) targets.actions = [pick(rng, ACTIONS)]
  if (rng() < 0.5) targets.resources = [pick(rng, RESOURCES)]
  if (rng() < 0.3) targets.roles = [pick(rng, ROLES)]
  return Object.keys(targets).length > 0 ? targets : undefined
}

function makePolicy(rng: () => number, idx: number): AccessControl.IPolicy {
  const numRules = 1 + Math.floor(rng() * 4)
  // 30% policies carry targets - exercises NotApplicable fallthrough.
  const targets = rng() < 0.3 ? makeTargets(rng) : undefined
  return {
    id: `p${idx}`,
    name: `P${idx}`,
    algorithm: pick(rng, ALGORITHMS),
    rules: Array.from({ length: numRules }, (_, i) => makeRule(rng, i)),
    ...(targets ? { targets } : {}),
  }
}

function makeRequest(rng: () => number, forceOversized = false): IamRequest.IAccessRequest {
  // Subject carries role + attributes so conditions resolve against real state.
  const numRoles = 1 + Math.floor(rng() * 2)
  const roles = Array.from({ length: numRoles }, () => pick(rng, ROLES))
  return {
    subject: {
      id: `u${Math.floor(rng() * 10)}`,
      roles,
      attributes: { status: pick(rng, STATUSES), level: Math.floor(rng() * 5) },
    },
    action: pick(rng, ACTIONS),
    resource: {
      type: pick(rng, RESOURCES),
      attributes: { ownerId: rng() < 0.5 ? 'u0' : 'other' },
    },
    // 10% of requests pad the user agent past the regex cap, as an attacker can, so any `matches` throws.
    environment: { userAgent: forceOversized || rng() < 0.1 ? OVERSIZED_USER_AGENT : 'curl/8.0' },
    scope: rng() < 0.3 ? pick(rng, SCOPES) : undefined,
  }
}

describe('property oracle: evaluate == evaluateFast', () => {
  // 1000 fuzz iterations per (combine, default) pair. Each pair covers small,
  // medium, and large policy sets; total suite cost stays under ~200ms.
  const ITERATIONS = 1000

  /**
   * Reference for `first-applicable`, which `evaluateFast` cannot represent: the first policy that is not
   * NotApplicable wins, and an evaluation error is Indeterminate, never a skip.
   */
  function firstApplicableReference(
    policies: AccessControl.IPolicy[],
    request: IamRequest.IAccessRequest,
    defaultEffect: AccessControl.Effect,
  ): boolean {
    for (const policy of policies) {
      let vote: boolean | null
      try {
        vote = evaluatePolicyFast(policy, request, defaultEffect)
      } catch {
        vote = policy.rules.some((r) => r.effect === 'deny') ? false : defaultEffect === 'allow'
      }
      if (vote === null) continue
      return vote
    }
    return defaultEffect === 'allow'
  }

  /**
   * A wildcard rule whose only condition is a `matches` on the user agent, so an oversized agent makes it throw.
   * Mixed in on a fixed fraction of iterations, since the random draw alone can miss throwing evaluations.
   */
  function poisonPolicy(effect: AccessControl.Effect, idx: number): AccessControl.IPolicy {
    return {
      algorithm: 'deny-overrides',
      id: `poison${idx}`,
      name: `Poison${idx}`,
      rules: [
        {
          actions: ['*'],
          conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
          effect,
          id: 'r-poison',
          priority: 1,
          resources: ['*'],
        },
      ],
    }
  }

  for (const combine of COMBINES) {
    for (const defaultEffect of DEFAULTS) {
      it(`combine="${combine}" default="${defaultEffect}"`, () => {
        const rng = mulberry32(0xdec1ded ^ defaultEffect.length ^ combine.length)
        let thrown = 0
        /** Iterations where no policy delegates, so two implementations really did run. */
        let independent = 0
        const onPolicyError = () => {
          thrown++
        }
        for (let i = 0; i < ITERATIONS; i++) {
          // Mix small (1-3) and larger (8-12) policy sets across iterations.
          const numPolicies = i % 5 === 0 ? 8 + Math.floor(rng() * 5) : 1 + Math.floor(rng() * 3)
          const policies = Array.from({ length: numPolicies }, (_, idx) => makePolicy(rng, idx))
          const poisoned = i % 4 === 0
          if (poisoned) policies.push(poisonPolicy(rng() < 0.5 ? 'allow' : 'deny', numPolicies))
          const request = makeRequest(rng, poisoned)
          if (!policies.some((policy) => indexPolicy(policy).mayThrow)) independent++
          const fullDecision = evaluate(policies, request, defaultEffect, combine, onPolicyError)
          const fastBool =
            combine === 'first-applicable'
              ? firstApplicableReference(policies, request, defaultEffect)
              : evaluateFast(policies, request, defaultEffect, combine, onPolicyError)
          if (fullDecision.allowed !== fastBool) {
            throw new Error(
              `Divergence at iter ${i}: evaluate=${fullDecision.allowed}, evaluateFast=${fastBool}\n` +
                `combine=${combine} default=${defaultEffect}\n` +
                `policies=${JSON.stringify(policies, null, 2)}\n` +
                `request=${JSON.stringify(request)}`,
            )
          }
        }
        // The poison `matches` arm has to actually fire, or the Indeterminate
        // dimension is back to being unfuzzed with the generator none the wiser.
        expect(thrown).toBeGreaterThan(0)
        // ...and the other half too, or the interpreter agreeing with itself passes as differential testing.
        // A floor on what the current generator produces (~450-550), not a target.
        expect(independent, 'no iteration compared two independent implementations').toBeGreaterThan(300)
      })
    }
  }
})
