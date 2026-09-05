import { describe, expect, it } from 'vitest'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl, IamRequest } from '../../types'
import { evaluate, evaluateFast, evaluatePolicyFast } from '../evaluate'
import { indexPolicy } from '../evaluate.libs'

/**
 * Property-based regression guard: generate deterministic-random policy sets
 * and assert `evaluate(...).allowed === evaluateFast(...)` for every
 * `(policies, request)` pair. Locks the contract that the trace path and the
 * zero-alloc fast path agree on every input, so any future optimization that
 * silently breaks one side trips a failing oracle iteration.
 *
 * Deterministic seed -> reproducible failures.
 *
 * **What a passing iteration does and does not prove.** `evaluatePolicyFast`
 * hands any policy carrying a throwable condition (`matches`, or an operator no
 * `ops` entry answers to) straight to `evaluatePolicy` - deliberately, so the
 * two modes agree by construction rather than by two implementations being kept
 * in step. On those iterations this oracle is comparing the interpreter with
 * itself, and agreement is guaranteed: they are a coverage measurement of the
 * *delegation*, not of a second implementation. That is roughly half of them,
 * because the poison policy is mixed in every fourth iteration and the
 * generator draws `matches` conditions besides.
 *
 * So the iterations that actually put two implementations against each other
 * are the ones where no policy in the set is throwable. Those are counted and
 * given a floor below, because "1000 iterations" meant something much smaller
 * than it sounded, and the delegation is pinned directly, on the shape that
 * would diverge without it, in `fast-path-throwable-delegation.test.ts`.
 */

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
// Rule-only wildcard patterns (never used for a request's own action/resource -
// a request is always literal, only a rule pattern can be expansive). Mixed into
// makeRule below so it exercises indexPolicy's wildcard buckets: two independent
// picks per rule naturally produce pure-literal, pure-wildcard, single-dimension-
// wildcard, and mixed literal+wildcard-in-one-list rules, all from one knob.
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
  // Pick from a small set of resolvable field/value combinations so most
  // conditions evaluate against the generated request state. The `matches`
  // arm is the only one that can throw, and it does so exactly when the
  // request's user agent is oversized - the Indeterminate dimension was
  // otherwise unreachable from this generator, so every dev/prod divergence
  // that lives on an error path was invisible to the oracle.
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
    // Deliberately narrow. `first-match` / `highest-priority` break equal
    // priorities by source order, and that tie-break is where the interpreter
    // and the indexed fast path can drift apart. Spread over 20 values, ties
    // were rare enough that a real literal-vs-wildcard divergence went unseen;
    // 4 values makes collisions the common case without losing ordering cover.
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
    // 10% of requests carry a user agent past the regex input cap, which makes
    // any generated `matches` condition throw. That is the shape an attacker
    // controls: padding a header is enough to turn a deny rule Indeterminate.
    environment: { userAgent: forceOversized || rng() < 0.1 ? OVERSIZED_USER_AGENT : 'curl/8.0' },
    scope: rng() < 0.3 ? pick(rng, SCOPES) : undefined,
  }
}

describe('property oracle: evaluate == evaluateFast', () => {
  // 1000 fuzz iterations per (combine, default) pair. Each pair covers small,
  // medium, and large policy sets; total suite cost stays under ~200ms.
  const ITERATIONS = 1000

  /**
   * `evaluateFast` cannot represent `first-applicable` - it falls through to
   * `'and'`, and the Engine constructor refuses the pairing - so two of the six
   * generated tests used to `return` before their first iteration and report
   * green under the name of the mode they did not cover. The combine loop is
   * driven against this reference instead, which re-derives the XACML rule from
   * the *other* engine's per-policy primitive: the first policy that is not
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
   * A wildcard rule whose only condition is a `matches` on the user agent, so
   * an oversized agent makes this policy throw whatever else was generated.
   * Mixed in on a fixed fraction of iterations rather than left to the random
   * draw: with the draw alone, two of the six generated tests saw zero throwing
   * evaluations in 1000 iterations, which is how the Indeterminate dimension
   * stayed unfuzzed even after the generator learned to produce `matches`.
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
        // ...and the *other* half has to fire too. Without this floor a
        // generator change that made every policy throwable would leave 1000
        // iterations of the interpreter agreeing with itself, reported as 1000
        // iterations of differential testing. The number is a floor on what the
        // current generator produces (~450-550), not a target.
        expect(independent, 'no iteration compared two independent implementations').toBeGreaterThan(300)
      })
    }
  }
})
