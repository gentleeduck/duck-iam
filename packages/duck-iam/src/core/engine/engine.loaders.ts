/**
 * Cache-fronted loaders pulled out of the Engine class. Each takes a
 * minimal dependency bag so the single-flight + adapter-timeout +
 * max-rows guard logic is testable in isolation.
 */

import type { IamLRUCache } from '../../shared/cache'
import { resolveEffectiveRoles, rolesToPolicy } from '../rbac'
import type { AccessControl, IamAdapter, IamRequest } from '../types'
import type { IEngineInFlightBag } from './engine.invalidation'
import { deepFreezePolicy, runSingleFlight, runSingleFlightKeyed } from './engine.libs'

/**
 * Everything a loader needs, passed explicitly rather than reached for through
 * `this`. Nothing here is optional at the call site: the Engine builds one bag
 * per instance and hands the same object to every loader, so a test can supply
 * a fake adapter and real caches - or real adapter and no caches - without
 * standing up an Engine.
 */
export interface IIamLoaderDeps<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
> {
  adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
  policyCache: IamLRUCache<AccessControl.IPolicy[]>
  roleCache: IamLRUCache<AccessControl.IRole[]>
  rbacPolicyCache: IamLRUCache<AccessControl.IPolicy>
  mergedPolicyCache: IamLRUCache<AccessControl.IPolicy[]>
  subjectCache: IamLRUCache<IamRequest.ISubject>
  inFlight: IEngineInFlightBag
  maxPolicies: number
  maxRoles: number
  /**
   * Hard ceiling on concurrent distinct-subject adapter loads. `0` (default)
   * is unbounded. Guards a cold-flat thundering herd: without a cap, a burst
   * of never-before-seen subjects issues one adapter call each with no
   * back-pressure, growing `inFlight.subjects` (and the promise closures it
   * holds) without limit. Only new loads are gated - a call that hits the
   * subject cache or joins an already-in-flight load for the same key never
   * counts against the cap.
   */
  maxConcurrentSubjectLoads: number
  /** `IConfig.scopeMode`; decides how `rolesToPolicy` gates a role-declared scope. */
  scopeMode: 'flat' | 'hierarchical'
  withTimeout: <T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string) => Promise<T>
}

/**
 * Every explicit policy the adapter holds, cached under one key and loaded at
 * most once per cold cache regardless of how many callers ask at the same time.
 *
 * Refuses a result larger than `maxPolicies` instead of caching it. An adapter
 * that suddenly answers with the whole table - an unbounded query, a lost
 * tenant filter - would otherwise be pinned in memory for the life of the TTL,
 * and every later evaluation would walk it. The throw names the count and the
 * limit so the fix is a decision (raise it, or repair the adapter) rather than
 * a hunt.
 */
export async function loadPolicies<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>): Promise<AccessControl.IPolicy[]> {
  const cached = deps.policyCache.get('all')
  if (cached) return cached
  if (deps.inFlight.policies.value) return deps.inFlight.policies.value
  return runSingleFlight(
    () => deps.inFlight.policies.value,
    (p) => {
      deps.inFlight.policies.value = p
    },
    async () => {
      const policies = await deps.withTimeout((opts) => deps.adapter.listPolicies(opts), 'listPolicies')
      if (policies.length > deps.maxPolicies) {
        throw new Error(
          `[@gentleduck/iam:engine] adapter returned ${policies.length} policies; maxPolicies is ${deps.maxPolicies}. Raise the limit or fix the adapter.`,
        )
      }
      return policies
    },
    (policies) => {
      deps.policyCache.set('all', policies)
    },
  )
}

/**
 * Every role definition the adapter holds. Same cache-then-single-flight shape
 * as {@link loadPolicies}, guarded by `maxRoles` for the same reason.
 *
 * Roles are loaded whole rather than per-subject because inheritance closure
 * needs the full graph: {@link resolveSubject} cannot expand `inherits` from a
 * subject's directly assigned ids alone.
 */
export async function loadRoles<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>): Promise<AccessControl.IRole[]> {
  const cached = deps.roleCache.get('all')
  if (cached) return cached
  if (deps.inFlight.roles.value) return deps.inFlight.roles.value
  return runSingleFlight(
    () => deps.inFlight.roles.value,
    (p) => {
      deps.inFlight.roles.value = p
    },
    async () => {
      const roles = await deps.withTimeout((opts) => deps.adapter.listRoles(opts), 'listRoles')
      if (roles.length > deps.maxRoles) {
        throw new Error(
          `[@gentleduck/iam:engine] adapter returned ${roles.length} roles; maxRoles is ${deps.maxRoles}. Raise the limit or fix the adapter.`,
        )
      }
      return roles
    },
    (roles) => {
      deps.roleCache.set('all', roles)
    },
  )
}

/**
 * The full authorization picture for one subject: effective roles (direct plus
 * everything they inherit), scoped role assignments, and attributes.
 *
 * Single-flighted per subject id, so a burst of concurrent checks for the same
 * subject issues one set of adapter reads. Two things make this loader more
 * than a cached read:
 *
 *   - **Load shedding.** A cold cache hit by many distinct subjects at once
 *     would open one adapter call per subject with no back-pressure;
 *     `maxConcurrentSubjectLoads` caps the in-flight set and rejects beyond it.
 *     Cache hits and joins onto an existing load never count against the cap.
 *   - **Grant boundary.** When the adapter can say when this subject's grants
 *     next change, the answer is cached only until then. The boundary read is
 *     advisory - if it fails, the subject is resolved but not cached, because
 *     a full TTL on an entry whose expiry nobody could name is exactly the
 *     stale allow the boundary exists to prevent.
 */
export async function resolveSubject<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>, subjectId: string): Promise<IamRequest.ISubject> {
  const cached = deps.subjectCache.get(subjectId)
  if (cached) return cached
  const inFlight = deps.inFlight.subjects.get(subjectId)
  if (inFlight) return inFlight
  if (deps.maxConcurrentSubjectLoads > 0 && deps.inFlight.subjects.size >= deps.maxConcurrentSubjectLoads) {
    throw new Error(
      `[@gentleduck/iam:engine] subject load shed: ${deps.inFlight.subjects.size} concurrent subject loads already in flight (cap ${deps.maxConcurrentSubjectLoads}); rejecting new load for "${subjectId}"`,
    )
  }
  let boundary: number | null = null
  // A boundary the store could not produce is not a boundary of `null`: `null`
  // means "nothing changes for a while" and buys the entry a full TTL, which is
  // exactly the stale allow the boundary exists to prevent. Unknown means the
  // subject is not cached at all.
  let cacheable = true
  return runSingleFlightKeyed(
    deps.inFlight.subjects,
    subjectId,
    async () => {
      // The boundary rides along in the same `Promise.all` as the reads it
      // describes: an adapter with time-boxed grants has to be asked, and
      // asking after the fact would add a round trip to every cold subject.
      const boundaryFn = deps.adapter.getSubjectGrantBoundary
      const [assignedRoles, attributes, allRoles, grantBoundary] = await Promise.all([
        deps.withTimeout((opts) => deps.adapter.getSubjectRoles(subjectId, opts), 'getSubjectRoles'),
        deps.withTimeout((opts) => deps.adapter.getSubjectAttributes(subjectId, opts), 'getSubjectAttributes'),
        loadRoles(deps),
        boundaryFn
          ? deps
              .withTimeout((opts) => boundaryFn.call(deps.adapter, subjectId, opts), 'getSubjectGrantBoundary')
              .catch((err: unknown) => {
                // Advisory, so its failure must not decide anything. The reads
                // above still apply the window, and `cacheable = false` keeps
                // the answer from outliving a bound nobody can name.
                cacheable = false
                console.warn(
                  `[@gentleduck/iam:engine] getSubjectGrantBoundary failed for "${subjectId}"; ` +
                    `not caching this subject: ${err instanceof Error ? err.message : String(err)}`,
                )
                return null
              })
          : Promise.resolve(null),
      ])
      const roles = resolveEffectiveRoles(assignedRoles, allRoles)
      const scopedRolesFn = deps.adapter.getSubjectScopedRoles
      const assignedScopedRoles = scopedRolesFn
        ? await deps.withTimeout((opts) => scopedRolesFn.call(deps.adapter, subjectId, opts), 'getSubjectScopedRoles')
        : undefined
      // A scoped assignment is an assignment: it has to be closed over `inherits` too, so a
      // check at the inherited-into scope can see it. `resolveEffectiveRoles` is scope-blind
      // and its result includes the directly assigned role itself, so only roles OTHER THAN
      // the direct assignment get retagged with their own `IRole.scope` (matching how
      // `rolesToPolicy` gates each role's rules) - falling back to the row's scope when the
      // role declares none of its own. The direct assignment's `sr.scope` is never overridden;
      // that's the scope it was actually assigned at.
      const rolesById = new Map(allRoles.map((r) => [r.id, r]))
      const scopedRoles = assignedScopedRoles?.flatMap((sr) =>
        resolveEffectiveRoles([sr.role], allRoles).map((role) =>
          role === sr.role ? { ...sr, role } : { ...sr, role, scope: rolesById.get(role)?.scope ?? sr.scope },
        ),
      )
      // Carried out to the cache write below rather than returned, so the
      // in-flight map still holds a plain `Promise<ISubject>` for the callers
      // already waiting on it.
      boundary = grantBoundary
      const subject: IamRequest.ISubject = { id: subjectId, roles, scopedRoles, attributes }
      return subject
    },
    (subject) => {
      if (!cacheable) return
      deps.subjectCache.set(subjectId, subject, boundary ?? undefined)
    },
  )
}

/**
 * The single synthetic policy that role definitions compile down to, so RBAC
 * and explicit ABAC policies are evaluated by one code path rather than two.
 *
 * Deep-frozen before caching: it is shared by every evaluation on this instance,
 * and a caller that mutated a rule in place would silently rewrite the
 * authorization model for everyone until the next invalidation.
 */
export async function loadRbacPolicy<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>): Promise<AccessControl.IPolicy> {
  const cached = deps.rbacPolicyCache.get('rbac')
  if (cached) return cached
  if (deps.inFlight.rbac.value) return deps.inFlight.rbac.value
  return runSingleFlight(
    () => deps.inFlight.rbac.value,
    (p) => {
      deps.inFlight.rbac.value = p
    },
    async () => {
      const roles = await loadRoles(deps)
      return deepFreezePolicy(rolesToPolicy(roles, deps.scopeMode))
    },
    (built) => {
      deps.rbacPolicyCache.set('rbac', built)
    },
  )
}

/**
 * Explicit policies plus the compiled RBAC policy, in the order the evaluator
 * expects, memoized under one key so the merge is not redone per check.
 *
 * The RBAC policy is prepended only when it has rules - a deployment with no
 * roles should not pay for an empty policy on every evaluation.
 */
export async function loadAllPolicies<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>): Promise<AccessControl.IPolicy[]> {
  const cached = deps.mergedPolicyCache.get('merged')
  if (cached) return cached
  if (deps.inFlight.merged.value) return deps.inFlight.merged.value
  return runSingleFlight(
    () => deps.inFlight.merged.value,
    (p) => {
      deps.inFlight.merged.value = p
    },
    async () => {
      const [policies, rbacPolicy] = await Promise.all([loadPolicies(deps), loadRbacPolicy(deps)])
      return rbacPolicy.rules.length === 0 ? policies : [rbacPolicy, ...policies]
    },
    (merged) => {
      deps.mergedPolicyCache.set('merged', merged)
    },
  )
}
