// Cache-fronted loaders, kept out of the engine class so single-flight, timeouts and row caps test in isolation.

import type { IamLRUCache } from '../../shared/cache'
import { resolveEffectiveRoles, rolesToPolicy } from '../rbac'
import type { AccessControl, IamAdapter, IamRequest } from '../types'
import type { IEngineInFlightBag } from './engine.invalidation'
import { deepFreezePolicy, runSingleFlight, runSingleFlightKeyed } from './engine.libs'

/** Everything a loader needs. The engine builds one bag per instance and shares it across every loader. */
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
   * Cap on concurrent new subject loads; `0` is unbounded. Cache hits and joins onto an in-flight load do not count.
   * NOTE: stops a cold-cache burst of new subjects from issuing one adapter call each with no back-pressure.
   */
  maxConcurrentSubjectLoads: number
  /** `IConfig.scopeMode`; decides how `rolesToPolicy` gates a role-declared scope. */
  scopeMode: 'flat' | 'hierarchical'
  withTimeout: <T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string) => Promise<T>
}

/**
 * Every explicit policy, cached under one key and loaded once per cold cache however many callers ask.
 * NOTE: throws above `maxPolicies` instead of caching, so a lost tenant filter is not pinned in memory for a TTL.
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
 * Every role definition, loaded like {@link loadPolicies} and capped by `maxRoles`.
 * Loaded whole, not per subject, because expanding `inherits` needs the full graph.
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
 * One subject's effective roles, scoped roles and attributes, single-flighted per id.
 * Throws past `maxConcurrentSubjectLoads`, and caches only until the role snapshot expires or, when the adapter
 * reports one, the subject's next grant boundary - whichever comes first.
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
  // SECURITY: a failed boundary read is not `null` (which buys a full TTL); it means do not cache at all.
  let cacheable = true
  return runSingleFlightKeyed(
    deps.inFlight.subjects,
    subjectId,
    async () => {
      // PERF: the boundary joins the same `Promise.all` as the reads it describes, adding no round trip.
      const boundaryFn = deps.adapter.getSubjectGrantBoundary
      const [assignedRoles, attributes, allRoles, grantBoundary] = await Promise.all([
        deps.withTimeout((opts) => deps.adapter.getSubjectRoles(subjectId, opts), 'getSubjectRoles'),
        deps.withTimeout((opts) => deps.adapter.getSubjectAttributes(subjectId, opts), 'getSubjectAttributes'),
        loadRoles(deps),
        boundaryFn
          ? deps
              .withTimeout((opts) => boundaryFn.call(deps.adapter, subjectId, opts), 'getSubjectGrantBoundary')
              .catch((err: unknown) => {
                // Advisory: the failure decides nothing, but the answer must not outlive a bound nobody can name.
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
      // Scoped assignments close over `inherits` too. Inherited roles take their own `IRole.scope` (as
      // `rolesToPolicy` gates them), else the row's; the directly assigned role keeps `sr.scope`.
      const rolesById = new Map(allRoles.map((r) => [r.id, r]))
      const scopedRoles = assignedScopedRoles?.flatMap((sr) =>
        resolveEffectiveRoles([sr.role], allRoles).map((role) =>
          role === sr.role ? { ...sr, role } : { ...sr, role, scope: rolesById.get(role)?.scope ?? sr.scope },
        ),
      )
      // Passed to the cache write below, not returned, so waiters still get a plain `Promise<ISubject>`.
      boundary = grantBoundary
      const subject: IamRequest.ISubject = { id: subjectId, roles, scopedRoles, attributes }
      return subject
    },
    (subject) => {
      if (!cacheable) return
      // `roles` and `scopedRoles` are resolved against the role snapshot, so the entry expires with it too.
      // An absent entry (`Infinity`) was read live and imposes no cap, as it does for the merged policies.
      deps.subjectCache.set(
        subjectId,
        subject,
        Math.min(boundary ?? Number.POSITIVE_INFINITY, deps.roleCache.expiresAt('all') ?? Number.POSITIVE_INFINITY),
      )
    },
  )
}

/**
 * The synthetic policy role definitions compile to, so RBAC and ABAC share one evaluation path.
 * SECURITY: deep-frozen before caching; every evaluation shares it, so an in-place mutation would rewrite the model.
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
      // Expire with the role snapshot it was built from; a fresh TTL would outlive its input.
      deps.rbacPolicyCache.set('rbac', built, deps.roleCache.expiresAt('all'))
    },
  )
}

/**
 * Explicit policies plus the RBAC policy, memoized so the merge is not redone per check.
 * PERF: RBAC is prepended only when it has rules, so a deployment without roles skips an empty policy.
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
      // Expire with the older input. An absent entry (`Infinity`) was read live and imposes no cap.
      deps.mergedPolicyCache.set(
        'merged',
        merged,
        Math.min(
          deps.policyCache.expiresAt('all') ?? Number.POSITIVE_INFINITY,
          deps.rbacPolicyCache.expiresAt('rbac') ?? Number.POSITIVE_INFINITY,
        ),
      )
    },
  )
}
