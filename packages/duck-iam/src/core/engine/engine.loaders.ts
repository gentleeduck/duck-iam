// Cache-fronted loaders, kept out of the engine class so single-flight, timeouts and row caps test in isolation.

import type { IamLRUCache } from '../../shared/cache'
import { throwIamError } from '../errors'
import { toErrorMessage } from '../errors/normalize'
import { resolveEffectiveRoles, rolesToPolicy } from '../rbac'
import type { AccessControl, IamAdapter, IamRequest } from '../types'
import type { IEngineInFlightBag, ISingleFlightSlot } from './engine.invalidation'
import { deepFreezePolicy, runSingleFlight, runSingleFlightKeyed } from './engine.libs'
import type { IIamCachesForStats } from './engine.stats'

/** Everything a loader needs. The engine builds one bag per instance and shares it across every loader. */
export interface IIamLoaderDeps<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
> extends IIamCachesForStats {
  adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
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
  /**
   * Reports a role a subject holds that no stored role defines. The id stays an effective role, but its
   * `inherits` edges are gone, so a deny targeting a role it conferred stops applying with nothing to show it.
   */
  reportUndefinedAssignedRole: (subjectId: string, roleId: string) => void

  /**
   * Reports a policy whose targets make it unreachable - a `targets.roles` naming no stored role, or an
   * action/resource target no rule can match. Called from here and from the compiled-table build, since either
   * path can be the only one that runs.
   */
  reportPolicyTargetProblems: (
    policies: readonly AccessControl.IPolicy[],
    roles: readonly AccessControl.IRole[],
  ) => void
  withTimeout: <T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string) => Promise<T>
}

/**
 * Cache-or-load-once for a single key: a cache hit returns immediately, an in-flight load is joined, and
 * everything else runs exactly once through {@link runSingleFlight}. Shared by {@link loadAllCapped},
 * {@link loadRbacPolicy} and {@link loadAllPolicies}, which differ only in which cache/key/slot they read and
 * what `build`/`onSuccess` do.
 */
async function cacheOrBuild<T>(opts: {
  cache: IamLRUCache<T>
  key: string
  slot: ISingleFlightSlot<T>
  build: () => Promise<T>
  onSuccess: (value: T) => void
}): Promise<T> {
  const cached = opts.cache.get(opts.key)
  if (cached) return cached
  if (opts.slot.value) return opts.slot.value
  return runSingleFlight(
    () => opts.slot.value,
    (p) => {
      opts.slot.value = p
    },
    opts.build,
    opts.onSuccess,
  )
}

/**
 * Cache-or-load-once for a whole-adapter list: single-flighted under the fixed key `'all'`, capped, and cached
 * only on success. Shared by {@link loadPolicies} and {@link loadRoles}, which differ only in which cache/slot/
 * adapter call/cap they use.
 * NOTE: throws above `cap` instead of caching, so e.g. a lost tenant filter is not pinned in memory for a TTL.
 */
async function loadAllCapped<T>(opts: {
  cache: IamLRUCache<T[]>
  slot: ISingleFlightSlot<T[]>
  fetch: () => Promise<T[]>
  cap: number
  capField: string
  noun: string
}): Promise<T[]> {
  return cacheOrBuild({
    cache: opts.cache,
    key: 'all',
    slot: opts.slot,
    build: async () => {
      const items = await opts.fetch()
      if (items.length > opts.cap) {
        throwIamError('IAM_ENGINE_ROW_CAP_EXCEEDED', {
          noun: opts.noun,
          count: items.length,
          cap: opts.cap,
          capField: opts.capField,
        })
      }
      return items
    },
    onSuccess: (items) => {
      opts.cache.set('all', items)
    },
  })
}

/** Every explicit policy. */
export async function loadPolicies<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
>(deps: IIamLoaderDeps<TAction, TResource, TRole, TScope>): Promise<AccessControl.IPolicy[]> {
  return loadAllCapped({
    cache: deps.policyCache,
    slot: deps.inFlight.policies,
    fetch: () => deps.withTimeout((opts) => deps.adapter.listPolicies(opts), 'listPolicies'),
    cap: deps.maxPolicies,
    capField: 'maxPolicies',
    noun: 'policies',
  })
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
  return loadAllCapped({
    cache: deps.roleCache,
    slot: deps.inFlight.roles,
    fetch: () => deps.withTimeout((opts) => deps.adapter.listRoles(opts), 'listRoles'),
    cap: deps.maxRoles,
    capField: 'maxRoles',
    noun: 'roles',
  })
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
    throwIamError('IAM_ENGINE_SUBJECT_LOAD_SHED', {
      subjectId,
      inFlight: deps.inFlight.subjects.size,
      cap: deps.maxConcurrentSubjectLoads,
    })
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
                    `not caching this subject: ${toErrorMessage(err)}`,
                )
                return null
              })
          : Promise.resolve(null),
      ])
      const roles = resolveEffectiveRoles(assignedRoles, allRoles, (roleId) =>
        deps.reportUndefinedAssignedRole(subjectId, roleId),
      )
      const scopedRolesFn = deps.adapter.getSubjectScopedRoles
      const assignedScopedRoles = scopedRolesFn
        ? await deps.withTimeout((opts) => scopedRolesFn.call(deps.adapter, subjectId, opts), 'getSubjectScopedRoles')
        : undefined
      // Scoped assignments close over `inherits` too. Inherited roles take their own `IRole.scope` (as
      // `rolesToPolicy` gates them), else the row's; the directly assigned role keeps `sr.scope`.
      const rolesById = new Map(allRoles.map((r) => [r.id, r]))
      const scopedRoles = assignedScopedRoles?.flatMap((sr) =>
        resolveEffectiveRoles([sr.role], allRoles, (roleId) => deps.reportUndefinedAssignedRole(subjectId, roleId)).map(
          (role) =>
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
  return cacheOrBuild({
    cache: deps.rbacPolicyCache,
    key: 'rbac',
    slot: deps.inFlight.rbac,
    build: async () => {
      const roles = await loadRoles(deps)
      return deepFreezePolicy(rolesToPolicy(roles, deps.scopeMode))
    },
    onSuccess: (built) => {
      // Expire with the role snapshot it was built from; a fresh TTL would outlive its input.
      deps.rbacPolicyCache.set('rbac', built, deps.roleCache.expiresAt('all'))
    },
  })
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
  return cacheOrBuild({
    cache: deps.mergedPolicyCache,
    key: 'merged',
    slot: deps.inFlight.merged,
    build: async () => {
      // `loadRoles` is a cache hit behind `loadRbacPolicy`, so the target check costs no extra read.
      const [policies, rbacPolicy, roles] = await Promise.all([
        loadPolicies(deps),
        loadRbacPolicy(deps),
        loadRoles(deps),
      ])
      deps.reportPolicyTargetProblems(policies, roles)
      return rbacPolicy.rules.length === 0 ? policies : [rbacPolicy, ...policies]
    },
    onSuccess: (merged) => {
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
  })
}
