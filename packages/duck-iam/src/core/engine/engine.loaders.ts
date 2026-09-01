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
  withTimeout: <T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string) => Promise<T>
}

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
  return runSingleFlightKeyed(
    deps.inFlight.subjects,
    subjectId,
    async () => {
      const [assignedRoles, attributes, allRoles] = await Promise.all([
        deps.withTimeout((opts) => deps.adapter.getSubjectRoles(subjectId, opts), 'getSubjectRoles'),
        deps.withTimeout((opts) => deps.adapter.getSubjectAttributes(subjectId, opts), 'getSubjectAttributes'),
        loadRoles(deps),
      ])
      const roles = resolveEffectiveRoles(assignedRoles, allRoles)
      const scopedRolesFn = deps.adapter.getSubjectScopedRoles
      const assignedScopedRoles = scopedRolesFn
        ? await deps.withTimeout((opts) => scopedRolesFn.call(deps.adapter, subjectId, opts), 'getSubjectScopedRoles')
        : undefined
      // A scoped assignment is an assignment: it has to be closed over `inherits` too, so a
      // check at the inherited-into scope can see it. `resolveEffectiveRoles` is scope-blind,
      // so each role it reaches is tagged with ITS OWN `IRole.scope` (matching how
      // `rolesToPolicy` gates each role's rules), not the source assignment row's scope -
      // falling back to the row's scope only when the role declares none of its own.
      const rolesById = new Map(allRoles.map((r) => [r.id, r]))
      const scopedRoles = assignedScopedRoles?.flatMap((sr) =>
        resolveEffectiveRoles([sr.role], allRoles).map((role) => ({
          ...sr,
          role,
          scope: rolesById.get(role)?.scope ?? sr.scope,
        })),
      )
      const subject: IamRequest.ISubject = { id: subjectId, roles, scopedRoles, attributes }
      return subject
    },
    (subject) => {
      deps.subjectCache.set(subjectId, subject)
    },
  )
}

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
      return deepFreezePolicy(rolesToPolicy(roles))
    },
    (built) => {
      deps.rbacPolicyCache.set('rbac', built)
    },
  )
}

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
