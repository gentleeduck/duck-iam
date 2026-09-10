import type { Explain } from '../explain'
import { createPending, type Pending } from '../pending'
import type { AccessControl, IamAdapter, IamClient, IamRequest } from '../types'
import type { IamEngine as IamEngineImpl } from './engine'
import { DEFAULT_HOOK_TIMEOUT_MS, safeHookCall } from './engine.hooks'
import { createAdmin } from './engine.libs'
import type { IamEngineTypes } from './engine.types'

/** The transaction-bound view of an {@link IamEngineImpl}. */
export namespace Bound {
  /**
   * Writes go through `admin`, the unbound engine's write interface; reads are served from transaction-local caches.
   * Read methods are declared explicitly, not spread, so this surface stays reviewable against the unbound one.
   */
  export interface IamEngine<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
    TMode extends AccessControl.Mode = 'production',
  > {
    /** The write surface, identical to `engine.admin` but bound to the transaction. */
    readonly admin: IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope>
    /** The transaction-local engine backing the reads. Reach for it only for methods not re-exposed here. */
    readonly engine: IamEngineImpl<TAction, TResource, TRole, TScope, TMode>
    /** Cache invalidations withheld until the caller's transaction commits. */
    readonly pending: Pending.Effects<TRole, TScope>

    authorize(request: IamRequest.IAccessRequest<TAction, TResource, TScope>): Promise<AccessControl.ModeResult<TMode>>
    can(
      subjectId: string,
      action: TAction,
      resource: IamRequest.IResource<TResource>,
      environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
      scope?: TScope,
    ): Promise<boolean>
    check(
      subjectId: string,
      action: TAction,
      resource: IamRequest.IResource<TResource>,
      environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
      scope?: TScope,
    ): Promise<AccessControl.ModeResult<TMode>>
    /** Mirrors the unbound `explain`, including its development-mode-only `this` constraint. */
    explain(
      this: IamEngine<TAction, TResource, TRole, TScope, 'development'>,
      subjectId: string,
      action: TAction,
      resource: IamRequest.IResource<TResource>,
      environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
      scope?: TScope,
    ): Promise<Explain.IResult>
    getEffectiveRoles(subjectId: string, scope?: TScope): Promise<readonly TRole[]>
    permissions(
      subjectId: string,
      checks: readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[],
      environment?: IamRequest.IAccessRequest<TAction, TResource, TScope>['environment'],
      opts?: { telemetry?: boolean },
    ): Promise<AccessControl.ModePermissionMap<TMode, TAction, TResource, TScope>>
  }
}

/**
 * Builds the bound view over a private engine with the transaction-bound adapter and fresh caches.
 * NOTE: fresh caches always miss, so reads see uncommitted writes and never leak them into the shared caches.
 */
export function buildBoundEngine<
  TAction extends string,
  TResource extends string,
  TRole extends string,
  TScope extends string,
  TMode extends AccessControl.Mode,
>(
  parent: IamEngineImpl<TAction, TResource, TRole, TScope, TMode>,
  boundAdapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>,
  config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>,
  makeEngine: (
    cfg: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>,
  ) => IamEngineImpl<TAction, TResource, TRole, TScope, TMode>,
): Bound.IamEngine<TAction, TResource, TRole, TScope, TMode> {
  // Drop the invalidator: never broadcast mid-transaction, nor leak a subscription per transaction.
  // Buffered invalidations broadcast through the parent on flush, after commit.
  const { invalidator: _dropped, ...rest } = config
  const local = makeEngine({ ...rest, adapter: boundAdapter })

  // Mutation events buffer with the invalidations and drain on flush, so a rolled-back transaction emits nothing.
  const onMutation = config.hooks?.onMutation
  const hookTimeoutMs = config.hookTimeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS
  const { cache, mutations, pending } = createPending<TRole, TScope>(
    {
      invalidatePolicies: () => parent.cache.invalidatePolicies(),
      invalidateRoles: (roleId) => parent.cache.invalidateRoles(roleId),
      invalidateSubject: (subjectId) => parent.cache.invalidateSubject(subjectId),
    },
    onMutation === undefined
      ? undefined
      : (event) => safeHookCall(() => onMutation(event), 'onMutation', hookTimeoutMs),
  )

  // Two sinks per write: local caches drop at once for read-after-write; shared caches learn on flush.
  // `broadcast: false` states the intent, though the local engine has no invalidator anyway.
  const admin = createAdmin<TAction, TResource, TRole, TScope>(boundAdapter, {
    cache: {
      invalidatePolicies: () => {
        local.cache.invalidatePolicies({ broadcast: false })
        cache.invalidatePolicies()
      },
      invalidateRoles: (roleId?: TRole) => {
        local.cache.invalidateRoles(roleId, { broadcast: false })
        cache.invalidateRoles(roleId)
      },
      invalidateSubject: (subjectId: string) => {
        local.cache.invalidateSubject(subjectId, { broadcast: false })
        cache.invalidateSubject(subjectId)
      },
    },
    mutations,
  })
  // `local.admin` would write through the transaction but invalidate and emit outside `pending`.
  Object.defineProperty(local, 'admin', { value: admin })

  return {
    admin,
    authorize: (request) => local.authorize(request),
    can: (subjectId, action, resource, environment, scope) =>
      local.can(subjectId, action, resource, environment, scope),
    check: (subjectId, action, resource, environment, scope) =>
      local.check(subjectId, action, resource, environment, scope),
    engine: local,
    explain(subjectId, action, resource, environment, scope) {
      // `this` is the development-mode instantiation, as the unbound `explain` requires of its receiver.
      return this.engine.explain(subjectId, action, resource, environment, scope)
    },
    getEffectiveRoles: (subjectId, scope) => local.getEffectiveRoles(subjectId, scope),
    pending,
    permissions: (subjectId, checks, environment, opts) => local.permissions(subjectId, checks, environment, opts),
  }
}
