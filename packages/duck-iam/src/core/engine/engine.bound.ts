import type { Explain } from '../explain'
import { createPending, type Pending } from '../pending'
import type { AccessControl, IamAdapter, IamClient, IamRequest } from '../types'
import type { IamEngine as IamEngineImpl } from './engine'
import { createAdmin } from './engine.libs'
import type { IamEngineTypes } from './engine.types'

/** The transaction-bound view of an {@link IamEngineImpl}. */
export namespace Bound {
  /**
   * Writes go through `admin` - the same interface as the unbound engine's, so
   * there is one write surface rather than two. Reads are the engine's own
   * methods, served from transaction-local caches.
   *
   * Every read method is declared explicitly rather than spread, so this
   * surface stays reviewable against the unbound one.
   */
  export interface IamEngine<
    TAction extends string = string,
    TResource extends string = string,
    TRole extends string = string,
    TScope extends string = string,
    TMode extends AccessControl.Mode = 'development',
  > {
    /** The write surface, identical to `engine.admin` but bound to the transaction. */
    readonly admin: IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope>
    /** The transaction-local engine backing the reads. Reach for it only for methods not re-exposed here. */
    readonly engine: IamEngineImpl<TAction, TResource, TRole, TScope, TMode>
    /** Cache invalidations withheld until the caller's transaction commits. */
    readonly pending: Pending.Effects<TRole>

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
 * Builds the bound view. Reads delegate to a private engine constructed with
 * the transaction-bound adapter and FRESH caches.
 *
 * Fresh caches are the whole trick. An empty cache always misses, so every
 * bound read reaches the transaction-bound adapter and therefore sees the
 * transaction's own uncommitted writes. They also keep uncommitted data out of
 * the shared caches: the transaction-local ones are collected with the facade.
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
  // The invalidator is deliberately dropped: a bound engine must never
  // broadcast to the fleet mid-transaction, and it must not subscribe either -
  // a facade built per transaction would otherwise leak a subscription each
  // time. Buffered entries broadcast through the PARENT on flush, after commit.
  const { invalidator: _dropped, ...rest } = config
  const local = makeEngine({ ...rest, adapter: boundAdapter })

  const { cache, pending } = createPending<TRole>({
    invalidatePolicies: () => parent.cache.invalidatePolicies(),
    invalidateRoles: (roleId) => parent.cache.invalidateRoles(roleId),
    invalidateSubject: (subjectId) => parent.cache.invalidateSubject(subjectId),
  })

  // Two sinks per write: the transaction-local caches drop the entry
  // immediately, so a read-after-write inside the transaction is correct, while
  // the shared caches only learn about it on flush. `broadcast: false` keeps the
  // local drop off the wire - the local engine has no invalidator anyway, but
  // saying so at the call site is what makes the intent legible.
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
  })

  return {
    admin,
    authorize: (request) => local.authorize(request),
    can: (subjectId, action, resource, environment, scope) =>
      local.can(subjectId, action, resource, environment, scope),
    check: (subjectId, action, resource, environment, scope) =>
      local.check(subjectId, action, resource, environment, scope),
    engine: local,
    explain(subjectId, action, resource, environment, scope) {
      // `this` is the development-mode instantiation per the interface, which is
      // exactly what the unbound `explain` demands of its receiver.
      return this.engine.explain(subjectId, action, resource, environment, scope)
    },
    getEffectiveRoles: (subjectId, scope) => local.getEffectiveRoles(subjectId, scope),
    pending,
    permissions: (subjectId, checks, environment, opts) => local.permissions(subjectId, checks, environment, opts),
  }
}
