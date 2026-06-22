import type { IamPolicyBuilder, IamRoleBuilder, IamRuleBuilder, IamWhen } from '../builder'
import type { IamEngine, IamEngineTypes } from '../engine'
import type { IamAccessControl, IamClient, IamDotPath } from '../types'
import type { IamValidate } from '../validate'

export namespace IamConfig {
  /**
   * Input shape for {@link createIam}. Pass `as const` arrays so the
   * factory extracts union types from each array and threads them through
   * every builder method.
   *
   * @template TActions   - Tuple of action strings declared `as const`.
   * @template TResources - Tuple of resource strings declared `as const`.
   * @template TScopes    - Tuple of scope strings declared `as const`.
   * @template TRoles     - Tuple of role ID strings declared `as const`.
   * @template TContext   - Shape of the evaluation context for typed dot-paths.
   * @example
   * ```ts
   * const input: IamConfig.IAccessConfigInput<['read'], ['post']> = {
   *   actions: ['read'] as const,
   *   resources: ['post'] as const,
   * }
   * ```
   */
  export interface IAccessConfigInput<
    TActions extends readonly string[],
    TResources extends readonly string[],
    TScopes extends readonly string[] = readonly string[],
    TRoles extends readonly string[] = readonly string[],
    TContext extends object = IamDotPath.IDefaultContext,
  > {
    /** Actions your application supports (`['create', 'read', ...]`). `as const`. */
    readonly actions: TActions
    /** Resource types your application manages. `as const`. */
    readonly resources: TResources
    /** Scope strings for multi-tenant authorization. `as const`. */
    readonly scopes?: TScopes
    /** Role IDs to constrain role builders. `as const`. */
    readonly roles?: TRoles
    /**
     * Phantom field for context type inference.
     *
     * Pass `{} as unknown as YourContext` to enable typed dot-path
     * intellisense on `.attr()`, `.resourceAttr()`, `.env()`, `.check()`.
     * Runtime value is never used - only the type information flows through.
     */
    readonly context?: TContext
  }

  /**
   * Typed configuration object returned by {@link createIam}. Every
   * builder method is constrained to the declared action / resource / scope /
   * role unions. Misspelling produces a compile-time error.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   * @template TRole     - Union of valid role ID strings.
   * @template TContext  - Shape of the evaluation context for typed dot-paths.
   */
  export interface IAccessConfig<
    TAction extends string,
    TResource extends string,
    TScope extends string = string,
    TRole extends string = string,
    TContext extends object = IamDotPath.IDefaultContext,
  > {
    readonly actions: readonly TAction[]
    readonly resources: readonly TResource[]
    /** Empty array if no scopes were declared. */
    readonly scopes: readonly TScope[]
    /** Empty array if no roles were declared. */
    readonly roles: readonly TRole[]

    /** Typed {@link IamRoleBuilder}; role ID constrained to declared roles. */
    iamDefineRole: (id: TRole) => IamRoleBuilder<TAction, TResource, TRole, TScope, TContext>

    /** Typed {@link IamPolicyBuilder}; rules constrained to declared actions/resources/roles. */
    iamDefinePolicy: (id: string) => IamPolicyBuilder<TAction, TResource, TRole, TScope, TContext>

    /** Typed standalone {@link IamRuleBuilder} for composing rules across policies. */
    iamDefineRule: (id: string) => IamRuleBuilder<TAction, TResource, TScope, TRole, TContext>

    /** Typed {@link IamWhen} builder for reusable condition groups. */
    when: () => IamWhen<TAction, TResource, TRole, TScope, TContext>

    /**
     * Typed {@link IamEngine} instance. Permission checks are constrained to the
     * declared actions / resources / scopes.
     */
    createEngine: <TMode extends IamAccessControl.Mode = 'development'>(
      config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>,
    ) => IamEngine<TAction, TResource, TRole, TScope, TMode>

    /** Compile-time-typed pass-through for `engine.permissions()` inputs. */
    checks: <const T extends readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[]>(checks: T) => T

    /** Role validation: duplicate IDs, dangling inherits, circular inheritance, empty roles. */
    iamValidateRoles: (roles: readonly IamAccessControl.IRole<TAction, TResource, string, TScope>[]) => IamValidate.IResult

    /**
     * IamValidate a policy object from an untrusted source (database, API, JSON).
     * Deep shape + semantic checks.
     */
    iamValidatePolicy: (input: unknown) => IamValidate.IResult
  }

  /**
   * Extracts the union of action strings from a config input.
   *
   * @template S - Config input shape with an `actions` tuple.
   */
  export type InferAction<S extends { actions: readonly string[] }> = S['actions'][number]

  /**
   * Extracts the union of resource strings from a config input.
   *
   * @template S - Config input shape with a `resources` tuple.
   */
  export type InferResource<S extends { resources: readonly string[] }> = S['resources'][number]

  /**
   * Extracts the union of scope strings from a config input.
   *
   * @template S - Config input shape with a `scopes` tuple.
   */
  export type InferScope<S extends { scopes: readonly string[] }> = S['scopes'][number]

  /**
   * Extracts the union of role strings from a config input.
   *
   * @template S - Config input shape with a `roles` tuple.
   */
  export type InferRole<S extends { roles: readonly string[] }> = S['roles'][number]
}
