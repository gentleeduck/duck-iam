import { PolicyBuilder, RoleBuilder, RuleBuilder, When } from '../builder'
import type { IamEngineTypes } from '../engine'
import { IamEngine } from '../engine'
import type { AccessControl, DotPath, IamClient } from '../types'
import { validatePolicy, validateRoles } from '../validate'
import type { IamConfig } from './config.types'

/**
 * Creates a type-safe access configuration for your application.
 *
 * The primary entry point for duck-iam. Pass your permission schema
 * using `as const` arrays and get back an {@link IamConfig.IAccessConfig} with fully typed
 * builder methods.
 *
 * @template TActions   - Tuple of action strings, declared `as const`.
 * @template TResources - Tuple of resource strings, declared `as const`.
 * @template TScopes    - Tuple of scope strings, declared `as const`.
 * @template TRoles     - Tuple of role ID strings, declared `as const`.
 * @template TContext   - Shape of the evaluation context for typed dot-paths.
 *
 * @param input - Your permission schema: actions, resources, and optionally scopes, roles, and context.
 * @returns A typed {@link IamConfig.IAccessConfig} with constrained builder methods.
 *
 * @example
 * ```ts
 * const iam = createIam({
 *   actions: ['create', 'read', 'update', 'delete'] as const,
 *   resources: ['post', 'comment', 'user'] as const,
 *   roles: ['viewer', 'editor', 'admin'] as const,
 *   context: {} as unknown as AppContext,
 * })
 *
 * // All builders are now type-safe:
 * iam.defineRole('viewer').grant('read', 'post')   // OK
 * iam.defineRole('viewer').grant('raed', 'post')   // compile error
 * ```
 */
export function createIam<
  const TActions extends readonly string[],
  const TResources extends readonly string[],
  const TRoles extends readonly string[] = readonly string[],
  const TScopes extends readonly string[] = readonly string[],
  TContext extends object = DotPath.IDefaultContext,
>(
  input: IamConfig.IAccessConfigInput<TActions, TResources, TRoles, TScopes, TContext>,
): IamConfig.IAccessConfig<TActions[number], TResources[number], TRoles[number], TScopes[number], TContext> {
  type TAction = TActions[number]
  type TResource = TResources[number]
  type TRole = TRoles[number]
  type TScope = TScopes[number]

  return {
    actions: input.actions,
    resources: input.resources,
    scopes: input.scopes ?? [],
    roles: input.roles ?? [],

    defineRole: (id: TRole) => new RoleBuilder<TAction, TResource, TRole, TScope, TContext>(id),

    definePolicy: (id: string) => new PolicyBuilder<TAction, TResource, TRole, TScope, TContext>(id),

    defineRule: (id: string) => new RuleBuilder<TAction, TResource, TScope, TRole, TContext>(id),

    when: () => new When<TAction, TResource, TRole, TScope, TContext>(),

    createEngine: <TMode extends AccessControl.Mode = 'development'>(
      config: IamEngineTypes.IConfig<TAction, TResource, TRole, TScope, TMode>,
    ) => new IamEngine<TAction, TResource, TRole, TScope, TMode>(config),

    checks: <const T extends readonly IamClient.IPermissionCheck<TAction, TResource, TScope>[]>(checks: T) => checks,

    validateRoles: (roles: readonly AccessControl.IRole<TAction, TResource, string, TScope>[]) => validateRoles(roles),

    validatePolicy: (input: unknown) => validatePolicy(input),
  }
}
