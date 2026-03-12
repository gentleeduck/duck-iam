import { PolicyBuilder, RoleBuilder, RuleBuilder, When } from './builder'
import { Engine } from './engine'
import type { DefaultContext, EngineConfig, PermissionCheck, Role } from './types'
import type { ValidationResult } from './validate'
import { validatePolicy, validateRoles } from './validate'

// ------------------------------------------------------------
// Input
// ------------------------------------------------------------

/**
 * Input shape for {@link createAccessConfig}.
 *
 * Pass `as const` arrays for compile-time type safety. The factory extracts
 * union types from each array and threads them through every builder method.
 *
 * @template TActions   - Literal tuple of action strings (inferred via `as const`)
 * @template TResources - Literal tuple of resource strings (inferred via `as const`)
 * @template TScopes    - Literal tuple of scope strings (optional, inferred via `as const`)
 * @template TRoles     - Literal tuple of role strings (optional, inferred via `as const`)
 * @template TContext   - Custom context type for typed dot-path intellisense
 *
 * @example
 * ```ts
 * createAccessConfig({
 *   actions: ['create', 'read', 'update', 'delete'] as const,
 *   resources: ['post', 'comment'] as const,
 *   roles: ['viewer', 'editor', 'admin'] as const,
 *   context: {} as unknown as AppContext,
 * })
 * ```
 */
export interface AccessConfigInput<
  TActions extends readonly string[],
  TResources extends readonly string[],
  TScopes extends readonly string[] = readonly string[],
  TRoles extends readonly string[] = readonly string[],
  TContext extends object = DefaultContext,
> {
  /** The actions your application supports (e.g. `['create', 'read', 'update', 'delete']`). Requires `as const`. */
  readonly actions: TActions
  /** The resource types your application manages (e.g. `['post', 'comment', 'user']`). Requires `as const`. */
  readonly resources: TResources
  /** Optional scope strings for multi-tenant authorization (e.g. `['org-acme', 'org-globex']`). Requires `as const`. */
  readonly scopes?: TScopes
  /** Optional role IDs to constrain role builders (e.g. `['viewer', 'editor', 'admin']`). Requires `as const`. */
  readonly roles?: TRoles
  /**
   * Phantom field for context type inference.
   *
   * Pass `{} as unknown as YourContext` to enable typed dot-path intellisense
   * on `.attr()`, `.resourceAttr()`, `.env()`, and `.check()`. The runtime value
   * is never used -- only the type information flows through to the builders.
   */
  readonly context?: TContext
}

// ------------------------------------------------------------
// Output
// ------------------------------------------------------------

/**
 * The typed configuration object returned by {@link createAccessConfig}.
 *
 * Every builder method on this object is constrained to the action, resource,
 * scope, and role unions declared in the input. Misspelling an action, referencing
 * a resource that does not exist, or passing an invalid role ID produces a
 * compile-time error.
 *
 * @template TAction   - Union of valid action strings
 * @template TResource - Union of valid resource strings
 * @template TScope    - Union of valid scope strings
 * @template TRole     - Union of valid role strings
 * @template TContext  - Custom context type for typed dot-path intellisense
 */
export interface AccessConfig<
  TAction extends string,
  TResource extends string,
  TScope extends string = string,
  TRole extends string = string,
  TContext extends object = DefaultContext,
> {
  /** The action strings declared in the config input. */
  readonly actions: readonly TAction[]
  /** The resource strings declared in the config input. */
  readonly resources: readonly TResource[]
  /** The scope strings declared in the config input (empty array if omitted). */
  readonly scopes: readonly TScope[]
  /** The role strings declared in the config input (empty array if omitted). */
  readonly roles: readonly TRole[]

  /**
   * Creates a typed {@link RoleBuilder}. The role ID is constrained to the
   * declared roles, and all grant methods are constrained to declared actions/resources.
   */
  defineRole: (id: TRole) => RoleBuilder<TAction, TResource, TRole, TScope, TContext>

  /**
   * Creates a typed {@link PolicyBuilder}. Rules within the policy are
   * constrained to declared actions, resources, and roles.
   */
  policy: (id: string) => PolicyBuilder<TAction, TResource, TRole, TScope, TContext>

  /**
   * Creates a typed standalone {@link RuleBuilder}. Useful when composing
   * rules across policies via `policy.addRule()`.
   */
  defineRule: (id: string) => RuleBuilder<TAction, TResource, TScope, TRole, TContext>

  /**
   * Creates a typed {@link When} condition builder for reusable condition groups.
   * Role references via `.role()` and `.roles()` are constrained to declared roles.
   */
  when: () => When<TAction, TResource, TRole, TScope, TContext>

  /**
   * Creates a typed {@link Engine} instance. Permission checks on this engine
   * are constrained to declared actions, resources, and scopes.
   */
  createEngine: (config: EngineConfig<TAction, TResource, TRole, TScope>) => Engine<TAction, TResource, TRole, TScope>

  /**
   * Pure typing utility that returns the input array as-is but constrains
   * the types at compile time. Use with `engine.permissions()` for type-safe
   * batch permission checks.
   */
  checks: <const T extends readonly PermissionCheck<TAction, TResource, TScope>[]>(checks: T) => T

  /**
   * Validates role definitions for common configuration mistakes:
   * duplicate IDs, dangling inherits, circular inheritance, and empty roles.
   */
  validateRoles: (roles: readonly Role<TAction, TResource, string, TScope>[]) => ValidationResult

  /**
   * Validates a policy object from an untrusted source (database, API, JSON).
   * Deeply checks the entire structure including rules, conditions, and operators.
   */
  validatePolicy: (input: unknown) => ValidationResult
}

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------

/**
 * Creates a type-safe access configuration for your application.
 *
 * This is the primary entry point for duck-iam. Pass your permission schema
 * using `as const` arrays and get back an {@link AccessConfig} with fully typed
 * builder methods.
 *
 * @param input - Your permission schema: actions, resources, and optionally scopes, roles, and context.
 * @returns A typed {@link AccessConfig} with constrained builder methods.
 *
 * @example
 * ```ts
 * const access = createAccessConfig({
 *   actions: ['create', 'read', 'update', 'delete'] as const,
 *   resources: ['post', 'comment', 'user'] as const,
 *   roles: ['viewer', 'editor', 'admin'] as const,
 *   context: {} as unknown as AppContext,
 * })
 *
 * // All builders are now type-safe:
 * access.defineRole('viewer').grant('read', 'post')   // OK
 * access.defineRole('viewer').grant('raed', 'post')   // compile error
 * ```
 */
export function createAccessConfig<
  const TActions extends readonly string[],
  const TResources extends readonly string[],
  const TScopes extends readonly string[] = readonly string[],
  const TRoles extends readonly string[] = readonly string[],
  TContext extends object = DefaultContext,
>(
  input: AccessConfigInput<TActions, TResources, TScopes, TRoles, TContext>,
): AccessConfig<TActions[number], TResources[number], TScopes[number], TRoles[number], TContext> {
  type TAction = TActions[number]
  type TResource = TResources[number]
  type TScope = TScopes[number]
  type TRole = TRoles[number]

  return {
    actions: input.actions,
    resources: input.resources,
    scopes: input.scopes ?? [],
    roles: input.roles ?? [],

    defineRole: (id: TRole) => new RoleBuilder<TAction, TResource, TRole, TScope, TContext>(id),

    policy: (id: string) => new PolicyBuilder<TAction, TResource, TRole, TScope, TContext>(id),

    defineRule: (id: string) => new RuleBuilder<TAction, TResource, TScope, TRole, TContext>(id),

    when: () => new When<TAction, TResource, TRole, TScope, TContext>(),

    createEngine: (config: EngineConfig<TAction, TResource, TRole, TScope>) =>
      new Engine<TAction, TResource, TRole, TScope>(config),

    checks: <const T extends readonly PermissionCheck<TAction, TResource, TScope>[]>(checks: T) => checks,

    validateRoles: (roles: readonly Role<TAction, TResource, string, TScope>[]) => validateRoles(roles),

    validatePolicy: (input: unknown) => validatePolicy(input),
  }
}
