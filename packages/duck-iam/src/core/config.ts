import { PolicyBuilder, RoleBuilder, RuleBuilder, When } from './builder'
import { Engine } from './engine'
import type { EngineConfig, PermissionCheck, Role } from './types'
import type { ValidationResult } from './validate'
import { validatePolicy, validateRoles } from './validate'

// ------------------------------------------------------------
// Input
// ------------------------------------------------------------

export interface AccessConfigInput<
  TActions extends readonly string[],
  TResources extends readonly string[],
  TScopes extends readonly string[] = Readonly<[]>,
> {
  readonly actions: TActions
  readonly resources: TResources
  readonly scopes?: TScopes
}

// ------------------------------------------------------------
// Output
// ------------------------------------------------------------

export interface AccessConfig<TAction extends string, TResource extends string, TScope extends string = string> {
  readonly actions: readonly TAction[]
  readonly resources: readonly TResource[]
  readonly scopes: readonly TScope[]

  /** Create a typed role builder */
  defineRole: <const TId extends string>(id: TId) => RoleBuilder<TAction, TResource, TId, TScope>
  /** Create a typed policy builder */
  policy: (id: string) => PolicyBuilder<TAction, TResource, string, TScope>
  /** Create a typed rule builder */
  defineRule: (id: string) => RuleBuilder<TAction, TResource, TScope>
  /** Create a typed condition builder */
  when: () => When<TAction, TResource, string, TScope>

  /** Create a typed engine instance */
  createEngine: <TRole extends string = string>(
    config: EngineConfig<TAction, TResource, TRole, TScope>,
  ) => Engine<TAction, TResource, TRole, TScope>

  /** Type-checked permission check definitions (compile-time validation) */
  checks: <const T extends readonly PermissionCheck<TAction, TResource, TScope>[]>(checks: T) => T

  /** Validate role definitions for common config mistakes (dangling inherits, cycles, duplicates) */
  validateRoles: (roles: readonly Role<TAction, TResource, string, TScope>[]) => ValidationResult

  /** Validate a policy object from an untrusted source (database, API, JSON) */
  validatePolicy: (input: unknown) => ValidationResult
}

// ------------------------------------------------------------
// Factory
// ------------------------------------------------------------

export function createAccessConfig<
  const TActions extends readonly string[],
  const TResources extends readonly string[],
  const TScopes extends readonly string[] = Readonly<[]>,
>(
  input: AccessConfigInput<TActions, TResources, TScopes>,
): AccessConfig<TActions[number], TResources[number], TScopes[number]> {
  type TAction = TActions[number]
  type TResource = TResources[number]
  type TScope = TScopes[number]

  return {
    actions: input.actions as readonly TAction[],
    resources: input.resources as readonly TResource[],
    scopes: (input.scopes ?? []) as readonly TScope[],

    defineRole: <const TId extends string>(id: TId) => new RoleBuilder<TAction, TResource, TId, TScope>(id),

    policy: (id: string) => new PolicyBuilder<TAction, TResource, string, TScope>(id),

    defineRule: (id: string) => new RuleBuilder<TAction, TResource, TScope>(id),

    when: () => new When<TAction, TResource, string, TScope>(),

    createEngine: <TRole extends string = string>(config: EngineConfig<TAction, TResource, TRole, TScope>) =>
      new Engine<TAction, TResource, TRole, TScope>(config),

    checks: <const T extends readonly PermissionCheck<TAction, TResource, TScope>[]>(checks: T) => checks,

    validateRoles: (roles: readonly Role<TAction, TResource, string, TScope>[]) => validateRoles(roles),

    validatePolicy: (input: unknown) => validatePolicy(input),
  }
}
