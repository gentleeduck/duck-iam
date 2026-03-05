// ------------------------------------------------------------
// duck-iam - Type System
// ------------------------------------------------------------

// --- Primitives ---

export type Scalar = string | number | boolean | null
export type AttributeValue = Scalar | Scalar[]
export type Attributes = Record<string, AttributeValue>

// --- Utility types ---

export type InferAction<S extends { actions: readonly string[] }> = S['actions'][number]
export type InferResource<S extends { resources: readonly string[] }> = S['resources'][number]
export type InferScope<S extends { scopes: readonly string[] }> = S['scopes'][number]

// --- Access Control Entities ---

export interface ScopedRole<TRole extends string = string, TScope extends string = string> {
  readonly role: TRole
  readonly scope?: TScope
}

export interface Subject<TRole extends string = string, TScope extends string = string> {
  readonly id: string
  readonly roles: readonly TRole[]
  readonly scopedRoles?: readonly ScopedRole<TRole, TScope>[]
  readonly attributes: Readonly<Attributes>
}

export interface Resource<TResource extends string = string> {
  /** Supports hierarchical types via dots: "dashboard.users.settings" */
  readonly type: TResource
  readonly id?: string
  readonly attributes: Readonly<Attributes>
}

export interface Environment {
  readonly ip?: string
  readonly userAgent?: string
  readonly timestamp?: number
  readonly [key: string]: AttributeValue | undefined
}

export interface AccessRequest<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  readonly subject: Subject
  readonly action: TAction
  readonly resource: Resource<TResource>
  readonly scope?: TScope
  readonly environment?: Environment
}

// --- Policy Model ---

export type Effect = 'allow' | 'deny'

export type Operator =
  | 'eq'
  | 'neq'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'in'
  | 'nin'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'matches'
  | 'exists'
  | 'not_exists'
  | 'subset_of'
  | 'superset_of'

export interface Condition {
  readonly field: string
  readonly operator: Operator
  readonly value?: AttributeValue
}

/** Logical grouping: AND/OR with nesting */
export type ConditionGroup =
  | { readonly all: ReadonlyArray<Condition | ConditionGroup> }
  | { readonly any: ReadonlyArray<Condition | ConditionGroup> }
  | { readonly none: ReadonlyArray<Condition | ConditionGroup> }

export interface Rule<TAction extends string = string, TResource extends string = string> {
  readonly id: string
  readonly effect: Effect
  readonly description?: string
  readonly priority: number
  readonly actions: readonly (TAction | '*')[]
  readonly resources: readonly (TResource | '*')[]
  readonly conditions: ConditionGroup
  readonly metadata?: Readonly<Attributes>
}

export type CombiningAlgorithm = 'deny-overrides' | 'allow-overrides' | 'first-match' | 'highest-priority'

export interface Policy<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
> {
  readonly id: string
  readonly name: string
  readonly description?: string
  readonly version?: number
  readonly algorithm: CombiningAlgorithm
  readonly rules: readonly Rule<TAction, TResource>[]
  readonly targets?: {
    readonly actions?: readonly (TAction | '*')[]
    readonly resources?: readonly (TResource | '*')[]
    readonly roles?: readonly TRole[]
  }
}

// --- RBAC ---

export interface Permission<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  readonly action: TAction | '*'
  readonly resource: TResource | '*'
  readonly scope?: TScope | '*'
  readonly conditions?: ConditionGroup
}

export interface Role<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  readonly id: TRole
  readonly name: string
  readonly description?: string
  readonly permissions: readonly Permission<TAction, TResource, TScope>[]
  readonly inherits?: readonly string[]
  readonly scope?: TScope
  readonly metadata?: Readonly<Attributes>
}

// --- Decision ---

export interface Decision {
  readonly allowed: boolean
  readonly effect: Effect
  readonly rule?: Rule
  readonly policy?: string
  readonly reason: string
  readonly duration: number
  readonly timestamp: number
}

// --- Adapter interface ---

export interface PolicyStore<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
> {
  listPolicies(): Promise<Policy<TAction, TResource, TRole>[]>
  getPolicy(id: string): Promise<Policy<TAction, TResource, TRole> | null>
  savePolicy(policy: Policy<TAction, TResource, TRole>): Promise<void>
  deletePolicy(id: string): Promise<void>
}

export interface RoleStore<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  listRoles(): Promise<Role<TAction, TResource, TRole, TScope>[]>
  getRole(id: string): Promise<Role<TAction, TResource, TRole, TScope> | null>
  saveRole(role: Role<TAction, TResource, TRole, TScope>): Promise<void>
  deleteRole(id: string): Promise<void>
}

export interface SubjectStore<TRole extends string = string, TScope extends string = string> {
  getSubjectRoles(subjectId: string): Promise<TRole[]>
  getSubjectScopedRoles?(subjectId: string): Promise<ScopedRole<TRole, TScope>[]>
  assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  getSubjectAttributes(subjectId: string): Promise<Attributes>
  setSubjectAttributes(subjectId: string, attrs: Attributes): Promise<void>
}

export interface Adapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> extends PolicyStore<TAction, TResource, TRole>,
    RoleStore<TAction, TResource, TRole, TScope>,
    SubjectStore<TRole, TScope> {}

// --- Engine Config ---

export interface EngineConfig<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  readonly adapter: Adapter<TAction, TResource, TRole, TScope>
  readonly defaultEffect?: Effect
  readonly cacheTTL?: number
  readonly maxCacheSize?: number
  readonly hooks?: EngineHooks<TAction, TResource, TScope>
}

export interface EngineHooks<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  beforeEvaluate?(
    request: AccessRequest<TAction, TResource, TScope>,
  ): AccessRequest<TAction, TResource, TScope> | Promise<AccessRequest<TAction, TResource, TScope>>
  afterEvaluate?(request: AccessRequest<TAction, TResource, TScope>, decision: Decision): void | Promise<void>
  onDeny?(request: AccessRequest<TAction, TResource, TScope>, decision: Decision): void | Promise<void>
  onError?(error: Error, request: AccessRequest<TAction, TResource, TScope>): void | Promise<void>
}

// --- Client types ---

export type PermissionKey<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> =
  | `${TAction}:${TResource}`
  | `${TAction}:${TResource}:${string}`
  | `${TScope}:${TAction}:${TResource}`
  | `${TScope}:${TAction}:${TResource}:${string}`

export type PermissionMap<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> = Record<PermissionKey<TAction, TResource, TScope>, boolean>

export interface PermissionCheck<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  readonly action: TAction
  readonly resource: TResource
  readonly resourceId?: string
  readonly scope?: TScope
}
