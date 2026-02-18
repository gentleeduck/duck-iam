// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// @access-engine/core - Type System
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// --- Primitives ---

export type Scalar = string | number | boolean | null
export type AttributeValue = Scalar | Scalar[]
export type Attributes = Record<string, AttributeValue>

// --- Access Control Entities ---

export interface Subject {
  readonly id: string
  readonly roles: readonly string[]
  readonly attributes: Readonly<Attributes>
}

export interface Resource {
  /** Supports hierarchical types: "org:project:document" */
  readonly type: string
  readonly id?: string
  readonly attributes: Readonly<Attributes>
}

export interface Environment {
  readonly ip?: string
  readonly userAgent?: string
  readonly timestamp?: number
  readonly [key: string]: AttributeValue | undefined
}

export interface AccessRequest {
  readonly subject: Subject
  readonly action: string
  readonly resource: Resource
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

export interface Rule {
  readonly id: string
  readonly effect: Effect
  readonly description?: string
  readonly priority: number
  readonly actions: readonly string[]
  readonly resources: readonly string[]
  readonly conditions: ConditionGroup
  readonly metadata?: Readonly<Attributes>
}

export type CombiningAlgorithm = 'deny-overrides' | 'allow-overrides' | 'first-match' | 'highest-priority'

export interface Policy {
  readonly id: string
  readonly name: string
  readonly description?: string
  readonly version?: number
  readonly algorithm: CombiningAlgorithm
  readonly rules: readonly Rule[]
  readonly targets?: {
    readonly actions?: readonly string[]
    readonly resources?: readonly string[]
    readonly roles?: readonly string[]
  }
}

// --- RBAC ---

export interface Permission {
  readonly action: string
  readonly resource: string
  readonly conditions?: ConditionGroup
}

export interface Role {
  readonly id: string
  readonly name: string
  readonly description?: string
  readonly permissions: readonly Permission[]
  readonly inherits?: readonly string[]
  readonly scope?: string
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

export interface PolicyStore {
  listPolicies(): Promise<Policy[]>
  getPolicy(id: string): Promise<Policy | null>
  savePolicy(policy: Policy): Promise<void>
  deletePolicy(id: string): Promise<void>
}

export interface RoleStore {
  listRoles(): Promise<Role[]>
  getRole(id: string): Promise<Role | null>
  saveRole(role: Role): Promise<void>
  deleteRole(id: string): Promise<void>
}

export interface SubjectStore {
  getSubjectRoles(subjectId: string): Promise<string[]>
  assignRole(subjectId: string, roleId: string, scope?: string): Promise<void>
  revokeRole(subjectId: string, roleId: string, scope?: string): Promise<void>
  getSubjectAttributes(subjectId: string): Promise<Attributes>
  setSubjectAttributes(subjectId: string, attrs: Attributes): Promise<void>
}

export interface Adapter extends PolicyStore, RoleStore, SubjectStore {}

// --- Engine Config ---

export interface EngineConfig {
  readonly adapter: Adapter
  readonly defaultEffect?: Effect
  readonly cacheTTL?: number
  readonly maxCacheSize?: number
  readonly hooks?: EngineHooks
}

export interface EngineHooks {
  beforeEvaluate?(request: AccessRequest): AccessRequest | Promise<AccessRequest>
  afterEvaluate?(request: AccessRequest, decision: Decision): void | Promise<void>
  onDeny?(request: AccessRequest, decision: Decision): void | Promise<void>
  onError?(error: Error, request: AccessRequest): void | Promise<void>
}

// --- Client types ---

export type PermissionMap = Record<string, boolean>

export interface PermissionCheck {
  readonly action: string
  readonly resource: string
  readonly resourceId?: string
}

export type PermissionKey = `${string}:${string}` | `${string}:${string}:${string}`
