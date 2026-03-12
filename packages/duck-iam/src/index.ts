// ── Types ────────────────────────────────────────────────────────────
export type {
  // Config
  AccessConfig,
  AccessConfigInput,

  // Access control primitives
  CombiningAlgorithm,
  Condition,
  ConditionGroup,
  Decision,
  Effect,
  Operator,
  Permission,
  Policy,
  Role,
  Rule,

  // Request types
  AccessRequest,
  Environment,
  Resource,
  ScopedRole,
  Subject,

  // Primitive types
  Attributes,
  AttributeValue,
  Scalar,

  // Engine types
  EngineConfig,
  EngineHooks,

  // Adapter interfaces
  Adapter,
  PolicyStore,
  RoleStore,
  SubjectStore,

  // Client types
  PermissionCheck,
  PermissionKey,
  PermissionMap,

  // Inference helpers
  InferAction,
  InferResource,
  InferRole,
  InferScope,

  // Explain / trace types
  ConditionGroupTrace,
  ConditionLeafTrace,
  ConditionTrace,
  ExplainResult,
  ExplainSubjectInfo,
  PolicyTrace,
  RuleTrace,

  // Validation types
  ValidationIssue,
  ValidationResult,

  // Dot-path types (advanced)
  AnyAttributes,
  AttrValue,
  DefaultContext,
  DotPaths,
  EnvAttrs,
  FieldValue,
  PathValue,
  ResolvedResourceAttrs,
  ResourceAttrMap,
  ResourceAttrs,
  SubjectAttrs,
} from './core'

// ── Config factory ───────────────────────────────────────────────────
export { createAccessConfig } from './core'

// ── Engine ───────────────────────────────────────────────────────────
export { Engine } from './core'

// ── Builders ─────────────────────────────────────────────────────────
export { defineRole, defineRule, policy, PolicyBuilder, RoleBuilder, RuleBuilder, When, when } from './core'

// ── Evaluation (advanced) ────────────────────────────────────────────
export {
  evalConditionGroup,
  evaluate,
  evaluateOperator,
  evaluatePolicy,
  explainEvaluation,
  matchesAction,
  matchesResource,
  matchesResourceHierarchical,
  matchesScope,
  resolve,
  resolveConditionValue,
  resolveEffectiveRoles,
  rolesToPolicy,
  validatePolicy,
  validateRoles,
} from './core'

// ── Memory adapter (included in root for convenience) ────────────────
export type { MemoryAdapterInit } from './adapters/memory'
export { MemoryAdapter } from './adapters/memory'

// ── Shared utilities ─────────────────────────────────────────────────
export { buildPermissionKey } from './shared/keys'
export { LRUCache } from './shared/cache'
