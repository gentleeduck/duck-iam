// ── Types ────────────────────────────────────────────────────────────

// ── Memory adapter (included in root for convenience) ────────────────
export type { MemoryAdapterInit } from './adapters/memory'
export { MemoryAdapter } from './adapters/memory'
export type {
  // Config
  AccessConfig,
  AccessConfigInput,
  // Request types
  AccessRequest,
  // Adapter interfaces
  Adapter,
  // Dot-path types (advanced)
  AnyAttributes,
  // Primitive types
  Attributes,
  AttributeValue,
  AttrValue,
  // Access control primitives
  CombiningAlgorithm,
  Condition,
  ConditionGroup,
  // Explain / trace types
  ConditionGroupTrace,
  ConditionLeafTrace,
  ConditionTrace,
  Decision,
  DefaultContext,
  DotPaths,
  Effect,
  // Engine types
  EngineConfig,
  EngineHooks,
  EnvAttrs,
  Environment,
  ExplainResult,
  ExplainSubjectInfo,
  FieldValue,
  // Inference helpers
  InferAction,
  InferResource,
  InferRole,
  InferScope,
  Operator,
  PathValue,
  Permission,
  // Client types
  PermissionCheck,
  PermissionKey,
  PermissionMap,
  Policy,
  PolicyStore,
  PolicyTrace,
  ResolvedResourceAttrs,
  Resource,
  ResourceAttrMap,
  ResourceAttrs,
  Role,
  RoleStore,
  Rule,
  RuleTrace,
  Scalar,
  ScopedRole,
  Subject,
  SubjectAttrs,
  SubjectStore,
  // Validation types
  ValidationIssue,
  ValidationResult,
} from './core'
// ── Config factory ───────────────────────────────────────────────────
// ── Engine ───────────────────────────────────────────────────────────
// ── Builders ─────────────────────────────────────────────────────────
// ── Evaluation (advanced) ────────────────────────────────────────────
export {
  createAccessConfig,
  defineRole,
  defineRule,
  Engine,
  evalConditionGroup,
  evaluate,
  evaluateOperator,
  evaluatePolicy,
  explainEvaluation,
  matchesAction,
  matchesResource,
  matchesResourceHierarchical,
  matchesScope,
  PolicyBuilder,
  policy,
  RoleBuilder,
  RuleBuilder,
  resolve,
  resolveConditionValue,
  resolveEffectiveRoles,
  rolesToPolicy,
  validatePolicy,
  validateRoles,
  When,
  when,
} from './core'
export { LRUCache } from './shared/cache'
// ── Shared utilities ─────────────────────────────────────────────────
export { buildPermissionKey } from './shared/keys'
