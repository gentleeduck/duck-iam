export { defineRole, defineRule, PolicyBuilder, policy, RoleBuilder, RuleBuilder, When, when } from './builder'
export { evalConditionGroup, evaluateOperator, resolveConditionValue } from './conditions'
export type { AccessConfig, AccessConfigInput } from './config'
export { createAccessConfig } from './config'
export { Engine } from './engine'
export { evaluate, evaluatePolicy } from './evaluate'
export type {
  ConditionGroupTrace,
  ConditionLeafTrace,
  ConditionTrace,
  ExplainResult,
  ExplainSubjectInfo,
  PolicyTrace,
  RuleTrace,
} from './explain'
export { explainEvaluation } from './explain'
export { resolveEffectiveRoles, rolesToPolicy } from './rbac'
export { matchesAction, matchesResource, matchesResourceHierarchical, matchesScope, resolve } from './resolve'
export * from './types'
export type { ValidationIssue, ValidationResult } from './validate'
export { validatePolicy, validateRoles } from './validate'
