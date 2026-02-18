export { defineRole, defineRule, PolicyBuilder, policy, RoleBuilder, RuleBuilder, When, when } from './builder'
export { evalConditionGroup } from './conditions'
export { Engine } from './engine'
export { evaluate, evaluatePolicy } from './evaluate'
export { resolveEffectiveRoles, rolesToPolicy } from './rbac'
export { matchesAction, matchesResource, resolve } from './resolve'

export type {
  AccessRequest,
  Adapter,
  Attributes,
  AttributeValue,
  CombiningAlgorithm,
  Condition,
  ConditionGroup,
  Decision,
  Effect,
  EngineConfig,
  EngineHooks,
  Environment,
  Operator,
  Permission,
  PermissionCheck,
  PermissionKey,
  PermissionMap,
  Policy,
  PolicyStore,
  Resource,
  Role,
  RoleStore,
  Rule,
  Scalar,
  Subject,
  SubjectStore,
} from './types'
