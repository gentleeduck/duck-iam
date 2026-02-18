export { Engine } from './engine'
export { evaluate, evaluatePolicy } from './evaluate'
export { rolesToPolicy, resolveEffectiveRoles } from './rbac'
export { policy, defineRole, defineRule, when, When, RuleBuilder, PolicyBuilder, RoleBuilder } from './builder'
export { resolve, matchesAction, matchesResource } from './resolve'
export { evalConditionGroup } from './conditions'

export type {
  Scalar,
  AttributeValue,
  Attributes,
  Subject,
  Resource,
  Environment,
  AccessRequest,
  Effect,
  Operator,
  Condition,
  ConditionGroup,
  Rule,
  CombiningAlgorithm,
  Policy,
  Permission,
  Role,
  Decision,
  PolicyStore,
  RoleStore,
  SubjectStore,
  Adapter,
  EngineConfig,
  EngineHooks,
  PermissionMap,
  PermissionCheck,
  PermissionKey,
} from './types'
