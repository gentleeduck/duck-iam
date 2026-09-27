import { detail, fault } from '@gentleduck/error'

export { detail, fault }

/** Every code this package raises, at its HTTP status, carrying what the code itself cannot say.
 *  Phase 1 only: the ~150 ad-hoc adapter/server/client sites are not in this registry yet. */
export const IAM_ERRORS = {
  IAM_CONDITION_REGEX_INPUT_TOO_LARGE: detail<{ field: string; length: number }>(400),
  IAM_CONDITION_GROUP_INVALID: detail<{ reason: 'depth' | 'unknown-keys'; detail: string }>(400),
  IAM_CONDITION_OPERAND_TYPE: detail<{ field: string; operator: string; detail: string }>(400),
  IAM_CONDITION_PATTERN_REFUSED: detail<{ field: string; reason: 'too-long' | 'uncompilable'; detail: string }>(400),
  IAM_CONDITION_USER_SOURCED_PATTERN: detail<{ field: string; value: string }>(400),
  IAM_CONDITION_OPERATOR_UNKNOWN: detail<{ operator: string; field?: string }>(400),
  IAM_CONDITION_ITEMS_NOT_ARRAY: detail<{ key: 'all' | 'any' | 'none' }>(400),
  IAM_ROLE_LIMIT_EXCEEDED: detail<{ roleCount: number; limit: number }>(500),
  IAM_POLICY_COMPILE_FAILED: detail<{ policyId: string; detail: string }>(500),
  IAM_VALIDATION_FAILED: detail<{ kind: 'policy' | 'role' | 'rule' | 'request'; issues: readonly string[] }>(400),
  IAM_SCOPE_INVALID: detail<{ adapter: string; reason: 'empty' | 'wildcard-on-grant' }>(400),
  IAM_ATTRIBUTES_INVALID: detail<{
    adapter: string
    subjectId: string
    reason: 'not-object' | 'forbidden-key'
    got?: string
  }>(400),
  IAM_UNREADABLE_POLICY: fault<{ adapter: string; policyId: string; detail: string }>(500),
  IAM_UNREADABLE_ROLE: fault<{ adapter: string; roleId: string; detail: string }>(500),
  IAM_ROLE_NOT_FOUND: fault<{ adapter: string }>(404),
  IAM_ASSIGN_OPTIONS_UNSUPPORTED: detail<{ adapter: string; fields: readonly string[] }>(400),
  IAM_ASSIGN_WINDOW_EMPTY: detail<{ adapter: string }>(400),
  IAM_ASSIGN_WINDOW_INVALID_DATE: detail<{ adapter: string; field: 'startsAt' | 'expiresAt' }>(400),
  IAM_ATTRIBUTES_CORRUPT: fault<{ adapter: string; subjectId: string; reason: 'parse-failed' | 'not-object' }>(500),
  IAM_ENGINE_INVALID_CONFIG: detail<{
    field: string
    got: string | number
    allowed?: readonly string[]
    constraint?: string
  }>(500),
  IAM_ENGINE_POLICY_COMBINE_INCOMPATIBLE: detail<{ mode: string; policyCombine: string }>(500),
  IAM_ENGINE_FAIL_OPEN_NOT_CONFIRMED: 500,
  IAM_EVALUATE_RULE_PRIORITY_INVALID: detail<{ policyId?: string; priority?: unknown }>(500),
  IAM_EVALUATE_RULE_EFFECT_UNKNOWN: detail<{ policyId: string; ruleId: string; effect: unknown }>(500),
  IAM_EVALUATE_ALGORITHM_UNKNOWN: detail<{ policyId: string; algorithm: string }>(500),
  IAM_BUILDER_WHEN_EMPTY_LIST: detail<{ method: 'roles' | 'scopes' | 'resourceType' }>(500),
  IAM_BUILDER_WHEN_GROUP_CONFLICT: 500,
  IAM_BUILDER_RULE_SCOPE_EMPTY: detail<{ ruleId: string }>(500),
  IAM_BUILDER_RULE_UNCONFIGURED: detail<{ ruleId: string }>(500),
  IAM_ENGINE_PARAM_INVALID: detail<{ name: string; reason: 'empty' | 'too-long'; got?: string; length?: number }>(400),
  IAM_ENGINE_ATTRIBUTES_PARAM_INVALID: detail<{
    reason: 'not-object' | 'too-many-keys' | 'too-deep'
    got?: string
    count?: number
    depth?: number
  }>(400),
  IAM_ENGINE_SNAPSHOT_VERSION_UNSUPPORTED: detail<{ got: string }>(400),
  IAM_ENGINE_SNAPSHOT_FIELD_INVALID: detail<{ field: 'policies' | 'roles' }>(400),
  IAM_ENGINE_PRELOAD_VALIDATION_FAILED: detail<{ count: number; problems: readonly string[] }>(500),
  IAM_ENGINE_ROW_CAP_EXCEEDED: detail<{ noun: string; count: number; cap: number; capField: string }>(500),
  IAM_ENGINE_SUBJECT_LOAD_SHED: detail<{ subjectId: string; inFlight: number; cap: number }>(503),
  IAM_ENGINE_INVALIDATOR_SHAPE_INVALID: 500,
  IAM_ENGINE_INTERPRETER_DISAGREEMENT: detail<{ compiled: boolean; interpreted: boolean; detail: string }>(500),
  IAM_ENGINE_EXPLAIN_UNAVAILABLE: 500,
  IAM_ENGINE_BATCH_TOO_LARGE: detail<{ count: number; limit: number }>(400),
  IAM_ENGINE_ADAPTER_NOT_TRANSACTIONAL: 500,
  IAM_CACHE_CONFIG_INVALID: detail<{ field: 'maxSize' | 'ttlMs'; got: number; constraint: string }>(500),
  IAM_DT_FLOW_BUFFER_SIZE_INVALID: detail<{ got: number }>(500),
  IAM_METRICS_SAMPLE_SIZE_INVALID: detail<{ got: number }>(500),
  IAM_REDIS_ASSIGNMENT_ENCODING_INVALID: detail<{ field: 'role' | 'scope' }>(500),
} as const satisfies Record<string, number>
