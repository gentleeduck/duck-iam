import { resolve } from './resolve'
import type { AccessRequest, AttributeValue, Condition, ConditionGroup, Operator, Scalar } from './types'

// --- Operator implementations ---

type OpFn = (field: AttributeValue, value: AttributeValue) => boolean

const ops: Record<Operator, OpFn> = {
  eq: (f, v) => f === v,
  neq: (f, v) => f !== v,

  gt: (f, v) => typeof f === 'number' && typeof v === 'number' && f > v,
  gte: (f, v) => typeof f === 'number' && typeof v === 'number' && f >= v,
  lt: (f, v) => typeof f === 'number' && typeof v === 'number' && f < v,
  lte: (f, v) => typeof f === 'number' && typeof v === 'number' && f <= v,

  in: (f, v) => {
    if (!Array.isArray(v)) return false
    if (Array.isArray(f)) return f.some((i) => (v as Scalar[]).includes(i))
    return (v as Scalar[]).includes(f as Scalar)
  },
  nin: (f, v) => {
    if (!Array.isArray(v)) return true
    if (Array.isArray(f)) return !f.some((i) => (v as Scalar[]).includes(i))
    return !(v as Scalar[]).includes(f as Scalar)
  },

  contains: (f, v) => {
    if (Array.isArray(f)) return f.includes(v as Scalar)
    if (typeof f === 'string' && typeof v === 'string') return f.includes(v)
    return false
  },
  not_contains: (f, v) => {
    if (Array.isArray(f)) return !f.includes(v as Scalar)
    if (typeof f === 'string' && typeof v === 'string') return !f.includes(v)
    return true
  },

  starts_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.startsWith(v),
  ends_with: (f, v) => typeof f === 'string' && typeof v === 'string' && f.endsWith(v),

  matches: (f, v) => {
    if (typeof f !== 'string' || typeof v !== 'string') return false
    try {
      return new RegExp(v).test(f)
    } catch {
      return false
    }
  },

  exists: (f) => f !== null && f !== undefined,
  not_exists: (f) => f === null || f === undefined,

  subset_of: (f, v) => {
    if (!Array.isArray(f) || !Array.isArray(v)) return false
    return f.every((i) => (v as Scalar[]).includes(i))
  },
  superset_of: (f, v) => {
    if (!Array.isArray(f) || !Array.isArray(v)) return false
    return (v as Scalar[]).every((i) => f.includes(i))
  },
}

// --- Condition evaluation ---

function evalCondition(req: AccessRequest, cond: Condition): boolean {
  const fieldVal = resolve(req, cond.field)
  return ops[cond.operator](fieldVal, cond.value ?? null)
}

export function evalConditionGroup(req: AccessRequest, group: ConditionGroup): boolean {
  if ('all' in group) {
    return group.all.every((item) =>
      'field' in item ? evalCondition(req, item as Condition) : evalConditionGroup(req, item as ConditionGroup),
    )
  }

  if ('any' in group) {
    return group.any.some((item) =>
      'field' in item ? evalCondition(req, item as Condition) : evalConditionGroup(req, item as ConditionGroup),
    )
  }

  if ('none' in group) {
    return group.none.every(
      (item) =>
        !('field' in item ? evalCondition(req, item as Condition) : evalConditionGroup(req, item as ConditionGroup)),
    )
  }

  return false
}
