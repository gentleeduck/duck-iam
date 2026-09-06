import { MAX_CONDITION_DEPTH } from '../conditions/conditions.libs'
import type { AccessControl } from '../types'
import { MAX_CONDITION_VALUE_LENGTH, MAX_FIELD_LENGTH, POLICY_LIMITS } from '../validate/validate.libs'

/** One branch of a condition-group `oneOf`: exactly one of `all` / `any` / `none`. */
interface IGroupBranch {
  readonly type: 'object'
  readonly required: readonly string[]
  readonly additionalProperties: false
  readonly properties: Readonly<Record<string, { readonly $ref: string }>>
}

/** A `$defs` entry for a condition group at one nesting level. */
interface IConditionGroupDef {
  readonly oneOf: readonly IGroupBranch[]
}

/** A `$defs` entry for the item list a condition group at one nesting level holds. */
interface IConditionListDef {
  readonly type: 'array'
  readonly items: Readonly<Record<string, unknown>>
}

/** `$defs` name for the group at `level`; level 0 keeps the historical unsuffixed name. */
function groupName(level: number): string {
  return level === 0 ? 'conditionGroup' : `conditionGroup${level}`
}

/** `$defs` name for the item list at `level`; level 0 keeps the historical unsuffixed name. */
function listName(level: number): string {
  return level === 0 ? 'conditionList' : `conditionList${level}`
}

/**
 * Mirrors `hasControlChar`: an action or resource name carrying a control
 * character is invisible in every UI that would show one, so it reads as a
 * different name than it is.
 */
const NO_CONTROL_CHARS = '^[^\\u0000-\\u001F\\u007F]*$'

function conditionGroup(level: number): IConditionGroupDef {
  const items = { $ref: `#/$defs/${listName(level)}` }
  return {
    oneOf: (['all', 'any', 'none'] as const).map((key) => ({
      additionalProperties: false,
      properties: { [key]: items },
      required: [key],
      type: 'object',
    })),
  }
}

/**
 * A group is only reachable while `evalConditionGroup` is still descending, so
 * the list at the deepest level admits leaves and nothing else. Expressed as a
 * finite `$defs` chain rather than one self-recursive `$ref`, which is what let
 * a 40-deep tree read as schema-valid while the runtime truncated it.
 */
function conditionList(level: number): IConditionListDef {
  const leaf = { $ref: '#/$defs/condition' }
  const deepest = level + 1 >= MAX_CONDITION_DEPTH
  return {
    items: deepest ? leaf : { oneOf: [leaf, { $ref: `#/$defs/${groupName(level + 1)}` }] },
    type: 'array',
  }
}

/** Levels 1..MAX_CONDITION_DEPTH-1 plus every list; level 0's group is spelled out in `$defs`. */
function nestedConditionDefs(): Record<string, IConditionGroupDef | IConditionListDef> {
  const defs: Record<string, IConditionGroupDef | IConditionListDef> = {}
  for (let level = 0; level < MAX_CONDITION_DEPTH; level++) {
    if (level > 0) defs[groupName(level)] = conditionGroup(level)
    defs[listName(level)] = conditionList(level)
  }
  return defs
}

/**
 * JSON Schema (Draft 2020-12) for {@link AccessControl.IPolicy}; tighten action/resource slots via `$ref` downstream.
 *
 * Anything this schema rejects, `validatePolicy` rejects too - a policy the
 * runtime accepts always validates here. The converse does not hold: four
 * checks are not expressible in JSON Schema and `validatePolicy` remains the
 * authority on them.
 *
 * 1. `matches` patterns are screened for catastrophic backtracking and for
 *    compiling at all (`ERR_REGEX_CATASTROPHIC` / `ERR_REGEX_INVALID`).
 * 2. A rule's `actions x resources` cartesian is capped at
 *    {@link POLICY_LIMITS.cartesianPerRule}; only the per-list caps are here.
 * 3. `targets` naming an (action, resource) pair no allow rule covers is an
 *    error (`UNREACHABLE_TARGET`), which needs the rules to decide.
 * 4. `priority` must be finite; JSON has no `NaN`/`Infinity` literal, so
 *    `type: 'number'` is as close as the schema gets.
 */
export const POLICY_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://gentleduck.dev/duck-iam/policy.schema.json',
  title: 'duck-iam Policy',
  type: 'object',
  required: ['id', 'name', 'algorithm', 'rules'],
  additionalProperties: false,
  properties: {
    id: { type: 'string', minLength: 1 },
    name: { type: 'string', minLength: 1 },
    description: { type: 'string' },
    version: { type: 'number' },
    algorithm: {
      enum: ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority'],
    },
    rules: {
      type: 'array',
      maxItems: POLICY_LIMITS.rulesPerPolicy,
      items: { $ref: '#/$defs/rule' },
    },
    targets: {
      type: 'object',
      additionalProperties: false,
      properties: {
        actions: { type: 'array', items: { type: 'string' } },
        resources: { type: 'array', items: { type: 'string' } },
        roles: { type: 'array', items: { type: 'string' } },
      },
    },
  },
  $defs: {
    condition: {
      type: 'object',
      required: ['field', 'operator'],
      additionalProperties: false,
      properties: {
        field: { type: 'string', minLength: 1, maxLength: MAX_FIELD_LENGTH },
        operator: {
          enum: [
            'eq',
            'neq',
            'gt',
            'gte',
            'lt',
            'lte',
            'in',
            'nin',
            'contains',
            'not_contains',
            'starts_with',
            'ends_with',
            'matches',
            'exists',
            'not_exists',
            'subset_of',
            'superset_of',
            'before',
            'after',
          ],
        },
        value: {},
      },
      // The operand rules `validateConditionItem` enforces, restated for
      // consumers that validate against the published schema instead. Omitting
      // `value` used to be legal here, and a missing operand reads as `null` at
      // evaluation - equal to a missing attribute, so the guard passes for the
      // subjects it was written to exclude. A `$`-prefixed string resolves from
      // the request, so it satisfies every operand type.
      // biome-ignore-start lint/suspicious/noThenProperty: `then` is the JSON Schema keyword paired with `if`; this constant is data, never awaited.
      allOf: [
        {
          if: { required: ['operator'], properties: { operator: { not: { enum: ['exists', 'not_exists'] } } } },
          then: { required: ['value'] },
        },
        {
          if: { required: ['operator'], properties: { operator: { enum: ['in', 'nin', 'subset_of', 'superset_of'] } } },
          then: { properties: { value: { oneOf: [{ type: 'array' }, { type: 'string', pattern: '^\\$' }] } } },
        },
        {
          if: { required: ['operator'], properties: { operator: { enum: ['gt', 'gte', 'lt', 'lte'] } } },
          then: { properties: { value: { oneOf: [{ type: 'number' }, { type: 'string', pattern: '^\\$' }] } } },
        },
        {
          if: { required: ['operator'], properties: { operator: { enum: ['starts_with', 'ends_with', 'matches'] } } },
          then: { properties: { value: { type: 'string' } } },
        },
        {
          if: { required: ['operator'], properties: { operator: { enum: ['before', 'after'] } } },
          then: { properties: { value: { type: ['number', 'string'] } } },
        },
        // The length caps `validateConditionItem` applies to a string operand
        // and to the string entries of an array one. Both were runtime-only,
        // so an admin UI validating against this schema green-lit a 4 KB
        // pattern the store then refused.
        {
          if: { properties: { value: { type: 'string' } } },
          then: { properties: { value: { maxLength: MAX_CONDITION_VALUE_LENGTH } } },
        },
        {
          if: { properties: { value: { type: 'array' } } },
          then: {
            properties: {
              value: { items: { if: { type: 'string' }, then: { maxLength: MAX_CONDITION_VALUE_LENGTH } } },
            },
          },
        },
      ],
      // biome-ignore-end lint/suspicious/noThenProperty: end of the JSON Schema if/then block.
    },
    conditionGroup: conditionGroup(0),
    rule: {
      type: 'object',
      required: ['id', 'effect', 'priority', 'actions', 'resources', 'conditions'],
      additionalProperties: false,
      properties: {
        id: { type: 'string', minLength: 1 },
        effect: { enum: ['allow', 'deny'] },
        description: { type: 'string' },
        priority: { type: 'number' },
        actions: {
          type: 'array',
          minItems: 1,
          maxItems: POLICY_LIMITS.actionsPerRule,
          items: { type: 'string', pattern: NO_CONTROL_CHARS },
        },
        resources: {
          type: 'array',
          minItems: 1,
          maxItems: POLICY_LIMITS.resourcesPerRule,
          items: { type: 'string', pattern: NO_CONTROL_CHARS },
        },
        conditions: { $ref: '#/$defs/conditionGroup' },
        metadata: { type: 'object', additionalProperties: true },
      },
    },
    ...nestedConditionDefs(),
  },
} as const
