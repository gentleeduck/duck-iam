import type { IamAccessControl } from '../types'
/** JSON Schema (Draft 2020-12) for {@link IamAccessControl.IPolicy}; tighten action/resource slots via `$ref` downstream. */
export const IAM_POLICY_JSON_SCHEMA = {
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
    rule: {
      type: 'object',
      required: ['id', 'effect', 'priority', 'actions', 'resources', 'conditions'],
      additionalProperties: false,
      properties: {
        id: { type: 'string', minLength: 1 },
        effect: { enum: ['allow', 'deny'] },
        description: { type: 'string' },
        priority: { type: 'number' },
        actions: { type: 'array', minItems: 1, items: { type: 'string' } },
        resources: { type: 'array', minItems: 1, items: { type: 'string' } },
        conditions: { $ref: '#/$defs/conditionGroup' },
        metadata: { type: 'object', additionalProperties: true },
      },
    },
    conditionGroup: {
      oneOf: [
        { type: 'object', required: ['all'], properties: { all: { $ref: '#/$defs/conditionList' } } },
        { type: 'object', required: ['any'], properties: { any: { $ref: '#/$defs/conditionList' } } },
        { type: 'object', required: ['none'], properties: { none: { $ref: '#/$defs/conditionList' } } },
      ],
    },
    conditionList: {
      type: 'array',
      items: {
        oneOf: [{ $ref: '#/$defs/condition' }, { $ref: '#/$defs/conditionGroup' }],
      },
    },
    condition: {
      type: 'object',
      required: ['field', 'operator'],
      additionalProperties: false,
      properties: {
        field: { type: 'string', minLength: 1 },
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
          ],
        },
        value: {},
      },
    },
  },
} as const
