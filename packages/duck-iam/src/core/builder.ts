import type {
  Attributes,
  AttributeValue,
  CombiningAlgorithm,
  Condition,
  ConditionGroup,
  Effect,
  Operator,
  Permission,
  Policy,
  Role,
  Rule,
} from './types'

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Condition builder with AND/OR/NONE nesting
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export class When {
  private items: Array<Condition | ConditionGroup> = []

  /** Raw condition */
  check(field: string, op: Operator, value?: AttributeValue): this {
    this.items.push({ field, operator: op, value })
    return this
  }

  // ── Shorthand conditions ──

  eq(field: string, value: AttributeValue): this {
    return this.check(field, 'eq', value)
  }

  neq(field: string, value: AttributeValue): this {
    return this.check(field, 'neq', value)
  }

  in(field: string, values: AttributeValue): this {
    return this.check(field, 'in', values)
  }

  contains(field: string, value: string): this {
    return this.check(field, 'contains', value)
  }

  exists(field: string): this {
    return this.check(field, 'exists')
  }

  gt(field: string, value: number): this {
    return this.check(field, 'gt', value)
  }

  gte(field: string, value: number): this {
    return this.check(field, 'gte', value)
  }

  lt(field: string, value: number): this {
    return this.check(field, 'lt', value)
  }

  lte(field: string, value: number): this {
    return this.check(field, 'lte', value)
  }

  matches(field: string, regex: string): this {
    return this.check(field, 'matches', regex)
  }

  // ── Semantic shortcuts ──

  role(roleId: string): this {
    return this.contains('subject.roles', roleId)
  }

  roles(...roleIds: string[]): this {
    return this.check('subject.roles', 'in', roleIds)
  }

  isOwner(ownerField = 'resource.attributes.ownerId'): this {
    // This will be checked against subject.id at eval time
    // We use a convention: value of "$subject.id"
    this.items.push({ field: ownerField, operator: 'eq', value: '$subject.id' })
    return this
  }

  resourceType(...types: string[]): this {
    return this.check('resource.type', 'in', types)
  }

  attr(path: string, op: Operator, value?: AttributeValue): this {
    return this.check(`subject.attributes.${path}`, op, value)
  }

  resourceAttr(path: string, op: Operator, value?: AttributeValue): this {
    return this.check(`resource.attributes.${path}`, op, value)
  }

  env(path: string, op: Operator, value?: AttributeValue): this {
    return this.check(`environment.${path}`, op, value)
  }

  // ── Nesting ──

  and(fn: (w: When) => When): this {
    const nested = new When()
    fn(nested)
    this.items.push(nested.buildAll())
    return this
  }

  or(fn: (w: When) => When): this {
    const nested = new When()
    fn(nested)
    this.items.push(nested.buildAny())
    return this
  }

  not(fn: (w: When) => When): this {
    const nested = new When()
    fn(nested)
    this.items.push(nested.buildNone())
    return this
  }

  // ── Build ──

  buildAll(): ConditionGroup {
    return { all: this.items }
  }

  buildAny(): ConditionGroup {
    return { any: this.items }
  }

  buildNone(): ConditionGroup {
    return { none: this.items }
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Rule builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export class RuleBuilder {
  private _id: string
  private _effect: Effect = 'allow'
  private _description?: string
  private _priority = 10
  private _actions: string[] = ['*']
  private _resources: string[] = ['*']
  private _conditions: ConditionGroup = { all: [] }
  private _metadata?: Attributes

  constructor(id: string) {
    this._id = id
  }

  allow(): this {
    this._effect = 'allow'
    return this
  }

  deny(): this {
    this._effect = 'deny'
    return this
  }

  desc(d: string): this {
    this._description = d
    return this
  }

  priority(p: number): this {
    this._priority = p
    return this
  }

  on(...actions: string[]): this {
    this._actions = actions
    return this
  }

  of(...resources: string[]): this {
    this._resources = resources
    return this
  }

  when(fn: (w: When) => When): this {
    const w = new When()
    fn(w)
    this._conditions = w.buildAll()
    return this
  }

  whenAny(fn: (w: When) => When): this {
    const w = new When()
    fn(w)
    this._conditions = w.buildAny()
    return this
  }

  meta(m: Attributes): this {
    this._metadata = m
    return this
  }

  build(): Rule {
    return {
      id: this._id,
      effect: this._effect,
      description: this._description,
      priority: this._priority,
      actions: this._actions,
      resources: this._resources,
      conditions: this._conditions,
      metadata: this._metadata,
    }
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Policy builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export class PolicyBuilder {
  private _id: string
  private _name: string
  private _description?: string
  private _algorithm: CombiningAlgorithm = 'deny-overrides'
  private _rules: Rule[] = []
  private _targets?: Policy['targets']
  private _version?: number

  constructor(id: string) {
    this._id = id
    this._name = id
  }

  name(n: string): this {
    this._name = n
    return this
  }

  desc(d: string): this {
    this._description = d
    return this
  }

  version(v: number): this {
    this._version = v
    return this
  }

  algorithm(a: CombiningAlgorithm): this {
    this._algorithm = a
    return this
  }

  /** Scope this policy to specific actions/resources/roles */
  target(t: NonNullable<Policy['targets']>): this {
    this._targets = t
    return this
  }

  rule(id: string, fn: (r: RuleBuilder) => RuleBuilder): this {
    const builder = new RuleBuilder(id)
    fn(builder)
    this._rules.push(builder.build())
    return this
  }

  addRule(rule: Rule): this {
    this._rules.push(rule)
    return this
  }

  build(): Policy {
    return {
      id: this._id,
      name: this._name,
      description: this._description,
      version: this._version,
      algorithm: this._algorithm,
      rules: this._rules,
      targets: this._targets,
    }
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Role builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export class RoleBuilder {
  private _id: string
  private _name: string
  private _description?: string
  private _permissions: Permission[] = []
  private _inherits: string[] = []
  private _scope?: string
  private _metadata?: Attributes

  constructor(id: string) {
    this._id = id
    this._name = id
  }

  name(n: string): this {
    this._name = n
    return this
  }

  desc(d: string): this {
    this._description = d
    return this
  }

  inherits(...roleIds: string[]): this {
    this._inherits = roleIds
    return this
  }

  scope(s: string): this {
    this._scope = s
    return this
  }

  /** Grant a permission */
  grant(action: string, resource: string): this {
    this._permissions.push({ action, resource })
    return this
  }

  /** Grant with conditions */
  grantWhen(action: string, resource: string, fn: (w: When) => When): this {
    const w = new When()
    fn(w)
    this._permissions.push({ action, resource, conditions: w.buildAll() })
    return this
  }

  /** Grant all actions on a resource */
  grantAll(resource: string): this {
    return this.grant('*', resource)
  }

  /** Grant read access to resources */
  grantRead(...resources: string[]): this {
    for (const r of resources) this.grant('read', r)
    return this
  }

  /** Grant CRUD on a resource */
  grantCRUD(resource: string): this {
    for (const a of ['create', 'read', 'update', 'delete']) {
      this.grant(a, resource)
    }
    return this
  }

  meta(m: Attributes): this {
    this._metadata = m
    return this
  }

  build(): Role {
    return {
      id: this._id,
      name: this._name,
      description: this._description,
      permissions: this._permissions,
      inherits: this._inherits.length > 0 ? this._inherits : undefined,
      scope: this._scope,
      metadata: this._metadata,
    }
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Factory functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const policy = (id: string) => new PolicyBuilder(id)
export const defineRole = <const TId extends string>(id: TId) => new RoleBuilder(id)
export const defineRule = (id: string) => new RuleBuilder(id)
export const when = () => new When()
