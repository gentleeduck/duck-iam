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

// ------------------------------------------------------------
// Condition builder with AND/OR/NONE nesting
// ------------------------------------------------------------

export class When<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  private items: Array<Condition | ConditionGroup> = []

  /** Raw condition */
  check(field: string, op: Operator, value?: AttributeValue): this {
    this.items.push({ field, operator: op, value })
    return this
  }

  // -- Shorthand conditions --

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

  // -- Semantic shortcuts --

  role(roleId: TRole): this {
    return this.contains('subject.roles', roleId)
  }

  roles(...roleIds: TRole[]): this {
    return this.check('subject.roles', 'in', roleIds as string[])
  }

  /** Require a specific scope on the request */
  scope(id: TScope): this {
    return this.check('scope', 'eq', id)
  }

  /** Require one of the given scopes */
  scopes(...ids: TScope[]): this {
    return this.check('scope', 'in', ids as string[])
  }

  isOwner(ownerField = 'resource.attributes.ownerId'): this {
    // This will be checked against subject.id at eval time
    // We use a convention: value of "$subject.id"
    this.items.push({ field: ownerField, operator: 'eq', value: '$subject.id' })
    return this
  }

  resourceType(...types: (TResource | '*')[]): this {
    return this.check('resource.type', 'in', types as string[])
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

  // -- Nesting --

  and(fn: (w: When<TAction, TResource, TRole, TScope>) => When<TAction, TResource, TRole, TScope>): this {
    const nested = new When<TAction, TResource, TRole, TScope>()
    fn(nested)
    this.items.push(nested.buildAll())
    return this
  }

  or(fn: (w: When<TAction, TResource, TRole, TScope>) => When<TAction, TResource, TRole, TScope>): this {
    const nested = new When<TAction, TResource, TRole, TScope>()
    fn(nested)
    this.items.push(nested.buildAny())
    return this
  }

  not(fn: (w: When<TAction, TResource, TRole, TScope>) => When<TAction, TResource, TRole, TScope>): this {
    const nested = new When<TAction, TResource, TRole, TScope>()
    fn(nested)
    this.items.push(nested.buildNone())
    return this
  }

  // -- Build --

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

// ------------------------------------------------------------
// Rule builder
// ------------------------------------------------------------

export class RuleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
> {
  private _id: string
  private _effect: Effect = 'allow'
  private _description?: string
  private _priority = 10
  private _actions: (TAction | '*')[] = ['*']
  private _resources: (TResource | '*')[] = ['*']
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

  on(...actions: (TAction | '*')[]): this {
    this._actions = actions
    return this
  }

  of(...resources: (TResource | '*')[]): this {
    this._resources = resources
    return this
  }

  /** Scope conditions are stored separately and merged at build time */
  private _scopeCondition?: Condition

  /** Restrict this rule to specific scopes */
  forScope(...scopes: (TScope | '*')[]): this {
    const nonWild = scopes.filter((s) => s !== '*') as string[]
    if (nonWild.length === 0) return this

    this._scopeCondition =
      nonWild.length === 1
        ? { field: 'scope', operator: 'eq', value: nonWild[0] }
        : { field: 'scope', operator: 'in', value: nonWild }

    return this
  }

  when(fn: (w: When<TAction, TResource, string, TScope>) => When<TAction, TResource, string, TScope>): this {
    const w = new When<TAction, TResource, string, TScope>()
    fn(w)
    this._conditions = w.buildAll()
    return this
  }

  whenAny(fn: (w: When<TAction, TResource, string, TScope>) => When<TAction, TResource, string, TScope>): this {
    const w = new When<TAction, TResource, string, TScope>()
    fn(w)
    this._conditions = w.buildAny()
    return this
  }

  meta(m: Attributes): this {
    this._metadata = m
    return this
  }

  build(): Rule<TAction, TResource> {
    // Merge scope condition into user conditions so forScope() + when() compose correctly
    let conditions = this._conditions
    if (this._scopeCondition) {
      const existing = 'all' in conditions ? [...conditions.all] : [conditions]
      conditions = { all: [this._scopeCondition, ...existing] }
    }

    return {
      id: this._id,
      effect: this._effect,
      description: this._description,
      priority: this._priority,
      actions: this._actions,
      resources: this._resources,
      conditions,
      metadata: this._metadata,
    }
  }
}

// ------------------------------------------------------------
// Policy builder
// ------------------------------------------------------------

export class PolicyBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  private _id: string
  private _name: string
  private _description?: string
  private _algorithm: CombiningAlgorithm = 'deny-overrides'
  private _rules: Rule<TAction, TResource>[] = []
  private _targets?: Policy<TAction, TResource, TRole>['targets']
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
  target(t: NonNullable<Policy<TAction, TResource, TRole>['targets']>): this {
    this._targets = t
    return this
  }

  rule(id: string, fn: (r: RuleBuilder<TAction, TResource, TScope>) => RuleBuilder<TAction, TResource, TScope>): this {
    const builder = new RuleBuilder<TAction, TResource, TScope>(id)
    fn(builder)
    this._rules.push(builder.build())
    return this
  }

  addRule(rule: Rule<TAction, TResource>): this {
    this._rules.push(rule)
    return this
  }

  build(): Policy<TAction, TResource, TRole> {
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

// ------------------------------------------------------------
// Role builder
// ------------------------------------------------------------

export class RoleBuilder<
  TAction extends string = string,
  TResource extends string = string,
  TId extends string = string,
  TScope extends string = string,
> {
  private _id: TId
  private _name: string
  private _description?: string
  private _permissions: Permission<TAction, TResource, TScope>[] = []
  private _inherits: string[] = []
  private _scope?: TScope
  private _metadata?: Attributes

  constructor(id: TId) {
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

  /** Set the default scope for all permissions in this role */
  scope(s: TScope): this {
    this._scope = s
    return this
  }

  /** Grant a permission */
  grant(action: TAction | '*', resource: TResource | '*'): this {
    this._permissions.push({ action, resource })
    return this
  }

  /** Grant a permission within a specific scope */
  grantScoped(scope: TScope, action: TAction | '*', resource: TResource | '*'): this {
    this._permissions.push({ action, resource, scope })
    return this
  }

  /** Grant with conditions */
  grantWhen(
    action: TAction | '*',
    resource: TResource | '*',
    fn: (w: When<TAction, TResource, string, TScope>) => When<TAction, TResource, string, TScope>,
  ): this {
    const w = new When<TAction, TResource, string, TScope>()
    fn(w)
    this._permissions.push({ action, resource, conditions: w.buildAll() })
    return this
  }

  /** Grant all actions on a resource */
  grantAll(resource: TResource | '*'): this {
    return this.grant('*', resource)
  }

  /** Grant read access to resources */
  grantRead(...resources: (TResource | '*')[]): this {
    for (const r of resources) this.grant('read' as TAction | '*', r)
    return this
  }

  /** Grant CRUD on a resource */
  grantCRUD(resource: TResource | '*'): this {
    for (const a of ['create', 'read', 'update', 'delete'] as (TAction | '*')[]) {
      this.grant(a, resource)
    }
    return this
  }

  meta(m: Attributes): this {
    this._metadata = m
    return this
  }

  build(): Role<TAction, TResource, TId, TScope> {
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

// ------------------------------------------------------------
// Factory functions
// ------------------------------------------------------------

export const policy = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: string,
) => new PolicyBuilder<TAction, TResource, string, TScope>(id)

export const defineRole = <
  const TId extends string,
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: TId,
) => new RoleBuilder<TAction, TResource, TId, TScope>(id)

export const defineRule = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: string,
) => new RuleBuilder<TAction, TResource, TScope>(id)

export const when = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>() => new When<TAction, TResource, string, TScope>()
