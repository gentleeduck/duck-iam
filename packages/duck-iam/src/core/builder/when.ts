import type { AttributeValue, Condition, ConditionGroup, Operator } from '../types'

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

  buildAll(): { readonly all: ReadonlyArray<Condition | ConditionGroup> } {
    return { all: this.items }
  }

  buildAny(): { readonly any: ReadonlyArray<Condition | ConditionGroup> } {
    return { any: this.items }
  }

  buildNone(): { readonly none: ReadonlyArray<Condition | ConditionGroup> } {
    return { none: this.items }
  }
}

export const when = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>() => new When<TAction, TResource, string, TScope>()
