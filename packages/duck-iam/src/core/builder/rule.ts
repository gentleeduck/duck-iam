import type { Attributes, Condition, ConditionGroup, Effect, Rule } from '../types'
import { When } from './when'

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

export const defineRule = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: string,
) => new RuleBuilder<TAction, TResource, TScope>(id)
