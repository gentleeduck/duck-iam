import type { CombiningAlgorithm, Policy, Rule } from '../types'
import { RuleBuilder } from './rule'

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

export const policy = <
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: string,
) => new PolicyBuilder<TAction, TResource, string, TScope>(id)
