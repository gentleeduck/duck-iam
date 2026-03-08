import type { Attributes, Permission, Role } from '../types'
import { When } from './when'

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

export const defineRole = <
  const TId extends string,
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(
  id: TId,
) => new RoleBuilder<TAction, TResource, TId, TScope>(id)
