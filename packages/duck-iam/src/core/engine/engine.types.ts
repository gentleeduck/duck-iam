import type { Attributes, Policy, Role } from '../types'

/**
 * Administrative interface for managing policies, roles, and subject data.
 *
 * Accessed via `engine.admin`. All mutation methods automatically invalidate
 * the relevant engine caches.
 *
 * @template TAction   - Union of valid action strings
 * @template TResource - Union of valid resource strings
 * @template TRole     - Union of valid role strings
 * @template TScope    - Union of valid scope strings
 */
export interface EngineAdmin<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  /** Returns all stored policies. */
  listPolicies(): Promise<Policy<TAction, TResource, TRole>[]>
  /** Returns a single policy by ID, or `null` if not found. */
  getPolicy(id: string): Promise<Policy<TAction, TResource, TRole> | null>
  /** Creates or updates a policy. Invalidates the policy cache. */
  savePolicy(policy: Policy<TAction, TResource, TRole>): Promise<void>
  /** Deletes a policy by ID. Invalidates the policy cache. */
  deletePolicy(id: string): Promise<void>
  /** Returns all stored roles. */
  listRoles(): Promise<Role<TAction, TResource, TRole, TScope>[]>
  /** Returns a single role by ID, or `null` if not found. */
  getRole(id: string): Promise<Role<TAction, TResource, TRole, TScope> | null>
  /** Creates or updates a role. Invalidates role and subject caches. */
  saveRole(role: Role<TAction, TResource, TRole, TScope>): Promise<void>
  /** Deletes a role by ID. Invalidates role and subject caches. */
  deleteRole(id: string): Promise<void>
  /** Assigns a role to a subject. Invalidates that subject's cache entry. */
  assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  /** Revokes a role from a subject. Invalidates that subject's cache entry. */
  revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  /** Sets the attribute bag for a subject. Invalidates that subject's cache entry. */
  setAttributes(subjectId: string, attrs: Attributes): Promise<void>
  /** Returns the attribute bag for a subject. */
  getAttributes(subjectId: string): Promise<Attributes>
}
