import type { IamPrimitives } from './primitives'

/**
 * One evaluation in flight: the subject asking, the resource it names, and the environment. Type-only.
 * The model those are checked against lives in `AccessControl`.
 */
export namespace IamRequest {
  /**
   * A role assignment limited to a tenant, organization or workspace (e.g. `editor` in `org-acme`).
   *
   * @template TRole  - Union of valid role IDs.
   * @template TScope - Union of valid scope strings.
   */
  export interface IScopedRole<TRole extends string = string, TScope extends string = string> {
    readonly role: TRole
    /** The scope this role assignment is restricted to. */
    readonly scope?: TScope
    /**
     * Attributes of this one grant, read by conditions as `subject.scopedRoles[].attributes`.
     * Distinct from the subject-wide {@link ISubject.attributes}; undefined when the adapter stores none.
     */
    readonly attributes?: IamPrimitives.Attributes
  }

  /**
   * Authenticated user or service making the request; the engine builds it via `resolveSubject(subjectId)`.
   *
   * @template TRole  - Union of valid role IDs.
   * @template TScope - Union of valid scope strings.
   */
  export interface ISubject<TRole extends string = string, TScope extends string = string> {
    /** Unique identifier (user ID, service account ID). */
    readonly id: string
    /** Effective roles after inheritance resolution. */
    readonly roles: readonly TRole[]
    /** Scoped role assignments for multi-tenant authorization. */
    readonly scopedRoles?: readonly IScopedRole<TRole, TScope>[]
    /** Subject attributes available to conditions. */
    readonly attributes: Readonly<IamPrimitives.Attributes>
  }

  /**
   * Target resource being accessed.
   *
   * @template TResource - Union of valid resource type strings.
   */
  export interface IResource<TResource extends string = string> {
    /** Resource type (e.g. `'post'`, `'comment'`, `'dashboard'`). */
    readonly type: TResource
    /** Specific instance ID (e.g. `'post-123'`). */
    readonly id?: string
    /** Resource attributes available to conditions. */
    readonly attributes: Readonly<IamPrimitives.Attributes>
  }

  /** Request-level context such as client IP, user agent or feature flags; custom keys are allowed. */
  export interface IEnvironment {
    readonly ip?: string
    readonly userAgent?: string
    /** Request timestamp in milliseconds since epoch. */
    readonly timestamp?: number
    /**
     * Evaluation clock in epoch ms, read by rules as `$environment.now`; the engine injects `Date.now()` when absent.
     * Set it in tests or a `beforeEvaluate` hook to pin the clock.
     */
    readonly now?: number
    readonly [key: string]: IamPrimitives.AttributeValue | undefined
  }

  /**
   * Complete authorization request the engine evaluates.
   *
   * @template TAction   - Union of valid action strings.
   * @template TResource - Union of valid resource strings.
   * @template TScope    - Union of valid scope strings.
   */
  export interface IAccessRequest<
    TAction extends string = string,
    TResource extends string = string,
    TScope extends string = string,
  > {
    readonly subject: ISubject
    /** Action being performed (e.g. `'read'`, `'update'`, `'delete'`). */
    readonly action: TAction
    readonly resource: IResource<TResource>
    /** Multi-tenant scope (e.g. `'org-acme'`). */
    readonly scope?: TScope
    readonly environment?: IEnvironment
  }
}
