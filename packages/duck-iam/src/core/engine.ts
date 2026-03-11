import { LRUCache } from '../shared/cache'
import { buildPermissionKey } from '../shared/keys'
import { evaluate } from './evaluate'
import type { ExplainResult } from './explain'
import { explainEvaluation } from './explain'
import { resolveEffectiveRoles, rolesToPolicy } from './rbac'
import type {
  AccessRequest,
  Adapter,
  Attributes,
  Decision,
  Effect,
  EngineConfig,
  EngineHooks,
  PermissionCheck,
  PermissionMap,
  Policy,
  Resource,
  Role,
  Subject,
} from './types'

interface EngineAdmin<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  listPolicies(): Promise<Policy<TAction, TResource, TRole>[]>
  getPolicy(id: string): Promise<Policy<TAction, TResource, TRole> | null>
  savePolicy(policy: Policy<TAction, TResource, TRole>): Promise<void>
  deletePolicy(id: string): Promise<void>
  listRoles(): Promise<Role<TAction, TResource, TRole, TScope>[]>
  getRole(id: string): Promise<Role<TAction, TResource, TRole, TScope> | null>
  saveRole(role: Role<TAction, TResource, TRole, TScope>): Promise<void>
  deleteRole(id: string): Promise<void>
  assignRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  revokeRole(subjectId: string, roleId: TRole, scope?: TScope): Promise<void>
  setAttributes(subjectId: string, attrs: Attributes): Promise<void>
  getAttributes(subjectId: string): Promise<Attributes>
}

export class Engine<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> {
  private adapter: Adapter<TAction, TResource, TRole, TScope>
  private defaultEffect: Effect
  private hooks: EngineHooks<TAction, TResource, TScope>
  private policyCache: LRUCache<Policy[]>
  private roleCache: LRUCache<Role[]>
  private rbacPolicyCache: LRUCache<Policy>
  private subjectCache: LRUCache<Subject>

  constructor(config: EngineConfig<TAction, TResource, TRole, TScope>) {
    this.adapter = config.adapter
    this.defaultEffect = config.defaultEffect ?? 'deny'
    this.hooks = config.hooks ?? {}

    const ttl = (config.cacheTTL ?? 60) * 1000
    const maxSize = config.maxCacheSize ?? 1000

    this.policyCache = new LRUCache(1, ttl) // single entry
    this.roleCache = new LRUCache(1, ttl)
    this.rbacPolicyCache = new LRUCache(1, ttl)
    this.subjectCache = new LRUCache(maxSize, ttl)
  }

  // -----------------------------------------------
  // Data loading
  // -----------------------------------------------

  private async loadPolicies(): Promise<Policy[]> {
    const cached = this.policyCache.get('all')
    if (cached) return cached
    const policies = await this.adapter.listPolicies()
    this.policyCache.set('all', policies as Policy[])
    return policies as Policy[]
  }

  private async loadRoles(): Promise<Role[]> {
    const cached = this.roleCache.get('all')
    if (cached) return cached
    const roles = await this.adapter.listRoles()
    this.roleCache.set('all', roles as Role[])
    return roles as Role[]
  }

  async resolveSubject(subjectId: string): Promise<Subject> {
    const cached = this.subjectCache.get(subjectId)
    if (cached) return cached

    const [assignedRoles, attributes, allRoles] = await Promise.all([
      this.adapter.getSubjectRoles(subjectId),
      this.adapter.getSubjectAttributes(subjectId),
      this.loadRoles(),
    ])

    const roles = resolveEffectiveRoles(assignedRoles, allRoles)

    // Load scoped roles if adapter supports it
    const scopedRoles = this.adapter.getSubjectScopedRoles
      ? await this.adapter.getSubjectScopedRoles(subjectId)
      : undefined

    const subject: Subject = { id: subjectId, roles, scopedRoles, attributes }
    this.subjectCache.set(subjectId, subject)
    return subject
  }

  // -----------------------------------------------
  // Core evaluation
  // -----------------------------------------------

  /**
   * Load RBAC + ABAC policies for evaluation.
   * Each user-defined policy keeps its own combining algorithm.
   * The RBAC-generated policy uses allow-overrides (set by rolesToPolicy).
   * The rolesToPolicy() conversion is cached to avoid recomputation.
   */
  private async loadAllPolicies(): Promise<Policy[]> {
    const [policies, roles] = await Promise.all([this.loadPolicies(), this.loadRoles()])

    let rbacPolicy = this.rbacPolicyCache.get('rbac')
    if (!rbacPolicy) {
      rbacPolicy = rolesToPolicy(roles)
      this.rbacPolicyCache.set('rbac', rbacPolicy)
    }

    return [rbacPolicy, ...policies]
  }

  /**
   * Enrich a subject's roles with scoped role assignments matching the request scope.
   * If user has role 'editor' scoped to 'org-1' and request.scope is 'org-1',
   * 'editor' is added to subject.roles for this evaluation.
   */
  private enrichSubjectWithScopedRoles(subject: Subject, scope: TScope | undefined): Subject {
    if (!scope || !subject.scopedRoles?.length) return subject

    const extraRoles = subject.scopedRoles.filter((sr) => sr.scope === scope).map((sr) => sr.role)

    if (extraRoles.length === 0) return subject

    const mergedRoles = [...new Set([...subject.roles, ...extraRoles])]
    return { ...subject, roles: mergedRoles }
  }

  /**
   * Full authorization check with a complete AccessRequest.
   */
  async authorize(request: AccessRequest<TAction, TResource, TScope>): Promise<Decision> {
    let req = request

    try {
      // Enrich subject with scoped roles matching the request scope
      if (req.scope && req.subject.scopedRoles?.length) {
        req = { ...req, subject: this.enrichSubjectWithScopedRoles(req.subject, req.scope) }
      }

      if (this.hooks.beforeEvaluate) {
        req = await this.hooks.beforeEvaluate(req)
      }

      const allPolicies = await this.loadAllPolicies()
      const decision = evaluate(allPolicies, req as AccessRequest, this.defaultEffect)

      if (this.hooks.afterEvaluate) {
        await this.hooks.afterEvaluate(req, decision)
      }
      if (!decision.allowed && this.hooks.onDeny) {
        await this.hooks.onDeny(req, decision)
      }

      return decision
    } catch (error) {
      if (this.hooks.onError) {
        await this.hooks.onError(error as Error, req)
      }
      return {
        allowed: false,
        effect: 'deny',
        reason: `Evaluation error: ${(error as Error).message}`,
        duration: 0,
        timestamp: Date.now(),
      }
    }
  }

  // -----------------------------------------------
  // Convenience methods
  // -----------------------------------------------

  /**
   * Simple boolean check: can this user do this action on this resource?
   */
  async can(
    subjectId: string,
    action: TAction,
    resource: Resource<TResource>,
    environment?: AccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<boolean> {
    const subject = await this.resolveSubject(subjectId)
    const decision = await this.authorize({ subject, action, resource, environment, scope })
    return decision.allowed
  }

  /**
   * Same as `can` but returns the full Decision.
   */
  async check(
    subjectId: string,
    action: TAction,
    resource: Resource<TResource>,
    environment?: AccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<Decision> {
    const subject = await this.resolveSubject(subjectId)
    return this.authorize({ subject, action, resource, environment, scope })
  }

  /**
   * Debug tool: returns a full evaluation trace showing exactly why
   * a permission was granted or denied. Shows which policies matched,
   * which rules fired, which conditions passed/failed with actual vs
   * expected values, and a human-readable summary.
   *
   * Does NOT trigger afterEvaluate/onDeny/onError hooks (read-only).
   * Does apply beforeEvaluate hook since it affects the evaluation.
   */
  async explain(
    subjectId: string,
    action: TAction,
    resource: Resource<TResource>,
    environment?: AccessRequest<TAction, TResource, TScope>['environment'],
    scope?: TScope,
  ): Promise<ExplainResult> {
    const subject = await this.resolveSubject(subjectId)
    const originalRoles = [...subject.roles] as string[]

    let enrichedSubject = subject
    if (scope && subject.scopedRoles?.length) {
      enrichedSubject = this.enrichSubjectWithScopedRoles(subject, scope)
    }

    const scopedRolesApplied = (enrichedSubject.roles as string[]).filter((r) => !originalRoles.includes(r))

    let req: AccessRequest<TAction, TResource, TScope> = {
      subject: enrichedSubject,
      action,
      resource,
      environment,
      scope,
    }

    // Apply beforeEvaluate hook (it may modify the request)
    if (this.hooks.beforeEvaluate) {
      req = await this.hooks.beforeEvaluate(req)
    }

    const allPolicies = await this.loadAllPolicies()

    return explainEvaluation(allPolicies, req as AccessRequest, this.defaultEffect, {
      subjectId,
      originalRoles,
      scopedRolesApplied,
    })
  }

  /**
   * Batch check: evaluate many permissions at once for a single subject.
   * Returns a PermissionMap keyed by "action:resource" or "scope:action:resource".
   * Loads DB data once, evaluates many.
   * Each check goes through scoped role enrichment and hooks, consistent with authorize().
   */
  async permissions(
    subjectId: string,
    checks: readonly PermissionCheck<TAction, TResource, TScope>[],
    environment?: AccessRequest<TAction, TResource, TScope>['environment'],
  ): Promise<PermissionMap<TAction, TResource, TScope>> {
    const [subject, allPolicies] = await Promise.all([this.resolveSubject(subjectId), this.loadAllPolicies()])

    const map = {} as Record<string, boolean>

    for (const c of checks) {
      const key = buildPermissionKey(c.action, c.resource, c.resourceId, c.scope)

      try {
        let req: AccessRequest<TAction, TResource, TScope> = {
          subject,
          action: c.action,
          resource: { type: c.resource, id: c.resourceId, attributes: {} },
          environment,
          scope: c.scope,
        }

        // Enrich with scoped roles matching this check's scope
        if (req.scope && req.subject.scopedRoles?.length) {
          req = { ...req, subject: this.enrichSubjectWithScopedRoles(req.subject, req.scope) }
        }

        if (this.hooks.beforeEvaluate) {
          req = await this.hooks.beforeEvaluate(req)
        }

        const decision = evaluate(allPolicies, req as AccessRequest, this.defaultEffect)

        if (this.hooks.afterEvaluate) {
          await this.hooks.afterEvaluate(req, decision)
        }
        if (!decision.allowed && this.hooks.onDeny) {
          await this.hooks.onDeny(req, decision)
        }

        map[key] = decision.allowed
      } catch (error) {
        if (this.hooks.onError) {
          await this.hooks.onError(error as Error, {
            subject,
            action: c.action,
            resource: { type: c.resource, id: c.resourceId, attributes: {} },
            environment,
            scope: c.scope,
          })
        }
        map[key] = false
      }
    }

    return map as PermissionMap<TAction, TResource, TScope>
  }

  // -----------------------------------------------
  // Admin operations
  // -----------------------------------------------

  private _admin?: EngineAdmin<TAction, TResource, TRole, TScope>

  get admin(): EngineAdmin<TAction, TResource, TRole, TScope> {
    if (this._admin) return this._admin

    const adapter = this.adapter
    const engine = this

    this._admin = {
      async listPolicies() {
        return adapter.listPolicies()
      },
      async getPolicy(id: string) {
        return adapter.getPolicy(id)
      },
      async savePolicy(policy: Policy<TAction, TResource, TRole>) {
        await adapter.savePolicy(policy)
        engine.invalidatePolicies()
      },
      async deletePolicy(id: string) {
        await adapter.deletePolicy(id)
        engine.invalidatePolicies()
      },
      async listRoles() {
        return adapter.listRoles()
      },
      async getRole(id: string) {
        return adapter.getRole(id)
      },
      async saveRole(role: Role<TAction, TResource, TRole, TScope>) {
        await adapter.saveRole(role)
        engine.invalidateRoles()
      },
      async deleteRole(id: string) {
        await adapter.deleteRole(id)
        engine.invalidateRoles()
      },
      async assignRole(subjectId: string, roleId: TRole, scope?: TScope) {
        await adapter.assignRole(subjectId, roleId, scope)
        engine.invalidateSubject(subjectId)
      },
      async revokeRole(subjectId: string, roleId: TRole, scope?: TScope) {
        await adapter.revokeRole(subjectId, roleId, scope)
        engine.invalidateSubject(subjectId)
      },
      async setAttributes(subjectId: string, attrs: Attributes) {
        await adapter.setSubjectAttributes(subjectId, attrs)
        engine.invalidateSubject(subjectId)
      },
      async getAttributes(subjectId: string) {
        return adapter.getSubjectAttributes(subjectId)
      },
    }
    return this._admin
  }

  /** Clear all caches */
  invalidate(): void {
    this.policyCache.clear()
    this.roleCache.clear()
    this.rbacPolicyCache.clear()
    this.subjectCache.clear()
  }

  /** Clear only a specific subject's cached data */
  invalidateSubject(subjectId: string): void {
    this.subjectCache.delete(subjectId)
  }

  /** Clear cached policies (after policy CRUD) */
  invalidatePolicies(): void {
    this.policyCache.clear()
  }

  /** Clear cached roles, RBAC policy, and all subjects (subjects cache resolved roles) */
  invalidateRoles(): void {
    this.roleCache.clear()
    this.rbacPolicyCache.clear()
    this.subjectCache.clear()
  }
}
