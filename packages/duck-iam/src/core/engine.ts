import { LRUCache } from '../shared/cache'
import { evaluate } from './evaluate'
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

export class Engine {
  private adapter: Adapter
  private defaultEffect: Effect
  private hooks: EngineHooks
  private policyCache: LRUCache<Policy[]>
  private roleCache: LRUCache<Role[]>
  private subjectCache: LRUCache<Subject>

  constructor(config: EngineConfig) {
    this.adapter = config.adapter
    this.defaultEffect = config.defaultEffect ?? 'deny'
    this.hooks = config.hooks ?? {}

    const ttl = (config.cacheTTL ?? 60) * 1000
    const maxSize = config.maxCacheSize ?? 1000

    this.policyCache = new LRUCache(1, ttl) // single entry
    this.roleCache = new LRUCache(1, ttl)
    this.subjectCache = new LRUCache(maxSize, ttl)
  }

  // ═══════════════════════════════════════════════
  // Data loading
  // ═══════════════════════════════════════════════

  private async loadPolicies(): Promise<Policy[]> {
    const cached = this.policyCache.get('all')
    if (cached) return cached
    const policies = await this.adapter.listPolicies()
    this.policyCache.set('all', policies)
    return policies
  }

  private async loadRoles(): Promise<Role[]> {
    const cached = this.roleCache.get('all')
    if (cached) return cached
    const roles = await this.adapter.listRoles()
    this.roleCache.set('all', roles)
    return roles
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

    const subject: Subject = { id: subjectId, roles, attributes }
    this.subjectCache.set(subjectId, subject)
    return subject
  }

  // ═══════════════════════════════════════════════
  // Core evaluation
  // ═══════════════════════════════════════════════

  /**
   * Full authorization check with a complete AccessRequest.
   */
  async authorize(request: AccessRequest): Promise<Decision> {
    let req = request

    try {
      if (this.hooks.beforeEvaluate) {
        req = await this.hooks.beforeEvaluate(req)
      }

      const [policies, roles] = await Promise.all([this.loadPolicies(), this.loadRoles()])

      const rbacPolicy = rolesToPolicy(roles)
      const allPolicies: Policy[] = [
        // RBAC policy combined with explicit ABAC policies
        {
          id: '__combined__',
          name: 'Combined',
          algorithm: 'deny-overrides',
          rules: [...rbacPolicy.rules, ...policies.flatMap((p) => p.rules)],
        },
      ]

      const decision = evaluate(allPolicies, req, this.defaultEffect)

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

  // ═══════════════════════════════════════════════
  // Convenience methods
  // ═══════════════════════════════════════════════

  /**
   * Simple boolean check: can this user do this action on this resource?
   */
  async can(
    subjectId: string,
    action: string,
    resource: Resource,
    environment?: AccessRequest['environment'],
  ): Promise<boolean> {
    const subject = await this.resolveSubject(subjectId)
    const decision = await this.authorize({ subject, action, resource, environment })
    return decision.allowed
  }

  /**
   * Same as `can` but returns the full Decision.
   */
  async check(
    subjectId: string,
    action: string,
    resource: Resource,
    environment?: AccessRequest['environment'],
  ): Promise<Decision> {
    const subject = await this.resolveSubject(subjectId)
    return this.authorize({ subject, action, resource, environment })
  }

  /**
   * Batch check: evaluate many permissions at once for a single subject.
   * Returns a PermissionMap keyed by "action:resource" or "action:resource:id".
   * Loads DB data once, evaluates many.
   */
  async permissions(
    subjectId: string,
    checks: PermissionCheck[],
    environment?: AccessRequest['environment'],
  ): Promise<PermissionMap> {
    const subject = await this.resolveSubject(subjectId)

    const [policies, roles] = await Promise.all([this.loadPolicies(), this.loadRoles()])

    const rbacPolicy = rolesToPolicy(roles)
    const allPolicies: Policy[] = [
      {
        id: '__combined__',
        name: 'Combined',
        algorithm: 'deny-overrides',
        rules: [...rbacPolicy.rules, ...policies.flatMap((p) => p.rules)],
      },
    ]

    const map: PermissionMap = {}

    for (const c of checks) {
      const key = c.resourceId ? `${c.action}:${c.resource}:${c.resourceId}` : `${c.action}:${c.resource}`

      const decision = evaluate(
        allPolicies,
        {
          subject,
          action: c.action,
          resource: { type: c.resource, id: c.resourceId, attributes: {} },
          environment,
        },
        this.defaultEffect,
      )

      map[key] = decision.allowed
    }

    return map
  }

  // ═══════════════════════════════════════════════
  // Admin operations
  // ═══════════════════════════════════════════════

  get admin() {
    const adapter = this.adapter
    const invalidate = () => this.invalidate()

    return {
      // Policy management
      async listPolicies() {
        return adapter.listPolicies()
      },
      async getPolicy(id: string) {
        return adapter.getPolicy(id)
      },
      async savePolicy(policy: Policy) {
        await adapter.savePolicy(policy)
        invalidate()
      },
      async deletePolicy(id: string) {
        await adapter.deletePolicy(id)
        invalidate()
      },

      // Role management
      async listRoles() {
        return adapter.listRoles()
      },
      async getRole(id: string) {
        return adapter.getRole(id)
      },
      async saveRole(role: Role) {
        await adapter.saveRole(role)
        invalidate()
      },
      async deleteRole(id: string) {
        await adapter.deleteRole(id)
        invalidate()
      },

      // Subject management
      async assignRole(subjectId: string, roleId: string, scope?: string) {
        await adapter.assignRole(subjectId, roleId, scope)
        invalidate()
      },
      async revokeRole(subjectId: string, roleId: string, scope?: string) {
        await adapter.revokeRole(subjectId, roleId, scope)
        invalidate()
      },
      async setAttributes(subjectId: string, attrs: Attributes) {
        await adapter.setSubjectAttributes(subjectId, attrs)
        invalidate()
      },
      async getAttributes(subjectId: string) {
        return adapter.getSubjectAttributes(subjectId)
      },
    }
  }

  /** Clear all caches */
  invalidate(): void {
    this.policyCache.clear()
    this.roleCache.clear()
    this.subjectCache.clear()
  }
}
