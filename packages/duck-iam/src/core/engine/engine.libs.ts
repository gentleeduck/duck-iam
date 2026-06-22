import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../types'
import type { IamValidate } from '../validate/validate.types'
import type { IamEngineTypes } from './engine.types'

/**
 * Lazy validator binding. The `../validate` module is ~12 KB gzipped; users who
 * never call `engine.admin.savePolicy/saveRole/import` shouldn't pay for it at
 * import time. Loaded on first admin write and memoised.
 */
let _validateBindings: {
  validatePolicy: typeof import('../validate').validatePolicy
  validateRole: typeof import('../validate').validateRole
} | null = null
async function _getValidate() {
  if (!_validateBindings) {
    const v = await import('../validate')
    _validateBindings = { validatePolicy: v.validatePolicy, validateRole: v.validateRole }
  }
  return _validateBindings
}

/**
 * Single-flight helper for single-slot in-flight promises.
 *
 * Encapsulates the sentinel-compare pattern used by `_loadPolicies`,
 * `_loadRoles`, `_loadRbacPolicy`, `_loadAllPolicies`. A concurrent caller
 * sees the same `pending` promise; an `invalidate*()` mid-await nulls the
 * slot, and the sentinel check prevents the late resolver from writing
 * stale data into the now-cleared cache.
 *
 * @template T - Resolved value type.
 * @param getSlot - Reads the current in-flight slot (returns `null` if empty).
 * @param setSlot - Writes the in-flight slot (`null` clears it).
 * @param produce - Async producer for the value.
 * @param onResolve - Called only when the slot still holds the original
 *   pending promise. Use this to populate the cache.
 * @returns The pending promise (also stored in the slot until resolved).
 */
export function runSingleFlight<T>(
  getSlot: () => Promise<T> | null,
  setSlot: (p: Promise<T> | null) => void,
  produce: () => Promise<T>,
  onResolve: (value: T) => void,
): Promise<T> {
  let pending!: Promise<T>
  pending = (async () => {
    try {
      const value = await produce()
      if (getSlot() === pending) onResolve(value)
      return value
    } finally {
      if (getSlot() === pending) setSlot(null)
    }
  })()
  setSlot(pending)
  return pending
}

/**
 * Keyed single-flight for per-key in-flight maps (subjects).
 *
 * Same shape as {@link runSingleFlight} but keyed on a Map entry. Identity
 * equality on the Promise reference disambiguates concurrent callers.
 */
export function runSingleFlightKeyed<K, T>(
  map: Map<K, Promise<T>>,
  key: K,
  produce: () => Promise<T>,
  onResolve: (value: T) => void,
): Promise<T> {
  let pending!: Promise<T>
  pending = (async () => {
    try {
      const value = await produce()
      if (map.get(key) === pending) onResolve(value)
      return value
    } finally {
      if (map.get(key) === pending) map.delete(key)
    }
  })()
  map.set(key, pending)
  return pending
}

/** Throw if the validate result has any `error`-type issue. */
function assertValidOrThrow(kind: 'policy' | 'role', result: IamValidate.IResult): void {
  if (result.valid) return
  const errs = result.issues
    .filter((i) => i.type === 'error')
    .map((i) => (i.path ? `${i.code} at "${i.path}"` : i.code))
  throw new Error(`[@gentleduck/iam:engine] ${kind} rejected by validator - ${errs.join('; ')}`)
}

function assertNonEmptyStringParam(name: string, value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    const got = value === null ? 'null' : typeof value
    throw new Error(`[@gentleduck/iam:engine] ${name} must be a non-empty string (got ${got})`)
  }
  // 1024-char cap so a hostile caller cannot bloat the adapter call (URL
  // length on HTTP adapter, key length on Redis, JSON column size on SQL).
  if (value.length > 1024) {
    throw new Error(`[@gentleduck/iam:engine] ${name} exceeds 1024-char cap (got length ${value.length})`)
  }
}

function assertOptionalNonEmptyStringParam(name: string, value: unknown): asserts value is string | undefined {
  if (value === undefined) return
  assertNonEmptyStringParam(name, value)
}

function assertAttributesParam(value: unknown): asserts value is IamPrimitives.Attributes {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value
    throw new Error(`[@gentleduck/iam:engine] attributes must be a plain object (got ${got})`)
  }
  // 256 own-key cap so a hostile caller cannot push an unbounded attributes
  // bag through setSubjectAttributes (would bloat the JSON column / Redis
  // string + every downstream resolve()).
  const keyCount = Object.keys(value).length
  if (keyCount > 256) {
    throw new Error(`[@gentleduck/iam:engine] attributes must have <=256 keys (got ${keyCount})`)
  }
  // Reject deep nesting: resolve() walks dot-paths to depth ~8 in practice.
  // 16 is a safe ceiling that defends against stack-overflow when the
  // walker recurses (and rejects pathological `{a:{a:{...}}}` shapes).
  const depth = _measureDepth(value)
  if (depth > 16) {
    throw new Error(`[@gentleduck/iam:engine] attributes nesting depth ${depth} exceeds cap (16)`)
  }
}

function _measureDepth(node: unknown, current = 0): number {
  if (current > 32) return current
  if (typeof node !== 'object' || node === null) return current
  let max = current
  if (Array.isArray(node)) {
    for (const v of node) {
      const d = _measureDepth(v, current + 1)
      if (d > max) max = d
      if (max > 32) return max
    }
  } else {
    for (const v of Object.values(node)) {
      const d = _measureDepth(v, current + 1)
      if (d > max) max = d
      if (max > 32) return max
    }
  }
  return max
}

function formatErrInterp(value: unknown, maxLen = 64): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  const t = typeof value
  if (t === 'string') {
    const s = value as string
    if (s.length <= maxLen) return `string '${s}'`
    return `string '${s.slice(0, maxLen)}...' (length ${s.length})`
  }
  if (t === 'number' || t === 'boolean' || t === 'bigint') return `${t} ${String(value)}`
  if (Array.isArray(value)) return `array (length ${value.length})`
  return t
}

/** Recursively freeze a policy's rules, condition groups, and condition leaves. */
export function deepFreezePolicy<TPolicy extends AccessControl.IPolicy>(policy: TPolicy): TPolicy {
  for (const rule of policy.rules) {
    if (Array.isArray(rule.actions)) Object.freeze(rule.actions)
    if (Array.isArray(rule.resources)) Object.freeze(rule.resources)
    if (rule.conditions) freezeConditionGroup(rule.conditions)
    Object.freeze(rule)
  }
  Object.freeze(policy.rules)
  return Object.freeze(policy)
}

function freezeConditionGroup(group: AccessControl.IConditionGroup): void {
  if ('all' in group) freezeConditionArray(group.all)
  if ('any' in group) freezeConditionArray(group.any)
  if ('none' in group) freezeConditionArray(group.none)
  Object.freeze(group)
}

function freezeConditionArray(arr: ReadonlyArray<AccessControl.ICondition | AccessControl.IConditionGroup>): void {
  for (const item of arr) {
    if ('field' in item) Object.freeze(item)
    else freezeConditionGroup(item)
  }
  Object.freeze(arr)
}
/**
 * Enrich a subject's roles with scoped role assignments matching the request scope.
 *
 * If a user has role `'editor'` scoped to `'org-1'` and the request scope is `'org-1'`,
 * `'editor'` is added to `subject.roles` for this evaluation. Returns the original
 * subject unchanged when no scoped roles match.
 *
 * @template TScope - Union of valid scope strings.
 *
 * @param subject - The resolved subject with potential scoped role assignments
 * @param scope   - The scope to match against scoped role assignments
 * @returns A new subject with merged roles, or the original subject if no matches
 */
export function enrichSubjectWithScopedRoles<TScope extends string = string>(
  subject: IamRequest.ISubject,
  scope: TScope | undefined,
): IamRequest.ISubject {
  if (scope == null || !subject.scopedRoles?.length) return subject

  const extraRoles = subject.scopedRoles.filter((sr) => sr.scope === scope).map((sr) => sr.role)

  if (extraRoles.length === 0) return subject

  const mergedRoles = [...new Set([...subject.roles, ...extraRoles])]
  return { ...subject, roles: mergedRoles }
}

/**
 * Create an {@link IamEngineTypes.IAdmin} instance that delegates storage operations to the
 * given adapter and invalidates the engine's caches after mutations.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
 *
 * @param adapter - The storage adapter for policies, roles, and subject data
 * @param engine  - The engine instance whose caches should be invalidated on writes
 * @returns An {@link IamEngineTypes.IAdmin} object wired to the adapter and engine
 */
export function createAdmin<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
>(
  adapter: IamAdapter.IAdapter<TAction, TResource, TRole, TScope>,
  engine: {
    cache: {
      invalidatePolicies(): void
      invalidateRoles(roleId?: TRole): void
      invalidateSubject(subjectId: string): void
    }
  },
): IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
  return {
    async listPolicies() {
      return adapter.listPolicies()
    },
    async getPolicy(id: string) {
      assertNonEmptyStringParam('id', id)
      return adapter.getPolicy(id)
    },
    async savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>) {
      const { validatePolicy } = await _getValidate()
      assertValidOrThrow('policy', validatePolicy(policy))
      await adapter.savePolicy(policy)
      engine.cache.invalidatePolicies()
    },
    async deletePolicy(id: string) {
      assertNonEmptyStringParam('id', id)
      await adapter.deletePolicy(id)
      engine.cache.invalidatePolicies()
    },
    async listRoles() {
      return adapter.listRoles()
    },
    async getRole(id: string) {
      assertNonEmptyStringParam('id', id)
      return adapter.getRole(id)
    },
    async saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>) {
      const { validateRole } = await _getValidate()
      assertValidOrThrow('role', validateRole(role))
      await adapter.saveRole(role)
      engine.cache.invalidateRoles(role.id)
    },
    async deleteRole(id: string) {
      assertNonEmptyStringParam('id', id)
      await adapter.deleteRole(id)
      engine.cache.invalidateRoles(id as TRole)
    },
    async assignRole(subjectId: string, roleId: TRole, scope?: TScope) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertNonEmptyStringParam('roleId', roleId)
      assertOptionalNonEmptyStringParam('scope', scope)
      await adapter.assignRole(subjectId, roleId, scope)
      engine.cache.invalidateSubject(subjectId)
    },
    async revokeRole(subjectId: string, roleId: TRole, scope?: TScope) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertNonEmptyStringParam('roleId', roleId)
      assertOptionalNonEmptyStringParam('scope', scope)
      await adapter.revokeRole(subjectId, roleId, scope)
      engine.cache.invalidateSubject(subjectId)
    },
    async setAttributes(subjectId: string, attrs: IamPrimitives.Attributes) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertAttributesParam(attrs)
      await adapter.setSubjectAttributes(subjectId, attrs)
      engine.cache.invalidateSubject(subjectId)
    },
    async getAttributes(subjectId: string) {
      assertNonEmptyStringParam('subjectId', subjectId)
      return adapter.getSubjectAttributes(subjectId)
    },
    async export(): Promise<IamEngineTypes.ISnapshot<TAction, TResource, TRole, TScope>> {
      const [policies, roles] = await Promise.all([adapter.listPolicies(), adapter.listRoles()])
      return {
        schemaVersion: 1 as const,
        exportedAt: new Date().toISOString(),
        policies,
        roles,
      }
    },
    async import(
      snapshot: IamEngineTypes.ISnapshot<TAction, TResource, TRole, TScope>,
      options: IamEngineTypes.IImportOptions = {},
    ): Promise<IamEngineTypes.IImportResult> {
      if (snapshot?.schemaVersion !== 1) {
        const incoming =
          snapshot !== null && typeof snapshot === 'object' ? Reflect.get(snapshot, 'schemaVersion') : snapshot
        throw new Error(
          `[@gentleduck/iam:engine] unsupported snapshot schemaVersion ${formatErrInterp(incoming)}; expected 1`,
        )
      }
      const mode = options.mode ?? 'merge'
      let policiesDeleted = 0
      let rolesDeleted = 0
      if (mode === 'replace') {
        const [existingPolicies, existingRoles] = await Promise.all([adapter.listPolicies(), adapter.listRoles()])
        const incomingPolicyIds = new Set(snapshot.policies.map((p) => p.id))
        const incomingRoleIds = new Set(snapshot.roles.map((r) => r.id))
        for (const p of existingPolicies) {
          if (!incomingPolicyIds.has(p.id)) {
            await adapter.deletePolicy(p.id)
            policiesDeleted++
          }
        }
        for (const r of existingRoles) {
          if (!incomingRoleIds.has(r.id)) {
            await adapter.deleteRole(r.id)
            rolesDeleted++
          }
        }
      }
      const { validatePolicy, validateRole } = await _getValidate()
      for (const p of snapshot.policies) {
        assertValidOrThrow('policy', validatePolicy(p))
        await adapter.savePolicy(p)
      }
      for (const r of snapshot.roles) {
        assertValidOrThrow('role', validateRole(r))
        await adapter.saveRole(r)
      }
      // Bulk write touched every cache; invalidate once instead of per-row.
      engine.cache.invalidatePolicies()
      engine.cache.invalidateRoles()
      return {
        policiesAdded: snapshot.policies.length,
        policiesDeleted,
        rolesAdded: snapshot.roles.length,
        rolesDeleted,
      }
    },
  }
}
