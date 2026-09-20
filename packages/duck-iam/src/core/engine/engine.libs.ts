import { IamValidationError } from '../../shared/errors'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral } from '../../shared/tenant-literals'
import type { Batch } from '../batch'
import { appliedRows, batchResult, loopFallback } from '../batch'
import { MAX_CONDITION_DEPTH } from '../conditions/conditions.libs'
import { matchesScope } from '../resolve/resolve'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../types'
import { isResolvablePath } from '../validate/validate.libs'
import type { IamValidate } from '../validate/validate.types'
import type { IamEngineTypes } from './engine.types'

/**
 * Role cap for the compiled table: a role's bit is `1 << index`, so a 33rd role would alias an earlier one.
 * NOTE: lives here so the engine can check it without statically importing the compiled chunk.
 */
export const IAM_MAX_COMPILED_ROLES = 32

/** Stands in for the engine's abort signal when an admin facade was built without a timeout. */
const NEVER_ABORTED: AbortSignal = new AbortController().signal

/**
 * Defaults `environment.now` to the current epoch ms so temporal operators and `$environment.now` see a real clock.
 * An explicit `now` is kept, so tests and `beforeEvaluate` can pin the clock.
 */
export function ensureEnvNow<TAction extends string, TResource extends string, TScope extends string>(
  req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
): IamRequest.IAccessRequest<TAction, TResource, TScope> {
  if (req.environment?.now !== undefined) return req
  return { ...req, environment: { ...req.environment, now: Date.now() } }
}

/**
 * The validators, loaded on the first admin write and memoized.
 * PERF: `../validate` is about 12 KB gzipped, which read-only installs never need.
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
 * Runs `produce` once for a single in-flight slot and stores the pending promise there until it settles.
 * NOTE: `onResolve` runs only if the slot still holds this promise, so a load an invalidation cleared caches nothing.
 *
 * @template T - Resolved value type.
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

/** {@link runSingleFlight} keyed on a map entry, compared by promise identity. */
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
  throw new IamValidationError(
    kind,
    errs,
    `[@gentleduck/iam:engine] ${kind} rejected by validator - ${errs.join('; ')}`,
  )
}

function assertNonEmptyStringParam(name: string, value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    const got = value === null ? 'null' : typeof value
    throw new Error(`[@gentleduck/iam:engine] ${name} must be a non-empty string (got ${got})`)
  }
  // SECURITY: capped so a hostile caller cannot bloat a URL, Redis key or SQL column.
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
  // SECURITY: capped so a hostile caller cannot store an unbounded bag that every resolve() then walks.
  const keyCount = Object.keys(value).length
  if (keyCount > 256) {
    throw new Error(`[@gentleduck/iam:engine] attributes must have <=256 keys (got ${keyCount})`)
  }
  // SECURITY: depth capped so a recursive walker cannot overflow the stack.
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
  // Narrow on the inline `typeof`: TypeScript does not narrow through the `t` alias below.
  if (typeof value === 'string') {
    if (value.length <= maxLen) return `string '${value}'`
    return `string '${value.slice(0, maxLen)}...' (length ${value.length})`
  }
  const t = typeof value
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

/** Accepted `IConfig.mode` values; the constructor refuses anything else, as it does for `policyCombine`. */
export const VALID_MODES = ['development', 'production'] as const

/** Accepted `IConfig.scopeMode` values; the constructor refuses anything else, as it does for `policyCombine`. */
export const VALID_SCOPE_MODES = ['flat', 'hierarchical'] as const

/** Accepted `IConfig.scopeCombine` values. */
export const VALID_SCOPE_COMBINES = ['union', 'override'] as const

/**
 * Visits every `field` in a condition tree, bounded as `evalConditionGroup` is. A `$`-prefixed *value* operand is
 * a path too, but `evalCondition` already reports that one and answers Indeterminate rather than false.
 */
function eachConditionPath(node: unknown, depth: number, visit: (path: string) => void): void {
  if (depth >= MAX_CONDITION_DEPTH || typeof node !== 'object' || node === null) return
  for (const key of ['all', 'any', 'none'] as const) {
    const branch = Reflect.get(node, key)
    if (!Array.isArray(branch)) continue
    for (const item of branch) eachConditionPath(item, depth + 1, visit)
  }
  const field = Reflect.get(node, 'field')
  if (typeof field === 'string') visit(field)
}

/**
 * Reports a condition naming a dot-path that can never resolve - a root outside `subject` / `resource` /
 * `environment`, or a segment the resolver refuses. `resolve` answers `null` for those on every request, so the
 * rule never matches for any input. Unlike an absent attribute, this is decidable without seeing a request.
 */
export function reportDeadConditionPaths(
  policies: readonly AccessControl.IPolicy[],
  seen: Set<string>,
  report: (err: Error, policyId: string) => void,
): void {
  for (const policy of policies) {
    if (!Array.isArray(policy.rules)) continue
    for (const rule of policy.rules) {
      if (typeof rule !== 'object' || rule === null) continue
      eachConditionPath(rule.conditions, 0, (path) => {
        if (isResolvablePath(path)) return
        const key = `${policy.id}\u0000${rule.id}\u0000${path}`
        if (seen.has(key)) return
        seen.add(key)
        report(
          new Error(
            `[@gentleduck/iam:engine] policy ${JSON.stringify(policy.id)} rule ${JSON.stringify(rule.id)} reads ` +
              `${JSON.stringify(path)}, which resolves to null on every request - the root must be "subject", ` +
              '"resource" or "environment", and no segment may be a prototype key. The condition cannot be ' +
              `satisfied by any input, so ${rule.effect === 'deny' ? 'a deny' : 'an allow'} written this way never fires.`,
          ),
          policy.id,
        )
      })
    }
  }
}

/**
 * Whether any concrete action/resource string could match both patterns. Patterns are `*`, a literal, or a
 * `prefix:*` / `prefix.*` form, so two of them intersect unless their fixed parts diverge.
 */
function patternsCanIntersect(a: string, b: string): boolean {
  if (a === '*' || b === '*') return true
  const aPrefix = a.endsWith(':*') || a.endsWith('.*') ? a.slice(0, -1) : null
  const bPrefix = b.endsWith(':*') || b.endsWith('.*') ? b.slice(0, -1) : null
  if (aPrefix === null && bPrefix === null) return a === b
  if (aPrefix === null) return bPrefix !== null && a.startsWith(bPrefix)
  if (bPrefix === null) return b.startsWith(aPrefix)
  return aPrefix.startsWith(bPrefix) || bPrefix.startsWith(aPrefix)
}

/** True when some rule in `policy` names a pattern that could match a request the targets admit. */
function someRuleReachable(policy: AccessControl.IPolicy, dimension: 'actions' | 'resources'): boolean {
  const targeted = policy.targets?.[dimension]
  if (!Array.isArray(targeted) || targeted.length === 0) return true
  for (const rule of policy.rules) {
    const patterns = rule?.[dimension]
    if (!Array.isArray(patterns)) continue
    for (const pattern of patterns) {
      if (typeof pattern !== 'string') continue
      if (targeted.some((t) => typeof t === 'string' && patternsCanIntersect(t, pattern))) return true
    }
  }
  return false
}

/**
 * Reports a policy whose `targets.actions` or `targets.resources` admits no request any of its own rules could
 * match, once per policy and dimension. Like an unreachable role target it is a policy that never fires, but it
 * needs no catalogue to detect: the rules are the vocabulary.
 */
export function reportDeadPolicyTargets(
  policies: readonly AccessControl.IPolicy[],
  seen: Set<string>,
  report: (err: Error, policyId: string) => void,
): void {
  for (const policy of policies) {
    if (!Array.isArray(policy.rules) || policy.rules.length === 0) continue
    for (const dimension of ['actions', 'resources'] as const) {
      if (someRuleReachable(policy, dimension)) continue
      const key = `${policy.id}\u0000targets.${dimension}`
      if (seen.has(key)) continue
      seen.add(key)
      report(
        new Error(
          `[@gentleduck/iam:engine] policy ${JSON.stringify(policy.id)} has targets.${dimension} ` +
            `${JSON.stringify(policy.targets?.[dimension])}, which no rule in the policy can match. ` +
            'The policy is NotApplicable for every request - a deny written this way never fires. ' +
            `Check for a typo, or widen targets.${dimension}.`,
        ),
        policy.id,
      )
    }
  }
}

/**
 * Reports each `targets.roles` entry naming no stored role, once per pair. `policyApplies` matches that list by
 * equality, so the policy applies to nobody: a deny written that way never fires and nothing else reports it.
 */
export function reportUnreachableRoleTargets(
  policies: readonly AccessControl.IPolicy[],
  roles: readonly AccessControl.IRole[],
  seen: Set<string>,
  report: (err: Error, policyId: string) => void,
): void {
  const stored = new Set(roles.map((r) => r.id))
  for (const policy of policies) {
    const targeted = policy.targets?.roles
    if (!Array.isArray(targeted)) continue
    for (const roleId of targeted) {
      if (typeof roleId !== 'string' || stored.has(roleId)) continue
      const key = `${policy.id}\u0000${roleId}`
      if (seen.has(key)) continue
      seen.add(key)
      report(
        new Error(
          `[@gentleduck/iam:engine] policy ${JSON.stringify(policy.id)} targets role ${JSON.stringify(roleId)}, ` +
            'which no stored role defines. Targets are matched by equality, so the policy applies to no subject - ' +
            'a deny written this way never fires. Fix the id or drop the target.',
        ),
        policy.id,
      )
    }
  }
}

/**
 * Whether a scope a role or permission declares reaches a request at `requestScope`.
 * `'flat'` is exact match; `'hierarchical'` also covers descendants, as {@link scopeAncestors} does for assignments.
 */
export function scopeCovers(
  declared: string,
  requestScope: string | undefined,
  scopeMode: 'flat' | 'hierarchical',
): boolean {
  // WARN: the exact-match arm must stay `matchesScope`, which owns the scope contract (including `'*'` as global).
  if (matchesScope(declared, requestScope)) return true
  if (requestScope === undefined) return false
  return scopeMode === 'hierarchical' && requestScope.startsWith(`${declared}.`)
}

/**
 * The scope and each ancestor, most specific first.
 *
 * @example
 * scopeAncestors('org-1.team-2.repo-3') // ['org-1.team-2.repo-3', 'org-1.team-2', 'org-1']
 */
export function scopeAncestors(scope: string): string[] {
  const out: string[] = [scope]
  let path = scope
  let dot = path.lastIndexOf('.')
  while (dot !== -1) {
    path = path.slice(0, dot)
    out.push(path)
    dot = path.lastIndexOf('.')
  }
  return out
}

/**
 * Merges scoped assignments matching `scope` into `subject.roles`, returning the same subject when none match.
 * `'hierarchical'` also matches ancestor scopes, combined per `scopeCombine` (see `IConfig.scopeMode`).
 */
export function enrichSubjectWithScopedRoles<TScope extends string = string>(
  subject: IamRequest.ISubject,
  scope: TScope | undefined,
  scopeMode: 'flat' | 'hierarchical' = 'flat',
  scopeCombine: 'union' | 'override' = 'union',
): IamRequest.ISubject {
  if (scope == null || !subject.scopedRoles?.length) return subject

  let extraRoles: string[]
  if (scopeMode === 'hierarchical') {
    if (scopeCombine === 'override') {
      // Most specific matching level wins - stop at the first hit.
      let matched: IamRequest.IScopedRole[] | null = null
      for (const level of scopeAncestors(scope)) {
        const atLevel = subject.scopedRoles.filter((sr) => sr.scope === level)
        if (atLevel.length > 0) {
          matched = atLevel
          break
        }
      }
      extraRoles = matched?.map((sr) => sr.role) ?? []
    } else {
      const ancestors = new Set(scopeAncestors(scope))
      extraRoles = subject.scopedRoles.filter((sr) => sr.scope != null && ancestors.has(sr.scope)).map((sr) => sr.role)
    }
  } else {
    extraRoles = subject.scopedRoles.filter((sr) => sr.scope === scope).map((sr) => sr.role)
  }

  if (extraRoles.length === 0) return subject

  const mergedRoles = [...new Set([...subject.roles, ...extraRoles])]
  return { ...subject, roles: mergedRoles }
}

/** An actor as an event spread, so an unattributed event has no `actor` key rather than `undefined`. */
function actorOf(opts?: { readonly actor?: string }): { actor?: string } {
  return opts?.actor === undefined ? {} : { actor: opts.actor }
}

/** The shape both batch role writes share: a triple that may name its own actor. */
interface IActorRow<TRole extends string, TScope extends string> extends IamAdapter.ITripleRow<TRole, TScope> {
  readonly opts?: { readonly actor?: string }
}

/**
 * Emits one `role.assigned` or `role.revoked` per row, not de-duplicated.
 * `changed` comes from the outcomes, so each event agrees with the returned {@link Batch.Result}.
 */
async function emitRowEvents<TRole extends string, TScope extends string>(
  emit: ((event: IamEngineTypes.IMutationEvent<TRole, TScope>) => Promise<void>) | undefined,
  result: {
    readonly outcomes: readonly { readonly row: IActorRow<TRole, TScope>; readonly value: Batch.Change }[]
  },
  type: 'role.assigned' | 'role.revoked',
): Promise<void> {
  if (!emit) return
  const at = Date.now()
  for (const { row, value } of result.outcomes) {
    const common = {
      at,
      subjectId: row.subjectId,
      roleId: row.roleId,
      ...(row.scope !== undefined && { scope: row.scope }),
      ...(value.changed !== undefined && { changed: value.changed }),
      ...actorOf(row.opts),
    }
    await emit(type === 'role.assigned' ? { type: 'role.assigned', ...common } : { type: 'role.revoked', ...common })
  }
}

/**
 * Creates an {@link IamEngineTypes.IAdmin} that writes through `adapter`, then invalidates caches and emits events.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
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
    /**
     * Bounds each adapter call with `adapterTimeoutMs`, as the decision path is bounded.
     * Omitted by the transaction-bound admin: aborting a call mid-transaction leaves the transaction for the
     * caller to roll back, and the transaction's own lifetime already bounds it.
     */
    withTimeout?<T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string): Promise<T>
    /**
     * Where mutation events go; structural, so the bound admin can pass a buffering sink.
     * PERF: omitted unless `hooks.onMutation` is set, so an unobserved install allocates no events.
     */
    mutations?: { emit(event: IamEngineTypes.IMutationEvent<TRole, TScope>): void | Promise<void> }
  },
): IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
  /** Runs one adapter call under `adapterTimeoutMs`; unbounded when the caller wired no `withTimeout`. */
  const run = <T>(fn: (opts: { signal: AbortSignal }) => Promise<T>, label: string): Promise<T> =>
    engine.withTimeout ? engine.withTimeout(fn, label) : fn({ signal: NEVER_ABORTED })
  /**
   * The adapters' scope rule, checked before any write so one bad batch row fails the batch before anything lands.
   * The adapter's own guard stays as the backstop for direct callers.
   */
  const assertAssignableScope = (scope: unknown, intent: 'grant' | 'lookup'): void => {
    iamAssertAssignableScope('engine', scope, intent)
  }
  const assertTriple = (
    subjectId: string,
    roleId: TRole,
    scope?: TScope,
    intent: 'grant' | 'lookup' = 'grant',
  ): void => {
    assertNonEmptyStringParam('subjectId', subjectId)
    assertNonEmptyStringParam('roleId', roleId)
    assertOptionalNonEmptyStringParam('scope', scope)
    assertAssignableScope(scope, intent)
  }
  const sink = engine.mutations
  /**
   * Emits one mutation event, if anything listens.
   * NOTE: call only after the write and invalidation, so a failed write emits nothing and no listener reads stale.
   */
  const emit =
    sink === undefined
      ? undefined
      : async (event: IamEngineTypes.IMutationEvent<TRole, TScope>): Promise<void> => {
          // Awaited (up to `hookTimeoutMs`) so a history write lands before the mutation resolves.
          // The sink swallows throws, so a hook bug cannot fail the write.
          await sink.emit(event)
        }
  /** One invalidation per subject, however many rows of the batch named it. */
  const invalidateEach = (rows: readonly IamEngineTypes.ITripleRow<TRole, TScope>[]): void => {
    for (const subjectId of new Set(rows.map((r) => r.subjectId))) engine.cache.invalidateSubject(subjectId)
  }
  /**
   * After a batch throws part-way, invalidates every requested row but emits only rows known to have landed.
   * SECURITY: earlier rows are already stored, so skipping this leaves a revoked grant cached until the TTL expires.
   */
  const settlePartialBatch = async (
    requested: readonly IamEngineTypes.ITripleRow<TRole, TScope>[],
    landed: readonly IActorRow<TRole, TScope>[],
    type: 'role.assigned' | 'role.revoked',
  ): Promise<void> => {
    invalidateEach(requested)
    await emitRowEvents(emit, appliedRows(landed, null), type)
  }
  /** Whether the subject actually holds this grant, so a move never invents one. */
  const holdsGrant = async (subjectId: string, roleId: TRole, fromScope?: TScope): Promise<boolean> => {
    if (fromScope === undefined) {
      return (await run((o) => adapter.getSubjectRoles(subjectId, o), 'admin.getSubjectRoles')).includes(roleId)
    }
    const scoped = adapter.getSubjectScopedRoles
    // Unknowable without it; guess "not held", since "held" would write a grant.
    if (!scoped) return false
    const rows = await run((o) => scoped.call(adapter, subjectId, o), 'admin.getSubjectScopedRoles')
    return rows.some((r) => r.role === roleId && r.scope === fromScope)
  }
  /** The single-row scope move, hoisted so `moveRoleScopes` reuses it without `this`. */
  const moveOne = async (
    subjectId: string,
    roleId: TRole,
    fromScope?: TScope,
    toScope?: TScope,
    actor?: string,
  ): Promise<void> => {
    const update = adapter.updateAssignmentScope
    if (update) {
      // SECURITY: `false` means "no such grant"; falling through to revoke + assign would create one.
      const moved = await run(
        () => update.call(adapter, subjectId, roleId, fromScope, toScope, actor),
        'admin.updateAssignmentScope',
      )
      if (!moved) return
    } else {
      // Emulate the update for a grant that exists, with the actor on both halves.
      if (!(await holdsGrant(subjectId, roleId, fromScope))) return
      await run(() => adapter.revokeRole(subjectId, roleId, fromScope, { actor }), 'admin.revokeRole')
      try {
        await run(() => adapter.assignRole(subjectId, roleId, toScope, { actor }), 'admin.assignRole')
      } catch (err) {
        // SECURITY: the revoke landed, so drop the cached grant at `fromScope` before rethrowing.
        engine.cache.invalidateSubject(subjectId)
        throw err
      }
    }
    engine.cache.invalidateSubject(subjectId)
    // One `role.scope-changed` on either path, reached only when a row moved.
    await emit?.({
      type: 'role.scope-changed',
      at: Date.now(),
      subjectId,
      roleId,
      ...(fromScope !== undefined && { fromScope }),
      ...(toScope !== undefined && { toScope }),
      ...(actor !== undefined && { actor }),
    })
  }

  return {
    async listPolicies() {
      return run((o) => adapter.listPolicies(o), 'admin.listPolicies')
    },
    async getPolicy(id: string) {
      assertNonEmptyStringParam('id', id)
      return run((o) => adapter.getPolicy(id, o), 'admin.getPolicy')
    },
    async savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>, opts?: IamEngineTypes.IActorOptions) {
      const { validatePolicy } = await _getValidate()
      assertValidOrThrow('policy', validatePolicy(policy))
      await run(() => adapter.savePolicy(policy, opts), 'admin.savePolicy')
      engine.cache.invalidatePolicies()
      await emit?.({ type: 'policy.saved', at: Date.now(), policyId: policy.id, ...actorOf(opts) })
    },
    async deletePolicy(id: string, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('id', id)
      await run(() => adapter.deletePolicy(id), 'admin.deletePolicy')
      engine.cache.invalidatePolicies()
      await emit?.({ type: 'policy.deleted', at: Date.now(), policyId: id, ...actorOf(opts) })
    },
    async listRoles() {
      return run((o) => adapter.listRoles(o), 'admin.listRoles')
    },
    async getRole(id: string) {
      assertNonEmptyStringParam('id', id)
      return run((o) => adapter.getRole(id, o), 'admin.getRole')
    },
    async saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>, opts?: IamEngineTypes.IActorOptions) {
      const { validateRole } = await _getValidate()
      assertValidOrThrow('role', validateRole(role))
      await run(() => adapter.saveRole(role, opts), 'admin.saveRole')
      engine.cache.invalidateRoles(role.id)
      await emit?.({ type: 'role.saved', at: Date.now(), roleId: role.id, ...actorOf(opts) })
    },
    async deleteRole(id: string, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('id', id)
      await run(() => adapter.deleteRole(id), 'admin.deleteRole')
      // `TRole` is erased at runtime, so there is nothing to narrow; `iamAsRoleLiteral` keeps it greppable.
      const roleId = iamAsRoleLiteral<TRole>(id)
      engine.cache.invalidateRoles(roleId)
      await emit?.({ type: 'role.deleted', at: Date.now(), roleId, ...actorOf(opts) })
    },
    async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions) {
      assertTriple(subjectId, roleId, scope)
      await run(() => adapter.assignRole(subjectId, roleId, scope, opts), 'admin.assignRole')
      engine.cache.invalidateSubject(subjectId)
      await emit?.({
        type: 'role.assigned',
        at: Date.now(),
        subjectId,
        roleId,
        ...(scope !== undefined && { scope }),
        ...actorOf(opts),
      })
    },
    async revokeRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IRevokeOptions) {
      // `'lookup'`: a revoke addresses an existing row, so legacy `'*'` rows stay deletable.
      assertTriple(subjectId, roleId, scope, 'lookup')
      await run(() => adapter.revokeRole(subjectId, roleId, scope, opts), 'admin.revokeRole')
      engine.cache.invalidateSubject(subjectId)
      await emit?.({
        type: 'role.revoked',
        at: Date.now(),
        subjectId,
        roleId,
        ...(scope !== undefined && { scope }),
        ...actorOf(opts),
      })
    },
    async updateAssignmentScope(
      subjectId: string,
      roleId: TRole,
      fromScope?: TScope,
      toScope?: TScope,
      actor?: string,
    ) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertNonEmptyStringParam('roleId', roleId)
      assertOptionalNonEmptyStringParam('fromScope', fromScope)
      assertOptionalNonEmptyStringParam('toScope', toScope)
      // `'*'` may be moved off, never to.
      assertAssignableScope(fromScope, 'lookup')
      assertAssignableScope(toScope, 'grant')
      await moveOne(subjectId, roleId, fromScope, toScope, actor)
    },
    async assignRoles(rows: readonly IamEngineTypes.IAssignRow<TRole, TScope>[]) {
      if (rows.length === 0) return batchResult([])
      // Validate every row first, so fixing a bad row and retrying cannot double-apply the rows that landed.
      for (const r of rows) assertTriple(r.subjectId, r.roleId, r.scope)
      // Bound: a class-instance adapter needs its `this`.
      const assignRoleMany = adapter.assignRoleMany?.bind(adapter)
      // `null` means written, but which rows changed is unknown, as on the loop path (`assignRole` returns void).
      let changed: readonly number[] | null = null
      const landed: IamEngineTypes.IAssignRow<TRole, TScope>[] = []
      try {
        if (assignRoleMany) changed = await run(() => assignRoleMany(rows), 'admin.assignRoleMany')
        else
          for (const r of rows) {
            await run(() => adapter.assignRole(r.subjectId, r.roleId, r.scope, r.opts), 'admin.assignRole')
            landed.push(r)
          }
      } catch (err) {
        await settlePartialBatch(rows, landed, 'role.assigned')
        throw err
      }
      invalidateEach(rows)
      const result = appliedRows(rows, changed)
      await emitRowEvents(emit, result, 'role.assigned')
      return result
    },
    async revokeRoles(rows: readonly IamEngineTypes.IRevokeRow<TRole, TScope>[]) {
      if (rows.length === 0) return batchResult([])
      for (const r of rows) assertTriple(r.subjectId, r.roleId, r.scope, 'lookup')
      const revokeRoleMany = adapter.revokeRoleMany?.bind(adapter)
      let changed: readonly number[] | null = null
      const landed: IamEngineTypes.IRevokeRow<TRole, TScope>[] = []
      try {
        if (revokeRoleMany) changed = await run(() => revokeRoleMany(rows), 'admin.revokeRoleMany')
        else
          for (const r of rows) {
            await run(() => adapter.revokeRole(r.subjectId, r.roleId, r.scope, r.opts), 'admin.revokeRole')
            landed.push(r)
          }
      } catch (err) {
        await settlePartialBatch(rows, landed, 'role.revoked')
        throw err
      }
      invalidateEach(rows)
      const result = appliedRows(rows, changed)
      await emitRowEvents(emit, result, 'role.revoked')
      return result
    },
    async moveRoleScopes(rows: readonly IamEngineTypes.IMoveRow<TRole, TScope>[]) {
      if (rows.length === 0) return batchResult([])
      for (const r of rows) {
        assertNonEmptyStringParam('subjectId', r.subjectId)
        assertNonEmptyStringParam('roleId', r.roleId)
        assertOptionalNonEmptyStringParam('fromScope', r.fromScope)
        assertOptionalNonEmptyStringParam('toScope', r.toScope)
        assertAssignableScope(r.fromScope, 'lookup')
        assertAssignableScope(r.toScope, 'grant')
      }
      // No set-based move exists, so this per-row loop is the only path, not a fallback.
      return loopFallback(rows, (r) => moveOne(r.subjectId, r.roleId, r.fromScope, r.toScope, r.actor))
    },
    invalidateSubjects(subjectIds: readonly string[]) {
      for (const id of new Set(subjectIds)) engine.cache.invalidateSubject(id)
    },
    async setAttributes(subjectId: string, attrs: IamPrimitives.Attributes, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertAttributesParam(attrs)
      await run(() => adapter.setSubjectAttributes(subjectId, attrs, opts), 'admin.setSubjectAttributes')
      engine.cache.invalidateSubject(subjectId)
      // SECURITY: key names only, so the event cannot carry personal data into a durable log.
      await emit?.({ type: 'attributes.set', at: Date.now(), subjectId, keys: Object.keys(attrs), ...actorOf(opts) })
    },
    async getAttributes(subjectId: string) {
      assertNonEmptyStringParam('subjectId', subjectId)
      return run((o) => adapter.getSubjectAttributes(subjectId, o), 'admin.getSubjectAttributes')
    },
    async export(): Promise<IamEngineTypes.ISnapshot<TAction, TResource, TRole, TScope>> {
      const [policies, roles] = await Promise.all([
        run((o) => adapter.listPolicies(o), 'admin.listPolicies'),
        run((o) => adapter.listRoles(o), 'admin.listRoles'),
      ])
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
      opts?: IamEngineTypes.IActorOptions,
    ): Promise<IamEngineTypes.IImportResult> {
      if (snapshot?.schemaVersion !== 1) {
        const incoming =
          snapshot !== null && typeof snapshot === 'object' ? Reflect.get(snapshot, 'schemaVersion') : snapshot
        throw new Error(
          `[@gentleduck/iam:engine] unsupported snapshot schemaVersion ${formatErrInterp(incoming)}; expected 1`,
        )
      }
      for (const field of ['policies', 'roles'] as const) {
        if (!Array.isArray(snapshot[field])) {
          throw new Error(`[@gentleduck/iam:engine] snapshot "${field}" must be an array`)
        }
      }
      // SECURITY: validate all before writing; in `replace` mode a late bad row would leave deny policies deleted.
      const { validatePolicy, validateRole } = await _getValidate()
      for (const p of snapshot.policies) assertValidOrThrow('policy', validatePolicy(p))
      for (const r of snapshot.roles) assertValidOrThrow('role', validateRole(r))

      const mode = options.mode ?? 'merge'
      let policiesDeleted = 0
      let rolesDeleted = 0
      // Emitted only after every write lands, so a failed import records no partial history.
      const imported: IamEngineTypes.IMutationEvent<TRole, TScope>[] = []
      const at = Date.now()
      if (mode === 'replace') {
        const [existingPolicies, existingRoles] = await Promise.all([
          run((o) => adapter.listPolicies(o), 'admin.listPolicies'),
          run((o) => adapter.listRoles(o), 'admin.listRoles'),
        ])
        const incomingPolicyIds = new Set(snapshot.policies.map((p) => p.id))
        const incomingRoleIds = new Set(snapshot.roles.map((r) => r.id))
        for (const p of existingPolicies) {
          if (!incomingPolicyIds.has(p.id)) {
            await run(() => adapter.deletePolicy(p.id), 'admin.deletePolicy')
            policiesDeleted++
            if (emit) imported.push({ type: 'policy.deleted', at, policyId: p.id, ...actorOf(opts) })
          }
        }
        for (const r of existingRoles) {
          if (!incomingRoleIds.has(r.id)) {
            await run(() => adapter.deleteRole(r.id), 'admin.deleteRole')
            rolesDeleted++
            if (emit) imported.push({ type: 'role.deleted', at, roleId: r.id, ...actorOf(opts) })
          }
        }
      }
      for (const p of snapshot.policies) {
        await run(() => adapter.savePolicy(p, opts), 'admin.savePolicy')
        if (emit) imported.push({ type: 'policy.saved', at, policyId: p.id, ...actorOf(opts) })
      }
      for (const r of snapshot.roles) {
        await run(() => adapter.saveRole(r, opts), 'admin.saveRole')
        if (emit) imported.push({ type: 'role.saved', at, roleId: r.id, ...actorOf(opts) })
      }
      // Bulk write touched every cache; invalidate once instead of per-row.
      engine.cache.invalidatePolicies()
      engine.cache.invalidateRoles()
      if (emit) for (const event of imported) await emit(event)
      return {
        policiesAdded: snapshot.policies.length,
        policiesDeleted,
        rolesAdded: snapshot.roles.length,
        rolesDeleted,
      }
    },
  }
}
