import { IamValidationError } from '../../shared/errors'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral } from '../../shared/tenant-literals'
import type { Batch } from '../batch'
import { appliedRows, batchResult, loopFallback } from '../batch'
import { matchesScope } from '../resolve/resolve'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../types'
import type { IamValidate } from '../validate/validate.types'
import type { IamEngineTypes } from './engine.types'

/**
 * A role's bit position in the compiled table's grant mask is `1 << index`, so
 * a 32-bit mask cannot address a 33rd role without aliasing an earlier one.
 * Lives here rather than in `compiled.compile.ts` so the engine can enforce it
 * at construction without statically importing the compiled chunk.
 */
export const IAM_MAX_COMPILED_ROLES = 32

/**
 * Default `environment.now` to the current epoch ms when the caller did not
 * supply one, so temporal operators (`before` / `after`) and `$environment.now`
 * references resolve to a real clock. Returns the request unchanged when `now`
 * is already set (tests / `beforeEvaluate` can pin a deterministic clock), so
 * an explicit `now` is never overwritten. Only allocates on the inject path.
 */
export function ensureEnvNow<TAction extends string, TResource extends string, TScope extends string>(
  req: IamRequest.IAccessRequest<TAction, TResource, TScope>,
): IamRequest.IAccessRequest<TAction, TResource, TScope> {
  if (req.environment?.now !== undefined) return req
  return { ...req, environment: { ...req.environment, now: Date.now() } }
}

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
  // Narrow on the inline `typeof`, not through the `t` alias - TS follows the
  // first and not the second, which is what forced the cast this replaces.
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

/**
 * Whether a grant declared at `declared` reaches a request made at
 * `requestScope`. Under `'flat'` that is exact equality; under
 * `'hierarchical'` a scope also covers everything beneath it, the same relation
 * {@link scopeAncestors} computes from the request's end for scoped
 * assignments. Used for the *other* kind of scope - the one a role or
 * permission declares - so one config flag means one thing.
 */
export function scopeCovers(
  declared: string,
  requestScope: string | undefined,
  scopeMode: 'flat' | 'hierarchical',
): boolean {
  // The exact-match arm is `matchesScope`'s, not a second copy of it. The scope
  // contract was documented in `resolve.ts` and enforced by three unrelated
  // expressions elsewhere, which is how the truth tables came to disagree;
  // this is the one imperative scope check in the engine, so it is the one
  // that routes through the module that owns the contract. `'*'` reaching here
  // is global, which `matchesScope` already says and the old `===` did not.
  if (matchesScope(declared, requestScope)) return true
  if (requestScope === undefined) return false
  return scopeMode === 'hierarchical' && requestScope.startsWith(`${declared}.`)
}

/**
 * Scope plus every ancestor prefix, specific first:
 * `'org-1.team-2.repo-3'` -> `['org-1.team-2.repo-3', 'org-1.team-2', 'org-1']`.
 * No `.` -> one entry (itself).
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
 * Merge scoped role assignments matching `scope` into `subject.roles`.
 * `scopeMode: 'flat'` (default) requires an exact scope match;
 * `'hierarchical'` also matches grants at any ancestor scope, combined per
 * `scopeCombine` (see `IConfig.scopeMode` / `IConfig.scopeCombine`).
 * Returns the original subject unchanged if nothing matches.
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

/**
 * Normalise an actor into the spread the event literals use, so `actor` is
 * absent rather than explicitly `undefined` on an event nobody attributed.
 */
function actorOf(opts?: { readonly actor?: string }): { actor?: string } {
  return opts?.actor === undefined ? {} : { actor: opts.actor }
}

/** The shape both batch role writes share: a triple that may name its own actor. */
interface IActorRow<TRole extends string, TScope extends string> extends IamAdapter.ITripleRow<TRole, TScope> {
  readonly opts?: { readonly actor?: string }
}

/**
 * Emit one `role.assigned` / `role.revoked` per row of a batch result.
 *
 * Reads `changed` off the outcomes rather than recomputing it from the
 * adapter's index list, so what a consumer sees on the event and what it sees
 * on the returned {@link Batch.Result} are the same value by construction.
 * One event per row and no de-duplication: two grants of the same role are two
 * entries in the consumer's history even though they are one cache job.
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
 * Create an {@link IamEngineTypes.IAdmin} instance that delegates storage operations to the
 * given adapter and invalidates the engine's caches after mutations.
 *
 * @template TAction   - Union of valid action strings.
 * @template TResource - Union of valid resource strings.
 * @template TRole     - Union of valid role IDs.
 * @template TScope    - Union of valid scope strings.
 *
 * @param adapter - The storage adapter for policies, roles, and subject data
 * @param engine  - The engine instance whose caches should be invalidated on
 *   writes, and the optional sink its mutation events go to
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
    /**
     * Where mutation events go. Omitted when nothing is listening - the engine
     * leaves it off unless `hooks.onMutation` is wired - so an unobserved
     * install allocates no events at all, which is what keeps a large
     * `assignRoles` as cheap as it was before the bus existed.
     *
     * Structural, like `cache`, so the transaction-bound admin substitutes a
     * buffering sink with no change here.
     */
    mutations?: { emit(event: IamEngineTypes.IMutationEvent<TRole, TScope>): void | Promise<void> }
  },
): IamEngineTypes.IAdmin<TAction, TResource, TRole, TScope> {
  /**
   * The scope rules the adapters enforce, applied one layer earlier.
   *
   * `iamAssertAssignableScope` is the predicate itself rather than a second
   * copy of it, but where it runs matters as much as what it says. The adapters
   * guard their own `assignRole`, which for `assignRoles` is *inside* the write
   * loop - so a batch carrying one `'*'` row would write every row before it
   * and then throw, which is exactly the half-applied batch the pre-pass at
   * `assignRoles` exists to prevent ("a caller who fixes a malformed row and
   * retries would otherwise double-apply every row that had already landed").
   * Running it in the pre-pass makes the whole batch fail before anything is
   * written; the adapter guard stays as the backstop for a caller who reaches
   * the adapter directly.
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
   * Emit one mutation event, if anything is listening.
   *
   * Every call site is placed *after* the adapter write has resolved and after
   * the cache invalidation, so a write that threw emits nothing and a consumer
   * reacting to an event never reads a cache that still holds the old answer.
   */
  const emit =
    sink === undefined
      ? undefined
      : async (event: IamEngineTypes.IMutationEvent<TRole, TScope>): Promise<void> => {
          // Awaited, not fire-and-forget. A consumer writing this event to its
          // own history table wants that write to have happened before
          // `assignRole` resolves; otherwise a crash between the two loses the
          // only record of the grant. The engine's sink already swallows
          // throws, so awaiting cannot turn a hook bug into a failed write.
          await sink.emit(event)
        }
  /** One invalidation per subject, however many rows of the batch named it. */
  const invalidateEach = (rows: readonly IamEngineTypes.ITripleRow<TRole, TScope>[]): void => {
    for (const subjectId of new Set(rows.map((r) => r.subjectId))) engine.cache.invalidateSubject(subjectId)
  }
  /**
   * The single-row scope move, hoisted so `moveRoleScopes` can reuse it without
   * relying on `this` inside the object literal below.
   */
  const moveOne = async (
    subjectId: string,
    roleId: TRole,
    fromScope?: TScope,
    toScope?: TScope,
    actor?: string,
  ): Promise<void> => {
    const moved = adapter.updateAssignmentScope
      ? await adapter.updateAssignmentScope(subjectId, roleId, fromScope, toScope, actor)
      : false
    if (!moved) {
      // Adapter has no in-place update, or nothing matched fromScope: fall back to
      // revoke + assign so the call still succeeds (assignRole is idempotent).
      // The actor rides along on both halves so the fallback path records the
      // same provenance the in-place update would have.
      await adapter.revokeRole(subjectId, roleId, fromScope, { actor })
      await adapter.assignRole(subjectId, roleId, toScope, { actor })
    }
    engine.cache.invalidateSubject(subjectId)
    // One `role.scope-changed`, not a revoke + an assign, whichever path ran:
    // the caller asked to move a grant, and reporting the fallback's mechanics
    // would make the history depend on which adapter is installed.
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
      return adapter.listPolicies()
    },
    async getPolicy(id: string) {
      assertNonEmptyStringParam('id', id)
      return adapter.getPolicy(id)
    },
    async savePolicy(policy: AccessControl.IPolicy<TAction, TResource, TRole>, opts?: IamEngineTypes.IActorOptions) {
      const { validatePolicy } = await _getValidate()
      assertValidOrThrow('policy', validatePolicy(policy))
      await adapter.savePolicy(policy, opts)
      engine.cache.invalidatePolicies()
      await emit?.({ type: 'policy.saved', at: Date.now(), policyId: policy.id, ...actorOf(opts) })
    },
    async deletePolicy(id: string, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('id', id)
      await adapter.deletePolicy(id)
      engine.cache.invalidatePolicies()
      await emit?.({ type: 'policy.deleted', at: Date.now(), policyId: id, ...actorOf(opts) })
    },
    async listRoles() {
      return adapter.listRoles()
    },
    async getRole(id: string) {
      assertNonEmptyStringParam('id', id)
      return adapter.getRole(id)
    },
    async saveRole(role: AccessControl.IRole<TAction, TResource, TRole, TScope>, opts?: IamEngineTypes.IActorOptions) {
      const { validateRole } = await _getValidate()
      assertValidOrThrow('role', validateRole(role))
      await adapter.saveRole(role, opts)
      engine.cache.invalidateRoles(role.id)
      await emit?.({ type: 'role.saved', at: Date.now(), roleId: role.id, ...actorOf(opts) })
    },
    async deleteRole(id: string, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('id', id)
      await adapter.deleteRole(id)
      // `TRole` is erased at runtime, so there is nothing to narrow against; a
      // predicate here would be a cast wearing a disguise. Routed through the
      // one documented place so it greps alongside the other tenant literals.
      const roleId = iamAsRoleLiteral<TRole>(id)
      engine.cache.invalidateRoles(roleId)
      await emit?.({ type: 'role.deleted', at: Date.now(), roleId, ...actorOf(opts) })
    },
    async assignRole(subjectId: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions) {
      assertTriple(subjectId, roleId, scope)
      await adapter.assignRole(subjectId, roleId, scope, opts)
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
      // `'lookup'`: a revoke addresses a row that already exists, and an
      // operator holding `'*'` rows written before the guard has to be able to
      // delete them.
      assertTriple(subjectId, roleId, scope, 'lookup')
      await adapter.revokeRole(subjectId, roleId, scope, opts)
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
      // A move reads one scope and writes the other, so the two ends are not
      // the same question: `'*'` may be moved *off*, never *to*.
      assertAssignableScope(fromScope, 'lookup')
      assertAssignableScope(toScope, 'grant')
      await moveOne(subjectId, roleId, fromScope, toScope, actor)
    },
    async assignRoles(rows: readonly IamEngineTypes.IAssignRow<TRole, TScope>[]) {
      if (rows.length === 0) return batchResult([])
      // A pre-pass, not per-row: a caller who fixes a malformed row and retries
      // would otherwise double-apply every row that had already landed.
      for (const r of rows) assertTriple(r.subjectId, r.roleId, r.scope)
      // Bound, not destructured: the adapter may be a class instance whose
      // method needs its `this`.
      const assignRoleMany = adapter.assignRoleMany?.bind(adapter)
      // `null` means "written, but I cannot say which rows moved". The loop
      // path is in that position by construction: `assignRole` returns void.
      let changed: readonly number[] | null = null
      if (assignRoleMany) changed = await assignRoleMany(rows)
      else for (const r of rows) await adapter.assignRole(r.subjectId, r.roleId, r.scope, r.opts)
      invalidateEach(rows)
      const result = appliedRows(rows, changed)
      // Driven off `result.outcomes` rather than recomputing from `changed`, so
      // the `changed` a consumer reads on the event and the one it reads on the
      // batch result cannot disagree.
      await emitRowEvents(emit, result, 'role.assigned')
      return result
    },
    async revokeRoles(rows: readonly IamEngineTypes.IRevokeRow<TRole, TScope>[]) {
      if (rows.length === 0) return batchResult([])
      for (const r of rows) assertTriple(r.subjectId, r.roleId, r.scope, 'lookup')
      const revokeRoleMany = adapter.revokeRoleMany?.bind(adapter)
      let changed: readonly number[] | null = null
      if (revokeRoleMany) changed = await revokeRoleMany(rows)
      else for (const r of rows) await adapter.revokeRole(r.subjectId, r.roleId, r.scope, r.opts)
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
      // Delegates per row to the single-row move, which owns the revoke + assign
      // fallback for adapters with no in-place update. There is no set-based
      // form to fall back FROM, so this loop is the fast path, not a shim.
      return loopFallback(rows, (r) => moveOne(r.subjectId, r.roleId, r.fromScope, r.toScope, r.actor))
    },
    invalidateSubjects(subjectIds: readonly string[]) {
      for (const id of new Set(subjectIds)) engine.cache.invalidateSubject(id)
    },
    async setAttributes(subjectId: string, attrs: IamPrimitives.Attributes, opts?: IamEngineTypes.IActorOptions) {
      assertNonEmptyStringParam('subjectId', subjectId)
      assertAttributesParam(attrs)
      await adapter.setSubjectAttributes(subjectId, attrs, opts)
      engine.cache.invalidateSubject(subjectId)
      // Key names only - see `IAttributesSetEvent`. `Object.keys` and not the
      // bag itself, so the event cannot carry personal data into a consumer's
      // durable log by accident.
      await emit?.({ type: 'attributes.set', at: Date.now(), subjectId, keys: Object.keys(attrs), ...actorOf(opts) })
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
      // Validate the whole snapshot before touching the adapter. Interleaving
      // meant an invalid row halfway through left the store half-applied: in
      // `replace` mode the deletions had already landed, so deny policies could
      // be gone with nothing written back in their place.
      const { validatePolicy, validateRole } = await _getValidate()
      for (const p of snapshot.policies) assertValidOrThrow('policy', validatePolicy(p))
      for (const r of snapshot.roles) assertValidOrThrow('role', validateRole(r))

      const mode = options.mode ?? 'merge'
      let policiesDeleted = 0
      let rolesDeleted = 0
      // Buffered and emitted after every write lands. An import that throws
      // halfway is not a history of the rows that happened to go first.
      const imported: IamEngineTypes.IMutationEvent<TRole, TScope>[] = []
      const at = Date.now()
      if (mode === 'replace') {
        const [existingPolicies, existingRoles] = await Promise.all([adapter.listPolicies(), adapter.listRoles()])
        const incomingPolicyIds = new Set(snapshot.policies.map((p) => p.id))
        const incomingRoleIds = new Set(snapshot.roles.map((r) => r.id))
        for (const p of existingPolicies) {
          if (!incomingPolicyIds.has(p.id)) {
            await adapter.deletePolicy(p.id)
            policiesDeleted++
            if (emit) imported.push({ type: 'policy.deleted', at, policyId: p.id, ...actorOf(opts) })
          }
        }
        for (const r of existingRoles) {
          if (!incomingRoleIds.has(r.id)) {
            await adapter.deleteRole(r.id)
            rolesDeleted++
            if (emit) imported.push({ type: 'role.deleted', at, roleId: r.id, ...actorOf(opts) })
          }
        }
      }
      for (const p of snapshot.policies) {
        await adapter.savePolicy(p)
        if (emit) imported.push({ type: 'policy.saved', at, policyId: p.id, ...actorOf(opts) })
      }
      for (const r of snapshot.roles) {
        await adapter.saveRole(r)
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
