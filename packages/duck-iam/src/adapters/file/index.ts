import * as nodePath from 'node:path'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamCopyAttributes, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamCloneRow,
  iamNormalizePolicy,
  iamRoleWithoutInherit,
  iamUnreadablePolicy,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

/** Types for the JSON-file adapter. Type-only namespace - zero bundle cost. */
export namespace IamFile {
  /**
   * The minimal `node:fs/promises`-compatible surface used by {@link IamFileAdapter}.
   * Tests inject an in-memory fake; production passes the real Node module.
   */
  export interface IFS {
    /** Reads a file as UTF-8 text. */
    readFile(path: string, encoding: 'utf8'): Promise<string>
    /** Writes a file as UTF-8 text. */
    writeFile(path: string, data: string, encoding: 'utf8'): Promise<void>
    /**
     * Creates a directory. The adapter never passes `options`, so the immediate parent must already exist.
     * NOTE: non-recursive so a typo in `init.path` cannot build a deep tree.
     */
    mkdir(path: string, options?: { recursive?: boolean }): Promise<unknown>
    /**
     * Optional: resolves symlinks. When present, the `rootDir` check rejects symlinks escaping the root;
     * when absent (typical for test fakes), that symlink check is skipped.
     */
    realpath?(path: string): Promise<string>
    /**
     * Optional: atomically moves `oldPath` over `newPath`, used to write a temp file and rename it over the store.
     * WARN: without it the adapter writes in place, and a crash mid-write can leave a truncated store.
     *
     * @param oldPath - Absolute path of the temporary file.
     * @param newPath - Absolute path to replace.
     */
    rename?(oldPath: string, newPath: string): Promise<void>
  }

  /** Describes initialization options for {@link IamFileAdapter}. */
  export interface IInit<TFS extends IFS = IFS> {
    /**
     * **Absolute** path of the JSON store file. Construction rejects a relative path, a `..` segment, or a path
     * escaping {@link rootDir}. The file is created on first write; its parent directory must already exist.
     */
    path: string
    /**
     * Optional containment root: {@link IamFile.IInit.path} must resolve inside it, after symlink resolution when `realpath` exists.
     * SECURITY: set it whenever `path` derives from caller input; omitting it logs a one-shot warning.
     */
    rootDir?: string
    /** Filesystem driver: `await import('node:fs/promises')` in Node or Bun, or any {@link IFS} for tests. */
    fs: TFS
    /**
     * Called when a stored row fails parse or validation: a bad role row is dropped, a bad policy row throws.
     * SECURITY: policy rows fail closed because the dropped policy could be the one that denies.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'file'>
  }

  /**
   * The on-disk JSON state shape held by {@link IamFileAdapter}; exposed for typing the cache, not wire API.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TRole - Constrains valid role strings.
   * @template TScope - Constrains valid scope strings.
   */
  export interface IState<
    TAction extends string,
    TResource extends string,
    TRole extends string,
    TScope extends string,
  > {
    policies: Record<string, AccessControl.IPolicy<TAction, TResource, TRole>>
    roles: Record<string, AccessControl.IRole<TAction, TResource, TRole, TScope>>
    assignments: Record<string, Array<{ role: TRole; scope?: TScope }>>
    attributes: Record<string, IamPrimitives.Attributes>
    /**
     * Ids whose attributes row was corrupt at load, mapped to the raw value; reads throw until a write replaces it.
     * NOTE: the raw value is written back on every flush so the next load still detects it, as redis/http do.
     */
    corruptAttributes?: Map<string, unknown>
    /**
     * Ids whose assignments row held a malformed entry, mapped to the raw row; reads throw until a write replaces it.
     * NOTE: a dropped grant may be the one a deny policy targets, so it fails closed exactly as `corruptAttributes` does.
     */
    corruptAssignments?: Map<string, unknown>
  }
}

/**
 * Process-wide latch for the missing-rootDir warning.
 * SECURITY: the warning omits the path so logs cannot act as a path-existence oracle.
 */
let _ROOTDIR_WARNED_FIRED = false

/**
 * Persists the access store as a single JSON file; single-writer model (no external locking).
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 *
 * @example
 * ```ts
 * const adapter = new IamFileAdapter({
 *   fs: await import('node:fs/promises'),
 *   path: path.resolve(__dirname, 'iam-store.json'),
 *   rootDir: __dirname,
 * })
 * const engine = new IamEngine({ adapter })
 * ```
 */
export class IamFileAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
  TFS extends IamFile.IFS = IamFile.IFS,
> implements IamAdapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private readonly _path: string
  private readonly _parentDir: string
  private readonly _rootDir: string | null
  /** Cache for {@link IamFileAdapter._canonicalRootDir}. */
  private _canonicalRoot: string | null = null
  private readonly _fs: TFS
  private readonly _onPolicyError?: IamAdapter.RowErrorHandler<'file'>
  private _cache: IamFile.IState<TAction, TResource, TRole, TScope> | null = null
  private _loadInFlight: Promise<IamFile.IState<TAction, TResource, TRole, TScope>> | null = null

  /** Creates the adapter; synchronously validates `init.path` for absoluteness, `..`, and `rootDir` containment. */
  constructor(init: IamFile.IInit<TFS>) {
    // Reject raw `..`; path.resolve would silently collapse it.
    if (init.path.split(/[\\/]+/).includes('..')) {
      throw new Error(`[@gentleduck/iam:file] IamFileAdapter path contains a ".." segment: "${init.path}"`)
    }
    const resolved = nodePath.resolve(init.path)
    if (!nodePath.isAbsolute(resolved)) {
      throw new Error(`[@gentleduck/iam:file] IamFileAdapter path must resolve to an absolute path: "${init.path}"`)
    }
    // Refuse pre-resolve relative paths; path.resolve would silently join cwd.
    if (!nodePath.isAbsolute(init.path)) {
      throw new Error(`[@gentleduck/iam:file] IamFileAdapter path must be supplied as an absolute path: "${init.path}"`)
    }

    let rootDir: string | null = null
    if (init.rootDir !== undefined) {
      if (!nodePath.isAbsolute(init.rootDir)) {
        throw new Error(`[@gentleduck/iam:file] IamFileAdapter rootDir must be absolute: "${init.rootDir}"`)
      }
      rootDir = nodePath.resolve(init.rootDir)
      const rel = nodePath.relative(rootDir, resolved)
      if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
        throw new Error(`[@gentleduck/iam:file] IamFileAdapter path "${resolved}" escapes rootDir "${rootDir}"`)
      }
    } else if (!_ROOTDIR_WARNED_FIRED) {
      // Once-per-process; do not echo the path (request-derived; log-oracle).
      _ROOTDIR_WARNED_FIRED = true
      console.warn(
        '[@gentleduck/iam:file] IamFileAdapter constructed without rootDir. ' +
          'Any caller deriving the path from request data should set rootDir for defence in depth.',
      )
    }

    this._path = resolved
    this._parentDir = nodePath.dirname(resolved)
    this._rootDir = rootDir
    this._fs = init.fs
    this._onPolicyError = init.onPolicyError
  }

  /**
   * Resolves symlinks via `realpath`, when the driver has one, and re-checks containment under `_rootDir`.
   * SECURITY: runs before every write but only on cache-miss reads; a later symlink swap fails the next write.
   */
  private async _assertWithinRoot(): Promise<void> {
    if (!this._rootDir || !this._fs.realpath) return
    // The store file may not exist yet (first run); fall back to the parent directory's realpath.
    let canonical: string
    try {
      canonical = await this._fs.realpath(this._path)
    } catch (err) {
      // SECURITY: non-ENOENT failures must propagate; hostile symlinks could bypass containment.
      const code = err !== null && err !== undefined ? Reflect.get(Object(err), 'code') : undefined
      if (code && code !== 'ENOENT') throw err
      try {
        const canonicalParent = await this._fs.realpath(this._parentDir)
        canonical = nodePath.join(canonicalParent, nodePath.basename(this._path))
      } catch (parentErr) {
        const parentCode =
          parentErr !== null && parentErr !== undefined ? Reflect.get(Object(parentErr), 'code') : undefined
        if (parentCode && parentCode !== 'ENOENT') throw parentErr
        // Parent missing too: the read path's ENOENT branch handles it and the write path reports it.
        return
      }
    }
    // Compare with the root's own realpath, or a symlinked root (`/var` -> `/private/var`) would contain nothing.
    const canonicalRoot = await this._canonicalRootDir(this._rootDir)
    const rel = nodePath.relative(canonicalRoot, canonical)
    if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
      throw new Error(
        `[@gentleduck/iam:file] IamFileAdapter realpath "${canonical}" escapes rootDir "${canonicalRoot}" (symlink traversal)`,
      )
    }
  }

  /**
   * `root` with symlinks resolved, cached for the adapter's lifetime (a failed resolution caches the textual form).
   * NOTE: assumes the root never moves; if it does, containment fails closed and writes are refused until restart.
   */
  private async _canonicalRootDir(root: string): Promise<string> {
    if (this._canonicalRoot !== null) return this._canonicalRoot
    try {
      this._canonicalRoot = this._fs.realpath ? await this._fs.realpath(root) : root
    } catch {
      // Root not created yet: fall back to the textual form the constructor validated.
      this._canonicalRoot = root
    }
    return this._canonicalRoot
  }

  /**
   * Reads a top-level `policies`/`roles` field: missing is empty, wrong-typed throws.
   * SECURITY: loading a corrupt `policies` field as `{}` would erase every deny in the store.
   */
  private _rootField(parsed: Record<string, unknown>, name: 'policies' | 'roles'): Record<string, unknown> {
    const v = parsed[name]
    if (v === undefined || v === null) return {}
    if (isPlainObject(v)) return v
    throw new Error(
      `[@gentleduck/iam:file] "${name}" must be an object, got ${Array.isArray(v) ? 'array' : typeof v}; refusing to load the store as empty`,
    )
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'file', rowId })
      return
    }
    console.warn(`[@gentleduck/iam:file] dropped malformed row "${rowId}": ${err.message}`)
  }

  private async _loadState(): Promise<IamFile.IState<TAction, TResource, TRole, TScope>> {
    if (this._cache) return this._cache
    if (this._loadInFlight) return this._loadInFlight
    // Clear in-flight on ANY throw, or a stuck rejected promise pins the adapter in failure until restart.
    const pending = (async () => {
      try {
        await this._assertWithinRoot()
        let raw: string
        try {
          raw = await this._fs.readFile(this._path, 'utf8')
        } catch (err) {
          // Only ENOENT is recoverable; anything else must surface.
          const code = err !== null && err !== undefined ? Reflect.get(Object(err), 'code') : undefined
          if (code !== 'ENOENT') {
            throw new Error(
              `[@gentleduck/iam:file] load failed (${code ?? 'unknown'}): ${err instanceof Error ? err.message : String(err)}`,
            )
          }
          // SECURITY: null-prototype dicts, so ids like `__proto__` cannot read or pollute the prototype chain.
          const empty: IamFile.IState<TAction, TResource, TRole, TScope> = {
            policies: Object.create(null),
            roles: Object.create(null),
            assignments: Object.create(null),
            attributes: Object.create(null),
          }
          this._cache = empty
          return empty
        }
        let parsedRaw: unknown
        try {
          parsedRaw = JSON.parse(raw)
        } catch (err) {
          // WARN: throw, never set _cache to {}; a later _flush would erase a recoverable file.
          this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), this._path)
          throw new Error(
            `[@gentleduck/iam:file] store at "${this._path}" is corrupt (JSON parse failed) - refusing to load; restore from backup before retrying`,
          )
        }

        if (!isPlainObject(parsedRaw)) {
          const got = parsedRaw === null ? 'null' : Array.isArray(parsedRaw) ? 'array' : typeof parsedRaw
          this._reportPolicyError(new Error(`store root: expected object, got ${got}`), this._path)
          throw new Error(
            `[@gentleduck/iam:file] store at "${this._path}" is corrupt (root is ${got}, not an object) - refusing to load; restore from backup before retrying`,
          )
        }
        const parsed = parsedRaw

        // Validate rows: a bad policy throws, a bad role is dropped. Null-proto dicts block prototype pollution.
        const policies: Record<string, AccessControl.IPolicy<TAction, TResource, TRole>> = Object.create(null)
        const policiesRaw = this._rootField(parsed, 'policies')
        for (const [rowId, p] of Object.entries(policiesRaw)) {
          const policy = parsePolicyRow<TAction, TResource, TRole>(p)
          if (policy !== null) {
            policies[rowId] = policy
          } else {
            const issues = validatePolicy(p)
              .issues.map((i) => i.message)
              .join('; ')
            this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
            throw iamUnreadablePolicy('file', rowId, issues)
          }
        }
        const roles: Record<string, AccessControl.IRole<TAction, TResource, TRole, TScope>> = Object.create(null)
        const rolesRaw = this._rootField(parsed, 'roles')
        for (const [rowId, r] of Object.entries(rolesRaw)) {
          const role = parseRoleRow<TAction, TResource, TRole, TScope>(r)
          if (role !== null) {
            roles[rowId] = role
          } else {
            const issues = validateRole(r)
              .issues.map((i) => i.message)
              .join('; ')
            this._reportPolicyError(new Error(`Invalid role "${rowId}": ${issues}`), rowId)
          }
        }

        const state: IamFile.IState<TAction, TResource, TRole, TScope> = {
          policies,
          roles,
          ...parseFileAssignments<TRole, TScope>(parsed.assignments, (rowId, reason) =>
            this._reportPolicyError(new Error(`assignments[${rowId}]: ${reason}`), rowId),
          ),
          ...parseFileAttributes(parsed.attributes, (rowId, reason) =>
            this._reportPolicyError(new Error(`attributes[${rowId}]: ${reason}`), rowId),
          ),
        }
        this._cache = state
        return state
      } finally {
        this._loadInFlight = null
      }
    })()
    this._loadInFlight = pending
    // No-op catch so an unawaited rejection cannot crash Node; the caller still sees it via `pending`.
    pending.catch(() => undefined)
    return pending
  }

  /** NOTE: serialises flushes, or two writes can rename out of order and leave the older snapshot on disk. */
  private _flushChain: Promise<void> = Promise.resolve()

  private _flush(): Promise<void> {
    const next = this._flushChain.then(
      () => this._flushNow(),
      () => this._flushNow(),
    )
    // The chain copy swallows rejections so one failed write does not poison later ones; the caller still gets `next`.
    this._flushChain = next.catch(() => {})
    return next
  }

  /** The on-disk shape: corrupt rows go back out verbatim, and the `corrupt*` markers never do. */
  private _serializableState(state: IamFile.IState<TAction, TResource, TRole, TScope>): Record<string, unknown> {
    // NOTE: null-prototype, since ids come from the file and `attributes['__proto__'] = raw` would drop that row.
    const attributes: Record<string, unknown> = Object.assign(Object.create(null), state.attributes)
    for (const [id, raw] of state.corruptAttributes ?? []) attributes[id] = raw
    const assignments: Record<string, unknown> = Object.assign(Object.create(null), state.assignments)
    for (const [id, raw] of state.corruptAssignments ?? []) assignments[id] = raw
    return { assignments, attributes, policies: state.policies, roles: state.roles }
  }

  /**
   * Flushes, and drops the cache if the flush fails so the next read reloads from disk.
   * WARN: writes mutate `_cache` before flushing; a kept cache would serve a refused write and persist it later.
   */
  private async _flushNow(): Promise<void> {
    const state = this._cache
    if (!state) {
      // NOTE: not a defensive no-op. A null cache means an earlier flush in this chain failed and discarded the
      // state this caller mutated, so its write is lost.
      throw new Error(
        '[@gentleduck/iam:file] IamFileAdapter discarded its in-memory state after an earlier write failed, ' +
          'so this write did not reach the store. Reload and retry it.',
      )
    }
    try {
      await this._writeState(state)
    } catch (err) {
      // Only if nobody reloaded meanwhile; clobbering a fresh cache would force a reload on every later reader.
      if (this._cache === state) this._cache = null
      throw err
    }
  }

  private async _writeState(state: IamFile.IState<TAction, TResource, TRole, TScope>): Promise<void> {
    await this._assertWithinRoot()
    // NOTE: non-recursive mkdir of the immediate parent only, so a typo'd `init.path` cannot build a deep tree.
    try {
      await this._fs.mkdir(this._parentDir)
    } catch (err) {
      // EEXIST is the happy path; anything else surfaces.
      const code = err !== null && err !== undefined ? Reflect.get(Object(err), 'code') : undefined
      if (code !== 'EEXIST') {
        throw new Error(
          `[@gentleduck/iam:file] IamFileAdapter parent directory "${this._parentDir}" is not accessible (${code ?? 'unknown'}). ` +
            'Create it explicitly; the adapter no longer does recursive mkdir.',
        )
      }
    }
    const data = JSON.stringify(this._serializableState(state), null, 2)
    if (!this._fs.rename) {
      // WARN: no rename (test fake, browser shim) means an in-place write, which a crash can truncate.
      await this._fs.writeFile(this._path, data, 'utf8')
      return
    }
    // WARN: temp file then rename, so a crash mid-write leaves the old store, not a truncated one with no denies.
    const tmpPath = `${this._path}.${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}.tmp`
    await this._fs.writeFile(tmpPath, data, 'utf8')
    await this._fs.rename(tmpPath, this._path)
  }

  /** Lists every policy persisted on disk. */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const s = await this._loadState()
    return Object.values(s.policies).map(iamCloneRow)
  }

  /** Fetches a policy by ID, or `null` when absent. */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const s = await this._loadState()
    const p = s.policies[id]
    return p === undefined ? null : iamCloneRow(p)
  }

  /** Stores or overwrites a policy and flushes to disk. */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('file', p)
    const s = await this._loadState()
    s.policies[p.id] = iamNormalizePolicy(p)
    await this._flush()
  }

  /** Removes a policy by ID and flushes to disk. */
  async deletePolicy(id: string): Promise<void> {
    const s = await this._loadState()
    delete s.policies[id]
    await this._flush()
  }

  /** Lists every role persisted on disk. */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const s = await this._loadState()
    return Object.values(s.roles).map(iamCloneRow)
  }

  /** Fetches a role by ID, or `null` when absent. */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const s = await this._loadState()
    const r = s.roles[id]
    return r === undefined ? null : iamCloneRow(r)
  }

  /** Stores or overwrites a role and flushes to disk. */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('file', r)
    const s = await this._loadState()
    s.roles[r.id] = iamCloneRow(r)
    await this._flush()
  }

  /**
   * Removes a role by ID and every grant that named it, then flushes to disk.
   * NOTE: mirrors the SQL `ON DELETE CASCADE`; a kept orphan would re-grant a role later recreated under that id.
   */
  async deleteRole(id: string): Promise<void> {
    const s = await this._loadState()
    delete s.roles[id]
    for (const [roleId, role] of Object.entries(s.roles)) {
      const stripped = iamRoleWithoutInherit(role, id)
      if (stripped !== null) s.roles[roleId] = stripped
    }
    for (const subjectId of s.corruptAssignments?.keys() ?? []) {
      // The raw row is what gets written back, so the sweep below cannot reach it; say so rather than imply it did.
      this._reportPolicyError(
        new Error(`assignments[${subjectId}]: corrupt, so the grant of role "${id}" was not swept`),
        subjectId,
      )
    }
    for (const [subjectId, entries] of Object.entries(s.assignments)) {
      const kept = entries.filter((e) => e.role !== id)
      if (kept.length === entries.length) continue
      if (kept.length === 0) delete s.assignments[subjectId]
      else s.assignments[subjectId] = kept
    }
    await this._flush()
  }

  /** Throws when the subject's assignments row is corrupt; a partial role set is what makes a deny stop applying. */
  private _assertReadableAssignments(s: IamFile.IState<TAction, TResource, TRole, TScope>, id: string): void {
    if (s.corruptAssignments?.has(id)) {
      throw new Error(`[@gentleduck/iam:file] corrupted assignments for "${id}" (malformed {role, scope?} entry)`)
    }
  }

  /** Lists a subject's unscoped (global) role IDs, deduplicated; throws on a corrupt row. */
  async getSubjectRoles(id: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const s = await this._loadState()
    this._assertReadableAssignments(s, id)
    const entries = s.assignments[id] ?? []
    return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
  }

  /** Lists a subject's scoped `(role, scope)` assignments only; throws on a corrupt row. */
  async getSubjectScopedRoles(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const s = await this._loadState()
    this._assertReadableAssignments(s, id)
    const hasScope = (e: { role: TRole; scope?: TScope }): e is { role: TRole; scope: TScope } => e.scope != null
    return (s.assignments[id] ?? []).filter(hasScope).map((e) => ({ role: e.role, scope: e.scope }))
  }

  /**
   * Grants a role to a subject, optionally within a scope; duplicate `(role, scope)` pairs are ignored.
   * Refuses a role that is not stored - see {@link iamAssertRoleExists}.
   */
  async assignRole(id: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('file', scope)
    iamAssertNoAssignOptions('file', opts)
    // NOTE: the loader refuses an empty scope, so it is refused here too (as redis does) rather than persisted.
    if (scope === '') {
      throw new Error('[@gentleduck/iam:file] scope must not be an empty string; omit it for a global assignment')
    }
    const s = await this._loadState()
    this._assertReadableAssignments(s, id)
    iamAssertRoleExists('file', Object.hasOwn(s.roles, roleId))
    let entries = s.assignments[id]
    if (!entries) {
      entries = []
      s.assignments[id] = entries
    }
    if (!entries.some((e) => e.role === roleId && e.scope === scope)) {
      entries.push({ role: roleId, scope })
    }
    await this._flush()
  }

  /**
   * Removes a role assignment from a subject.
   * WARN: omitting `scope` removes EVERY assignment for the role, scoped ones included (as redis/drizzle/prisma do).
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('file', scope, 'lookup')
    const s = await this._loadState()
    this._assertReadableAssignments(s, id)
    const entries = s.assignments[id]
    if (!entries) return
    s.assignments[id] =
      scope === undefined
        ? entries.filter((e) => e.role !== roleId)
        : entries.filter((e) => !(e.role === roleId && e.scope === scope))
    await this._flush()
  }

  /**
   * Moves an existing assignment to a different scope in place.
   *
   * @returns `false` when no `(roleId, fromScope)` assignment exists for this subject.
   */
  async updateAssignmentScope(id: string, roleId: TRole, fromScope?: TScope, toScope?: TScope): Promise<boolean> {
    const s = await this._loadState()
    this._assertReadableAssignments(s, id)
    const entries = s.assignments[id]
    const entry = entries?.find((e) => e.role === roleId && e.scope === fromScope)
    if (!entry) return false
    // The target scope may already be granted; drop the source rather than duplicate it.
    if (entries?.some((e) => e !== entry && e.role === roleId && e.scope === toScope)) {
      s.assignments[id] = (entries ?? []).filter((e) => e !== entry)
    } else {
      entry.scope = toScope
    }
    await this._flush()
    return true
  }

  /** Fetches a subject's attribute bag, or `{}` when none is recorded; throws on a corrupt row. */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const s = await this._loadState()
    if (s.corruptAttributes?.has(id)) {
      // SECURITY: corrupt is not empty; `{}` would strip ABAC. Matches redis/http.
      throw new Error(`[@gentleduck/iam:file] corrupted attributes for "${id}" (not a JSON object)`)
    }
    // NOTE: return a copy (see `iamCopyAttributes`); the cached bag is live state the next flush writes to disk.
    const stored = s.attributes[id]
    return stored === undefined ? {} : iamCopyAttributes(stored)
  }

  /** Shallow-merges an attribute patch into the subject's bag and flushes; replaces a corrupt row. */
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('file', id, attrs)
    const s = await this._loadState()
    s.corruptAttributes?.delete(id)
    // NOTE: copy the patch too; `Object.assign` is shallow, so nested caller arrays would ride out on a later flush.
    s.attributes[id] = Object.assign(Object.create(null), s.attributes[id] ?? {}, iamCopyAttributes(attrs))
    await this._flush()
  }
}

/** Structural parser for the `assignments` map; malformed rows are reported and kept in `corruptAssignments`. */
function parseFileAssignments<TRole extends string, TScope extends string>(
  raw: unknown,
  report: (rowId: string, reason: string) => void,
): {
  assignments: Record<string, Array<{ role: TRole; scope?: TScope }>>
  corruptAssignments: Map<string, unknown>
} {
  const corruptAssignments = new Map<string, unknown>()
  if (raw === undefined || raw === null) return { assignments: Object.create(null), corruptAssignments }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    report('__root__', `expected object, got ${Array.isArray(raw) ? 'array' : typeof raw}`)
    return { assignments: Object.create(null), corruptAssignments }
  }
  const out: Record<string, Array<{ role: TRole; scope?: TScope }>> = Object.create(null)
  for (const [rowId, rowVal] of Object.entries(raw)) {
    if (!Array.isArray(rowVal)) {
      report(rowId, `expected array of {role, scope?}, got ${rowVal === null ? 'null' : typeof rowVal}`)
      corruptAssignments.set(rowId, rowVal)
      continue
    }
    // SECURITY: a dropped grant may be the one a deny policy targets, so a bad entry corrupts the row and
    // reads throw; the readable entries are kept only so an explicit write can repair the row without losing them.
    const entries: Array<{ role: TRole; scope?: TScope }> = []
    for (const [i, entry] of rowVal.entries()) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        report(rowId, `assignment entry [${i}] not a plain object`)
        corruptAssignments.set(rowId, rowVal)
        continue
      }
      const role = Reflect.get(entry, 'role')
      if (typeof role !== 'string' || role.length === 0) {
        report(rowId, `assignment entry [${i}] missing/non-string role`)
        corruptAssignments.set(rowId, rowVal)
        continue
      }
      const scope = Reflect.get(entry, 'scope')
      if (scope !== undefined && (typeof scope !== 'string' || scope.length === 0)) {
        report(rowId, `assignment entry [${i}] scope must be a non-empty string when present`)
        corruptAssignments.set(rowId, rowVal)
        continue
      }
      const narrowed: { role: TRole; scope?: TScope } =
        scope === undefined
          ? { role: iamAsRoleLiteral<TRole>(role) }
          : { role: iamAsRoleLiteral<TRole>(role), scope: iamAsScopeLiteral<TScope>(scope) }
      entries.push(narrowed)
    }
    out[rowId] = entries
  }
  return { assignments: out, corruptAssignments }
}

/** Structural parser for the `attributes` map; malformed rows are reported and kept in `corruptAttributes`. */
function parseFileAttributes(
  raw: unknown,
  report: (rowId: string, reason: string) => void,
): { attributes: Record<string, IamPrimitives.Attributes>; corruptAttributes: Map<string, unknown> } {
  const corruptAttributes = new Map<string, unknown>()
  if (raw === undefined || raw === null) return { attributes: Object.create(null), corruptAttributes }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    report('__root__', `expected object, got ${Array.isArray(raw) ? 'array' : typeof raw}`)
    return { attributes: Object.create(null), corruptAttributes }
  }
  const out: Record<string, IamPrimitives.Attributes> = Object.create(null)
  for (const [rowId, rowVal] of Object.entries(raw)) {
    if (typeof rowVal !== 'object' || rowVal === null || Array.isArray(rowVal)) {
      report(rowId, `expected attributes object, got ${rowVal === null ? 'null' : typeof rowVal}`)
      corruptAttributes.set(rowId, rowVal)
      continue
    }
    // SECURITY: an unstorable value corrupts the whole row so reads throw; an absent attribute would retire denies.
    const narrowed = iamNarrowAttributes(rowVal)
    if (narrowed === null) {
      report(rowId, 'attribute values must be scalars, arrays of scalars, or flat records of scalars')
      corruptAttributes.set(rowId, rowVal)
      continue
    }
    const attrs: IamPrimitives.Attributes = Object.assign(Object.create(null), narrowed)
    out[rowId] = attrs
  }
  return { attributes: out, corruptAttributes }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Factory around {@link IamFileAdapter}, for callers who prefer functions to `new`. */
export function iamFileAdapter(...args: ConstructorParameters<typeof IamFileAdapter>): IamFileAdapter {
  return new IamFileAdapter(...args)
}
