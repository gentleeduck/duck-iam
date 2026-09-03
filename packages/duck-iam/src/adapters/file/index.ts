import * as nodePath from 'node:path'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import { parsePolicyRow, parseRoleRow, validatePolicy, validateRole } from '../../core/validate'
import { iamAssertNoAssignOptions } from '../../shared/assign-options'
import { iamAssertRoleExists } from '../../shared/assignment-target'
import { iamAssertAttributesParam, iamNarrowAttributes } from '../../shared/attributes'
import {
  iamAssertSavablePolicy,
  iamAssertSavableRole,
  iamNormalizePolicy,
  iamUnreadablePolicy,
} from '../../shared/rows'
import { iamAssertAssignableScope } from '../../shared/scope'
import { iamAsRoleLiteral, iamAsScopeLiteral } from '../../shared/tenant-literals'

export namespace IamFile {
  /**
   * Describes the minimal `node:fs/promises`-compatible surface used by {@link IamFileAdapter}.
   *
   * Tests inject an in-memory fake; production passes the real Node module.
   */
  export interface IFS {
    /**
     * Reads a file as UTF-8 text.
     *
     * @param path - Absolute path to read.
     * @param encoding - Must be `'utf8'`.
     * @returns The file contents as a string.
     */
    readFile(path: string, encoding: 'utf8'): Promise<string>
    /**
     * Writes a file as UTF-8 text.
     *
     * @param path - Absolute path to write.
     * @param data - String contents to persist.
     * @param encoding - Must be `'utf8'`.
     * @returns Resolves once the write completes.
     */
    writeFile(path: string, data: string, encoding: 'utf8'): Promise<void>
    /**
     * Creates a directory. The adapter always calls this **without options**,
     * so the immediate parent must already exist and a typo in `init.path`
     * cannot silently build a deep tree.
     *
     * @param path - Absolute directory to create.
     * @param options - Accepted for `node:fs/promises` structural compatibility; never passed by the adapter.
     * @returns Resolves once the directory exists.
     */
    mkdir(path: string, options?: { recursive?: boolean }): Promise<unknown>
    /**
     * Optional: resolve symlinks for a path. When present (e.g. the real
     * `node:fs/promises` provides it) the adapter uses it during the
     * `rootDir` containment check to reject symlinks that escape the root.
     * Test fakes typically omit this; the symlink check is skipped when
     * unavailable.
     *
     * @param path - Path to canonicalise.
     * @returns The canonical path with all symlinks resolved.
     */
    realpath?(path: string): Promise<string>
    /**
     * Optional: atomically replace `oldPath` with `newPath`. When present the
     * adapter writes to a temporary file and renames it over the store, so a
     * crash mid-write cannot leave a truncated file that reads back as zero
     * policies. Without it the adapter falls back to writing in place.
     *
     * @param oldPath - Absolute path of the temporary file.
     * @param newPath - Absolute path to replace.
     * @returns Resolves once the rename completes.
     */
    rename?(oldPath: string, newPath: string): Promise<void>
  }

  /** Describes initialization options for {@link IamFileAdapter}. */
  export interface IInit<TFS extends IFS = IFS> {
    /**
     * Specifies the **absolute** path of the JSON store file.
     *
     * Rejected at construction when:
     * - the resolved path is not absolute,
     * - the normalized path contains a `..` segment, or
     * - {@link rootDir} is set and the path escapes it.
     *
     * The adapter creates the file on first write, but **does not** recursively
     * create directories - the immediate parent must already exist, guarding
     * against a typo in `path` accidentally building deep paths.
     */
    path: string
    /**
     * Optional containment root. When set, {@link path} must resolve to a
     * location inside this directory (after symlink resolution if the
     * filesystem driver exposes `realpath`). Strongly recommended whenever
     * any part of `path` is derived from caller-controlled input.
     *
     * If omitted, the adapter logs a one-shot `console.warn` at construction
     * and accepts any absolute path.
     */
    rootDir?: string
    /**
     * Provides the filesystem driver. Pass `await import('node:fs/promises')`
     * in Node or Bun, or any object implementing {@link IFS} for tests.
     */
    fs: TFS
    /**
     * Invoked when a stored row fails JSON parse or shape validation. The
     * malformed row is dropped from the loaded state; the rest are returned
     * intact. Wire this to your alerting pipeline so corrupt rows do not
     * silently vanish from authorization decisions.
     */
    onPolicyError?: IamAdapter.RowErrorHandler<'file'>
  }

  /**
   * Describes the on-disk JSON state shape held by {@link IamFileAdapter}.
   *
   * Exposed for typing the internal cache field; not part of the wire API.
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
     * Subject ids whose attributes row was dropped as corrupt at load, mapped to
     * the raw value read from the file. Reads throw until an admin write
     * replaces the row, and the raw value is written back on every flush so the
     * next load re-detects the corruption - redis and http re-derive it from the
     * stored bytes on every read, and this is how the file adapter matches them.
     * Without it the marker lived for one process: the next flush serialised a
     * cache whose corrupt row had already been dropped, quietly repairing the
     * store into the "empty" state the read had just refused to serve.
     */
    corruptAttributes?: Map<string, unknown>
  }
}

/**
 * Process-wide latch for the missing-rootDir warning. The warning text is the
 * same regardless of which adapter triggered it, and the resolved path is
 * deliberately omitted so log scrapers cannot use it as a path-existence
 * oracle.
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
  /** Cache for {@link _canonicalRootDir}. */
  private _canonicalRoot: string | null = null
  private readonly _fs: TFS
  private readonly _onPolicyError?: IamAdapter.RowErrorHandler<'file'>
  private _cache: IamFile.IState<TAction, TResource, TRole, TScope> | null = null
  private _loadInFlight: Promise<IamFile.IState<TAction, TResource, TRole, TScope>> | null = null
  // realpath is re-checked on the first read (cache miss) and before EVERY
  // write. It is not re-checked on a cache hit: `_loadState` returns `_cache`
  // before reaching `_assertWithinRoot`. Swapping the file for a symlink after
  // the first read therefore does not re-open the read path - but it also
  // cannot steer a later write, because the write path checks unconditionally
  // and fails closed. This comment used to say "every I/O", which is the
  // reason a reviewer would not look.

  /**
   * Create the adapter; synchronously validates `init.path` for absoluteness, `..`, and `rootDir` containment.
   *
   * @param init - Provides the store path and filesystem driver.
   */
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
   * Resolves symlinks via `realpath` (when the FS driver exposes one) and
   * re-checks containment under `_rootDir`.
   *
   * Runs before every write (`:449`) and on a read that actually touches the
   * filesystem (`:319`) - **not** on a read served from `_cache`, which returns
   * one line earlier. So a symlink swapped in after the first read is not
   * re-detected by later reads; it is caught the next time anything writes, and
   * that write throws rather than following the link.
   *
   * The symlink check is skipped when `realpath` is unavailable (test fakes,
   * browser bundles) - the constructor already enforced textual containment.
   */
  private async _assertWithinRoot(): Promise<void> {
    if (!this._rootDir || !this._fs.realpath) return
    // The store file itself may not exist yet (first run); fall back to the
    // parent directory's realpath, which must exist by the time we read or
    // write.
    let canonical: string
    try {
      canonical = await this._fs.realpath(this._path)
    } catch (err) {
      // Non-ENOENT failures must propagate; hostile symlinks could bypass containment.
      const code = err !== null && err !== undefined ? Reflect.get(Object(err), 'code') : undefined
      if (code && code !== 'ENOENT') throw err
      try {
        const canonicalParent = await this._fs.realpath(this._parentDir)
        canonical = nodePath.join(canonicalParent, nodePath.basename(this._path))
      } catch (parentErr) {
        const parentCode =
          parentErr !== null && parentErr !== undefined ? Reflect.get(Object(parentErr), 'code') : undefined
        if (parentCode && parentCode !== 'ENOENT') throw parentErr
        // Parent doesn't exist either - the read path's ENOENT branch handles
        // it; the write path will surface the missing-parent error explicitly.
        return
      }
    }
    // Compare against the root's own realpath. A textually-resolved root that
    // is itself reached through a symlink (a `/var` -> `/private/var` style
    // link) would otherwise never contain a canonical path.
    const canonicalRoot = await this._canonicalRootDir(this._rootDir)
    const rel = nodePath.relative(canonicalRoot, canonical)
    if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
      throw new Error(
        `[@gentleduck/iam:file] IamFileAdapter realpath "${canonical}" escapes rootDir "${canonicalRoot}" (symlink traversal)`,
      )
    }
  }

  /**
   * `root` with symlinks resolved, computed once and cached for the adapter's
   * lifetime - including a resolution that failed and fell back to the textual
   * form.
   *
   * "The root does not move under us" is an assumption, not something enforced.
   * When it is violated every direction fails closed (the containment check
   * throws), so the adapter refuses its own writes until the process restarts
   * rather than writing outside the root. That is the right side to fail on,
   * but it is a liveness cost worth knowing about before caching more here.
   */
  private async _canonicalRootDir(root: string): Promise<string> {
    if (this._canonicalRoot !== null) return this._canonicalRoot
    try {
      this._canonicalRoot = this._fs.realpath ? await this._fs.realpath(root) : root
    } catch {
      // Root not resolvable yet (not created): the textual form is the best
      // available base, and it is what the constructor already validated.
      this._canonicalRoot = root
    }
    return this._canonicalRoot
  }

  /**
   * Present-but-wrong-typed top-level field. Unlike a single malformed row,
   * this one throws: treating a corrupt `policies` field as `{}` reports the
   * store as having no policies at all, which erases every deny in it.
   * A missing field is still an empty set.
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
    // Clear in-flight on ANY throw (including _assertWithinRoot
    // symlink-escape) - a stuck rejected promise would otherwise pin the
    // adapter in a permanent failure state until process restart.
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
          // Null-proto dicts so attacker-controlled ids (`__proto__`) cannot
          // (a) read Object.prototype back, or (b) pollute the proto chain
          // via setter assignment.
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
          // Throw, never set _cache to {}; a later _flush would erase a recoverable file.
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

        // Validate each row; drop malformed entries instead of returning them.
        // Null-proto so prototype-key reads/writes can't pollute the proto chain.
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
          assignments: parseFileAssignments<TRole, TScope>(parsed.assignments, (rowId, reason) =>
            this._reportPolicyError(new Error(`assignments[${rowId}]: ${reason}`), rowId),
          ),
          ...parseFileAttributes(parsed.attributes, (rowId, reason) =>
            this._reportPolicyError(new Error(`attributes[${rowId}]: ${reason}`), rowId),
          ),
        }
        this._cache = state
        return state
      } finally {
        // Always clear in-flight, even on throw.
        this._loadInFlight = null
      }
    })()
    this._loadInFlight = pending
    // Catch-noop on the stored promise so an unawaited rejection elsewhere
    // doesn't crash Node; the caller still sees the rejection via `pending`.
    pending.catch(() => undefined)
    return pending
  }

  /**
   * Serialises flushes. Without this, two in-flight writes can each snapshot
   * the cache and then rename in the opposite order, leaving the older snapshot
   * on disk and losing the newer write.
   */
  private _flushChain: Promise<void> = Promise.resolve()

  private _flush(): Promise<void> {
    const next = this._flushChain.then(
      () => this._flushNow(),
      () => this._flushNow(),
    )
    // The chain copy swallows rejections so one failed write does not poison
    // every later one; the caller still owns `next`'s rejection.
    this._flushChain = next.catch(() => {})
    return next
  }

  /**
   * The on-disk shape. Serialising `_cache` directly wrote `corruptAttributes`
   * out as `{}` - a `Set` has no enumerable own properties - and, worse, wrote
   * an `attributes` map with the corrupt rows simply missing, so an unrelated
   * write repaired a store the adapter had refused to read. Corrupt rows go back
   * out verbatim, and the marker itself never reaches the file.
   */
  private _serializableState(state: IamFile.IState<TAction, TResource, TRole, TScope>): Record<string, unknown> {
    // Null-prototype: `id` is a subject id read from the file, and on a normal
    // object `attributes['__proto__'] = raw` runs the setter - the corrupt row
    // would be silently dropped from the output this method exists to preserve
    // verbatim.
    const attributes: Record<string, unknown> = Object.assign(Object.create(null), state.attributes)
    for (const [id, raw] of state.corruptAttributes ?? []) attributes[id] = raw
    return { assignments: state.assignments, attributes, policies: state.policies, roles: state.roles }
  }

  private async _flushNow(): Promise<void> {
    if (!this._cache) return
    await this._assertWithinRoot()
    // Non-recursive mkdir of the immediate parent only. If a grandparent is
    // missing the caller's deployment is misconfigured - throwing here is
    // safer than silently building a deep tree from a typo'd `init.path`.
    try {
      await this._fs.mkdir(this._parentDir)
    } catch (err) {
      // EEXIST is the happy path - directory already there. Anything else is
      // a real problem and must surface to the caller.
      const code = err !== null && err !== undefined ? Reflect.get(Object(err), 'code') : undefined
      if (code !== 'EEXIST') {
        throw new Error(
          `[@gentleduck/iam:file] IamFileAdapter parent directory "${this._parentDir}" is not accessible (${code ?? 'unknown'}). ` +
            'Create it explicitly; the adapter no longer does recursive mkdir.',
        )
      }
    }
    const data = JSON.stringify(this._serializableState(this._cache), null, 2)
    if (!this._fs.rename) {
      // No rename available (test fake, browser shim): in-place write, which a
      // crash can truncate. Documented on IamFile.IFS.rename.
      await this._fs.writeFile(this._path, data, 'utf8')
      return
    }
    // Write beside the store then rename over it. A crash mid-write leaves the
    // previous file intact instead of a truncated one that would load as zero
    // policies, i.e. as if every deny had been deleted.
    const tmpPath = `${this._path}.${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}.tmp`
    await this._fs.writeFile(tmpPath, data, 'utf8')
    await this._fs.rename(tmpPath, this._path)
  }

  /**
   * Lists every policy persisted on disk.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All stored policies.
   */
  async listPolicies(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const s = await this._loadState()
    return Object.values(s.policies)
  }

  /**
   * Fetches a single policy by ID.
   *
   * @param id - Identifies the policy to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching policy or `null` when absent.
   */
  async getPolicy(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const s = await this._loadState()
    return s.policies[id] ?? null
  }

  /**
   * Stores or overwrites a policy and flushes to disk.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the file is rewritten.
   */
  async savePolicy(p: AccessControl.IPolicy<TAction, TResource, TRole>): Promise<void> {
    iamAssertSavablePolicy('file', p)
    const s = await this._loadState()
    s.policies[p.id] = iamNormalizePolicy(p)
    await this._flush()
  }

  /**
   * Removes a policy by ID and flushes to disk.
   *
   * @param id - Identifies the policy to delete.
   * @returns Resolves once the file is rewritten.
   */
  async deletePolicy(id: string): Promise<void> {
    const s = await this._loadState()
    delete s.policies[id]
    await this._flush()
  }

  /**
   * Lists every role persisted on disk.
   *
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns All stored roles.
   */
  async listRoles(_opts?: IamAdapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const s = await this._loadState()
    return Object.values(s.roles)
  }

  /**
   * Fetches a single role by ID.
   *
   * @param id - Identifies the role to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching role or `null` when absent.
   */
  async getRole(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const s = await this._loadState()
    return s.roles[id] ?? null
  }

  /**
   * Stores or overwrites a role and flushes to disk.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the file is rewritten.
   */
  async saveRole(r: AccessControl.IRole<TAction, TResource, TRole, TScope>): Promise<void> {
    iamAssertSavableRole('file', r)
    const s = await this._loadState()
    s.roles[r.id] = r
    await this._flush()
  }

  /**
   * Removes a role by ID, and with it every grant that named it.
   *
   * The grants go too because the SQL schemas take them: `fk_iam_assignments_role`
   * is `ON DELETE CASCADE`, so `deleteRole('editor')` left `getSubjectRoles`
   * returning `editor` here and `[]` on drizzle and prisma - one call, two
   * answers. Keeping the orphan is not the harmless option either: it reads as
   * a grant, `assignRole` now refuses to create one like it, and recreating a
   * role under the reused id hands it back to everyone who once held it,
   * without an operator granting anything.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the file is rewritten.
   */
  async deleteRole(id: string): Promise<void> {
    const s = await this._loadState()
    delete s.roles[id]
    for (const [subjectId, entries] of Object.entries(s.assignments)) {
      const kept = entries.filter((e) => e.role !== id)
      if (kept.length === entries.length) continue
      if (kept.length === 0) delete s.assignments[subjectId]
      else s.assignments[subjectId] = kept
    }
    await this._flush()
  }

  /**
   * Lists unscoped (global) roles assigned to a subject.
   *
   * @param id - Identifies the subject whose global roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Deduplicated array of role IDs without scope.
   */
  async getSubjectRoles(id: string, _opts?: IamAdapter.IReadOptions): Promise<TRole[]> {
    const s = await this._loadState()
    const entries = s.assignments[id] ?? []
    return [...new Set(entries.filter((e) => e.scope == null).map((e) => e.role))]
  }

  /**
   * Lists scoped role assignments for a subject.
   *
   * @param id - Identifies the subject whose scoped roles are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns Array of `(role, scope)` pairs for scoped assignments only.
   */
  async getSubjectScopedRoles(
    id: string,
    _opts?: IamAdapter.IReadOptions,
  ): Promise<IamRequest.IScopedRole<TRole, TScope>[]> {
    const s = await this._loadState()
    const hasScope = (e: { role: TRole; scope?: TScope }): e is { role: TRole; scope: TScope } => e.scope != null
    return (s.assignments[id] ?? []).filter(hasScope).map((e) => ({ role: e.role, scope: e.scope }))
  }

  /**
   * Grants a role to a subject, optionally restricted to a scope.
   *
   * Duplicate `(role, scope)` pairs are silently ignored. A role that is not
   * stored is refused - see {@link iamAssertRoleExists}.
   *
   * @param id - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the file is rewritten.
   */
  async assignRole(id: string, roleId: TRole, scope?: TScope, opts?: IamAdapter.IAssignOptions): Promise<void> {
    iamAssertAssignableScope('file', scope)
    iamAssertNoAssignOptions('file', opts)
    // The loader refuses an empty scope, so writing one persisted a state this
    // adapter cannot read back - and the read failure took the subject's *other*
    // grants with it. Refused at the write, as redis does, rather than widened.
    if (scope === '') {
      throw new Error('[@gentleduck/iam:file] scope must not be an empty string; omit it for a global assignment')
    }
    const s = await this._loadState()
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
   *
   * @param id - Identifies the subject losing the role.
   * @param roleId - Specifies the role being revoked.
   * @param scope - Optional scope to match. Omitting it removes EVERY
   *                assignment for the role, scoped ones included - not just the
   *                unscoped grant. This doc used to say the opposite, on a
   *                destructive operation.
   * @returns Resolves once the file is rewritten.
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    iamAssertAssignableScope('file', scope)
    const s = await this._loadState()
    const entries = s.assignments[id]
    if (!entries) return
    // scope-undefined removes ALL matching role assignments - matches the
    // redis/drizzle/prisma contract.
    s.assignments[id] =
      scope === undefined
        ? entries.filter((e) => e.role !== roleId)
        : entries.filter((e) => !(e.role === roleId && e.scope === scope))
    await this._flush()
  }

  /**
   * Moves an existing assignment to a different scope in place.
   *
   * @param id - Identifies the subject whose assignment is moving.
   * @param roleId - Specifies the role of the assignment being moved.
   * @param fromScope - The assignment's current scope.
   * @param toScope - The scope to move it to.
   * @returns `false` when no `(roleId, fromScope)` assignment exists for this subject.
   */
  async updateAssignmentScope(id: string, roleId: TRole, fromScope?: TScope, toScope?: TScope): Promise<boolean> {
    const s = await this._loadState()
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

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param id - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const s = await this._loadState()
    if (s.corruptAttributes?.has(id)) {
      // Corruption != empty; `{}` would silently strip ABAC. Matches redis/http.
      throw new Error(`[@gentleduck/iam:file] corrupted attributes for "${id}" (not a JSON object)`)
    }
    return s.attributes[id] ?? {}
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param id - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the file is rewritten.
   */
  async setSubjectAttributes(id: string, attrs: IamPrimitives.Attributes): Promise<void> {
    iamAssertAttributesParam('file', id, attrs)
    const s = await this._loadState()
    s.corruptAttributes?.delete(id)
    s.attributes[id] = Object.assign(Object.create(null), s.attributes[id] ?? {}, attrs)
    await this._flush()
  }
}

/**
 * Structural parser for the file adapter's `assignments` map. Malformed
 * rows are dropped and reported via the supplied error sink.
 */
function parseFileAssignments<TRole extends string, TScope extends string>(
  raw: unknown,
  report: (rowId: string, reason: string) => void,
): Record<string, Array<{ role: TRole; scope?: TScope }>> {
  if (raw === undefined || raw === null) return Object.create(null)
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    report('__root__', `expected object, got ${Array.isArray(raw) ? 'array' : typeof raw}`)
    return Object.create(null)
  }
  const out: Record<string, Array<{ role: TRole; scope?: TScope }>> = Object.create(null)
  for (const [rowId, rowVal] of Object.entries(raw)) {
    if (!Array.isArray(rowVal)) {
      report(rowId, `expected array of {role, scope?}, got ${rowVal === null ? 'null' : typeof rowVal}`)
      continue
    }
    // One malformed entry costs that entry, not the row. `break` here dropped
    // every assignment the subject had - an unrelated `viewer` grant vanished
    // because a sibling `editor` entry was bad - which is a silent, permanent
    // denial of service on that subject with nothing but a warning to show for
    // it. Each rejection is reported on its own so the operator can find it.
    const entries: Array<{ role: TRole; scope?: TScope }> = []
    for (const [i, entry] of rowVal.entries()) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        report(rowId, `assignment entry [${i}] not a plain object`)
        continue
      }
      const role = Reflect.get(entry, 'role')
      if (typeof role !== 'string' || role.length === 0) {
        report(rowId, `assignment entry [${i}] missing/non-string role`)
        continue
      }
      const scope = Reflect.get(entry, 'scope')
      if (scope !== undefined && (typeof scope !== 'string' || scope.length === 0)) {
        report(rowId, `assignment entry [${i}] scope must be a non-empty string when present`)
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
  return out
}

/**
 * Structural parser for the file adapter's `attributes` map. Malformed
 * rows are dropped and reported via the supplied error sink.
 */
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
    // A value that is not storable (a nested object-of-objects, say) makes the
    // whole row corrupt rather than being quietly typed as a primitive. The row
    // then throws on read like any other corruption, instead of reporting the
    // attribute as absent - which would retire every deny rule that tests it.
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
