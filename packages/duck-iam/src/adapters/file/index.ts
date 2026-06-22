import * as nodePath from 'node:path'
import type { AccessControl, IamAdapter, IamPrimitives, IamRequest } from '../../core/types'
import {
  parsePolicyRow as parsePolicyRowShared,
  parseRoleRow as parseRoleRowShared,
  validatePolicy,
  validateRole,
} from '../../core/validate'

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
     * Creates a directory. **Not recursive** - the immediate parent must
     * already exist, so a typo in `init.path` cannot silently build a deep
     * tree.
     *
     * @param path - Absolute directory to create.
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
    onPolicyError?: (err: Error, ctx: { adapter: 'file'; rowId: string }) => void
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
  }
}

/**
 * Persists the access store as a single JSON file; single-writer model (no external locking).
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 */
/**
 * Process-wide latch for the missing-rootDir warning. The warning text is the
 * same regardless of which adapter triggered it, and the resolved path is
 * deliberately omitted so log scrapers cannot use it as a path-existence
 * oracle.
 */
let _ROOTDIR_WARNED_FIRED = false

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
  private readonly _fs: TFS
  private readonly _onPolicyError?: (err: Error, ctx: { adapter: 'file'; rowId: string }) => void
  private _cache: IamFile.IState<TAction, TResource, TRole, TScope> | null = null
  private _loadInFlight: Promise<IamFile.IState<TAction, TResource, TRole, TScope>> | null = null
  // realpath is re-checked on every I/O so an attacker cannot swap the file
  // for a symlink after first read and redirect subsequent writes.

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
      // eslint-disable-next-line no-console
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
   * re-checks containment under `_rootDir`. Runs on every read AND every
   * write so an attacker cannot swap the file for a symlink after the first
   * I/O and steer later writes elsewhere. Symlink check is skipped when
   * `realpath` is unavailable (test fakes, browser bundles) - the
   * constructor already enforced textual containment.
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
    const rel = nodePath.relative(this._rootDir, canonical)
    if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
      throw new Error(
        `[@gentleduck/iam:file] IamFileAdapter realpath "${canonical}" escapes rootDir "${this._rootDir}" (symlink traversal)`,
      )
    }
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'file', rowId })
      return
    }
    // eslint-disable-next-line no-console
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

        const parsed = isPlainObject(parsedRaw) ? parsedRaw : {}

        // IamValidate each row; drop malformed entries instead of returning them.
        // Null-proto so prototype-key reads/writes can't pollute the proto chain.
        const policies: Record<string, AccessControl.IPolicy<TAction, TResource, TRole>> = Object.create(null)
        const policiesRaw = isPlainObject(parsed.policies) ? parsed.policies : {}
        for (const [rowId, p] of Object.entries(policiesRaw)) {
          const policy = parsePolicyRow<TAction, TResource, TRole>(p)
          if (policy !== null) {
            policies[rowId] = policy
          } else {
            const issues = validatePolicy(p)
              .issues.map((i) => i.message)
              .join('; ')
            this._reportPolicyError(new Error(`Invalid policy "${rowId}": ${issues}`), rowId)
          }
        }
        const roles: Record<string, AccessControl.IRole<TAction, TResource, TRole, TScope>> = Object.create(null)
        const rolesRaw = isPlainObject(parsed.roles) ? parsed.roles : {}
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
          attributes: parseFileAttributes(parsed.attributes, (rowId, reason) =>
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

  private async _flush(): Promise<void> {
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
    await this._fs.writeFile(this._path, JSON.stringify(this._cache, null, 2), 'utf8')
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
    const s = await this._loadState()
    s.policies[p.id] = p
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
    const s = await this._loadState()
    s.roles[r.id] = r
    await this._flush()
  }

  /**
   * Removes a role by ID and flushes to disk.
   *
   * @param id - Identifies the role to delete.
   * @returns Resolves once the file is rewritten.
   */
  async deleteRole(id: string): Promise<void> {
    const s = await this._loadState()
    delete s.roles[id]
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
   * Duplicate `(role, scope)` pairs are silently ignored.
   *
   * @param id - Identifies the subject receiving the role.
   * @param roleId - Specifies the role being granted.
   * @param scope - Optional scope binding the assignment.
   * @returns Resolves once the file is rewritten.
   */
  async assignRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    const s = await this._loadState()
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
   * @param scope - Optional scope to match; omit to revoke unscoped only.
   * @returns Resolves once the file is rewritten.
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
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
   * Fetches the attribute bag stored for a subject.
   *
   * @param id - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   */
  async getSubjectAttributes(id: string, _opts?: IamAdapter.IReadOptions): Promise<IamPrimitives.Attributes> {
    const s = await this._loadState()
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
    const s = await this._loadState()
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
    const entries: Array<{ role: TRole; scope?: TScope }> = []
    let perEntryError: string | null = null
    for (const entry of rowVal) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        perEntryError = `assignment entry not a plain object`
        break
      }
      const role = Reflect.get(entry, 'role')
      if (typeof role !== 'string' || role.length === 0) {
        perEntryError = `assignment entry missing/non-string role`
        break
      }
      const scope = Reflect.get(entry, 'scope')
      if (scope !== undefined && (typeof scope !== 'string' || scope.length === 0)) {
        perEntryError = `assignment entry scope must be a non-empty string when present`
        break
      }
      const narrowed: { role: TRole; scope?: TScope } =
        scope === undefined
          ? { role: roleAs<TRole>(role) }
          : { role: roleAs<TRole>(role), scope: scopeAs<TScope>(scope) }
      entries.push(narrowed)
    }
    if (perEntryError !== null) {
      report(rowId, perEntryError)
      continue
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
): Record<string, IamPrimitives.Attributes> {
  if (raw === undefined || raw === null) return Object.create(null)
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    report('__root__', `expected object, got ${Array.isArray(raw) ? 'array' : typeof raw}`)
    return Object.create(null)
  }
  const out: Record<string, IamPrimitives.Attributes> = Object.create(null)
  for (const [rowId, rowVal] of Object.entries(raw)) {
    if (typeof rowVal !== 'object' || rowVal === null || Array.isArray(rowVal)) {
      report(rowId, `expected attributes object, got ${rowVal === null ? 'null' : typeof rowVal}`)
      continue
    }
    const attrs: IamPrimitives.Attributes = Object.create(null)
    for (const [k, v] of Object.entries(rowVal)) {
      attrs[k] = v as IamPrimitives.AttributeValue
    }
    out[rowId] = attrs
  }
  return out
}

/**
 * Narrowing helpers for the typed-string generics. We have already
 * runtime-validated that the value is a non-empty string; the role/scope
 * type parameters are TS-only constraints that the file adapter can't
 * verify (the legitimate string values are determined by the calling
 * app's `createIam`).
 */
function roleAs<TRole extends string>(s: string): TRole {
  return s as TRole
}
function scopeAs<TScope extends string>(s: string): TScope {
  return s as TScope
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const parsePolicyRow = parsePolicyRowShared
const parseRoleRow = parseRoleRowShared
