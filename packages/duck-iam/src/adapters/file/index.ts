import * as nodePath from 'node:path'
import type { AccessControl, Adapter, Primitives, Request } from '../../core/types'
import { validatePolicy, validateRole } from '../../core/validate'

export namespace File {
  /**
   * Describes the minimal `node:fs/promises`-compatible surface used by {@link FileAdapter}.
   *
   * Tests inject an in-memory fake; production passes the real Node module.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IFS {
    /**
     * Reads a file as UTF-8 text.
     *
     * @param path - Absolute path to read.
     * @param encoding - Must be `'utf8'`.
     * @returns The file contents as a string.
     * @author wildduck2 <https://github.com/wildduck2>
     */
    readFile(path: string, encoding: 'utf8'): Promise<string>
    /**
     * Writes a file as UTF-8 text.
     *
     * @param path - Absolute path to write.
     * @param data - String contents to persist.
     * @param encoding - Must be `'utf8'`.
     * @returns Resolves once the write completes.
     * @author wildduck2 <https://github.com/wildduck2>
     */
    writeFile(path: string, data: string, encoding: 'utf8'): Promise<void>
    /**
     * Creates a directory. **Not recursive** — the immediate parent must
     * already exist. This is intentional after SEC-003: a typo in `init.path`
     * must not silently build a deep tree.
     *
     * @param path - Absolute directory to create.
     * @returns Resolves once the directory exists.
     * @author wildduck2 <https://github.com/wildduck2>
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
     * @author wildduck2 <https://github.com/wildduck2>
     */
    realpath?(path: string): Promise<string>
  }

  /**
   * Describes initialization options for {@link FileAdapter}.
   *
   * @author wildduck2 <https://github.com/wildduck2>
   */
  export interface IInit {
    /**
     * Specifies the **absolute** path of the JSON store file.
     *
     * Rejected at construction when:
     * - the resolved path is not absolute,
     * - the normalized path contains a `..` segment, or
     * - {@link rootDir} is set and the path escapes it.
     *
     * The adapter creates the file on first write, but **does not** recursively
     * create directories — the immediate parent must already exist. This guards
     * against a typo in `path` accidentally building deep paths (SEC-003).
     */
    path: string
    /**
     * Optional containment root. When set, {@link path} must resolve to a
     * location inside this directory (after symlink resolution if the
     * filesystem driver exposes `realpath`). Strongly recommended whenever
     * any part of `path` is derived from caller-controlled input.
     *
     * If omitted, the adapter logs a one-shot `console.warn` at construction
     * and accepts any absolute path. See `audit/MIGRATION.md`.
     */
    rootDir?: string
    /**
     * Provides the filesystem driver. Pass `await import('node:fs/promises')`
     * in Node or Bun, or any object implementing {@link IFS} for tests.
     */
    fs: IFS
    /**
     * Invoked when a stored row fails JSON parse or shape validation. The
     * malformed row is dropped from the loaded state; the rest are returned
     * intact. Wire this to your alerting pipeline so corrupt rows do not
     * silently vanish from authorization decisions.
     */
    onPolicyError?: (err: Error, ctx: { adapter: 'file'; rowId: string }) => void
  }

  /**
   * Describes the on-disk JSON state shape held by {@link FileAdapter}.
   *
   * Exposed for typing the internal cache field; not part of the wire API.
   *
   * @template TAction - Constrains valid action strings.
   * @template TResource - Constrains valid resource strings.
   * @template TRole - Constrains valid role strings.
   * @template TScope - Constrains valid scope strings.
   * @author wildduck2 <https://github.com/wildduck2>
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
    attributes: Record<string, Primitives.Attributes>
  }
}

/**
 * Persists the access store as a single JSON file with read-through cache.
 *
 * Single-writer model: concurrent writers against the same file clobber each
 * other without external locking. Use only for CLIs, dev fixtures, and single
 * process apps with modest policy counts.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TRole - Constrains valid role strings.
 * @template TScope - Constrains valid scope strings.
 * @example
 * ```ts
 * import * as fs from 'node:fs/promises'
 * const adapter = new FileAdapter({ path: '/var/lib/iam/store.json', fs })
 * await adapter.savePolicy(policy)
 * ```
 * @author wildduck2 <https://github.com/wildduck2>
 */
/**
 * Process-wide latch for the missing-rootDir warning (SEC-026).
 * A single-shot Set keyed by nothing is fine — the warning text is the same
 * regardless of which adapter triggered it, and we deliberately don't include
 * the path (SEC-027) so there is nothing to key on either.
 */
let _ROOTDIR_WARNED_FIRED = false

export class FileAdapter<
  TAction extends string = string,
  TResource extends string = string,
  TRole extends string = string,
  TScope extends string = string,
> implements Adapter.IAdapter<TAction, TResource, TRole, TScope>
{
  private readonly _path: string
  private readonly _parentDir: string
  private readonly _rootDir: string | null
  private readonly _fs: File.IFS
  private readonly _onPolicyError?: (err: Error, ctx: { adapter: 'file'; rowId: string }) => void
  private _cache: File.IState<TAction, TResource, TRole, TScope> | null = null
  private _loadInFlight: Promise<File.IState<TAction, TResource, TRole, TScope>> | null = null
  // SEC-025: re-check realpath on every I/O. A one-shot latch meant an
  // attacker who swapped the file for a symlink after the first read could
  // make subsequent writes target the symlink's destination.

  /**
   * Creates a new file-backed adapter.
   *
   * Validates `init.path` synchronously (SEC-003):
   * - resolves to an absolute path via `path.resolve`,
   * - rejects relative paths and `..` segments after normalization,
   * - when `init.rootDir` is provided, requires the path to live under it.
   *
   * The symlink-escape check happens lazily on first read/write (because it
   * needs `realpath`, which is async) — see `_assertWithinRoot`.
   *
   * @param init - Provides the store path and filesystem driver.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  constructor(init: File.IInit) {
    // Reject `..` segments in the raw input. `path.normalize`/`path.resolve`
    // eagerly collapse `..` against the preceding segment, so a literal
    // `/var/lib/iam/../../etc/passwd` simplifies silently to `/etc/passwd`.
    // The user-visible intent of `..` is "escape the parent" - we refuse the
    // input regardless of where it lands.
    if (init.path.split(/[\\/]+/).includes('..')) {
      throw new Error(`duck-iam: FileAdapter path contains a ".." segment: "${init.path}"`)
    }
    const resolved = nodePath.resolve(init.path)
    if (!nodePath.isAbsolute(resolved)) {
      throw new Error(`duck-iam: FileAdapter path must resolve to an absolute path: "${init.path}"`)
    }
    // The pre-resolve form must already have been absolute. `path.resolve`
    // happily turns `./foo` into an absolute path by joining cwd; we refuse
    // that quietly-promoted case because relative inputs are exactly the
    // class of bug SEC-003 is about.
    if (!nodePath.isAbsolute(init.path)) {
      throw new Error(`duck-iam: FileAdapter path must be supplied as an absolute path: "${init.path}"`)
    }

    let rootDir: string | null = null
    if (init.rootDir !== undefined) {
      if (!nodePath.isAbsolute(init.rootDir)) {
        throw new Error(`duck-iam: FileAdapter rootDir must be absolute: "${init.rootDir}"`)
      }
      rootDir = nodePath.resolve(init.rootDir)
      const rel = nodePath.relative(rootDir, resolved)
      if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
        throw new Error(`duck-iam: FileAdapter path "${resolved}" escapes rootDir "${rootDir}"`)
      }
    } else if (!_ROOTDIR_WARNED_FIRED) {
      // SEC-026: fire the missing-rootDir warning at most once per process,
      // not per construction — a multi-tenant host that instantiates many
      // FileAdapters would otherwise drown its log stream and operators
      // start filtering the warning out, masking real misconfigurations.
      // SEC-027: do not echo the resolved path. The path may be derived
      // from request data; reflecting it back into stderr would let an
      // attacker confirm a path-existence oracle via log scraping.
      _ROOTDIR_WARNED_FIRED = true
      // eslint-disable-next-line no-console
      console.warn(
        '[duck-iam:file] FileAdapter constructed without rootDir. ' +
          'Any caller deriving the path from request data should set rootDir for defence in depth. ' +
          'See audit/MIGRATION.md.',
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
   * re-checks containment under `_rootDir`. Symlink check is skipped when
   * `realpath` is unavailable (test fakes, browser bundles) — the constructor
   * already enforced the textual containment, which is enough for those
   * environments.
   *
   * SEC-025: runs on every read AND every write. A one-shot latch let an
   * attacker swap the file for a symlink after the first I/O and steer
   * later writes to anywhere the process can reach.
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
      // SEC-053: only fall back to the parent-realpath shortcut when the
      // file is genuinely absent (ENOENT). Other errors — symlink loops
      // (ELOOP), permission denied (EACCES), filesystem busy (EBUSY) —
      // must propagate. Falling through on those errors would let an
      // attacker who can induce a non-ENOENT failure on a hostile symlink
      // bypass the containment check by reconstructing the canonical path
      // from the parent + the unverified basename.
      const code = (err as NodeJS.ErrnoException | undefined)?.code
      if (code && code !== 'ENOENT') throw err
      try {
        const canonicalParent = await this._fs.realpath(this._parentDir)
        canonical = nodePath.join(canonicalParent, nodePath.basename(this._path))
      } catch (parentErr) {
        const parentCode = (parentErr as NodeJS.ErrnoException | undefined)?.code
        if (parentCode && parentCode !== 'ENOENT') throw parentErr
        // Parent doesn't exist either - the read path's ENOENT branch handles
        // it; the write path will surface the missing-parent error explicitly.
        return
      }
    }
    const rel = nodePath.relative(this._rootDir, canonical)
    if (rel.startsWith('..') || nodePath.isAbsolute(rel)) {
      throw new Error(
        `duck-iam: FileAdapter realpath "${canonical}" escapes rootDir "${this._rootDir}" (symlink traversal)`,
      )
    }
  }

  private _reportPolicyError(err: Error, rowId: string): void {
    if (this._onPolicyError) {
      this._onPolicyError(err, { adapter: 'file', rowId })
      return
    }
    // eslint-disable-next-line no-console
    console.warn(`[duck-iam:file] dropped malformed row "${rowId}": ${err.message}`)
  }

  private async _loadState(): Promise<File.IState<TAction, TResource, TRole, TScope>> {
    if (this._cache) return this._cache
    if (this._loadInFlight) return this._loadInFlight
    // SEC-063: clear in-flight on ANY throw (including _assertWithinRoot
    // symlink-escape) — a stuck rejected promise would otherwise pin the
    // adapter in a permanent failure state until process restart.
    const pending = (async () => {
      try {
        await this._assertWithinRoot()
        let raw: string
        try {
          raw = await this._fs.readFile(this._path, 'utf8')
        } catch (err) {
          // SEC-054: only ENOENT is recoverable; anything else surfaces.
          const code = (err as NodeJS.ErrnoException | undefined)?.code
          if (code !== 'ENOENT') {
            throw new Error(
              `duck-iam FileAdapter: load failed (${code ?? 'unknown'}): ${err instanceof Error ? err.message : String(err)}`,
            )
          }
          const empty: File.IState<TAction, TResource, TRole, TScope> = {
            policies: {},
            roles: {},
            assignments: {},
            attributes: {},
          }
          this._cache = empty
          return empty
        }
        let parsed: Partial<File.IState<TAction, TResource, TRole, TScope>>
        try {
          parsed = JSON.parse(raw) as Partial<File.IState<TAction, TResource, TRole, TScope>>
        } catch (err) {
          // SEC-064: do NOT populate _cache with {} here. A subsequent
          // _flush() would serialise the empty cache and overwrite the
          // recoverable-but-corrupt file, permanently destroying the
          // operator's data. Throw the corruption so the operator restores
          // from backup before any write lands.
          this._reportPolicyError(err instanceof Error ? err : new Error(String(err)), this._path)
          throw new Error(
            `duck-iam FileAdapter: store at "${this._path}" is corrupt (JSON parse failed) — refusing to load; restore from backup before retrying`,
          )
        }

        // Validate each row; drop malformed entries instead of returning them.
        const policies: Record<string, AccessControl.IPolicy<TAction, TResource, TRole>> = {}
        for (const [rowId, p] of Object.entries(parsed.policies ?? {})) {
          const result = validatePolicy(p)
          if (result.valid) {
            policies[rowId] = p as AccessControl.IPolicy<TAction, TResource, TRole>
          } else {
            this._reportPolicyError(
              new Error(`Invalid policy "${rowId}": ${result.issues.map((i) => i.message).join('; ')}`),
              rowId,
            )
          }
        }
        const roles: Record<string, AccessControl.IRole<TAction, TResource, TRole, TScope>> = {}
        for (const [rowId, r] of Object.entries(parsed.roles ?? {})) {
          const result = validateRole(r)
          if (result.valid) {
            roles[rowId] = r as AccessControl.IRole<TAction, TResource, TRole, TScope>
          } else {
            this._reportPolicyError(
              new Error(`Invalid role "${rowId}": ${result.issues.map((i) => i.message).join('; ')}`),
              rowId,
            )
          }
        }

        const state: File.IState<TAction, TResource, TRole, TScope> = {
          policies,
          roles,
          assignments: parsed.assignments ?? {},
          attributes: parsed.attributes ?? {},
        }
        this._cache = state
        return state
      } finally {
        // SEC-063: always clear in-flight, even on throw.
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
      const code = (err as NodeJS.ErrnoException | undefined)?.code
      if (code !== 'EEXIST') {
        throw new Error(
          `duck-iam: FileAdapter parent directory "${this._parentDir}" is not accessible (${code ?? 'unknown'}). ` +
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async listPolicies(_opts?: Adapter.IReadOptions): Promise<AccessControl.IPolicy<TAction, TResource, TRole>[]> {
    const s = await this._loadState()
    return Object.values(s.policies)
  }

  /**
   * Fetches a single policy by ID.
   *
   * @param id - Identifies the policy to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching policy or `null` when absent.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getPolicy(
    id: string,
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IPolicy<TAction, TResource, TRole> | null> {
    const s = await this._loadState()
    return s.policies[id] ?? null
  }

  /**
   * Stores or overwrites a policy and flushes to disk.
   *
   * @param p - Provides the policy to persist.
   * @returns Resolves once the file is rewritten.
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async listRoles(_opts?: Adapter.IReadOptions): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope>[]> {
    const s = await this._loadState()
    return Object.values(s.roles)
  }

  /**
   * Fetches a single role by ID.
   *
   * @param id - Identifies the role to look up.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The matching role or `null` when absent.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getRole(
    id: string,
    _opts?: Adapter.IReadOptions,
  ): Promise<AccessControl.IRole<TAction, TResource, TRole, TScope> | null> {
    const s = await this._loadState()
    return s.roles[id] ?? null
  }

  /**
   * Stores or overwrites a role and flushes to disk.
   *
   * @param r - Provides the role to persist.
   * @returns Resolves once the file is rewritten.
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectRoles(id: string, _opts?: Adapter.IReadOptions): Promise<TRole[]> {
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectScopedRoles(id: string, _opts?: Adapter.IReadOptions): Promise<Request.IScopedRole<TRole, TScope>[]> {
    const s = await this._loadState()
    return (s.assignments[id] ?? [])
      .filter((e) => e.scope != null)
      .map((e) => ({ role: e.role, scope: e.scope as TScope }))
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
   * @author wildduck2 <https://github.com/wildduck2>
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
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async revokeRole(id: string, roleId: TRole, scope?: TScope): Promise<void> {
    const s = await this._loadState()
    const entries = s.assignments[id]
    if (!entries) return
    s.assignments[id] = entries.filter((e) => !(e.role === roleId && e.scope === scope))
    await this._flush()
  }

  /**
   * Fetches the attribute bag stored for a subject.
   *
   * @param id - Identifies the subject whose attributes are read.
   * @param _opts - Ignored read options accepted for interface compatibility.
   * @returns The subject's attributes or `{}` when none are recorded.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async getSubjectAttributes(id: string, _opts?: Adapter.IReadOptions): Promise<Primitives.Attributes> {
    const s = await this._loadState()
    return s.attributes[id] ?? {}
  }

  /**
   * Shallow-merges new attributes into the subject's existing bag.
   *
   * @param id - Identifies the subject whose attributes are written.
   * @param attrs - Provides the partial attribute patch to merge in.
   * @returns Resolves once the file is rewritten.
   * @author wildduck2 <https://github.com/wildduck2>
   */
  async setSubjectAttributes(id: string, attrs: Primitives.Attributes): Promise<void> {
    const s = await this._loadState()
    s.attributes[id] = { ...(s.attributes[id] ?? {}), ...attrs }
    await this._flush()
  }
}
