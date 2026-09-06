import type { AccessControl } from '../core/types'
import { validatePolicy, validateRole } from '../core/validate'

/**
 * Adapter-boundary guards for `savePolicy` / `saveRole`.
 *
 * Shape validation ran on the *read* path for four of the six adapters, never
 * for memory, and only-after-a-restart for file:
 *
 * ```
 * savePolicy(malformed: rules not array) -> getPolicy
 *     memory   {"algorithm":"deny-overrides","id":"p1","name":"P","rules":"nope"}
 *     file     {... "rules":"nope"}      (same process; `null` after a restart)
 *     redis/prisma/drizzle/http   null
 * ```
 *
 * Two problems, not one. Memory is the adapter every test suite and every
 * prototype runs on, and it was the one that handed the engine a policy whose
 * `rules` is a string. And the file adapter gave two different answers for one
 * store depending on whether the process had restarted since the write - a
 * dev-vs-prod divergence produced by a single deploy.
 *
 * Validating on write moves the rejection to the moment the bad row is
 * introduced, where the caller still has the context to fix it, and makes all
 * six agree. The read-path checks stay: they defend against a row that reached
 * the store some other way (a migration, a second writer, a hand-edited file),
 * which is a different threat from a bad write.
 */
function assertValid(
  adapter: string,
  kind: string,
  row: unknown,
  issues: readonly { type: string; message: string }[],
): void {
  const errors = issues.filter((i) => i.type === 'error')
  if (errors.length === 0) return
  const messages = errors.map((e) => e.message).join('; ')
  throw new Error(`[@gentleduck/iam:${adapter}] refusing to save invalid ${kind} "${rowLabel(row)}": ${messages}`)
}

/** The row's own string `id` for the error message, or a stand-in when it has none. */
function rowLabel(row: unknown): string {
  if (typeof row !== 'object' || row === null || !('id' in row)) return '<no id>'
  return typeof row.id === 'string' ? row.id : String(row.id)
}

/**
 * Refuses a policy the read path would drop.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param policy  - The policy as the caller passed it. `unknown`, deliberately:
 *                  a runtime validator exists for values whose type is not
 *                  trusted - a config file, an admin form, a migration - and a
 *                  parameter narrowed to `IPolicy` could only be handed rows
 *                  already proven correct.
 * @throws When {@link validatePolicy} reports any error-level issue.
 */
export function iamAssertSavablePolicy(adapter: string, policy: unknown): void {
  assertValid(adapter, 'policy', policy, validatePolicy(policy).issues)
}

/**
 * Refuses a role the read path would drop.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param role    - The role as the caller passed it; `unknown` for the reason
 *                  given on {@link iamAssertSavablePolicy}.
 * @throws When {@link validateRole} reports any error-level issue.
 */
export function iamAssertSavableRole(adapter: string, role: unknown): void {
  assertValid(adapter, 'role', role, validateRole(role).issues)
}

/**
 * Returns the policy in the one shape every adapter round-trips.
 *
 * `savePolicy(p)` followed by `getPolicy(p.id)` used to give six answers for
 * five backends. The SQL adapters normalise through a fixed column set, so a
 * policy stored without a version came back with `version: 1`, with
 * `description`/`targets` keys present-but-undefined, and with any field
 * outside the column set gone. The other four handed the caller's own object
 * straight back. A consumer reading `policy.version` therefore got `1` on
 * prisma/drizzle and `undefined` on memory/file/redis/http, from the same
 * write - the dev-vs-prod divergence class again, this time reached by
 * swapping the adapter rather than the engine mode.
 *
 * Normalising on the write path makes the stored shape the same everywhere,
 * which is the only place the two families can be made to agree without a
 * schema migration: the SQL column set cannot grow a "field was absent" state
 * for `version`, so the four in-memory-ish adapters adopt the SQL default
 * instead. Keys stay *absent* rather than present-and-undefined so that
 * `Object.keys` agrees too, not merely `toEqual`.
 *
 * Two consequences worth stating, since both are deliberate:
 * - Fields outside {@link AccessControl.IPolicy} are dropped on every adapter.
 *   The SQL ones already dropped them; the type is the contract.
 * - The store keeps a copy, so mutating the argument after `savePolicy`
 *   returns no longer reaches back into the memory adapter's map.
 */
export function iamNormalizePolicy<TAction extends string, TResource extends string, TRole extends string>(
  policy: AccessControl.IPolicy<TAction, TResource, TRole>,
): AccessControl.IPolicy<TAction, TResource, TRole> {
  return {
    id: policy.id,
    name: policy.name,
    ...(policy.description === undefined ? {} : { description: policy.description }),
    version: policy.version ?? 1,
    algorithm: policy.algorithm,
    rules: policy.rules,
    ...(policy.targets === undefined ? {} : { targets: policy.targets }),
  }
}

/**
 * The error every adapter raises for a policy row it cannot read.
 *
 * A malformed *role* row is dropped and reported: role permissions are
 * allow-only (`rolesToPolicy` emits `effect: 'allow'` and nothing else), so
 * losing one can only cost a subject a grant. A malformed *policy* row is not
 * the same shape of loss. It may have been the rule saying NO, and dropping it
 * turns a corrupt byte into an allow - and under `policyCombine: 'and'` even an
 * allow-only policy votes deny when none of its rules match, so there is no
 * subset of policies it is safe to drop without knowing the combine mode, which
 * an adapter does not.
 *
 * So the row is refused, the read fails, and the engine denies. That is the
 * same answer this package already gives for a corrupt attribute row
 * ("Corruption != empty; `{}` would silently strip ABAC"), applied to the value
 * where getting it wrong is more expensive.
 *
 * The cost is stated plainly: one unreadable policy row denies every request
 * until it is repaired. That is the deliberate trade - an authorization system
 * that cannot read its own rules must not answer as though the rules said yes.
 * `onPolicyError` fires first, so the row is named before anything throws.
 */
export function iamUnreadablePolicy(adapter: string, id: string, detail: string): Error {
  return new Error(
    `[@gentleduck/iam:${adapter}] policy "${id}" cannot be read and will not be skipped - a dropped policy may be ` +
      `the one that denies. Repair or delete the row. (${detail})`,
  )
}
