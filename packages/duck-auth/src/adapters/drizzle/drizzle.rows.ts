import { type Column, eq, type GetColumnData, type SQL, sql } from 'drizzle-orm'
import type { Adapter } from '~/adapters/adapter'
import { actorId } from '~/core/actor'
import type { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import { patchOrNone, stripUndefined } from '~/core/patch'

/** `Profile` refines a column no dialect ever reads - it is stored opaquely and handed back.
 *  WARN: this narrows a whole store, which is not checked; {@link rowWithLinks} narrows where it is built. */
export function forProfile<Profile extends Identities.ProfileMetadataBase, Code extends AuthError.Code>(
  store: Adapter.Wrapped<Adapter.Me['identities'], Code>,
): Adapter.Wrapped<Adapter.Me<Profile>['identities'], Code> {
  return store as Adapter.Wrapped<Adapter.Me<Profile>['identities'], Code>
}

/** NOTE: a patch says which columns a caller may move; what a write adds is who moved them. */
export function stamped<T extends object>(patch: T): Partial<T> & { updatedBy: string | null } {
  return { ...stripUndefined(patch), updatedBy: actorId() }
}

/** A join repeats the identity once per login, so the row is the first and the logins are all of them.
 *  NOTE: a drizzle table is a module singleton whose `$type` cannot take an adapter's `Profile`. */
export function rowWithLinks<Profile extends Identities.ProfileMetadataBase>(
  rows: { identity: Omit<Identities.Me, 'providers'>; link: Identities.ProviderLink | null }[],
): Identities.Me<Profile> | null {
  const [first] = rows
  if (!first) return null

  const providers: Identities.ProviderLink[] = []
  for (const row of rows) if (row.link) providers.push(row.link)

  return { ...first.identity, providers } as Identities.Me<Profile>
}

/** A tenant filter only when the caller named one, since `and` drops an undefined. A named tenant never
 *  matches a global (NULL) row, because `eq` never matches NULL. */
export function inTenant<T extends Column>(column: T, tenantId: GetColumnData<T, 'raw'> | undefined): SQL | undefined {
  return tenantId === undefined ? undefined : eq(column, tenantId)
}

/** A shallow merge the way `json_set` takes it, matching the object spread the memory adapter runs.
 *  WARN: not `json_patch`/`json_merge_patch` - RFC 7396 drops a key whose value is null. */
export function jsonMerged(doc: SQL, patch: object, literal: (json: string) => SQL): SQL | undefined {
  const kept = patchOrNone(patch)
  if (!kept) return undefined

  // Backslash before quote, or a key ending in one escapes the closing quote and the path no longer parses:
  // sqlite and mysql answer a raw driver error where pg and the memory adapter store the key.
  const args = Object.entries(kept).flatMap(([key, value]) => [
    sql`${`$."${key.replace(/["\\]/g, '\\$&')}"`}`,
    literal(JSON.stringify(value)),
  ])

  return sql`json_set(${doc}, ${sql.join(args, sql`, `)})`
}
