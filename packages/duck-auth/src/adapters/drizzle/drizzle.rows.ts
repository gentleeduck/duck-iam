import { type Column, eq, type GetColumnData, type SQL, sql } from 'drizzle-orm'
import type { Identities } from '~/core/identities/identities.types'
import { patchOrNone } from '~/core/patch'

/** An identity row read whole, with its logins attached. Drizzle types the `profile` column by the
 *  schema and nothing at runtime can prove an arbitrary `Profile`, so this is the one place in the
 *  adapters where that is taken at its word. */
export function rowWithLinks<Profile extends Identities.ProfileMetadataBase>(
  row: Omit<Identities.Me, 'providers'>,
  providers: Identities.ProviderLink[] = [],
): Identities.Me<Profile> {
  return { ...row, providers } as Identities.Me<Profile>
}

/** A join repeats the identity once per login, so the rows fold by id and the logins gather under each.
 *  A caller that read one row destructures the first. Order is the join's; a caller matching its input
 *  back against the answer goes by id. */
export function rowsWithLinks<Profile extends Identities.ProfileMetadataBase>(
  rows: { identity: Omit<Identities.Me, 'providers'>; link: Identities.ProviderLink | null }[],
): Identities.Me<Profile>[] {
  const byId = new Map<string, Identities.Me<Profile>>()
  for (const row of rows) {
    const seen = byId.get(row.identity.id)
    const me = seen ?? rowWithLinks<Profile>(row.identity)
    if (!seen) byId.set(row.identity.id, me)
    if (row.link) me.providers.push(row.link)
  }

  return [...byId.values()]
}

/** A tenant filter only when the caller named one, since `and` drops an undefined. A named tenant never
 *  matches a global (NULL) row, because `eq` never matches NULL. */
export function inTenant<T extends Column>(column: T, tenantId: GetColumnData<T, 'raw'> | undefined): SQL | undefined {
  return tenantId === undefined ? undefined : eq(column, tenantId)
}

/** A shallow merge the way `json_set` takes it, matching the object spread the memory adapter runs.
 *  WARN: not `json_patch`/`json_merge_patch`, because RFC 7396 drops a key whose value is null. */
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
