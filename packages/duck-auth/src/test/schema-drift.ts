import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { expect } from 'vitest'

/**
 * The generated DDL each e2e suite applies, read rather than composed so the tests and a consumer's
 * `drizzle-kit` output cannot disagree.
 */
const read = (file: string): string => readFileSync(fileURLToPath(new URL(`./${file}`, import.meta.url)), 'utf8')

export const PG_DDL: string = read('pg-e2e-schema.sql')
export const MYSQL_DDL: string = read('mysql-e2e-schema.sql')

/** Every constraint a table declares, by name. Uniques are declared as `uniqueIndex`, so they arrive
 *  under `indexes` rather than `uniqueConstraints` on both dialects. */
export function declaredNames(config: {
  checks: { name: string }[]
  foreignKeys: { getName(): string }[]
  indexes: { config: { name?: string } }[]
  uniqueConstraints: { name?: string }[]
}): string[] {
  return [
    ...config.checks.map((c) => c.name),
    ...config.indexes.map((i) => i.config.name ?? '(unnamed index)'),
    ...config.uniqueConstraints.map((u) => u.name ?? '(unnamed unique)'),
    ...config.foreignKeys.map((f) => f.getName()),
  ]
}

/** Every name the schema declares reaches the DDL a deployment is handed. */
export function expectSchemaReachesDdl(ddl: string, declared: string[], label: string): void {
  for (const name of declared) {
    expect(ddl, `${label}: \`${name}\` is declared but never reached the generated DDL`).toMatch(
      new RegExp(`[\`"]${name}[\`"]`),
    )
  }
}

/** The other direction, which is the one a stale file fails: a constraint deleted from the schema stays in
 *  the DDL and every suite goes on testing against it. Limited to the library's own name prefixes, so a
 *  driver's implicit primary-key names do not read as drift. */
export function expectDdlDeclaresNothingExtra(ddl: string, declared: string[], label: string): void {
  const known = new Set(declared)
  const found = [...new Set([...ddl.matchAll(/\b((?:chk|uq|fk)_[a-z0-9_]+)\b/g)].map((m) => m[1] as string))]

  expect(
    found.filter((name) => !known.has(name)),
    `${label}: the generated DDL carries names the schema no longer declares`,
  ).toEqual([])
}
