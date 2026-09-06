import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/**
 * The declared sqlite schema, as DDL.
 *
 * Both sqlite test files used to hand-write their own `CREATE TABLE`s. They had
 * drifted: they declared a `tenant_id` on `auth_identities` that no query in any
 * dialect reads, and they carried none of the unique indexes or check
 * constraints - so the suite ran against a laxer schema than any real database
 * and the email/username guards were never under test at all.
 *
 * Read from the generated file rather than composed here, so the tests and a
 * consumer's `drizzle-kit` output cannot disagree. Regenerate with
 * `bun run e2e:schema` after any change to the sqlite schema.
 */
export const SQLITE_DDL: string = readFileSync(
  fileURLToPath(new URL('./sqlite-e2e-schema.sql', import.meta.url)),
  'utf8',
)
