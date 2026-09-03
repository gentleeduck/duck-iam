// Folds the drizzle-kit sqlite output into the single .sql file the sqlite
// adapter tests apply. Run via `bun run e2e:schema`, which regenerates it first.
//
// These tables used to be hand-written inside the test files, which is how they
// came to declare a `tenant_id` no query reads and to omit the unique indexes
// entirely - so the suite exercised a laxer schema than any real database, and
// the email/username guards were never actually under test.
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const OUT_DIR = '.drizzle-e2e-out-sqlite'
const TARGET = join('src', 'test', 'sqlite-e2e-schema.sql')

const migration = readdirSync(OUT_DIR)
  .filter((f) => f.endsWith('.sql'))
  .sort()
  .at(-1)
if (!migration) throw new Error(`no .sql found in ${OUT_DIR}; did drizzle-kit generate run?`)

const header = [
  '-- Generated from src/adapters/drizzle/sqlite/sqlite.schema.ts by `bun run e2e:schema`.',
  '-- Applied by the sqlite adapter tests so they run against the declared schema,',
  '-- unique indexes and checks included. Do not hand-edit; regenerate on schema change.',
].join('\n')

const ddl = readFileSync(join(OUT_DIR, migration), 'utf8').replaceAll('--> statement-breakpoint', '')

writeFileSync(TARGET, `${header}\n${ddl}`)
rmSync(OUT_DIR, { force: true, recursive: true })
console.log(`wrote ${TARGET} from ${migration}`)
