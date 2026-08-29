// Folds the drizzle-kit mysql output into the single .sql file the mysql e2e
// suite applies. Run via `bun run e2e:schema`, which regenerates it first.
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const OUT_DIR = '.drizzle-e2e-out-mysql'
const TARGET = join('src', 'test', 'mysql-e2e-schema.sql')

const migration = readdirSync(OUT_DIR)
  .filter((f) => f.endsWith('.sql'))
  .sort()
  .at(-1)
if (!migration) throw new Error(`no .sql found in ${OUT_DIR}; did drizzle-kit generate run?`)

const header = [
  '-- Generated from src/adapters/drizzle/mysql/mysql.schema.ts by `bun run e2e:schema`.',
  '-- Applied by the mysql e2e suite so it provisions its own database. Do not hand-edit;',
  '-- regenerate when the drizzle schema changes.',
].join('\n')

const ddl = readFileSync(join(OUT_DIR, migration), 'utf8').replaceAll('--> statement-breakpoint', '')

writeFileSync(TARGET, `${header}\n${ddl}`)
rmSync(OUT_DIR, { force: true, recursive: true })
console.log(`wrote ${TARGET} from ${migration}`)
