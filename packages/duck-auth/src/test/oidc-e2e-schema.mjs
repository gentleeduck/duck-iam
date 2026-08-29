// Folds the drizzle-kit OIDC output into the .sql files the OP e2e suites apply.
// Run via `bun run e2e:schema`, which regenerates them first.
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** @type {Array<{ dialect: string, outDir: string }>} */
const TARGETS = [
  { dialect: 'pg', outDir: '.drizzle-e2e-out-oidc-pg' },
  { dialect: 'mysql', outDir: '.drizzle-e2e-out-oidc-mysql' },
]

for (const { dialect, outDir } of TARGETS) {
  const migrations = readdirSync(outDir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
  const migration = migrations[migrations.length - 1]
  if (!migration) throw new Error(`no .sql found in ${outDir}; did drizzle-kit generate run?`)

  const header = [
    `-- Generated from src/oidc/op/drizzle/${dialect}.ts by \`bun run e2e:schema\`.`,
    '-- Applied by the OIDC OP e2e suites. Do not hand-edit; regenerate when the',
    '-- drizzle schema changes.',
  ].join('\n')

  const ddl = readFileSync(join(outDir, migration), 'utf8').replaceAll('--> statement-breakpoint', '')
  const target = join('src', 'test', `oidc-${dialect}-e2e-schema.sql`)
  writeFileSync(target, `${header}\n${ddl}`)
  rmSync(outDir, { force: true, recursive: true })
  console.log(`wrote ${target} from ${migration}`)
}
