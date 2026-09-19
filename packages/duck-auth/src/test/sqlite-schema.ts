import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/** The declared sqlite schema, as DDL. */
export const SQLITE_DDL: string = readFileSync(
  fileURLToPath(new URL('./sqlite-e2e-schema.sql', import.meta.url)),
  'utf8',
)
