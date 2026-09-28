import { resolve } from 'node:path'
import { migrate } from 'drizzle-orm/node-postgres/migrator'
import { db, pool } from '.'

await migrate(db, { migrationsFolder: resolve(import.meta.dir, '../../../shared/drizzle') })
await pool.end()

console.log('Migration complete - duckiam_examples ready')
