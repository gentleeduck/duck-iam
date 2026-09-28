import { resolve } from 'node:path'
import { migrate } from 'drizzle-orm/node-postgres/migrator'
import { db, pool } from '.'

await migrate(db, { migrationsFolder: resolve(process.cwd(), '../shared/drizzle') })
await pool.end()

console.log('Migration complete - duck_auth_examples ready')
