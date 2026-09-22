import { resolve } from 'node:path'
import { migrate } from 'drizzle-orm/bun-sqlite/migrator'
import { db } from '.'

migrate(db, { migrationsFolder: resolve(import.meta.dir, '../../drizzle') })

console.log('Migration complete - data.db ready')
