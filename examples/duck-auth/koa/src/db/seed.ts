import { buildAuth } from '@examples/duck-auth-shared/auth'
import { seedDb } from '@examples/duck-auth-shared/seed'
import { db, pool } from '.'

await seedDb(buildAuth(db))
await pool.end()
