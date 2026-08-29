import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'mysql',
  out: './.drizzle-e2e-out-mysql',
  schema: './src/adapters/drizzle/mysql/mysql.schema.ts',
})
