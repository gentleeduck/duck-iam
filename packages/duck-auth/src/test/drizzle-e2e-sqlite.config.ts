import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'sqlite',
  out: './.drizzle-e2e-out-sqlite',
  schema: './src/adapters/drizzle/sqlite/sqlite.schema.ts',
})
