import { defineConfig } from 'drizzle-kit'

// Generated from `src/db/schema.ts`, which re-exports the auth and iam adapters' own tables, so the local
// schema cannot drift from the one the adapters read and write.
export default defineConfig({
  dbCredentials: { url: './data.db' },
  dialect: 'sqlite',
  out: './drizzle',
  schema: './src/db/schema.ts',
})
