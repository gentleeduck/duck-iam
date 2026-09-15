import { defineConfig } from 'drizzle-kit'

/** INFO: the seeded pg on the e2e container, for browsing the schema in `drizzle-kit studio`. Not shipped. */
export default defineConfig({
  dbCredentials: { url: 'postgres://duckauth:duckauth@127.0.0.1:55184/duckauth_studio' },
  dialect: 'postgresql',
  schema: './src/adapters/drizzle/pg/pg.schema.ts',
})
