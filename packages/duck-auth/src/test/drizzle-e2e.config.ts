import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'postgresql',
  out: './.drizzle-e2e-out',
  schema: './src/adapters/drizzle/pg/pg.schema.ts',
})
