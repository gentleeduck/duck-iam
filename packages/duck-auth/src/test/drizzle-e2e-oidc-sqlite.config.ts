import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'sqlite',
  out: './.drizzle-e2e-out-oidc-sqlite',
  schema: './src/oidc/op/drizzle/sqlite.ts',
})
