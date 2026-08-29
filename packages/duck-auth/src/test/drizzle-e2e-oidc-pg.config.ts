import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'postgresql',
  out: './.drizzle-e2e-out-oidc-pg',
  schema: './src/oidc/op/drizzle/pg.ts',
})
