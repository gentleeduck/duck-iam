import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'mysql',
  out: './.drizzle-e2e-out-oidc-mysql',
  schema: './src/oidc/op/drizzle/mysql.ts',
})
