import { fileURLToPath } from 'node:url'
import baseConfig from '@gentleduck/vitest-config'
import { mergeConfig } from 'vitest/config'

// Local override: register the `~` alias -> ./src so tests resolve `~/…`
// imports (the shared base config has no path-alias plugin).
export default mergeConfig(baseConfig, {
  resolve: {
    alias: {
      '~': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    // Provisions throwaway Redis + Postgres for the e2e suites and removes them
    // afterwards. No-ops when DUCKAUTH_E2E_* is already set or docker is absent.
    globalSetup: [fileURLToPath(new URL('./src/test/e2e-containers.ts', import.meta.url))],
  },
})
