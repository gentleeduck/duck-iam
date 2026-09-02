import { fileURLToPath } from 'node:url'
import baseConfig from '@gentleduck/vitest-config'
import { configDefaults, mergeConfig } from 'vitest/config'

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
    // Split so the two kinds of test can have the deadline each one deserves.
    //
    // A unit test that has not finished in five seconds is hung, and the short
    // default is what says so quickly. An e2e case is a different animal: the
    // token-quality suite issues two thousand sessions against real Postgres
    // and Redis, which is minutes of round trips, and the valkey suites wait on
    // pub/sub delivery. Holding those to the unit-test deadline made them fail
    // whenever the machine was busy - a red suite that said nothing about the
    // code, on tests that pass in isolation.
    //
    // The deadlines below are a backstop against a genuine hang, not a
    // performance budget. Nothing asserts on elapsed time.
    projects: [
      {
        extends: true,
        test: {
          exclude: [...configDefaults.exclude, '**/*.e2e.test.ts'],
          name: 'unit',
        },
      },
      {
        extends: true,
        test: {
          hookTimeout: 120_000,
          include: ['**/*.e2e.test.ts'],
          name: 'e2e',
          testTimeout: 60_000,
        },
      },
    ],
  },
})
