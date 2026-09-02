import baseConfig from '@gentleduck/vitest-config'
import { defineConfig, mergeConfig } from 'vitest/config'

/**
 * Vitest's default `include` glob reaches the whole package, so `.stryker-tmp/`
 * has to be excluded by hand: a mutation sandbox is a full copy of `src`, and
 * the Stryker config deliberately keeps tests in it. It is gitignored and does
 * not belong in `bun run test`.
 */
export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/cypress/**',
        '**/.{idea,git,cache,output,temp}/**',
        '.stryker-tmp/**',
      ],
    },
  }),
)
