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
})
