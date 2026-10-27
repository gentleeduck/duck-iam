import { defineConfig } from 'tsdown'

/**
 * Shared base for tsdown builds across duck-iam packages.
 * Pass entry (and any overrides) per-package.
 *
 * @param {Parameters<typeof defineConfig>[0]} overrides
 * @returns {ReturnType<typeof defineConfig>}
 */
export function createTsdownConfig(overrides = {}) {
  return defineConfig({
    clean: true,
    dts: { sourcemap: false },
    format: ['esm', 'cjs'],
    minify: false,
    outDir: './dist',
    platform: 'neutral',
    sourcemap: false,
    target: 'esnext',
    treeshake: true,
    ...overrides,
  })
}

export const baseExternal = ['react', 'react/jsx-runtime', 'react/jsx-dev-runtime']
