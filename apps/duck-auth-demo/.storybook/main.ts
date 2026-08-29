import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { StorybookConfig } from '@storybook/react-vite'
import { mergeConfig } from 'vite'

const config: StorybookConfig = {
  framework: {
    name: '@storybook/react-vite',
    options: {
      builder: {
        viteConfigPath: undefined,
      },
    },
  },
  stories: ['../src/ui/**/*.stories.@(tsx|ts)'],
  typescript: { reactDocgen: 'react-docgen-typescript' },
  async viteFinal(viteConfig) {
    // Replace any stock react plugin with one explicitly using the
    // automatic JSX runtime so stories don't need `import React`.
    const plugins = (viteConfig.plugins ?? []).filter((p) => {
      if (!p || typeof p !== 'object') return true
      const name = (p as { name?: string }).name
      return name !== 'vite:react-babel' && name !== 'vite:react-refresh' && name !== 'vite:react-jsx'
    })
    return mergeConfig({ ...viteConfig, plugins }, {
      plugins: [react({ jsxRuntime: 'automatic' }), tailwindcss()],
    })
  },
}

export default config
