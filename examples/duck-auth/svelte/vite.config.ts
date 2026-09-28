import { proxy } from '@examples/duck-auth-ui/backends'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  server: { port: 5300, strictPort: true, proxy },
})
