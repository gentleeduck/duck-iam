import { proxy } from '@examples/duck-auth-ui/backends'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

export default defineConfig({
  plugins: [solid(), tailwindcss()],
  server: { port: 5400, strictPort: true, proxy },
})
