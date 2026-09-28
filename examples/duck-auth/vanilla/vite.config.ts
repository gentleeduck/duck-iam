import { proxy } from '@examples/duck-auth-ui/backends'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [tailwindcss()],
  server: { port: 5500, strictPort: true, proxy },
})
