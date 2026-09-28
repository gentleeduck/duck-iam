import { proxy } from '@examples/duck-auth-ui/backends'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: { port: 5200, strictPort: true, proxy },
})
