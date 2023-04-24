import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    proxy: {
    '/api': {
      target: 'https://localhost:9543/',
      changeOrigin: true,
      secure: false,
      cors:false
//      rewrite: (path) => path.replace(/^\/api/, '')
    },
    '/ca': {
      target: 'https://localhost:9543/',
      changeOrigin: true,
      secure: false,
      cors:false
    },
    },
  }
})
