import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  base: "/web/",
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080', // 目标服务器地址
        changeOrigin: true,
        rewrite: (path) => {
          let replace = path.replace(/^\/api/, '');
          return replace;
        },
      },
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})

