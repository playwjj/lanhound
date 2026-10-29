import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The build lands in internal/web/dist, which the Go binary embeds.
// `npm run dev` proxies the API to a local `lanhound -demo`.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 300,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8686' },
  },
})
