import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { readFileSync } from 'node:fs'

// A key defined twice in a locale silently overrides the first one (it
// happened: a field label replaced an unrelated hint). Fail the build.
function noDuplicateI18nKeys() {
  return {
    name: 'no-duplicate-i18n-keys',
    buildStart() {
      const src = readFileSync(new URL('./src/i18n.js', import.meta.url), 'utf8')
      for (const block of src.split(/\n  (?=\w+: \{)/).slice(1)) {
        const seen = new Set()
        for (const [, key] of block.matchAll(/\n    (\w+):/g)) {
          if (seen.has(key)) this.error(`i18n: key "${key}" defined twice in locale ${block.slice(0, 2)}`)
          seen.add(key)
        }
      }
    },
  }
}

// The build lands in internal/web/dist, which the Go binary embeds.
// `npm run dev` proxies the API to a local `lanhound -demo`.
export default defineConfig({
  plugins: [noDuplicateI18nKeys(), vue()],
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 300,
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8686' },
  },
})
