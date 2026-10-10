import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// In development the report API and screenshots come from a local analyzer, as Caddy forwards them
// on the VM. Point TRIPWIRE_ANALYZER at another port when the default one is taken.
const analyzer = process.env.TRIPWIRE_ANALYZER ?? 'http://127.0.0.1:8001'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': analyzer,
      '/shots': analyzer,
    },
  },
})
