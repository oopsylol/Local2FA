import { defineConfig } from 'vite'

export default defineConfig({
  root: 'app',
  server: {
    port: 5173,
    strictPort: true,
    host: 'localhost'
  }
})