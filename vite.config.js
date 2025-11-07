import { defineConfig } from 'vite'

export default defineConfig({
  root: 'app',
  server: {
    port: 5173,
    strictPort: true,
    host: 'localhost'
  },
  // Ensure build output goes to app/dist so Tauri bundles latest assets
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})