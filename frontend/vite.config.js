import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { outDir: '../ipsec_xray/webui', emptyOutDir: true, sourcemap: false },
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    proxy: { '/api': { target: 'http://localhost:8000', changeOrigin: true } },
  },
})
