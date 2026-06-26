import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  base: '/',
  build: {
    outDir: '../backend/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:6380',
        // Upgrade WebSocket connections (the live progress stream at
        // /api/progress/ws) through to the backend, not just HTTP.
        ws: true,
      },
    },
  },
});
