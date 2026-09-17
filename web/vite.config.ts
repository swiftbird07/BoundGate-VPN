import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The build lands in the Go package that embeds it (internal/control/web).
// `vite dev` proxies the API to the lab control plane; passkeys then need
// http://localhost:5173 in admin.origins.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../internal/control/web/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'https://localhost:18443', changeOrigin: false, secure: false },
    },
  },
});
