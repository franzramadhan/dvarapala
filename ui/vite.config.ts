import { defineConfig } from 'vitest/config';
import solid from 'vite-plugin-solid';
import tailwindcss from '@tailwindcss/vite';

// The Rust binary embeds dist/*.gz under fixed names, so no hashes and a
// single chunk. base is /ui/ so index.html points at /ui/app.js and /ui/app.css.
export default defineConfig({
  base: '/ui/',
  plugins: [solid(), tailwindcss()],
  build: {
    target: 'es2022',
    assetsDir: '',
    cssCodeSplit: false,
    modulePreload: false,
    assetsInlineLimit: 0,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: 'app.js',
        assetFileNames: (info) => (info.names.some((n) => n.endsWith('.css')) ? 'app.css' : '[name][extname]'),
      },
    },
  },
  server: {
    proxy: Object.fromEntries(
      ['/status', '/top', '/blocks', '/reload', '/session'].map((p) => [
        p,
        { target: 'http://127.0.0.1:9091', changeOrigin: false },
      ]),
    ),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    restoreMocks: true,
  },
});
