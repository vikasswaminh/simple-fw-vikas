import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: 'src',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'src/index.html'),
      },
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: assetInfo => {
          const info = assetInfo.name?.split('.') ?? [''];
          const ext = info[info.length - 1];
          return `assets/[name]-[hash][extname]`;
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@components': resolve(__dirname, './src/components'),
      '@pages': resolve(__dirname, './src/pages'),
      '@schemas': resolve(__dirname, './src/schemas'),
      '@utils': resolve(__dirname, './src/utils'),
      '@api': resolve(__dirname, './src/api'),
      '@router': resolve(__dirname, './src/router'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'https://127.0.0.1',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  css: {
    devSourcemap: true,
  },
});
