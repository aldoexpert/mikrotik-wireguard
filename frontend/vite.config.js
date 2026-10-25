import path from 'path';
import framework7 from 'rollup-plugin-framework7';

const SRC_DIR = path.resolve(__dirname, './src');
const PUBLIC_DIR = path.resolve(__dirname, './public');
const BUILD_DIR = path.resolve(__dirname, './www');

export default async () => {
  return {
    plugins: [framework7({ emitCss: false })],
    root: SRC_DIR,
    base: '',
    publicDir: PUBLIC_DIR,
    build: {
      outDir: BUILD_DIR,
      assetsInlineLimit: 0,
      emptyOutDir: true,
      chunkSizeWarningLimit: 2000,
    },
    resolve: {
      alias: {
        '@': SRC_DIR,
      },
    },
    server: {
      host: true,
      port: 5173,
      historyApiFallback: true,
      proxy: {
        '/auth':      { target: 'http://localhost:8200', changeOrigin: true },
        '/wireguard': { target: 'http://localhost:8200', changeOrigin: true },
        '/network':   { target: 'http://localhost:8200', changeOrigin: true },
        '/users':     { target: 'http://localhost:8200', changeOrigin: true },
        '/system':    { target: 'http://localhost:8200', changeOrigin: true },
      },
    },
  };
};
