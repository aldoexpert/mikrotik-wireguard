import path from 'path';
import framework7 from 'rollup-plugin-framework7';

const SRC_DIR = path.resolve(__dirname, './src');
const PUBLIC_DIR = path.resolve(__dirname, './public');
const BUILD_DIR = path.resolve(__dirname, './www');

export default async () => {
  return {
    plugins: [framework7({ emitCss: false })],
    root: SRC_DIR,
    // Must be '/' (absolute), not '' (relative). The app uses browserHistory
    // with clean URLs (/login/, /clients/5/edit/, ...), and the Go backend
    // serves the SAME index.html for every one of them (SPA fallback). A
    // relative base makes the browser resolve asset URLs against whatever
    // path happens to be in the address bar (e.g. "./assets/x.js" becomes
    // "/login/assets/x.js" on the login page) instead of the site root --
    // every asset 404s on any route other than literally "/".
    base: '/',
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
