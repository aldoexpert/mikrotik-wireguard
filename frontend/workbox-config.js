module.exports = {
  globDirectory: 'www/',
  globPatterns: ['**/*.{html,js,css,png,svg,woff,woff2}'],
  swDest: 'www/service-worker.js',
  ignoreURLParametersMatching: [/^utm_/, /^fbclid$/],
  // Without these, an updated build can sit "waiting" behind an old,
  // already-active service worker indefinitely (nothing in this app sends
  // the SKIP_WAITING message), so the browser keeps serving a stale
  // index.html that references JS/CSS chunk hashes which no longer exist
  // on the server after a new deploy -- the blank white screen users saw.
  skipWaiting: true,
  clientsClaim: true,
  cleanupOutdatedCaches: true,
  // SPA fallback: browserHistory routes like /login/, /clients/5/edit/
  // aren't individual precached URLs, so without this the service worker
  // has no match for them and behaves inconsistently between online/
  // offline. Always resolve navigation requests to the (now always
  // current, thanks to skipWaiting+clientsClaim) cached shell.
  navigateFallback: '/index.html',
};
