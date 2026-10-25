module.exports = {
  globDirectory: 'www/',
  globPatterns: ['**/*.{html,js,css,png,svg,woff,woff2}'],
  swDest: 'www/service-worker.js',
  ignoreURLParametersMatching: [/^utm_/, /^fbclid$/],
};
